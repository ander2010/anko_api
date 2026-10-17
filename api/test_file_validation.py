"""Tests for the document upload policy (api/services/file_validation.py) and its wiring."""
import io
import shutil
import tempfile
import zipfile

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from reportlab.pdfgen import canvas
from rest_framework.test import APITestCase

from api.models import AuditLog, Document, Project, User
from api.services.file_validation import FileValidationError, validate_document, validate_stream

# ─── Sample files ────────────────────────────────────────────────────────────

def make_pdf() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(72, 720, "Manual de procedimientos")
    c.showPage()
    c.save()
    return buf.getvalue()


OOXML = {
    "docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    "xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    "pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
}


def make_ooxml(kind: str, extra: dict | None = None) -> bytes:
    part, content_type = OOXML[kind]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/{part}" ContentType="{content_type}"/></Types>',
        )
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        zf.writestr(part, '<?xml version="1.0"?><root/>')
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_plain_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes/readme.txt", "just a zip")
    return buf.getvalue()


EXE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 200 + b"This program cannot be run in DOS mode."
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 500  # .msi / legacy Office container


# ─── Validator unit tests ────────────────────────────────────────────────────

class FileValidatorTests(SimpleTestCase):
    def assertAccepted(self, name, data, expected_type):
        result = validate_document(name, data)
        self.assertEqual(result.document_type, expected_type)

    def assertRejected(self, name, data, status_code):
        with self.assertRaises(FileValidationError) as ctx:
            validate_document(name, data)
        self.assertEqual(ctx.exception.status_code, status_code, ctx.exception.code)
        return ctx.exception

    def test_valid_pdf(self):
        self.assertAccepted("manual.pdf", make_pdf(), "PDF")

    def test_valid_docx(self):
        self.assertAccepted("manual.docx", make_ooxml("docx"), "DOCX")

    def test_valid_xlsx(self):
        self.assertAccepted("report.xlsx", make_ooxml("xlsx"), "XLSX")

    def test_valid_pptx(self):
        self.assertAccepted("presentation.pptx", make_ooxml("pptx"), "PPTX")

    def test_valid_txt(self):
        self.assertAccepted("notes.txt", "Notas del turno: revisar inventario.\n".encode(), "TXT")

    def test_valid_markdown(self):
        self.assertAccepted("guide.md", b"# Onboarding\n\n- Step 1\n", "MD")

    def test_exe_rejected(self):
        self.assertRejected("program.exe", EXE, 415)

    def test_bat_rejected(self):
        self.assertRejected("script.bat", b"@echo off\r\ndel *.*\r\n", 415)

    def test_msi_rejected(self):
        self.assertRejected("installer.msi", OLE, 415)

    def test_double_extension_rejected(self):
        self.assertRejected("manual.pdf.exe", EXE, 415)
        self.assertRejected("manual.exe.pdf", make_pdf(), 415)

    def test_exe_renamed_to_pdf_rejected(self):
        err = self.assertRejected("manual.pdf", EXE, 415)
        self.assertEqual(err.code, "content_windows_executable")

    def test_exe_renamed_to_txt_rejected(self):
        self.assertRejected("notes.txt", EXE, 415)

    def test_msi_renamed_to_docx_rejected(self):
        self.assertRejected("manual.docx", OLE, 415)

    def test_plain_zip_renamed_to_docx_rejected(self):
        self.assertRejected("manual.docx", make_plain_zip(), 422)

    def test_docx_structure_under_xlsx_name_rejected(self):
        self.assertRejected("report.xlsx", make_ooxml("docx"), 422)

    def test_macro_document_rejected(self):
        self.assertRejected("manual.docx", make_ooxml("docx", {"word/vbaProject.bin": b"\x00macro"}), 415)
        self.assertRejected("manual.docm", make_ooxml("docx"), 415)

    def test_corrupt_pdf_rejected(self):
        self.assertRejected("manual.pdf", b"%PDF-1.4\nthis is not really a pdf", 422)
        self.assertRejected("manual.pdf", make_pdf()[:300], 422)  # truncated
        self.assertRejected("manual.pdf", b"hello world", 422)

    def test_html_or_svg_disguised_as_text_rejected(self):
        self.assertRejected("notes.txt", b"<html><script>alert(1)</script></html>", 415)
        self.assertRejected("notes.md", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', 415)
        self.assertRejected("page.html", b"<p>hi</p>", 415)
        self.assertRejected("logo.svg", b"<svg/>", 415)

    def test_binary_disguised_as_text_rejected(self):
        self.assertRejected("notes.txt", b"abc\x00\x01\x02", 422)

    def test_over_400mb_rejected(self):
        # Sparse temp file: reports 400 MB + 1 byte without allocating it.
        with tempfile.TemporaryFile() as fh:
            fh.truncate(400 * 1024 * 1024 + 1)
            with self.assertRaises(FileValidationError) as ctx:
                validate_stream("big.pdf", fh)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_rejection_message_names_the_extension(self):
        err = self.assertRejected("QA-TEST-malicioso.exe", EXE, 415)
        self.assertIn("Unsupported file type: .exe", err.message)
        self.assertIn("Unsupported file type: .js", self.assertRejected("app.js", b"alert(1)", 415).message)
        self.assertIn("Unsupported file type: .html", self.assertRejected("page.html", b"<p>x</p>", 415).message)

    @override_settings(UPLOAD_MAX_FILE_SIZE_MB=1)
    def test_size_limit_is_configurable(self):
        self.assertRejected("big.txt", b"a" * (1024 * 1024 + 1), 413)
        self.assertAccepted("small.txt", b"a" * 1024, "TXT")

    def test_unsupported_and_dangerous_names(self):
        self.assertRejected("manual", make_pdf(), 415)
        self.assertRejected("legacy.doc", OLE, 415)
        self.assertRejected("run.sh", b"#!/bin/sh\necho hi", 415)
        self.assertRejected("x.ps1", b"Write-Host hi", 415)

    def test_empty_file_rejected(self):
        self.assertRejected("notes.txt", b"", 422)

    def test_path_in_name_is_stripped(self):
        result = validate_document("../../etc/manual.pdf", make_pdf())
        self.assertEqual(result.original_name, "manual.pdf")


# ─── API wiring tests ────────────────────────────────────────────────────────

class UploadEndpointTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media_root = tempfile.mkdtemp(prefix="anko-upload-tests-")
        cls._override = override_settings(
            DEFAULT_FILE_STORAGE="django.core.files.storage.FileSystemStorage",
            MEDIA_ROOT=cls._media_root,
        )
        cls._override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        shutil.rmtree(cls._media_root, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        from api.enterprise_document_intelligence_models import KnowledgeSource
        from api.enterprise_models import Company, CompanyMembership

        self.owner_a = User.objects.create_user(username="owner_a", email="a@test.com", password="Pass123!")
        self.owner_b = User.objects.create_user(username="owner_b", email="b@test.com", password="Pass123!")
        self.company_a = Company.objects.create(name="Company A", slug="company-a", owner=self.owner_a)
        self.company_b = Company.objects.create(name="Company B", slug="company-b", owner=self.owner_b)
        CompanyMembership.objects.create(user=self.owner_a, company=self.company_a, role="admin", status="active")
        CompanyMembership.objects.create(user=self.owner_b, company=self.company_b, role="admin", status="active")

        seed = Document.objects.create(filename="seed.txt", type="txt", size=4, hash="seed", uploaded_by=self.owner_a, status="ready")
        self.ks_a = KnowledgeSource.objects.create(
            company=self.company_a, document=seed, title="Safety", source_type="manual",
            status="pending", created_by=self.owner_a,
        )
        self.project = Project.objects.create(title="P", owner=self.owner_a)

    def _add_document(self, user, company, upload):
        self.client.force_authenticate(user)
        url = f"/api/enterprise/knowledge-sources/{self.ks_a.id}/add-document/?company_id={company.id}"
        return self.client.post(url, {"file": upload}, format="multipart")

    def test_valid_pdf_is_uploaded_with_random_storage_name(self):
        response = self._add_document(self.owner_a, self.company_a, SimpleUploadedFile("manual.pdf", make_pdf()))
        self.assertEqual(response.status_code, 201, response.content)
        doc = Document.objects.get(filename="manual.pdf")
        self.assertEqual(doc.type, "pdf")
        self.assertTrue(doc.file.name.startswith(f"documents/{self.owner_a.id}/"))
        self.assertNotIn("manual", doc.file.name)  # internal name is random
        self.assertTrue(default_storage.exists(doc.file.name))

    def test_direct_api_exe_is_rejected_and_not_stored(self):
        before = Document.objects.count()
        response = self._add_document(self.owner_a, self.company_a, SimpleUploadedFile("program.exe", EXE))
        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.data["file"].split(".")[0:2], ["Unsupported file type: ", "exe"])
        self.assertEqual(Document.objects.count(), before)
        self.assertTrue(AuditLog.objects.filter(operation="upload_rejected", user_id=self.owner_a.id).exists())

    def test_renamed_exe_is_rejected(self):
        response = self._add_document(self.owner_a, self.company_a, SimpleUploadedFile("manual.pdf", EXE))
        self.assertEqual(response.status_code, 415)
        self.assertFalse(Document.objects.filter(filename="manual.pdf").exists())

    def test_other_company_cannot_upload_to_process(self):
        # Company B admin using their own company id: the process belongs to A -> not found.
        response = self._add_document(self.owner_b, self.company_b, SimpleUploadedFile("manual.pdf", make_pdf()))
        self.assertEqual(response.status_code, 404)
        # ...and using company A's id: not a member -> forbidden.
        response = self._add_document(self.owner_b, self.company_a, SimpleUploadedFile("manual.pdf", make_pdf()))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Document.objects.filter(filename="manual.pdf").exists())

    def test_other_company_cannot_read_process(self):
        self.client.force_authenticate(self.owner_b)
        response = self.client.get(f"/api/enterprise/knowledge-sources/{self.ks_a.id}/?company_id={self.company_a.id}")
        self.assertEqual(response.status_code, 403)

    def test_project_upload_rejects_exe(self):
        self.client.force_authenticate(self.owner_a)
        response = self.client.post(
            f"/api/projects/{self.project.id}/documents/",
            {"files": [SimpleUploadedFile("manual.pdf.exe", EXE)]},
            format="multipart",
        )
        self.assertEqual(response.status_code, 415)
        self.assertFalse(Document.objects.filter(project=self.project).exists())

    def test_documents_api_rejects_exe(self):
        self.client.force_authenticate(self.owner_a)
        response = self.client.post(
            "/api/documents/",
            {"file": SimpleUploadedFile("program.exe", EXE), "project": self.project.id, "type": "PDF", "size": 1, "hash": "x"},
            format="multipart",
        )
        self.assertIn(response.status_code, (400, 415))
        self.assertFalse(Document.objects.filter(project=self.project).exists())

    def _register(self, key, filename="manual.pdf"):
        self.client.force_authenticate(self.owner_a)
        return self.client.post(
            "/api/documents/register/",
            {"project_id": self.project.id, "filename": filename, "file_key": key, "size": 10, "hash": "client-hash", "type": "PDF"},
            format="json",
        )

    def test_register_rejects_key_outside_project_folder(self):
        other_key = f"documents/{self.owner_b.id}/999/someone-else.pdf"
        default_storage.save(other_key, ContentFile(make_pdf()))
        response = self._register(other_key)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(default_storage.exists(other_key))  # never touched

    def test_register_rejects_and_deletes_quarantined_exe(self):
        key = default_storage.save(f"documents/{self.owner_a.id}/{self.project.id}/upload.pdf", ContentFile(EXE))
        response = self._register(key)
        self.assertEqual(response.status_code, 415)
        self.assertFalse(default_storage.exists(key))  # quarantine object removed
        self.assertFalse(Document.objects.filter(project=self.project).exists())

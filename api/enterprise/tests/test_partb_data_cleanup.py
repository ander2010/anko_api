"""Part B: data cleanup commands (dry-run by default, --apply to change, reversible)."""
import datetime
import shutil
import tempfile
from io import StringIO
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from api.enterprise.services.process_status import mark_finished, mark_processing
from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_document_intelligence_models import KnowledgeSource
from api.enterprise_models import Company, CompanyMembership
from api.models import Document, EnumValueBackup, Project, User

EXE = b"MZ\x90\x00" + b"\x00" * 200


def run(*args):
    out = StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


class PartBTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media = tempfile.mkdtemp(prefix="anko-partb-")
        cls._storage = override_settings(DEFAULT_FILE_STORAGE="django.core.files.storage.FileSystemStorage", MEDIA_ROOT=cls._media)
        cls._storage.enable()

    @classmethod
    def tearDownClass(cls):
        cls._storage.disable()
        shutil.rmtree(cls._media, ignore_errors=True)
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("pb", "pb@test.com", "Pass123!")
        cls.company = Company.objects.create(name="PB", slug="pb", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    # ---------------------------------------------------------------- B2
    def _malicious_doc(self):
        project = Project.objects.create(title="PB project", owner=self.owner)
        doc = Document(project=project, filename="QA-TEST-malicioso.exe", type="exe", size=len(EXE), hash="pb-exe", uploaded_by=self.owner)
        doc.file.save("QA-TEST-malicioso.exe", ContentFile(EXE), save=False)
        doc.save()
        return doc

    def test_b2_quarantine_is_dry_run_by_default_then_moves_and_hides_the_file(self):
        doc = self._malicious_doc()
        original = doc.file.name
        out = run("audit_uploaded_documents", "--quarantine")
        self.assertIn("would quarantine doc=%d" % doc.id, out)
        doc.refresh_from_db()
        self.assertIsNone(doc.quarantined_at)

        run("audit_uploaded_documents", "--quarantine", "--apply")
        doc.refresh_from_db()
        self.assertIsNotNone(doc.quarantined_at)
        self.assertTrue(doc.file.name.startswith(f"quarantine/{doc.id}/"))
        self.assertEqual(doc.quarantine_original_key, original)
        self.assertTrue(default_storage.exists(doc.file.name))
        self.assertFalse(default_storage.exists(original))

        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get(f"/api/documents/{doc.id}/download-url/").status_code, 404)
        self.assertEqual(self.client.get(f"/api/documents/{doc.id}/").status_code, 404)
        with patch("api.tasks.orchestrate_auto_generate_run_task.delay"):
            r = self.client.post("/api/process-runs/auto-generate/", {"document_ids": [doc.id]}, format="json")
        self.assertEqual(r.status_code, 400)

        self.assertIn("Released doc=%d" % doc.id, run("audit_uploaded_documents", "--release", str(doc.id), "--apply"))
        doc.refresh_from_db()
        self.assertIsNone(doc.quarantined_at)
        self.assertTrue(default_storage.exists(doc.file.name))

    def test_b2_quarantined_doc_is_flagged_in_process_and_not_offered_for_generation(self):
        ks, _, doc, _ = make_process_with_generated_topic(self.company, self.owner)
        Document.objects.filter(pk=doc.pk).update(quarantined_at=timezone.now())
        self.client.force_authenticate(self.owner)
        q = f"?company_id={self.company.id}"
        detail = self.client.get(f"/api/enterprise/knowledge-sources/{ks.id}/{q}").data
        self.assertTrue(detail["documents"][0]["quarantined"])
        sections = self.client.get(f"/api/enterprise/knowledge-sources/{ks.id}/documents-with-sections/{q}").data
        self.assertEqual(sections["documents"], [])

    # ---------------------------------------------------------------- B3 / 14
    def test_b3_backfill_marks_complete_processes_and_reverts(self):
        ks, _, _, _ = make_process_with_generated_topic(self.company, self.owner)
        empty = KnowledgeSource.objects.create(company=self.company, title="PB empty", created_by=self.owner)
        self.assertIn(f"KS {ks.id}", run("sync_process_status"))
        ks.refresh_from_db()
        self.assertEqual(ks.status, "pending")  # dry-run

        run("sync_process_status", "--apply")
        ks.refresh_from_db()
        empty.refresh_from_db()
        self.assertEqual((ks.status, empty.status), ("processed", "pending"))
        self.assertTrue(EnumValueBackup.objects.filter(row_id=ks.id, old_value="pending").exists())
        self.assertNotIn(f"KS {ks.id}", run("sync_process_status"))  # idempotent

        run("sync_process_status", "--revert", "--apply")
        ks.refresh_from_db()
        self.assertEqual(ks.status, "pending")

    def test_14_lifecycle_hooks(self):
        ks, _, doc, _ = make_process_with_generated_topic(self.company, self.owner)
        mark_processing([doc.id])
        ks.refresh_from_db()
        self.assertEqual(ks.status, "processing")
        mark_finished([doc.id], "failed", "Hope service unavailable")
        ks.refresh_from_db()
        self.assertEqual((ks.status, ks.error_message), ("failed", "Hope service unavailable"))
        mark_finished([doc.id], "completed")
        ks.refresh_from_db()
        self.assertEqual((ks.status, ks.error_message), ("processed", ""))
        with patch("api.enterprise.services.process_status.processes_for_documents", side_effect=RuntimeError("boom")):
            mark_finished([doc.id], "completed")  # never raises

    def test_14_auto_generate_marks_process_processing(self):
        ks, _, doc, _ = make_process_with_generated_topic(self.company, self.owner)
        self.client.force_authenticate(self.owner)
        with patch("api.tasks.orchestrate_auto_generate_run_task.delay"):
            r = self.client.post("/api/process-runs/auto-generate/", {"document_ids": [doc.id]}, format="json")
        self.assertIn(r.status_code, (200, 201, 202), r.content)
        ks.refresh_from_db()
        self.assertEqual(ks.status, "processing")

    # ---------------------------------------------------------------- B4
    def test_b4_stuck_documents(self):
        old = Document.objects.create(filename="old.md", type="md", size=1, hash="pb-old", uploaded_by=self.owner, status="processing", job_id="j1")
        recent = Document.objects.create(filename="new.md", type="md", size=1, hash="pb-new", uploaded_by=self.owner, status="processing")
        Document.objects.filter(pk=old.pk).update(uploaded_at=timezone.now() - datetime.timedelta(hours=10))
        self.assertIn(f"doc={old.id}", run("fail_stuck_documents"))
        old.refresh_from_db()
        self.assertEqual(old.status, "processing")
        out = run("fail_stuck_documents", "--apply")
        self.assertNotIn(f"doc={recent.id}", out)
        old.refresh_from_db()
        recent.refresh_from_db()
        self.assertEqual((old.status, recent.status), ("failed", "processing"))
        self.assertIn("Run Auto-generate again", old.processing_error)

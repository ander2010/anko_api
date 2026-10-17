"""
Read-only security review of documents already stored.

Re-runs the upload validator (api/services/file_validation.py) against every stored
Document and reports which ones would be rejected today. Nothing is modified or deleted.

    python manage.py audit_uploaded_documents
    python manage.py audit_uploaded_documents --csv /tmp/document_audit.csv --limit 500
"""
import csv

from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand

from api.models import Document
from api.services.file_validation import FileValidationError, validate_stream

# Reasons that point to a potentially malicious file (review first).
SUSPICIOUS_CODES = {
    "dangerous_extension", "content_mismatch", "active_content", "macro_content",
    "content_windows_executable", "content_elf_executable", "content_macho_executable",
    "content_macho_or_java_class", "content_ole_compound_file", "content_script_shebang",
}


def classify(code: str) -> str:
    if code in SUSPICIOUS_CODES:
        return "SUSPICIOUS"
    if code == "unsupported_extension":
        return "FORMAT_NO_LONGER_ALLOWED"
    if code == "file_too_large":
        return "OVER_SIZE_LIMIT"
    return "INVALID"


class Command(BaseCommand):
    help = "Report stored documents that the current upload validator would reject (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--csv", dest="csv_path", help="Write the findings to this CSV file.")
        parser.add_argument("--limit", type=int, default=0, help="Only check the first N documents.")

    def handle(self, *args, csv_path=None, limit=0, **options):
        qs = Document.objects.exclude(file="").exclude(file__isnull=True).order_by("id")
        if limit:
            qs = qs[:limit]

        findings, checked, missing = [], 0, 0
        for doc in qs.iterator():
            key = doc.file.name
            try:
                fh = default_storage.open(key, "rb")
            except Exception as exc:  # missing object / storage error
                missing += 1
                findings.append(self._row(doc, "STORAGE_ERROR", "missing_or_unreadable", type(exc).__name__))
                continue
            checked += 1
            try:
                with fh:
                    validate_stream(doc.filename or key.rsplit("/", 1)[-1], fh)
            except FileValidationError as err:
                findings.append(self._row(doc, classify(err.code), err.code, err.message))
            except Exception as exc:  # storage read failure mid-stream
                missing += 1
                findings.append(self._row(doc, "STORAGE_ERROR", "missing_or_unreadable", type(exc).__name__))

        for row in findings:
            self.stdout.write(
                f"[{row['category']}] doc={row['document_id']} {row['filename']!r} key={row['storage_key']} reason={row['reason']}"
            )

        if csv_path:
            with open(csv_path, "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(findings[0].keys()) if findings else ["document_id"])
                writer.writeheader()
                writer.writerows(findings)

        counts = {}
        for row in findings:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.stdout.write(self.style.SUCCESS(
            f"Checked {checked} stored documents ({missing} unreadable). Findings: {counts or 'none'}"
        ))
        self.stdout.write("Nothing was modified. Review SUSPICIOUS entries first.")

    @staticmethod
    def _row(doc, category, reason, detail):
        return {
            "category": category,
            "document_id": doc.id,
            "filename": doc.filename,
            "type": doc.type,
            "storage_key": doc.file.name,
            "uploaded_by_id": doc.uploaded_by_id,
            "project_id": doc.project_id,
            "reason": reason,
            "detail": detail,
        }

"""
Security review of documents already stored.

Re-runs the upload validator (api/services/file_validation.py) against every stored
Document and reports which ones would be rejected today. Read-only by default.

    python manage.py audit_uploaded_documents
    python manage.py audit_uploaded_documents --csv /tmp/document_audit.csv --limit 500

B2 - quarantine (dry-run unless --apply). SUSPICIOUS and INVALID findings are
quarantined; formats that are simply no longer allowed are only reported.
    python manage.py audit_uploaded_documents --quarantine            # what would be quarantined
    python manage.py audit_uploaded_documents --quarantine --apply    # do it
    python manage.py audit_uploaded_documents --release 42 --apply    # undo for document 42

Quarantine copies the file to the private "quarantine/<doc id>/" prefix, points the
Document at the copy and only then removes the original key; the document is no
longer listed, viewed or used for generation. Nothing is deleted for good.
"""
import csv
import logging
import uuid

from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

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


logger = logging.getLogger("api.document_quarantine")
QUARANTINE_CATEGORIES = {"SUSPICIOUS", "INVALID"}


def quarantine_document(doc, reason: str) -> str:
    """Moves the stored file under quarantine/ and flags the Document. Returns the new key."""
    original = doc.file.name
    name = original.rsplit("/", 1)[-1]
    with default_storage.open(original, "rb") as fh:
        new_key = default_storage.save(f"quarantine/{doc.id}/{uuid.uuid4().hex}-{name}", fh)
    if not default_storage.exists(new_key):
        raise RuntimeError(f"copy to {new_key} not found; original kept")
    Document.objects.filter(pk=doc.pk).update(
        file=new_key, quarantined_at=timezone.now(), quarantine_reason=reason[:255], quarantine_original_key=original,
    )
    default_storage.delete(original)
    return new_key


def release_document(doc) -> str:
    """Undo quarantine_document: copies the file back to its original key and clears the flags."""
    original = doc.quarantine_original_key or f"documents/released/{doc.id}-{doc.filename}"
    with default_storage.open(doc.file.name, "rb") as fh:
        restored = default_storage.save(original, fh)
    quarantined_key = doc.file.name
    Document.objects.filter(pk=doc.pk).update(
        file=restored, quarantined_at=None, quarantine_reason="", quarantine_original_key="",
    )
    default_storage.delete(quarantined_key)
    return restored


class Command(BaseCommand):
    help = "Report (and optionally quarantine) stored documents that the current upload validator would reject."

    def add_arguments(self, parser):
        parser.add_argument("--csv", dest="csv_path", help="Write the findings to this CSV file.")
        parser.add_argument("--limit", type=int, default=0, help="Only check the first N documents.")
        parser.add_argument("--quarantine", action="store_true", help="Quarantine SUSPICIOUS/INVALID documents (needs --apply).")
        parser.add_argument("--release", type=int, help="Release one quarantined document id (needs --apply).")
        parser.add_argument("--apply", action="store_true", help="Actually change data (default: dry-run).")

    def handle(self, *args, csv_path=None, limit=0, quarantine=False, release=None, apply=False, **options):
        if release:
            doc = Document.objects.filter(pk=release, quarantined_at__isnull=False).first()
            if doc is None:
                raise CommandError(f"Document {release} is not quarantined.")
            if not apply:
                self.stdout.write(self.style.WARNING(f"DRY-RUN: would release doc={doc.id} back to {doc.quarantine_original_key!r}"))
                return
            key = release_document(doc)
            logger.warning("document %s released from quarantine to %s", doc.id, key)
            self.stdout.write(self.style.SUCCESS(f"Released doc={doc.id} -> {key}"))
            return

        qs = Document.objects.exclude(file="").exclude(file__isnull=True).filter(quarantined_at__isnull=True).order_by("id")
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
        if not quarantine:
            self.stdout.write("Nothing was modified. Review SUSPICIOUS entries first.")
            return

        to_quarantine = [row for row in findings if row["category"] in QUARANTINE_CATEGORIES]
        mode = "APPLY" if apply else "DRY-RUN (nothing changed)"
        self.stdout.write(self.style.WARNING(f"{mode}: {len(to_quarantine)} document(s) to quarantine"))
        for row in to_quarantine:
            if not apply:
                self.stdout.write(f"  would quarantine doc={row['document_id']} {row['filename']!r} ({row['reason']})")
                continue
            doc = Document.objects.get(pk=row["document_id"])
            try:
                key = quarantine_document(doc, f"{row['category']}: {row['reason']}")
            except Exception as exc:  # noqa: BLE001 - keep going, original stays in place
                logger.exception("quarantine failed for document %s", doc.id)
                self.stdout.write(self.style.ERROR(f"  FAILED doc={doc.id}: {exc}"))
                continue
            logger.warning("document %s quarantined (%s) %s -> %s", doc.id, row["reason"], row["storage_key"], key)
            self.stdout.write(f"  quarantined doc={doc.id} {row['filename']!r} -> {key}")

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

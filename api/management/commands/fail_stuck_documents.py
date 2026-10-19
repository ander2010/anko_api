"""
B4: documents stuck in "processing" for more than --hours (default 6) are marked
"failed" with the reason in processing_error.

    python manage.py fail_stuck_documents                 # dry-run
    python manage.py fail_stuck_documents --hours 12 --apply

Retrying: a failed document is no longer treated as "in flight", so running
Auto-generate again on its process dispatches it for processing again
(api/services/auto_generate_workflow.py). Nothing is deleted.
"""
import logging
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Max
from django.utils import timezone

from api.models import Document, ProcessStepRun
from api.services.auto_generate_workflow import AUTO_STAGE_KEYS

PROCESS_DOCUMENT = AUTO_STAGE_KEYS["process_document"]

logger = logging.getLogger("api.data_cleanup")


def stuck_documents(hours: float):
    cutoff = timezone.now() - timedelta(hours=hours)
    for doc in Document.objects.filter(status="processing").order_by("id"):
        last_activity = (
            ProcessStepRun.objects.filter(step_key=PROCESS_DOCUMENT, item_key=str(doc.id)).aggregate(m=Max("updated_at"))["m"]
            or doc.uploaded_at
        )
        if last_activity and last_activity < cutoff:
            yield doc, last_activity


class Command(BaseCommand):
    help = "Mark documents stuck in processing as failed (dry-run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--hours", type=float, default=6.0, help="Minimum hours without progress (default 6).")
        parser.add_argument("--apply", action="store_true", help="Change the data (default: dry-run).")

    def handle(self, *args, hours=6.0, apply=False, **options):
        rows = list(stuck_documents(hours))
        mode = "APPLIED" if apply else "DRY-RUN (nothing changed)"
        self.stdout.write(self.style.WARNING(f"{mode}: {len(rows)} document(s) in processing for more than {hours:g} h"))
        for doc, last in rows:
            reason = f"Stuck in processing since {last:%Y-%m-%d %H:%M} UTC (marked failed by fail_stuck_documents). Run Auto-generate again to retry."
            line = f"  doc={doc.id} {doc.filename!r} job={doc.job_id or '-'} last activity {last:%Y-%m-%d %H:%M}"
            self.stdout.write(line)
            if apply:
                Document.objects.filter(pk=doc.pk, status="processing").update(status="failed", processing_error=reason)
                logger.info("fail_stuck_documents %s", line.strip())

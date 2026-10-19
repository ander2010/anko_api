"""
B3 / finding 14: mark as processed ("Ready") the processes that are already complete
but still show "pending"/"processing" (Auto-generate never updated KnowledgeSource.status).

    python manage.py sync_process_status            # dry-run: lists what would change
    python manage.py sync_process_status --apply    # change it (previous value kept in enum_value_backups)
    python manage.py sync_process_status --revert --apply

A process counts as complete when all its documents are ready, its latest Auto-generate
run finished and it has topics, decks or batteries. Idempotent.
"""
import logging

from django.core.management.base import BaseCommand

from api.enterprise.services.process_status import backfill, revert

logger = logging.getLogger("api.data_cleanup")


class Command(BaseCommand):
    help = "Mark complete processes as processed (dry-run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Change the data (default: dry-run).")
        parser.add_argument("--revert", action="store_true", help="Restore the status saved by a previous --apply.")

    def handle(self, *args, apply=False, **options):
        do_revert = options.get("revert", False)
        rows = revert(apply=apply) if do_revert else backfill(apply=apply)
        mode = "APPLIED" if apply else "DRY-RUN (nothing changed)"
        self.stdout.write(self.style.WARNING(f"{mode}: {len(rows)} process(es) {'reverted' if do_revert else 'to mark processed'}"))
        for row in rows:
            line = f"  KS {row['id']} (company {row['company_id']}) {row['title']!r}: {row['old']} -> {row['new']}"
            self.stdout.write(line)
            if apply:
                logger.info("sync_process_status %s", line.strip())

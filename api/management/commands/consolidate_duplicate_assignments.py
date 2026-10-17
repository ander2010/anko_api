"""
Report (default) or consolidate duplicate active assignments (F-02).

    python manage.py consolidate_duplicate_assignments           # dry-run, safe before migrating
    python manage.py consolidate_duplicate_assignments --apply   # after migration 0057

Migration 0057 already runs the consolidation; this command lets you preview the
row count first and re-run it idempotently. To undo, roll the migration back
(`migrate api 0056`), which restores every superseded row's previous status.
"""
from django.core.management.base import BaseCommand

from api.enterprise.services.assignment_dedup import consolidate
from api.enterprise_compliance_models import ComplianceAssignment
from api.enterprise_learning_models import LearningModuleProgress, LearningPathAssignment


class Command(BaseCommand):
    help = "Preview (default) or apply the consolidation of duplicate active assignments."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Mark duplicates as superseded (no rows are deleted).")

    def handle(self, *args, apply=False, **options):
        report = consolidate(LearningPathAssignment, LearningModuleProgress, ComplianceAssignment, apply=apply)
        mode = "APPLIED" if apply else "DRY-RUN (nothing changed)"
        self.stdout.write(self.style.WARNING(mode))
        for label in ("learning", "compliance"):
            info = report[label]
            self.stdout.write(f"{label}: {info['groups']} duplicate groups, {info['rows']} rows to supersede"
                              + (f", {info['changed']} changed" if apply else ""))
            for keeper_id, duplicate_ids in info["details"]:
                self.stdout.write(f"  keep #{keeper_id} -> supersede {duplicate_ids}")

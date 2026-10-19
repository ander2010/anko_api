"""
C8: read-only data integrity report. Nothing is modified.

    python manage.py audit_data_integrity
    python manage.py audit_data_integrity --details   # list the affected ids

Run it in production before adding database CHECK constraints (scores 0-100):
a CHECK migration fails if any existing row violates it, so the data is cleaned
first (by hand or with a reviewed data migration) and only then constrained.
"""
from django.core.management.base import BaseCommand
from django.db.models import Count, Q
from django.db.models.functions import Lower


class Command(BaseCommand):
    help = "Report scores out of range, orphan content and duplicates (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--details", action="store_true", help="Print the ids of the affected rows.")

    def handle(self, *args, details=False, **options):
        from api.enterprise_certification_models import CertificateTemplate, CertificationRequirement
        from api.enterprise_compliance_models import ComplianceProgram
        from api.enterprise_document_intelligence_models import KnowledgeSource, KnowledgeSourceTopic
        from api.enterprise_learning_models import LearningModule
        from api.models import Battery, BatteryAttempt, Deck
        from api.services.content_access import content_company_ids

        out_of_range = lambda qs, field: qs.filter(Q(**{f"{field}__lt": 0}) | Q(**{f"{field}__gt": 100}))  # noqa: E731
        checks = {
            "scores: KnowledgeSource.minimum_passing_score outside 0-100": out_of_range(KnowledgeSource.objects, "minimum_passing_score"),
            "scores: LearningModule.minimum_passing_score outside 0-100": out_of_range(LearningModule.objects, "minimum_passing_score"),
            "scores: ComplianceProgram.passing_score outside 0-100": out_of_range(ComplianceProgram.objects, "passing_score"),
            "scores: CertificateTemplate.minimum_score outside 0-100": out_of_range(CertificateTemplate.objects, "minimum_score"),
            "scores: CertificationRequirement.minimum_score outside 0-100": out_of_range(CertificationRequirement.objects, "minimum_score"),
            "scores: BatteryAttempt.percent outside 0-100": out_of_range(BatteryAttempt.objects, "percent"),
            "dates: ComplianceProgram expiry_date <= effective_date": ComplianceProgram.objects.filter(
                effective_date__isnull=False, expiry_date__isnull=False).extra(where=["expiry_date <= effective_date"]),
        }
        total = 0
        for label, qs in checks.items():
            ids = list(qs.values_list("id", flat=True)[:500])
            total += len(ids)
            self._line(label, ids, details)

        dup_topics = (
            KnowledgeSourceTopic.objects.annotate(t=Lower("title")).values("knowledge_source_id", "t")
            .annotate(n=Count("id")).filter(n__gt=1)
        )
        self._line("duplicates: topic names per process (case-insensitive)", [f"{d['knowledge_source_id']}:{d['t']}" for d in dup_topics], details)

        # Project-less decks/batteries no company can reach (e.g. their process was deleted).
        orphan_decks = [d.id for d in Deck.objects.filter(project__isnull=True, collection__isnull=True).iterator()
                        if not content_company_ids(deck=d)]
        orphan_batteries = [b.id for b in Battery.objects.filter(project__isnull=True, collection__isnull=True).iterator()
                            if not content_company_ids(battery=b)]
        self._line("orphans: project-less decks not reachable by any company", orphan_decks, details)
        self._line("orphans: project-less batteries not reachable by any company", orphan_batteries, details)
        total += len(orphan_decks) + len(orphan_batteries) + len(dup_topics)

        self.stdout.write(self.style.SUCCESS(f"{total} finding(s). Nothing was modified."))

    def _line(self, label, ids, details):
        self.stdout.write(f"{label}: {len(ids)}" + (f"  ids={ids[:50]}" if details and ids else ""))

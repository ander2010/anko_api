"""
F-13 backfill: builds the knowledge graph of existing processes from their topics,
tags and procedures (see api/enterprise/services/knowledge_graph_builder.py).

    python manage.py build_knowledge_graph --all --dry-run
    python manage.py build_knowledge_graph --ks 42
    python manage.py build_knowledge_graph --company 3

Idempotent: re-running only updates what changed. --dry-run rolls everything back.
"""
from django.core.management.base import BaseCommand, CommandError

from api.enterprise.services.knowledge_graph_builder import build_knowledge_graph
from api.enterprise_document_intelligence_models import KnowledgeSource


class Command(BaseCommand):
    help = "Build the knowledge graph of processes from their topics, tags and procedures."

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--ks", type=int, help="One KnowledgeSource (process) id.")
        target.add_argument("--company", type=int, help="Every process of one company.")
        target.add_argument("--all", action="store_true", help="Every process.")
        parser.add_argument("--dry-run", action="store_true", help="Show what would change without saving.")

    def handle(self, *args, ks=None, company=None, all=False, dry_run=False, **options):
        qs = KnowledgeSource.objects.select_related("company").order_by("id")
        if ks:
            qs = qs.filter(pk=ks)
            if not qs.exists():
                raise CommandError(f"KnowledgeSource {ks} not found.")
        elif company:
            qs = qs.filter(company_id=company)

        totals = {"nodes_created": 0, "nodes_updated": 0, "nodes_deleted": 0, "relationships_created": 0}
        for source in qs:
            stats = build_knowledge_graph(source, dry_run=dry_run)
            for key in totals:
                totals[key] += stats[key]
            self.stdout.write(
                f"KS {source.id} '{source.title}' (company {source.company_id}): "
                f"{stats['topics']} topics, {stats['concepts']} concepts, {stats['procedures']} procedures -> "
                f"+{stats['nodes_created']} ~{stats['nodes_updated']} -{stats['nodes_deleted']} nodes, "
                f"+{stats['relationships_created']} edges"
            )
        prefix = "[DRY RUN] nothing saved. " if dry_run else ""
        self.stdout.write(self.style.SUCCESS(
            f"{prefix}{qs.count()} process(es): +{totals['nodes_created']} ~{totals['nodes_updated']} "
            f"-{totals['nodes_deleted']} nodes, +{totals['relationships_created']} edges"
        ))

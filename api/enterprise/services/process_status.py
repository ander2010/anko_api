"""
Finding 14 - lifecycle of a process (KnowledgeSource.status):

    pending ──(Auto-generate starts)──> processing ──(run finishes with content)──> processed  ("Ready" in the UI)
                                                    └─(run fails)─────────────────> failed + error_message

"processed" is the existing key for the ready state: the brief's "ready" maps to it so
no normalized enum key changes. Adding documents later does not reset a processed
process; a new Auto-generate run moves it to processing again.

The hooks never raise: a status problem must not break the generation pipeline.
"""
from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

BACKUP_TABLE = "enterprise_knowledge_sources#B3"
SUCCESS_RUN_STATUSES = {"completed", "completed_with_errors"}


def processes_for_documents(document_ids):
    """KnowledgeSources whose linked documents include every id in document_ids."""
    from api.enterprise_document_intelligence_models import KnowledgeSource

    doc_ids = {int(d) for d in document_ids if str(d).strip().isdigit()}
    if not doc_ids:
        return []
    matches = []
    for ks in KnowledgeSource.objects.filter(source_documents__document_id__in=doc_ids).distinct():
        if doc_ids <= set(ks.source_documents.values_list("document_id", flat=True)):
            matches.append(ks)
    return matches


def mark_processing(document_ids) -> None:
    try:
        now = timezone.now()
        for ks in processes_for_documents(document_ids):
            ks.status = "processing"
            ks.processing_started_at = now
            ks.error_message = ""
            ks.save(update_fields=["status", "processing_started_at", "error_message", "updated_at"])
    except Exception:  # noqa: BLE001
        logger.exception("could not mark processes as processing for documents %s", document_ids)


def mark_finished(document_ids, run_status: str, message: str = "") -> None:
    try:
        now = timezone.now()
        for ks in processes_for_documents(document_ids):
            if str(run_status) in SUCCESS_RUN_STATUSES:
                ks.status, ks.error_message = "processed", ""
            else:
                ks.status, ks.error_message = "failed", (message or "Auto-generate failed.")[:2000]
            ks.processing_completed_at = now
            ks.save(update_fields=["status", "error_message", "processing_completed_at", "updated_at"])
    except Exception:  # noqa: BLE001
        logger.exception("could not mark processes as finished for documents %s", document_ids)


def process_has_content(ks) -> bool:
    """Every linked document is ready and Auto-generate produced topics, decks or batteries."""
    from api.enterprise.views.document_intelligence import _ks_generated_topics
    from api.models import Document

    doc_ids = list(ks.source_documents.values_list("document_id", flat=True))
    if not doc_ids or Document.objects.filter(id__in=doc_ids).exclude(status="ready").exists():
        return False
    runs, _, topics = _ks_generated_topics(ks, sorted(doc_ids))
    if any(run.status not in SUCCESS_RUN_STATUSES for run in runs[-1:]):
        return False  # the latest run is still going (or failed)
    has_outputs = any(run.artifacts.filter(artifact_type__in=("deck", "battery")).exists() for run in runs)
    return bool(topics) or has_outputs


def backfill(*, apply: bool) -> list[dict]:
    """B3: pending/processing processes that are actually complete -> processed (with a backup row)."""
    from api.enterprise_document_intelligence_models import KnowledgeSource
    from api.models import EnumValueBackup

    rows = []
    for ks in KnowledgeSource.objects.filter(status__in=("pending", "processing")).order_by("id"):
        if not process_has_content(ks):
            continue
        rows.append({"id": ks.id, "company_id": ks.company_id, "title": ks.title, "old": ks.status, "new": "processed"})
        if apply:
            with transaction.atomic():
                EnumValueBackup.objects.create(table_name=BACKUP_TABLE, row_id=ks.id, field_name="status",
                                               old_value=ks.status, new_value="processed")
                KnowledgeSource.objects.filter(pk=ks.pk).update(status="processed",
                                                                processing_completed_at=ks.processing_completed_at or timezone.now())
    return rows


def revert(*, apply: bool) -> list[dict]:
    """Undo backfill(): restore the backed-up status of rows still marked processed by it."""
    from api.enterprise_document_intelligence_models import KnowledgeSource
    from api.models import EnumValueBackup

    rows = []
    for backup in EnumValueBackup.objects.filter(table_name=BACKUP_TABLE, field_name="status").order_by("-id"):
        ks = KnowledgeSource.objects.filter(pk=backup.row_id, status=backup.new_value).first()
        if ks is None:
            continue
        rows.append({"id": ks.id, "company_id": ks.company_id, "title": ks.title, "old": ks.status, "new": backup.old_value})
        if apply:
            with transaction.atomic():
                KnowledgeSource.objects.filter(pk=ks.pk).update(status=backup.old_value)
                backup.delete()
    return rows

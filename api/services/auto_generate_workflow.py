from __future__ import annotations

import os
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from django.db import transaction
from django.utils import timezone

from api.utils.logging import get_logger
from ..models import (
    Battery,
    BatteryQuestion,
    BatterySourceDocument,
    BatterySourceSection,
    BatterySourceTagGroup,
    Collection,
    Deck,
    DeckSourceDocument,
    DeckSourceSection,
    DeckSourceTagGroup,
    Document,
    Flashcard,
    ProcessArtifact,
    ProcessRun,
    ProcessStepDependency,
    ProcessStepRun,
    Project,
    Section,
    TagGroup,
    TagGroupItem,
)
from .workflow_progress import publish_run_event, recompute_run_progress, update_step_progress
from .workflow_progress_consumer import enqueue_progress_consumer
from .hope_broker import (
    HopeDispatchError,
    dispatch_battery_generation,
    dispatch_flashcard_generation,
    dispatch_process_document,
)

logger = get_logger(__name__)

AUTO_WORKFLOW_KEY = "collection_auto_generate"
AUTO_WORKFLOW_VERSION = 1
AUTO_STAGE_KEYS = {
    "prepare": "prepare_inputs",
    "preflight": "preflight_reconciliation",
    "process_document": "process_document",
    "aggregate": "aggregate_unique_tags",
    "partition": "partition_tags",
    "generate_flashcards": "generate_flashcards",
    "generate_battery": "generate_battery",
    "finalize": "finalize_outputs",
}
AUTO_TERMINAL_STEP_STATUSES = {
    ProcessStepRun.Status.COMPLETED,
    ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
    ProcessStepRun.Status.FAILED,
    ProcessStepRun.Status.SKIPPED,
    ProcessStepRun.Status.CANCELED,
}
DEFAULTS = {
    "tag_group_size": 10,
    "flashcard_options": {
        "cards_per_group": 20,
        "difficulty": "medium",
    },
    "battery_options": {
        "questions_per_group": 15,
        "difficulty": "medium",
        "question_format": "true_false",
    },
    "reconciliation": {
        "decision": "override",
        "status": "fine",
    },
}


class AutoGenerateWorkflowError(Exception):
    pass


def _coerce_int_list(values: Any) -> list[int]:
    cleaned: list[int] = []
    seen: set[int] = set()
    for raw in values or []:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
    return cleaned


def _normalize_difficulty(value: Any, *, battery: bool = False) -> str:
    normalized = str(value or "medium").strip().lower()
    if battery:
        return {"easy": "Easy", "medium": "Medium", "hard": "Hard"}.get(normalized, "Medium")
    return normalized if normalized in {"easy", "medium", "hard"} else "medium"


def cleanup_empty_generated_deck(*, deck: Deck | None = None, deck_id: int | None = None) -> bool:
    if deck is None and deck_id is not None:
        deck = Deck.objects.filter(id=deck_id).first()
    if deck is None:
        return False
    if Flashcard.objects.filter(deck_id=deck.id).exists():
        return False

    cleanup_id = deck.id
    ProcessArtifact.objects.filter(resource_type="deck", resource_id=str(cleanup_id)).delete()
    deck.delete()
    logger.info("Deleted empty generated deck placeholder %s", cleanup_id)
    return True


def cleanup_empty_generated_battery(*, battery: Battery | None = None, battery_id: int | None = None) -> bool:
    if battery is None and battery_id is not None:
        battery = Battery.objects.filter(id=battery_id).first()
    if battery is None:
        return False
    if BatteryQuestion.objects.filter(battery_id=battery.id).exists():
        return False

    cleanup_id = battery.id
    ProcessArtifact.objects.filter(resource_type="battery", resource_id=str(cleanup_id)).delete()
    battery.delete()
    logger.info("Deleted empty generated battery placeholder %s", cleanup_id)
    return True


def _normalize_auto_generate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    flashcard_options = dict(DEFAULTS["flashcard_options"])
    flashcard_options.update(payload.get("flashcard_options") or {})
    battery_options = dict(DEFAULTS["battery_options"])
    battery_options.update(payload.get("battery_options") or {})

    try:
        tag_group_size = int(payload.get("tag_group_size") or DEFAULTS["tag_group_size"])
    except (TypeError, ValueError):
        tag_group_size = DEFAULTS["tag_group_size"]
    tag_group_size = max(1, min(tag_group_size, 100))

    try:
        flashcard_options["cards_per_group"] = int(
            flashcard_options.get("cards_per_group") or DEFAULTS["flashcard_options"]["cards_per_group"]
        )
    except (TypeError, ValueError):
        flashcard_options["cards_per_group"] = DEFAULTS["flashcard_options"]["cards_per_group"]
    flashcard_options["cards_per_group"] = max(1, min(int(flashcard_options["cards_per_group"]), 500))
    flashcard_options["difficulty"] = _normalize_difficulty(flashcard_options.get("difficulty"))

    try:
        battery_options["questions_per_group"] = int(
            battery_options.get("questions_per_group") or DEFAULTS["battery_options"]["questions_per_group"]
        )
    except (TypeError, ValueError):
        battery_options["questions_per_group"] = DEFAULTS["battery_options"]["questions_per_group"]
    battery_options["questions_per_group"] = max(1, min(int(battery_options["questions_per_group"]), 500))
    battery_options["difficulty"] = _normalize_difficulty(battery_options.get("difficulty"))
    battery_options["question_format"] = str(
        battery_options.get("question_format") or DEFAULTS["battery_options"]["question_format"]
    ).strip() or DEFAULTS["battery_options"]["question_format"]

    return {
        "document_ids": _coerce_int_list(payload.get("document_ids")),
        "workspace_id": payload.get("workspace_id"),
        "tag_group_size": tag_group_size,
        "flashcard_options": flashcard_options,
        "battery_options": battery_options,
    }


def normalize_auto_generate_request(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_auto_generate_payload(payload)
    if not normalized["document_ids"]:
        raise AutoGenerateWorkflowError("document_ids is required and must be a non-empty list")
    return normalized


def _infer_scope(*, documents: list[Document], workspace_id: Any = None) -> tuple[str, str, str | None, str | None]:
    collection_ids = sorted({doc.collection_id for doc in documents if doc.collection_id})
    project_ids = sorted({doc.project_id for doc in documents if doc.project_id})

    if len(collection_ids) > 1:
        raise AutoGenerateWorkflowError("All documents must belong to the same collection for auto-generate")
    if len(project_ids) > 1 and not collection_ids:
        raise AutoGenerateWorkflowError("All documents must belong to the same project for auto-generate")

    if collection_ids:
        scope_id = str(collection_ids[0])
        return "collection", scope_id, scope_id, None
    if project_ids:
        scope_id = str(project_ids[0])
        return "project", scope_id, None, scope_id
    if workspace_id not in (None, ""):
        return "workspace", str(workspace_id), None, None
    return "document_batch", "unscoped", None, None


def _build_internal_callback_base() -> str:
    return os.getenv("INTERNAL_API_BASE_URL", "http://localhost:8000").rstrip("/")


def _internal_service_token() -> str:
    return os.getenv("INTERNAL_SERVICE_TOKEN", "andelef").strip() or "andelef"


def _normalize_base_url(base_url: str) -> str:
    return str(base_url or "").rstrip("/")


def _build_ws_url(base_url: str, job_id: str) -> str:
    ws_base = _normalize_base_url(base_url).replace("http://", "ws://", 1).replace("https://", "wss://", 1)
    return f"{ws_base}/ws/progress/{job_id}"

def _chunk_tags(tags: list[str], group_size: int) -> list[list[str]]:
    return [tags[idx: idx + group_size] for idx in range(0, len(tags), group_size)]


def _step_requires_finalize_callback(step: ProcessStepRun) -> bool:
    return step.step_key in {
        AUTO_STAGE_KEYS["generate_flashcards"],
        AUTO_STAGE_KEYS["generate_battery"],
    }


def _step_finalize_callback_status(step: ProcessStepRun) -> str:
    payload = dict(step.result_payload or {})
    payload.update(step.input_payload or {})

    if step.step_key == AUTO_STAGE_KEYS["generate_flashcards"]:
        deck_id = payload.get("deck_id")
        deck = Deck.objects.filter(id=deck_id).only("config").first() if deck_id else None
        return str((deck.config or {}).get("last_generation_status") or "").strip().lower() if deck else ""

    if step.step_key == AUTO_STAGE_KEYS["generate_battery"]:
        battery_id = payload.get("battery_id")
        battery = Battery.objects.filter(id=battery_id).only("config").first() if battery_id else None
        return str((battery.config or {}).get("last_generation_status") or "").strip().lower() if battery else ""

    return ""


def _title_case(text: str) -> str:
    words = [word for word in str(text or "").strip().split() if word]
    return " ".join(word[:1].upper() + word[1:] for word in words)


def _fallback_output_title(*, tags: list[str], kind: str, index: int) -> str:
    hints = [_title_case(tag) for tag in tags[:3] if str(tag).strip()]
    if hints:
        base = " ".join(hints)
        if kind == "battery":
            return f"{base} Assessment"
        if kind == "flashcards":
            return f"{base} Flashcards"
        return base
    return f"{'Assessment' if kind == 'battery' else 'Flashcards'} Set {index}"


def _derive_unique_tags(*, documents: list[Document]) -> list[str]:
    seen: set[str] = set()
    tags: list[str] = []
    sections = Section.objects.filter(document_id__in=[doc.id for doc in documents]).order_by("document_id", "order", "id")
    for section in sections:
        title = str(section.title or "").strip()
        if not title:
            continue
        key = title.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(title)
    if tags:
        return tags

    for doc in documents:
        stem = Path(str(doc.filename or "")).stem.replace("_", " ").strip()
        if not stem:
            continue
        key = stem.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(stem)
    return tags


@transaction.atomic
def sync_deck_source_links(*, deck: Deck, source_bundle: dict[str, Any] | None) -> dict[str, list[int]]:
    source_bundle = source_bundle or {}
    document_ids = _coerce_int_list(source_bundle.get("document_ids"))
    section_ids = _coerce_int_list(source_bundle.get("section_ids"))
    tag_group_ids = _coerce_int_list(source_bundle.get("tag_group_ids"))

    DeckSourceDocument.objects.filter(deck=deck).delete()
    DeckSourceSection.objects.filter(deck=deck).delete()
    DeckSourceTagGroup.objects.filter(deck=deck).delete()

    documents = list(Document.objects.filter(id__in=document_ids))
    sections = list(Section.objects.filter(id__in=section_ids))
    tag_groups = list(TagGroup.objects.filter(id__in=tag_group_ids))

    if documents:
        DeckSourceDocument.objects.bulk_create(
            [DeckSourceDocument(deck=deck, document=document, role="input", metadata={}) for document in documents]
        )
    if sections:
        DeckSourceSection.objects.bulk_create(
            [DeckSourceSection(deck=deck, section=section, role="input", metadata={}) for section in sections]
        )
        deck.sections.set([section.id for section in sections])
    if tag_groups:
        DeckSourceTagGroup.objects.bulk_create(
            [DeckSourceTagGroup(deck=deck, tag_group=tag_group, role="input", metadata={}) for tag_group in tag_groups]
        )

    collection_id = source_bundle.get("collection_id")
    update_fields: list[str] = []
    if collection_id not in (None, ""):
        try:
            normalized_collection_id = int(collection_id)
        except (TypeError, ValueError):
            normalized_collection_id = None
        if normalized_collection_id and Collection.objects.filter(id=normalized_collection_id).exists():
            deck.collection_id = normalized_collection_id
            update_fields.append("collection")

    config = dict(deck.config or {})
    config["source_bundle"] = source_bundle
    deck.config = config
    update_fields.append("config")
    if update_fields:
        deck.save(update_fields=list(dict.fromkeys(update_fields)))

    return {
        "document_ids": [document.id for document in documents],
        "section_ids": [section.id for section in sections],
        "tag_group_ids": [tag_group.id for tag_group in tag_groups],
    }


@transaction.atomic
def sync_battery_source_links(*, battery: Battery, source_bundle: dict[str, Any] | None) -> dict[str, list[int]]:
    source_bundle = source_bundle or {}
    document_ids = _coerce_int_list(source_bundle.get("document_ids"))
    section_ids = _coerce_int_list(source_bundle.get("section_ids"))
    tag_group_ids = _coerce_int_list(source_bundle.get("tag_group_ids"))

    BatterySourceDocument.objects.filter(battery=battery).delete()
    BatterySourceSection.objects.filter(battery=battery).delete()
    BatterySourceTagGroup.objects.filter(battery=battery).delete()

    documents = list(Document.objects.filter(id__in=document_ids))
    sections = list(Section.objects.filter(id__in=section_ids))
    tag_groups = list(TagGroup.objects.filter(id__in=tag_group_ids))

    if documents:
        BatterySourceDocument.objects.bulk_create(
            [BatterySourceDocument(battery=battery, document=document, role="input", metadata={}) for document in documents]
        )
    if sections:
        BatterySourceSection.objects.bulk_create(
            [BatterySourceSection(battery=battery, section=section, role="input", metadata={}) for section in sections]
        )
        battery.sections.set([section.id for section in sections])
    if tag_groups:
        BatterySourceTagGroup.objects.bulk_create(
            [BatterySourceTagGroup(battery=battery, tag_group=tag_group, role="input", metadata={}) for tag_group in tag_groups]
        )

    collection_id = source_bundle.get("collection_id")
    update_fields: list[str] = []
    if collection_id not in (None, ""):
        try:
            normalized_collection_id = int(collection_id)
        except (TypeError, ValueError):
            normalized_collection_id = None
        if normalized_collection_id and Collection.objects.filter(id=normalized_collection_id).exists():
            battery.collection_id = normalized_collection_id
            update_fields.append("collection")

    config = dict(battery.config or {})
    config["source_bundle"] = source_bundle
    battery.config = config
    update_fields.append("config")
    if update_fields:
        battery.save(update_fields=list(dict.fromkeys(update_fields)))

    return {
        "document_ids": [document.id for document in documents],
        "section_ids": [section.id for section in sections],
        "tag_group_ids": [tag_group.id for tag_group in tag_groups],
    }


@transaction.atomic
def create_auto_generate_run(*, initiated_by, documents: list[Document], payload: dict[str, Any]) -> ProcessRun:
    normalized = normalize_auto_generate_request(payload)
    scope_type, scope_id, collection_scope_id, project_scope_id = _infer_scope(
        documents=documents,
        workspace_id=normalized.get("workspace_id"),
    )
    now = timezone.now()
    run = ProcessRun.objects.create(
        workflow_key=AUTO_WORKFLOW_KEY,
        workflow_version=AUTO_WORKFLOW_VERSION,
        status=ProcessRun.Status.QUEUED,
        trigger_mode=ProcessRun.TriggerMode.MANUAL,
        initiated_by=initiated_by if getattr(initiated_by, "is_authenticated", False) else None,
        scope_type=scope_type,
        scope_id=scope_id,
        resource_type="document_batch",
        resource_id=",".join(str(doc.id) for doc in documents),
        idempotency_key=f"{AUTO_WORKFLOW_KEY}:{'-'.join(str(doc.id) for doc in documents)}",
        current_step_key=AUTO_STAGE_KEYS["process_document"],
        current_stage=AUTO_STAGE_KEYS["process_document"],
        status_message="Queued for automatic generation",
        input_payload=normalized,
        context_payload={
            "collection_id": collection_scope_id,
            "project_id": project_scope_id,
            "reconciliation": dict(DEFAULTS["reconciliation"]),
        },
        started_at=now,
    )

    prepare_step = ProcessStepRun.objects.create(
        run=run,
        step_key=AUTO_STAGE_KEYS["prepare"],
        step_type="input_prepare",
        status=ProcessStepRun.Status.COMPLETED,
        execution_mode=ProcessStepRun.ExecutionMode.SYNC,
        sequence=10,
        weight=5,
        progress_percent=100,
        status_message="Inputs prepared",
        input_payload={"document_ids": normalized["document_ids"]},
        result_payload={"document_count": len(documents)},
        started_at=now,
        finished_at=now,
    )
    preflight_step = ProcessStepRun.objects.create(
        run=run,
        step_key=AUTO_STAGE_KEYS["preflight"],
        step_type="preflight_reconciliation",
        status=ProcessStepRun.Status.COMPLETED,
        execution_mode=ProcessStepRun.ExecutionMode.SYNC,
        sequence=20,
        weight=5,
        progress_percent=100,
        status_message="Auto-continued with override",
        result_payload=dict(DEFAULTS["reconciliation"]),
        started_at=now,
        finished_at=now,
    )

    process_steps: list[ProcessStepRun] = []
    dependencies: list[ProcessStepDependency] = []
    for index, document in enumerate(documents, start=1):
        process_step = ProcessStepRun.objects.create(
            run=run,
            step_key=AUTO_STAGE_KEYS["process_document"],
            item_key=str(document.id),
            step_type="document_processing",
            status=ProcessStepRun.Status.PENDING,
            execution_mode=ProcessStepRun.ExecutionMode.FANOUT,
            sequence=100 + index,
            weight=10,
            status_message="Pending document processing",
            input_payload={"document_id": document.id, "file_path": document.file.name},
        )
        process_steps.append(process_step)
        dependencies.append(ProcessStepDependency(step=process_step, depends_on=preflight_step))

    aggregate_step = ProcessStepRun.objects.create(
        run=run,
        step_key=AUTO_STAGE_KEYS["aggregate"],
        step_type="tag_aggregation",
        status=ProcessStepRun.Status.PENDING,
        execution_mode=ProcessStepRun.ExecutionMode.JOIN,
        sequence=300,
        weight=10,
        status_message="Waiting for document processing",
    )
    partition_step = ProcessStepRun.objects.create(
        run=run,
        step_key=AUTO_STAGE_KEYS["partition"],
        step_type="tag_partition",
        status=ProcessStepRun.Status.PENDING,
        execution_mode=ProcessStepRun.ExecutionMode.SYNC,
        sequence=310,
        weight=10,
        status_message="Waiting for tag aggregation",
    )
    finalize_step = ProcessStepRun.objects.create(
        run=run,
        step_key=AUTO_STAGE_KEYS["finalize"],
        step_type="finalize_outputs",
        status=ProcessStepRun.Status.PENDING,
        execution_mode=ProcessStepRun.ExecutionMode.JOIN,
        sequence=900,
        weight=10,
        status_message="Waiting for output generation",
    )

    dependencies.extend(ProcessStepDependency(step=aggregate_step, depends_on=step) for step in process_steps)
    dependencies.append(ProcessStepDependency(step=partition_step, depends_on=aggregate_step))
    dependencies.append(ProcessStepDependency(step=finalize_step, depends_on=partition_step))
    ProcessStepDependency.objects.bulk_create(dependencies)

    ProcessArtifact.objects.bulk_create(
        [
            ProcessArtifact(
                run=run,
                step=prepare_step,
                artifact_key=f"document:{document.id}",
                artifact_type="document",
                role=ProcessArtifact.Role.INPUT,
                resource_type="document",
                resource_id=str(document.id),
                payload={"document_id": document.id, "filename": document.filename},
            )
            for document in documents
        ]
    )
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.QUEUED,
        current_step_key=AUTO_STAGE_KEYS["process_document"],
        current_stage=AUTO_STAGE_KEYS["process_document"],
        status_message="Queued for automatic generation",
        started_at=now,
    )
    return run


def _step_by_key(run: ProcessRun, step_key: str, *, item_key: str | None = None) -> ProcessStepRun | None:
    qs = run.steps.filter(step_key=step_key)
    if item_key is not None:
        qs = qs.filter(item_key=item_key)
    return qs.order_by("sequence", "id").first()


def _sync_run_output_artifact(
    *,
    run: ProcessRun,
    step: ProcessStepRun | None,
    artifact_key: str,
    artifact_type: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    produced: bool = True,
) -> None:
    ProcessArtifact.objects.update_or_create(
        run=run,
        artifact_key=artifact_key,
        defaults={
            "step": step,
            "artifact_type": artifact_type,
            "role": ProcessArtifact.Role.OUTPUT,
            "status": ProcessArtifact.Status.ACTIVE,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "payload": payload,
            "metadata": metadata or {},
            "produced_at": timezone.now() if produced else None,
        },
    )


def _wait_for_steps(
    *,
    run_id: int,
    step_key: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 2.0,
    require_callback_status: bool = False,
) -> list[ProcessStepRun]:
    deadline = time.monotonic() + timeout_seconds
    latest_steps: list[ProcessStepRun] = []
    stale_step_seconds = max(float(os.getenv("AUTO_GENERATE_STEP_STALE_SECONDS", "900")), poll_interval_seconds)
    callback_stale_seconds = max(float(os.getenv("AUTO_GENERATE_CALLBACK_STALE_SECONDS", "600")), poll_interval_seconds)
    while time.monotonic() < deadline:
        run = ProcessRun.objects.prefetch_related("steps").get(pk=run_id)
        latest_steps = list(run.steps.filter(step_key=step_key).order_by("sequence", "id"))
        stale_detected = False
        state_changed = False
        now = timezone.now()
        for step in latest_steps:
            if step.status in AUTO_TERMINAL_STEP_STATUSES:
                continue

            activity_at = (
                step.last_heartbeat_at
                or step.last_progress_at
                or step.updated_at
                or step.started_at
                or step.created_at
            )
            age_seconds = (now - activity_at).total_seconds() if activity_at else None
            if age_seconds is None or age_seconds < stale_step_seconds:
                continue

            update_step_progress(
                step=step,
                status=ProcessStepRun.Status.FAILED,
                status_message="Worker heartbeat timed out",
                error_payload={
                    "reason": "stale_progress",
                    "step_key": step_key,
                    "external_job_id": step.external_job_id,
                    "stale_after_seconds": stale_step_seconds,
                    "last_activity_at": activity_at.isoformat() if activity_at else None,
                },
                finished_at=now,
            )
            stale_detected = True

        if require_callback_status and latest_steps:
            for step in latest_steps:
                if step.status != ProcessStepRun.Status.COMPLETED:
                    continue
                if not _step_requires_finalize_callback(step):
                    continue
                if _finalize_completed_output_step(run_id=run_id, step=step):
                    state_changed = True
                    continue
                last_status = _step_finalize_callback_status(step)
                if last_status:
                    continue

                activity_at = (
                    step.finished_at
                    or step.last_heartbeat_at
                    or step.last_progress_at
                    or step.updated_at
                    or step.started_at
                    or step.created_at
                )
                age_seconds = (now - activity_at).total_seconds() if activity_at else None
                if age_seconds is None or age_seconds < callback_stale_seconds:
                    continue

                update_step_progress(
                    step=step,
                    status=ProcessStepRun.Status.FAILED,
                    status_message="Finalize callback timed out",
                    error_payload={
                        "reason": "callback_timeout",
                        "step_key": step_key,
                        "external_job_id": step.external_job_id,
                        "resource_id": (
                            (step.result_payload or {}).get("deck_id")
                            or (step.input_payload or {}).get("deck_id")
                            or (step.result_payload or {}).get("battery_id")
                            or (step.input_payload or {}).get("battery_id")
                        ),
                        "stale_after_seconds": callback_stale_seconds,
                        "last_activity_at": activity_at.isoformat() if activity_at else None,
                    },
                    finished_at=now,
                )
                stale_detected = True

        if stale_detected or state_changed:
            run = _refresh_run(run_id)
            recompute_run_progress(
                run=run,
                status=None,
                current_step_key=step_key,
                current_stage=step_key,
                status_message=f"Detected stale {step_key} step" if stale_detected else run.status_message,
            )
            publish_run_event(run, event="process_run.updated")
            latest_steps = list(run.steps.filter(step_key=step_key).order_by("sequence", "id"))

        if latest_steps and all(step.status in AUTO_TERMINAL_STEP_STATUSES for step in latest_steps):
            if require_callback_status:
                pending_callback = False
                for step in latest_steps:
                    if step.status == ProcessStepRun.Status.COMPLETED and _step_requires_finalize_callback(step):
                        if not _step_finalize_callback_status(step):
                            pending_callback = True
                            break
                if not pending_callback:
                    return latest_steps
            else:
                return latest_steps
        time.sleep(poll_interval_seconds)
    return latest_steps


def _refresh_run(run_id: int) -> ProcessRun:
    return ProcessRun.objects.prefetch_related("steps").get(pk=run_id)


def _finalize_completed_output_step(*, run_id: int, step: ProcessStepRun) -> bool:
    if step.step_key == AUTO_STAGE_KEYS["generate_flashcards"]:
        return _finalize_completed_flashcard_step(run_id=run_id, step=step)
    if step.step_key == AUTO_STAGE_KEYS["generate_battery"]:
        return _finalize_completed_battery_step(run_id=run_id, step=step)
    return False


def _finalize_completed_flashcard_step(*, run_id: int, step: ProcessStepRun) -> bool:
    result_payload = dict(step.result_payload or {})
    deck_id = result_payload.get("deck_id") or (step.input_payload or {}).get("deck_id")
    job_id = str(step.external_job_id or result_payload.get("job_id") or "").strip()
    if not deck_id or not job_id:
        return False

    deck = Deck.objects.filter(id=deck_id).first()
    if deck is None:
        return False

    from api.views import DeckViewSet

    sync_result = DeckViewSet._sync_generated_flashcards(deck=deck, job_id=job_id)
    config = dict(deck.config or {})
    config["last_generation_status"] = "completed"
    deck.config = config
    if deck.external_job_id != job_id:
        deck.external_job_id = job_id
        deck.save(update_fields=["external_job_id", "config"])
    else:
        deck.save(update_fields=["config"])

    if sync_result.get("card_count", 0) <= 0:
        cleanup_empty_generated_deck(deck=deck)
        return False

    update_step_progress(
        step=step,
        status=ProcessStepRun.Status.COMPLETED,
        progress_percent=100,
        status_message="Flashcards generated",
        result_payload={
            **result_payload,
            "deck_id": deck.id,
            "job_id": job_id,
            "cards_synced": sync_result.get("cards_synced", 0),
            "cards_total": sync_result.get("card_count", 0),
        },
        finished_at=step.finished_at or timezone.now(),
    )
    return True


def _finalize_completed_battery_step(*, run_id: int, step: ProcessStepRun) -> bool:
    result_payload = dict(step.result_payload or {})
    battery_id = result_payload.get("battery_id") or (step.input_payload or {}).get("battery_id")
    job_id = str(step.external_job_id or result_payload.get("job_id") or "").strip()
    if not battery_id or not job_id:
        return False

    battery = Battery.objects.filter(id=battery_id).first()
    if battery is None:
        return False

    from api.views import BatteryViewSet

    run = _refresh_run(run_id)
    battery_options = dict((run.input_payload or {}).get("battery_options") or {})
    question_format = battery_options.get("question_format") or "true_false"
    result = BatteryViewSet.save_questions_from_qa_pairs(
        battery=battery,
        job_id=job_id,
        question_format=str(question_format),
        overwrite=True,
        points_default=1,
    )
    config = dict(battery.config or {})
    config["last_generation_status"] = "completed"
    battery.config = config
    update_fields = ["config"]
    if battery.external_job_id != job_id:
        battery.external_job_id = job_id
        update_fields.append("external_job_id")
    if result.get("questions_created", 0) > 0 and battery.status != "Ready":
        battery.status = "Ready"
        update_fields.append("status")
    battery.save(update_fields=update_fields)

    if result.get("questions_created", 0) <= 0:
        cleanup_empty_generated_battery(battery=battery)
        return False

    update_step_progress(
        step=step,
        status=ProcessStepRun.Status.COMPLETED,
        progress_percent=100,
        status_message="Battery generated",
        result_payload={
            **result_payload,
            "battery_id": battery.id,
            "job_id": job_id,
            "questions_created": result.get("questions_created", 0),
            "options_created": result.get("options_created", 0),
            "qa_pairs_found": result.get("qa_pairs_found", 0),
        },
        finished_at=step.finished_at or timezone.now(),
    )
    return True


def _mark_run_failed(*, run: ProcessRun, step: ProcessStepRun | None, message: str, error_payload: dict[str, Any]) -> None:
    failed_now = timezone.now()
    if step:
        update_step_progress(
            step=step,
            status=ProcessStepRun.Status.FAILED,
            status_message=message,
            error_payload=error_payload,
            finished_at=failed_now,
        )
    finalize_step = _step_by_key(run, AUTO_STAGE_KEYS["finalize"])
    if finalize_step and finalize_step.status not in AUTO_TERMINAL_STEP_STATUSES:
        update_step_progress(
            step=finalize_step,
            status=ProcessStepRun.Status.BLOCKED,
            status_message="Blocked by upstream failure",
            error_payload=error_payload,
        )
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.FAILED,
        current_step_key=step.step_key if step else run.current_step_key,
        current_stage=step.step_key if step else run.current_stage,
        status_message=message,
        error_payload=error_payload,
        finished_at=failed_now,
    )
    publish_run_event(run, event="process_run.updated")


def _document_ready(document: Document) -> bool:
    return document.status == "ready" and Section.objects.filter(document_id=document.id).exists()


def _document_processing_job_id(document: Document) -> str:
    return str(document.job_id or "").strip()


def _document_has_inflight_processing(document: Document) -> bool:
    return document.status in {"pending", "processing"} and bool(_document_processing_job_id(document))


def _finalize_run_summary(*, run: ProcessRun, dispatch_errors: list[dict[str, Any]] | None = None) -> str:
    """Compute and persist the finalize_outputs step + run-level summary.

    Shared by the live orchestrator (orchestrate_auto_generate_run) and by
    reconcile_late_auto_generate_output, which re-runs this same computation
    when a Hope callback backfills an output artifact after the run already
    finalized. Keeping one implementation avoids the two call sites drifting
    apart on how deck/battery/tag_group counts and run status are derived.
    """
    finalize_step = _step_by_key(run, AUTO_STAGE_KEYS["finalize"])
    if finalize_step is None:
        logger.warning("auto-generate run %s has no finalize_outputs step; skipping summary recompute", run.run_id)
        return run.status

    if dispatch_errors is None:
        # Preserve dispatch errors recorded during the original run instead of
        # wiping them out when this is called again for a late callback.
        dispatch_errors = list((finalize_step.error_payload or {}).get("dispatch_errors") or [])

    flashcard_failures = [
        step for step in run.steps.filter(step_key=AUTO_STAGE_KEYS["generate_flashcards"])
        if step.status == ProcessStepRun.Status.FAILED
    ]
    battery_failures = [
        step for step in run.steps.filter(step_key=AUTO_STAGE_KEYS["generate_battery"])
        if step.status == ProcessStepRun.Status.FAILED
    ]
    completed_outputs = [
        step
        for step in run.steps.filter(step_key__in=[AUTO_STAGE_KEYS["generate_flashcards"], AUTO_STAGE_KEYS["generate_battery"]])
        if step.status in {ProcessStepRun.Status.COMPLETED, ProcessStepRun.Status.COMPLETED_WITH_ERRORS}
    ]

    if flashcard_failures or battery_failures or dispatch_errors:
        final_status = ProcessRun.Status.COMPLETED_WITH_ERRORS if completed_outputs else ProcessRun.Status.FAILED
        finalize_step_status = (
            ProcessStepRun.Status.COMPLETED_WITH_ERRORS if completed_outputs else ProcessStepRun.Status.FAILED
        )
        finalize_message = "Auto generation finished with errors" if completed_outputs else "Auto generation failed"
    else:
        final_status = ProcessRun.Status.COMPLETED
        finalize_step_status = ProcessStepRun.Status.COMPLETED
        finalize_message = "Auto generation completed"

    tag_group_count = run.artifacts.filter(artifact_type="tag_group").count()
    update_step_progress(
        step=finalize_step,
        status=finalize_step_status,
        progress_percent=100 if finalize_step_status != ProcessStepRun.Status.FAILED else finalize_step.progress_percent,
        status_message=finalize_message,
        result_payload={
            "tag_group_count": tag_group_count,
            "deck_count": run.artifacts.filter(artifact_type="deck").count(),
            "battery_count": run.artifacts.filter(artifact_type="battery").count(),
        },
        error_payload={"dispatch_errors": dispatch_errors} if dispatch_errors else {},
        started_at=finalize_step.started_at or timezone.now(),
        finished_at=timezone.now(),
    )
    recompute_run_progress(
        run=run,
        status=final_status,
        current_step_key=AUTO_STAGE_KEYS["finalize"],
        current_stage=AUTO_STAGE_KEYS["finalize"],
        status_message=finalize_message,
        result_payload={
            "tag_group_count": tag_group_count,
            "deck_ids": list(run.artifacts.filter(artifact_type="deck").values_list("resource_id", flat=True)),
            "battery_ids": list(run.artifacts.filter(artifact_type="battery").values_list("resource_id", flat=True)),
        },
        error_payload={"dispatch_errors": dispatch_errors} if dispatch_errors else {},
        finished_at=timezone.now(),
    )
    publish_run_event(
        run,
        event="process_run.completed" if final_status in {ProcessRun.Status.COMPLETED, ProcessRun.Status.COMPLETED_WITH_ERRORS} else "process_run.updated",
    )
    return final_status


def orchestrate_auto_generate_run(*, run_id: int, timeout_seconds: float = 7200.0) -> None:
    run = _refresh_run(run_id)
    payload = normalize_auto_generate_request(run.input_payload or {})
    document_ids = payload["document_ids"]
    flashcard_options = payload["flashcard_options"]
    battery_options = payload["battery_options"]
    documents = list(
        Document.objects.select_related("project", "collection", "uploaded_by")
        .filter(id__in=document_ids)
        .order_by("id")
    )
    documents_by_id = {document.id: document for document in documents}
    collection_id = (run.context_payload or {}).get("collection_id")
    project_id = (run.context_payload or {}).get("project_id")

    if len(documents) != len(document_ids):
        _mark_run_failed(
            run=run,
            step=_step_by_key(run, AUTO_STAGE_KEYS["process_document"]),
            message="Some documents were not found",
            error_payload={"missing_document_ids": [doc_id for doc_id in document_ids if doc_id not in documents_by_id]},
        )
        return

    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.RUNNING,
        current_step_key=AUTO_STAGE_KEYS["process_document"],
        current_stage=AUTO_STAGE_KEYS["process_document"],
        status_message="Dispatching document processing",
    )
    publish_run_event(run, event="process_run.updated")

    for document in documents:
        run = _refresh_run(run_id)
        step = _step_by_key(run, AUTO_STAGE_KEYS["process_document"], item_key=str(document.id))
        if not step:
            continue
        existing_job_id = _document_processing_job_id(document)
        if _document_ready(document):
            update_step_progress(
                step=step,
                status=ProcessStepRun.Status.COMPLETED,
                progress_percent=100,
                status_message="Document already processed",
                result_payload={"document_id": document.id, "status": "ready"},
                started_at=timezone.now(),
                finished_at=timezone.now(),
            )
            continue
        if _document_has_inflight_processing(document):
            update_step_progress(
                step=step,
                status=ProcessStepRun.Status.QUEUED,
                progress_percent=0,
                status_message="Reusing existing document processing",
                external_job_id=existing_job_id,
                result_payload={"document_id": document.id, "job_id": existing_job_id, "reused_existing_job": True},
                started_at=step.started_at or timezone.now(),
            )
            enqueue_progress_consumer(run_id=run.id, job_id=existing_job_id)
            continue

        job_id = str(uuid.uuid4())
        request_payload = {
            "job_id": job_id,
            "doc_id": document.id,
            "file_path": document.file.name,
            "process": "process_pdf",
            "options": {},
            "metadata": {"run_id": str(run.run_id)},
        }
        try:
            response_payload = dispatch_process_document(request_payload)
        except HopeDispatchError as exc:
            _mark_run_failed(
                run=run,
                step=step,
                message="Document dispatch failed",
                error_payload={"error": str(exc), "document_id": document.id},
            )
            return

        ws_job_id = str(response_payload.get("job_id") or job_id)
        update_step_progress(
            step=step,
            status=ProcessStepRun.Status.QUEUED,
            progress_percent=0,
            status_message="Queued in Hope",
            external_job_id=ws_job_id,
            result_payload=response_payload,
            started_at=timezone.now(),
        )
        document.status = "processing"
        document.job_id = ws_job_id
        document.processing_error = None
        document.save(update_fields=["status", "job_id", "processing_error"])
        enqueue_progress_consumer(run_id=run.id, job_id=ws_job_id)

    run = _refresh_run(run_id)
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.RUNNING,
        current_step_key=AUTO_STAGE_KEYS["process_document"],
        current_stage=AUTO_STAGE_KEYS["process_document"],
        status_message="Processing documents",
    )
    publish_run_event(run, event="process_run.updated")

    document_steps = _wait_for_steps(run_id=run.id, step_key=AUTO_STAGE_KEYS["process_document"], timeout_seconds=timeout_seconds)
    if not document_steps or any(step.status in {ProcessStepRun.Status.FAILED, ProcessStepRun.Status.CANCELED} for step in document_steps):
        run = _refresh_run(run_id)
        _mark_run_failed(
            run=run,
            step=_step_by_key(run, AUTO_STAGE_KEYS["process_document"]),
            message="One or more documents failed during processing",
            error_payload={"step_key": AUTO_STAGE_KEYS["process_document"]},
        )
        return

    for document in documents:
        if Document.objects.filter(id=document.id).exists():
            Document.objects.filter(id=document.id).update(status="ready", processing_error=None)

    run = _refresh_run(run_id)
    aggregate_step = _step_by_key(run, AUTO_STAGE_KEYS["aggregate"])
    update_step_progress(
        step=aggregate_step,
        status=ProcessStepRun.Status.RUNNING,
        progress_percent=10,
        status_message="Collecting unique tags",
        started_at=timezone.now(),
    )
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.RUNNING,
        current_step_key=AUTO_STAGE_KEYS["aggregate"],
        current_stage=AUTO_STAGE_KEYS["aggregate"],
        status_message="Collecting unique tags",
    )
    publish_run_event(run, event="process_run.updated")

    tags = _derive_unique_tags(documents=documents)
    if not tags:
        _mark_run_failed(
            run=run,
            step=aggregate_step,
            message="No tags could be derived from the documents",
            error_payload={"document_ids": document_ids},
        )
        return
    update_step_progress(
        step=aggregate_step,
        status=ProcessStepRun.Status.COMPLETED,
        progress_percent=100,
        status_message="Unique tags collected",
        result_payload={"tag_count": len(tags), "tags": tags},
        finished_at=timezone.now(),
    )

    run = _refresh_run(run_id)
    partition_step = _step_by_key(run, AUTO_STAGE_KEYS["partition"])
    update_step_progress(
        step=partition_step,
        status=ProcessStepRun.Status.RUNNING,
        progress_percent=25,
        status_message="Grouping tags",
        started_at=timezone.now(),
    )
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.RUNNING,
        current_step_key=AUTO_STAGE_KEYS["partition"],
        current_stage=AUTO_STAGE_KEYS["partition"],
        status_message="Grouping tags",
    )
    publish_run_event(run, event="process_run.updated")

    tag_groups_payload = _chunk_tags(tags, payload["tag_group_size"])
    created_groups: list[tuple[int, list[str]]] = []
    for group_index, group_tags in enumerate(tag_groups_payload, start=1):
        tag_group = TagGroup.objects.create(
            collection_id=int(collection_id) if collection_id else None,
            name=_fallback_output_title(tags=group_tags, kind="group", index=group_index),
            metadata={"run_id": str(run.run_id), "group_index": group_index, "tag_count": len(group_tags)},
        )
        TagGroupItem.objects.bulk_create(
            [
                TagGroupItem(
                    tag_group=tag_group,
                    value=tag_value,
                    order=item_index,
                    metadata={"run_id": str(run.run_id)},
                )
                for item_index, tag_value in enumerate(group_tags, start=1)
            ]
        )
        created_groups.append((tag_group.id, group_tags))
        _sync_run_output_artifact(
            run=run,
            step=partition_step,
            artifact_key=f"tag_group:{tag_group.id}",
            artifact_type="tag_group",
            resource_type="tag_group",
            resource_id=str(tag_group.id),
            payload={"tag_group_id": tag_group.id, "tags": group_tags},
            metadata={"group_index": group_index},
        )

    if not created_groups:
        _mark_run_failed(
            run=run,
            step=partition_step,
            message="No tag groups could be created",
            error_payload={"tag_count": len(tags)},
        )
        return

    update_step_progress(
        step=partition_step,
        status=ProcessStepRun.Status.COMPLETED,
        progress_percent=100,
        status_message="Tags grouped",
        result_payload={"tag_group_ids": [group_id for group_id, _ in created_groups], "group_count": len(created_groups)},
        finished_at=timezone.now(),
    )

    output_dependencies: list[ProcessStepDependency] = []
    flashcard_steps: list[ProcessStepRun] = []
    battery_steps: list[ProcessStepRun] = []
    run = _refresh_run(run_id)
    partition_step = _step_by_key(run, AUTO_STAGE_KEYS["partition"])
    finalize_step = _step_by_key(run, AUTO_STAGE_KEYS["finalize"])

    for group_index, (tag_group_id, group_tags) in enumerate(created_groups, start=1):
        flashcard_step = ProcessStepRun.objects.create(
            run=run,
            step_key=AUTO_STAGE_KEYS["generate_flashcards"],
            item_key=str(tag_group_id),
            step_type="flashcard_generation",
            status=ProcessStepRun.Status.PENDING,
            execution_mode=ProcessStepRun.ExecutionMode.FANOUT,
            sequence=400 + group_index,
            weight=10,
            status_message="Pending flashcard generation",
            input_payload={"tag_group_id": tag_group_id, "tags": group_tags},
        )
        battery_step = ProcessStepRun.objects.create(
            run=run,
            step_key=AUTO_STAGE_KEYS["generate_battery"],
            item_key=str(tag_group_id),
            step_type="battery_generation",
            status=ProcessStepRun.Status.PENDING,
            execution_mode=ProcessStepRun.ExecutionMode.FANOUT,
            sequence=600 + group_index,
            weight=10,
            status_message="Pending battery generation",
            input_payload={"tag_group_id": tag_group_id, "tags": group_tags},
        )
        flashcard_steps.append(flashcard_step)
        battery_steps.append(battery_step)
        output_dependencies.extend(
            [
                ProcessStepDependency(step=flashcard_step, depends_on=partition_step),
                ProcessStepDependency(step=battery_step, depends_on=partition_step),
                ProcessStepDependency(step=finalize_step, depends_on=flashcard_step),
                ProcessStepDependency(step=finalize_step, depends_on=battery_step),
            ]
        )
    ProcessStepDependency.objects.bulk_create(output_dependencies)

    process_base_url = _normalize_base_url(os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080"))
    progress_base_url = _normalize_base_url(os.getenv("WS_PROCESS_REQUEST_BASE_URL", process_base_url))
    dispatch_errors: list[dict[str, Any]] = []

    for group_index, (tag_group_id, group_tags) in enumerate(created_groups, start=1):
        run = _refresh_run(run_id)
        flashcard_step = _step_by_key(run, AUTO_STAGE_KEYS["generate_flashcards"], item_key=str(tag_group_id))
        battery_step = _step_by_key(run, AUTO_STAGE_KEYS["generate_battery"], item_key=str(tag_group_id))
        source_bundle = {
            "collection_id": collection_id,
            "document_ids": [str(doc_id) for doc_id in document_ids],
            "section_ids": [],
            "tag_group_ids": [str(tag_group_id)],
            "tags": group_tags,
            "title_hints": group_tags[:6],
        }

        deck = Deck.objects.create(
            project_id=int(project_id) if project_id else None,
            collection_id=int(collection_id) if collection_id else None,
            owner=run.initiated_by,
            title=_fallback_output_title(tags=group_tags, kind="flashcards", index=group_index),
            description="",
            visibility="private",
        )
        sync_deck_source_links(deck=deck, source_bundle=source_bundle)
        flashcard_payload = {
            "job_id": str(uuid.uuid4()),
            "user_id": str(run.initiated_by_id or ""),
            "deck_id": deck.id,
            "title": deck.title,
            "quantity": flashcard_options["cards_per_group"],
            "difficulty": flashcard_options["difficulty"],
            "source_bundle": source_bundle,
            "metadata": {
                "run_id": str(run.run_id),
                "tag_group_id": tag_group_id,
                "group_index": group_index,
                "skip_summary": True,
                "callback_url": f"{_build_internal_callback_base()}/api/decks/{deck.id}/finalize-from-service/",
                "callback_token": _internal_service_token(),
            },
        }
        try:
            flashcard_response = dispatch_flashcard_generation(flashcard_payload)
            flashcard_job_id = str(flashcard_response.get("job_id") or flashcard_payload["job_id"])
            deck.external_job_id = flashcard_job_id
            deck.title = str(flashcard_response.get("title") or deck.title)
            deck.save(update_fields=["external_job_id", "title"])
            update_step_progress(
                step=flashcard_step,
                status=ProcessStepRun.Status.QUEUED,
                progress_percent=0,
                status_message="Queued flashcard generation",
                external_job_id=flashcard_job_id,
                result_payload={
                    "deck_id": deck.id,
                    "job_id": flashcard_job_id,
                    "ws_url": _build_ws_url(progress_base_url, flashcard_job_id),
                },
            )
            enqueue_progress_consumer(run_id=run.id, job_id=flashcard_job_id)
        except HopeDispatchError as exc:
            dispatch_errors.append({"kind": "flashcards", "tag_group_id": tag_group_id, "error": str(exc)})
            update_step_progress(
                step=flashcard_step,
                status=ProcessStepRun.Status.FAILED,
                status_message="Flashcard dispatch failed",
                error_payload={"error": str(exc)},
                finished_at=timezone.now(),
            )
            cleanup_empty_generated_deck(deck=deck)

        battery = Battery.objects.create(
            project_id=int(project_id) if project_id else None,
            collection_id=int(collection_id) if collection_id else None,
            name=_fallback_output_title(tags=group_tags, kind="battery", index=group_index),
            status="Draft",
            difficulty=_normalize_difficulty(battery_options["difficulty"], battery=True),
            visibility="private",
        )
        source_sync_payload = dict(source_bundle)
        sync_battery_source_links(battery=battery, source_bundle=source_sync_payload)
        battery_payload = {
            "job_id": str(uuid.uuid4()),
            "battery_id": battery.id,
            "title": battery.name,
            "query_text": group_tags,
            "quantity_question": battery_options["questions_per_group"],
            "difficulty": battery_options["difficulty"],
            "question_format": battery_options["question_format"],
            "source_bundle": source_bundle,
            "metadata": {
                "run_id": str(run.run_id),
                "tag_group_id": tag_group_id,
                "group_index": group_index,
                "skip_summary": True,
                "callback_url": f"{_build_internal_callback_base()}/api/batteries/{battery.id}/finalize-from-service/",
                "callback_token": _internal_service_token(),
            },
        }
        try:
            battery_response = dispatch_battery_generation(battery_payload)
            battery_job_id = str(battery_response.get("job_id") or battery_payload["job_id"])
            battery.external_job_id = battery_job_id
            battery.name = str(battery_response.get("title") or battery.name)
            battery.save(update_fields=["external_job_id", "name"])
            update_step_progress(
                step=battery_step,
                status=ProcessStepRun.Status.QUEUED,
                progress_percent=0,
                status_message="Queued battery generation",
                external_job_id=battery_job_id,
                result_payload={
                    "battery_id": battery.id,
                    "job_id": battery_job_id,
                    "ws_url": _build_ws_url(progress_base_url, battery_job_id),
                },
            )
            enqueue_progress_consumer(run_id=run.id, job_id=battery_job_id)
        except HopeDispatchError as exc:
            dispatch_errors.append({"kind": "battery", "tag_group_id": tag_group_id, "error": str(exc)})
            update_step_progress(
                step=battery_step,
                status=ProcessStepRun.Status.FAILED,
                status_message="Battery dispatch failed",
                error_payload={"error": str(exc)},
                finished_at=timezone.now(),
            )
            cleanup_empty_generated_battery(battery=battery)

    run = _refresh_run(run_id)
    finalize_step = _step_by_key(run, AUTO_STAGE_KEYS["finalize"])
    if finalize_step and finalize_step.status == ProcessStepRun.Status.PENDING:
        update_step_progress(
            step=finalize_step,
            status=ProcessStepRun.Status.WAITING,
            status_message="Waiting for output callbacks",
        )
        run = _refresh_run(run_id)
    recompute_run_progress(
        run=run,
        status=ProcessRun.Status.RUNNING,
        current_step_key=AUTO_STAGE_KEYS["generate_flashcards"],
        current_stage=AUTO_STAGE_KEYS["generate_flashcards"],
        status_message="Generating outputs",
    )
    publish_run_event(run, event="process_run.updated")

    flashcard_steps = _wait_for_steps(
        run_id=run.id,
        step_key=AUTO_STAGE_KEYS["generate_flashcards"],
        timeout_seconds=timeout_seconds,
        require_callback_status=True,
    )
    for step in flashcard_steps:
        deck_id = (step.result_payload or {}).get("deck_id")
        job_id = step.external_job_id
        if not deck_id and job_id:
            matched_deck = Deck.objects.filter(external_job_id=job_id).only("id").first()
            deck_id = matched_deck.id if matched_deck else None
        if not deck_id or not job_id or step.status in {ProcessStepRun.Status.FAILED, ProcessStepRun.Status.CANCELED}:
            continue
        completed_at = step.finished_at or step.last_heartbeat_at or timezone.now()
        deck = Deck.objects.filter(id=deck_id).first()
        if deck is None:
            continue
        from api.views import DeckViewSet

        sync_result = DeckViewSet._sync_generated_flashcards(deck=deck, job_id=job_id)
        updated_count = int(sync_result.get("cards_synced", 0) or 0)
        card_count = int(sync_result.get("card_count", 0) or 0)
        if card_count <= 0:
            update_step_progress(
                step=step,
                status=ProcessStepRun.Status.FAILED,
                status_message="No flashcards were synced",
                error_payload={"deck_id": deck_id, "job_id": job_id},
                finished_at=completed_at,
            )
            continue
        update_step_progress(
            step=step,
            status=ProcessStepRun.Status.COMPLETED,
            progress_percent=100,
            status_message="Flashcards generated",
            result_payload={"deck_id": deck_id, "job_id": job_id, "cards_synced": updated_count, "cards_total": card_count},
            finished_at=completed_at,
        )
        deck = Deck.objects.filter(id=deck_id).first()
        if deck:
            _sync_run_output_artifact(
                run=run,
                step=step,
                artifact_key=f"deck:{deck.id}",
                artifact_type="deck",
                resource_type="deck",
                resource_id=str(deck.id),
                payload={"deck_id": deck.id, "job_id": job_id, "card_count": card_count},
                metadata={"title": deck.title},
            )

    battery_steps = _wait_for_steps(
        run_id=run.id,
        step_key=AUTO_STAGE_KEYS["generate_battery"],
        timeout_seconds=timeout_seconds,
        require_callback_status=True,
    )
    for step in battery_steps:
        battery_id = (step.result_payload or {}).get("battery_id") or (step.input_payload or {}).get("battery_id")
        battery = Battery.objects.filter(id=battery_id).first() if battery_id else None
        if battery:
            question_count = battery.questions_rel.count()
            _sync_run_output_artifact(
                run=run,
                step=step,
                artifact_key=f"battery:{battery.id}",
                artifact_type="battery",
                resource_type="battery",
                resource_id=str(battery.id),
                payload={"battery_id": battery.id, "job_id": step.external_job_id, "question_count": question_count},
                metadata={"title": battery.name, "status": battery.status},
                produced=battery.status == "Ready",
            )

    run = _refresh_run(run_id)
    _finalize_run_summary(run=run, dispatch_errors=dispatch_errors)


def reconcile_late_auto_generate_output(*, step: ProcessStepRun) -> None:
    """Backfill a missing deck/battery artifact from a late Hope callback.

    orchestrate_auto_generate_run's watchdog (_wait_for_steps) can mark a
    generate_flashcards/generate_battery step FAILED for a "stale worker" if
    Hope takes longer than the stale-timeout to call back (e.g. a slow LLM
    generation with no intermediate heartbeat). When Hope's real callback
    (DeckViewSet/BatteryViewSet.finalize_from_service) arrives afterward, it
    already overwrites that step back to COMPLETED with the correct
    deck_id/battery_id - but by then the orchestrator has already finalized
    the run without ever creating the corresponding ProcessArtifact, so the
    run stays stuck reporting e.g. deck_count=0 even though generation
    actually succeeded.

    Call this right after finalize_from_service marks its auto_workflow_step
    COMPLETED. It only acts if the run's finalize_outputs step already
    reached a terminal state (i.e. the orchestrator is no longer waiting on
    this step itself) - otherwise the live orchestrator will pick up the
    output through its normal aggregation loop and this is a no-op.
    """
    run = step.run
    if run.workflow_key != AUTO_WORKFLOW_KEY or step.status != ProcessStepRun.Status.COMPLETED:
        return
    if step.step_key not in {AUTO_STAGE_KEYS["generate_flashcards"], AUTO_STAGE_KEYS["generate_battery"]}:
        return

    run = _refresh_run(run.id)
    finalize_step = _step_by_key(run, AUTO_STAGE_KEYS["finalize"])
    if finalize_step is None or finalize_step.status not in AUTO_TERMINAL_STEP_STATUSES:
        return

    logger.info(
        "Reconciling late auto-generate callback for run %s step %s (%s) after finalize already ran at %s",
        run.run_id,
        step.id,
        step.step_key,
        finalize_step.finished_at,
    )

    result_payload = dict(step.result_payload or {})
    if step.step_key == AUTO_STAGE_KEYS["generate_flashcards"]:
        deck_id = result_payload.get("deck_id")
        deck = Deck.objects.filter(id=deck_id).first() if deck_id else None
        if deck is not None:
            _sync_run_output_artifact(
                run=run,
                step=step,
                artifact_key=f"deck:{deck.id}",
                artifact_type="deck",
                resource_type="deck",
                resource_id=str(deck.id),
                payload={
                    "deck_id": deck.id,
                    "job_id": step.external_job_id,
                    "card_count": result_payload.get("card_count", 0),
                },
                metadata={"title": deck.title},
            )
        else:
            logger.warning(
                "Late auto-generate callback for run %s step %s had no resolvable deck (deck_id=%s)",
                run.run_id,
                step.id,
                deck_id,
            )
    else:
        battery_id = result_payload.get("battery_id")
        battery = Battery.objects.filter(id=battery_id).first() if battery_id else None
        if battery is not None:
            _sync_run_output_artifact(
                run=run,
                step=step,
                artifact_key=f"battery:{battery.id}",
                artifact_type="battery",
                resource_type="battery",
                resource_id=str(battery.id),
                payload={
                    "battery_id": battery.id,
                    "job_id": step.external_job_id,
                    "question_count": battery.questions_rel.count(),
                },
                metadata={"title": battery.name, "status": battery.status},
                produced=battery.status == "Ready",
            )
        else:
            logger.warning(
                "Late auto-generate callback for run %s step %s had no resolvable battery (battery_id=%s)",
                run.run_id,
                step.id,
                battery_id,
            )

    _finalize_run_summary(run=run)

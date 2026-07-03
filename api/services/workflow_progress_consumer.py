from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

from django.db import close_old_connections
from django.utils import timezone
from redis import Redis
from redis.exceptions import RedisError

from api.utils.logging import get_logger
from ..models import ProcessRun, ProcessStepRun
from .workflow_progress import publish_run_event, recompute_run_progress, update_step_progress

logger = get_logger(__name__)

DONE_STATUSES = {"COMPLETED", "FAILED", "ERROR"}
RUNNING_LIKE_STATUSES = {
    "RUNNING",
    "VALIDATED",
    "PREPARED",
    "OCR",
    "PERSISTED",
    "TAGGING",
    "TAGGED",
    "GENERATING_QUESTIONS",
    "QA_GENERATING",
    "QA_VARIANTS",
    "ANSWERING",
    "NO_EMBEDDINGS",
}


@dataclass
class HopeProgressSnapshot:
    job_id: str
    payload: dict[str, Any]
    source: str


def _progress_redis_url() -> str:
    return os.getenv("WORKFLOW_PROGRESS_REDIS_URL") or os.getenv("PROGRESS_REDIS_URL") or "redis://localhost:6379/2"


def _build_redis_client() -> Redis:
    return Redis.from_url(_progress_redis_url(), decode_responses=True)


def _normalize_progress(value: Any) -> float:
    try:
        pct = float(value)
    except (TypeError, ValueError):
        pct = 0.0
    return max(0.0, min(100.0, pct))


def _map_hope_status(hope_status: str) -> str:
    normalized = str(hope_status or "").upper()
    if normalized == "QUEUED":
        return ProcessStepRun.Status.QUEUED
    if normalized in DONE_STATUSES:
        return ProcessStepRun.Status.COMPLETED if normalized == "COMPLETED" else ProcessStepRun.Status.FAILED
    if normalized in RUNNING_LIKE_STATUSES:
        return ProcessStepRun.Status.RUNNING
    return ProcessStepRun.Status.RUNNING


def _load_run(run_id: str | int) -> ProcessRun:
    return ProcessRun.objects.prefetch_related("steps").get(pk=run_id)


def _resolve_step(run: ProcessRun, *, job_id: str, payload: dict[str, Any]) -> ProcessStepRun | None:
    external_job_id = str(job_id or "").strip()
    if external_job_id:
        step = (
            run.steps.filter(external_job_id=external_job_id)
            .order_by("sequence", "id")
            .first()
        )
        if step:
            return step

    doc_id = str(payload.get("doc_id") or "").strip()
    if doc_id:
        for candidate in run.steps.all():
            if candidate.item_key == doc_id:
                return candidate

    return (
        run.steps.exclude(
            status__in=[
                ProcessStepRun.Status.COMPLETED,
                ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
                ProcessStepRun.Status.FAILED,
                ProcessStepRun.Status.CANCELED,
                ProcessStepRun.Status.SKIPPED,
            ]
        )
        .order_by("sequence", "id")
        .first()
    )


def _runtime_metrics_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    ignored = {"doc_id", "progress", "status", "current_step"}
    return {key: value for key, value in payload.items() if key not in ignored}


def _apply_progress_snapshot(run_id: str | int, snapshot: HopeProgressSnapshot) -> bool:
    close_old_connections()
    run = _load_run(run_id)
    if run.status in {
        ProcessRun.Status.COMPLETED,
        ProcessRun.Status.COMPLETED_WITH_ERRORS,
        ProcessRun.Status.FAILED,
        ProcessRun.Status.CANCELED,
    }:
        return True

    payload = snapshot.payload or {}
    step = _resolve_step(run, job_id=snapshot.job_id, payload=payload)
    if not step:
        logger.warning("workflow_progress_consumer no step matched run_id=%s job_id=%s", run.id, snapshot.job_id)
        return False

    hope_status = str(payload.get("status", "")).upper()
    current_step = str(payload.get("current_step") or "").strip()
    progress_percent = _normalize_progress(payload.get("progress"))
    runtime_metrics = _runtime_metrics_from_payload(payload)
    result_payload = payload if hope_status == "COMPLETED" else None
    status_message = current_step or hope_status.title()
    worker_step = current_step

    if hope_status == "COMPLETED":
        existing_result = dict(step.result_payload or {})
        preserves_callback_state = (
            (step.step_key == "generate_flashcards" and existing_result.get("deck_id"))
            or (step.step_key == "generate_battery" and existing_result.get("battery_id"))
        )
        if preserves_callback_state:
            merged_payload = dict(payload)
            merged_payload.update(existing_result)
            result_payload = merged_payload
            status_message = step.status_message or status_message
            worker_step = step.worker_step or worker_step

    update_step_progress(
        step=step,
        status=_map_hope_status(hope_status),
        progress_percent=progress_percent,
        status_message=status_message,
        worker_step=worker_step,
        external_job_id=snapshot.job_id,
        runtime_metrics=runtime_metrics if runtime_metrics else None,
        result_payload=result_payload,
        error_payload=payload if hope_status in {"FAILED", "ERROR"} else None,
        last_heartbeat_at=timezone.now(),
    )

    recompute_run_progress(
        run=run,
        status=None,
        current_step_key=step.step_key,
        current_stage=step.step_key,
        status_message=current_step or hope_status.title(),
        job_id=snapshot.job_id,
    )

    event_name = "process_run.completed" if run.status in {
        ProcessRun.Status.COMPLETED,
        ProcessRun.Status.COMPLETED_WITH_ERRORS,
    } else "process_run.updated"
    publish_run_event(run, event=event_name)
    return hope_status in DONE_STATUSES or run.status in {
        ProcessRun.Status.COMPLETED,
        ProcessRun.Status.COMPLETED_WITH_ERRORS,
        ProcessRun.Status.FAILED,
        ProcessRun.Status.CANCELED,
    }


def consume_hope_progress_for_run(
    *,
    run_id: str | int,
    job_id: str,
    poll_interval_seconds: float = 5.0,
    pubsub_timeout_seconds: float = 10.0,
    max_runtime_seconds: float = 7200.0,
) -> None:
    started = time.monotonic()
    client: Redis | None = None
    pubsub = None
    last_snapshot: dict[str, Any] | None = None
    channel = f"progress:{job_id}"
    key = f"job:{job_id}"

    try:
        client = _build_redis_client()
        pubsub = client.pubsub()
        pubsub.subscribe(channel)
        logger.info("workflow_progress_consumer subscribed run_id=%s job_id=%s channel=%s", run_id, job_id, channel)
    except RedisError:
        logger.warning("workflow_progress_consumer pubsub unavailable; starting in polling mode run_id=%s job_id=%s", run_id, job_id, exc_info=True)
        client = None
        pubsub = None

    try:
        while time.monotonic() - started < max_runtime_seconds:
            close_old_connections()
            run = ProcessRun.objects.filter(pk=run_id).only("id", "status", "control_state").first()
            if not run:
                logger.warning("workflow_progress_consumer run missing run_id=%s job_id=%s", run_id, job_id)
                return
            if run.status in {
                ProcessRun.Status.COMPLETED,
                ProcessRun.Status.COMPLETED_WITH_ERRORS,
                ProcessRun.Status.FAILED,
                ProcessRun.Status.CANCELED,
            }:
                return

            processed_terminal = False
            try:
                if client is None:
                    client = _build_redis_client()
                if pubsub is None:
                    pubsub = client.pubsub()
                    pubsub.subscribe(channel)

                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=pubsub_timeout_seconds)
                if message and message.get("data"):
                    raw_data = message["data"]
                    try:
                        payload = json.loads(raw_data)
                    except (TypeError, json.JSONDecodeError):
                        payload = {"raw": raw_data}
                    processed_terminal = _apply_progress_snapshot(
                        run_id,
                        HopeProgressSnapshot(job_id=job_id, payload=payload, source="pubsub"),
                    )
                else:
                    snapshot = client.hgetall(key) or {}
                    if snapshot and snapshot != last_snapshot:
                        last_snapshot = snapshot
                        processed_terminal = _apply_progress_snapshot(
                            run_id,
                            HopeProgressSnapshot(job_id=job_id, payload=snapshot, source="poll"),
                        )
                    else:
                        time.sleep(poll_interval_seconds)
            except RedisError:
                logger.warning("workflow_progress_consumer redis failure; falling back to polling run_id=%s job_id=%s", run_id, job_id, exc_info=True)
                try:
                    if pubsub is not None:
                        pubsub.close()
                except Exception:
                    pass
                pubsub = None
                client = None
                time.sleep(poll_interval_seconds)
            if processed_terminal:
                return
    finally:
        try:
            if pubsub is not None:
                pubsub.unsubscribe(channel)
                pubsub.close()
        except Exception:
            pass
        try:
            if client is not None:
                client.close()
        except Exception:
            pass


def enqueue_progress_consumer(*, run_id: str | int, job_id: str) -> bool:
    try:
        from api.tasks import consume_hope_progress_task
    except Exception:
        logger.warning("workflow_progress_consumer enqueue skipped because Celery task import failed", exc_info=True)
        return False

    consume_hope_progress_task.delay(str(run_id), str(job_id))
    return True

from __future__ import annotations

import json
import os
from typing import Any

from redis import Redis

from api.utils.logging import get_logger

logger = get_logger(__name__)

HOPE_PROCESS_DOCUMENT_TASK = "pipeline.prepare.dispatch_document"
HOPE_GENERATE_BATTERY_TASK = "pipeline.llm.generate_questions"
HOPE_GENERATE_FLASHCARDS_TASK = "flashcards.generate"

_hope_celery_app: Any | None = None


class HopeDispatchError(Exception):
    pass


def _hope_broker_url() -> str:
    return os.getenv("HOPE_CELERY_BROKER_URL", "redis://hope-redis:6379/0")


def _hope_default_queue() -> str:
    return os.getenv("HOPE_CELERY_DEFAULT_QUEUE", "celery")


def _hope_semantic_queue() -> str:
    return os.getenv("HOPE_CELERY_SEMANTIC_QUEUE", "semantic")


def _progress_redis_url() -> str:
    return os.getenv("WORKFLOW_PROGRESS_REDIS_URL") or os.getenv("PROGRESS_REDIS_URL") or "redis://hope-redis:6379/2"


def _celery_app() -> Any:
    global _hope_celery_app
    if _hope_celery_app is None:
        from celery import Celery

        broker_url = _hope_broker_url()
        _hope_celery_app = Celery("hope_dispatch")
        # Celery will otherwise inherit CELERY_BROKER_URL from the Anko process
        # environment, which points at Anko's own broker DB instead of Hope's.
        _hope_celery_app.conf.update(
            broker_url=broker_url,
            broker_read_url=broker_url,
            broker_write_url=broker_url,
            task_default_queue=_hope_default_queue(),
        )
    return _hope_celery_app


def _publish_queued_progress(
    *,
    job_id: str,
    doc_id: str | None,
    current_step: str,
    extra: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "doc_id": doc_id,
        "progress": 0,
        "status": "QUEUED",
        "current_step": current_step,
    }
    if extra:
        payload.update(extra)

    mapping = {key: str(value) for key, value in payload.items() if value is not None}
    client = Redis.from_url(_progress_redis_url(), decode_responses=True)
    try:
        client.hset(f"job:{job_id}", mapping=mapping)
        client.hset(f"job:{job_id}:progress", mapping={"progress": 0})
        client.publish(f"progress:{job_id}", json.dumps(payload))
    finally:
        try:
            client.close()
        except Exception:
            pass


def _queue_for_task(task_name: str) -> str:
    if task_name in {HOPE_GENERATE_BATTERY_TASK, HOPE_GENERATE_FLASHCARDS_TASK}:
        return _hope_semantic_queue()
    return _hope_default_queue()


def _send_task(*, task_name: str, args: list[Any], job_id: str):
    try:
        app = _celery_app()
        with app.connection_for_write(url=_hope_broker_url()) as connection:
            return app.send_task(
                task_name,
                args=args,
                task_id=job_id,
                queue=_queue_for_task(task_name),
                connection=connection,
            )
    except Exception as exc:
        raise HopeDispatchError(f"Failed to dispatch Hope task {task_name}: {exc}") from exc


def dispatch_process_document(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        raise HopeDispatchError("job_id is required for Hope document dispatch")

    doc_id = payload.get("doc_id")
    settings_payload = dict(payload.get("metadata") or {})
    settings_payload.setdefault("job_id", job_id)
    settings_payload.setdefault("document_id", doc_id)
    task = _send_task(task_name=HOPE_PROCESS_DOCUMENT_TASK, args=[payload, settings_payload], job_id=job_id)
    _publish_queued_progress(
        job_id=job_id,
        doc_id=str(doc_id) if doc_id is not None else None,
        current_step="ingestion",
        extra={"process": "process_pdf", "task_id": task.id},
    )
    return {
        "task_id": task.id,
        "job_id": job_id,
        "document_id": doc_id,
        "process": "process_pdf",
        "metadata": payload.get("metadata") or {},
        "status": "queued",
    }


def dispatch_battery_generation(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        raise HopeDispatchError("job_id is required for Hope battery dispatch")

    task = _send_task(
        task_name=HOPE_GENERATE_BATTERY_TASK,
        args=[payload, dict(payload.get("metadata") or {})],
        job_id=job_id,
    )
    source_bundle = payload.get("source_bundle") or {}
    document_ids = source_bundle.get("document_ids") or payload.get("document_ids") or []
    progress_doc_id = ",".join(str(item) for item in document_ids if str(item).strip()) or None
    _publish_queued_progress(
        job_id=job_id,
        doc_id=progress_doc_id,
        current_step="generate_question",
        extra={"process": "generate_question", "task_id": task.id},
    )
    return {
        "task_id": task.id,
        "job_id": job_id,
        "battery_id": payload.get("battery_id"),
        "title": payload.get("title"),
        "status": "queued",
    }


def dispatch_flashcard_generation(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        raise HopeDispatchError("job_id is required for Hope flashcard dispatch")

    task = _send_task(task_name=HOPE_GENERATE_FLASHCARDS_TASK, args=[job_id, payload], job_id=job_id)
    source_bundle = payload.get("source_bundle") or {}
    document_ids = source_bundle.get("document_ids") or payload.get("document_ids") or []
    progress_doc_id = ",".join(str(item) for item in document_ids if str(item).strip()) or None
    _publish_queued_progress(
        job_id=job_id,
        doc_id=progress_doc_id,
        current_step="flashcard_generation",
        extra={"task_id": task.id, "title": payload.get("title")},
    )
    return {
        "task_id": task.id,
        "job_id": job_id,
        "deck_id": payload.get("deck_id"),
        "title": payload.get("title"),
        "status": "queued",
    }

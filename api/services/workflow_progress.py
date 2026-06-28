from __future__ import annotations

from decimal import Decimal, InvalidOperation

from django.db import transaction
from django.utils import timezone

from api.utils.logging import get_logger
from ..models import ProcessRun, ProcessStepRun

logger = get_logger(__name__)

TERMINAL_RUN_STATUSES = {
    ProcessRun.Status.COMPLETED,
    ProcessRun.Status.COMPLETED_WITH_ERRORS,
    ProcessRun.Status.FAILED,
    ProcessRun.Status.CANCELED,
}

TERMINAL_STEP_STATUSES = {
    ProcessStepRun.Status.COMPLETED,
    ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
    ProcessStepRun.Status.FAILED,
    ProcessStepRun.Status.SKIPPED,
    ProcessStepRun.Status.CANCELED,
}


def _to_decimal_percent(value) -> Decimal:
    if value is None:
        return Decimal("0")
    if isinstance(value, Decimal):
        percent = value
    else:
        try:
            percent = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            percent = Decimal("0")
    if percent < 0:
        return Decimal("0")
    if percent > 100:
        return Decimal("100")
    return percent.quantize(Decimal("0.01"))


def _effective_step_progress(step: ProcessStepRun) -> Decimal:
    if step.status in {
        ProcessStepRun.Status.COMPLETED,
        ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
        ProcessStepRun.Status.SKIPPED,
    }:
        return Decimal("100")
    return _to_decimal_percent(step.progress_percent)


def _pick_active_step(steps: list[ProcessStepRun]) -> ProcessStepRun | None:
    priority = {
        ProcessStepRun.Status.RUNNING: 0,
        ProcessStepRun.Status.PAUSED: 1,
        ProcessStepRun.Status.WAITING: 2,
        ProcessStepRun.Status.BLOCKED: 3,
        ProcessStepRun.Status.QUEUED: 4,
        ProcessStepRun.Status.PENDING: 5,
    }
    ordered = sorted(
        steps,
        key=lambda step: (
            priority.get(step.status, 99),
            step.sequence,
            step.id,
        ),
    )
    for step in ordered:
        if step.status in priority:
            return step
    return None


def _infer_run_status(run: ProcessRun, steps: list[ProcessStepRun]) -> str:
    if run.status in TERMINAL_RUN_STATUSES:
        return run.status
    statuses = {step.status for step in steps}
    if not steps:
        return run.status
    if ProcessStepRun.Status.RUNNING in statuses:
        return ProcessRun.Status.RUNNING
    if ProcessStepRun.Status.PAUSED in statuses:
        return ProcessRun.Status.PAUSED
    if ProcessStepRun.Status.WAITING in statuses:
        return ProcessRun.Status.WAITING
    if ProcessStepRun.Status.BLOCKED in statuses:
        return ProcessRun.Status.BLOCKED
    if ProcessStepRun.Status.FAILED in statuses:
        return ProcessRun.Status.FAILED
    if ProcessStepRun.Status.CANCELED in statuses:
        return ProcessRun.Status.CANCELED
    if statuses.intersection({ProcessStepRun.Status.QUEUED, ProcessStepRun.Status.PENDING}):
        return ProcessRun.Status.QUEUED
    if statuses.issubset(
        {
            ProcessStepRun.Status.COMPLETED,
            ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
            ProcessStepRun.Status.SKIPPED,
        }
    ):
        if ProcessStepRun.Status.COMPLETED_WITH_ERRORS in statuses:
            return ProcessRun.Status.COMPLETED_WITH_ERRORS
        return ProcessRun.Status.COMPLETED
    return run.status


@transaction.atomic
def update_step_progress(
    *,
    step: ProcessStepRun,
    status: str | None = None,
    progress_percent=None,
    status_message: str | None = None,
    worker_step: str | None = None,
    external_job_id: str | None = None,
    control_state: str | None = None,
    result_payload: dict | None = None,
    error_payload: dict | None = None,
    runtime_metrics: dict | None = None,
    checkpoint_payload: dict | None = None,
    checkpoint_version: int | None = None,
    available_at=None,
    started_at=None,
    finished_at=None,
    last_heartbeat_at=None,
    pause_requested_at=None,
    paused_at=None,
    cancel_requested_at=None,
    canceled_at=None,
) -> ProcessStepRun:
    now = timezone.now()
    changed_fields: list[str] = []

    if status and step.status != status:
        step.status = status
        changed_fields.append("status")
    if progress_percent is not None:
        normalized = _to_decimal_percent(progress_percent)
        if status in {
            ProcessStepRun.Status.COMPLETED,
            ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
            ProcessStepRun.Status.SKIPPED,
        }:
            normalized = Decimal("100.00")
        if normalized < _to_decimal_percent(step.progress_percent):
            normalized = _to_decimal_percent(step.progress_percent)
        if step.progress_percent != normalized:
            step.progress_percent = normalized
            changed_fields.append("progress_percent")
            step.last_progress_at = now
            changed_fields.append("last_progress_at")
    elif status in {
        ProcessStepRun.Status.COMPLETED,
        ProcessStepRun.Status.COMPLETED_WITH_ERRORS,
        ProcessStepRun.Status.SKIPPED,
    } and _to_decimal_percent(step.progress_percent) != Decimal("100.00"):
        step.progress_percent = Decimal("100.00")
        step.last_progress_at = now
        changed_fields.extend(["progress_percent", "last_progress_at"])

    if status_message is not None and step.status_message != status_message:
        step.status_message = status_message
        changed_fields.append("status_message")
    if worker_step is not None and step.worker_step != worker_step:
        step.worker_step = worker_step
        changed_fields.append("worker_step")
    if external_job_id is not None and step.external_job_id != external_job_id:
        step.external_job_id = external_job_id
        changed_fields.append("external_job_id")
    if control_state is not None and step.control_state != control_state:
        step.control_state = control_state
        changed_fields.append("control_state")
    if result_payload is not None and step.result_payload != result_payload:
        step.result_payload = result_payload
        changed_fields.append("result_payload")
    if error_payload is not None and step.error_payload != error_payload:
        step.error_payload = error_payload
        changed_fields.append("error_payload")
    if runtime_metrics is not None and step.runtime_metrics != runtime_metrics:
        step.runtime_metrics = runtime_metrics
        changed_fields.append("runtime_metrics")
    if checkpoint_payload is not None and step.checkpoint_payload != checkpoint_payload:
        step.checkpoint_payload = checkpoint_payload
        changed_fields.append("checkpoint_payload")
    if checkpoint_version is not None and step.checkpoint_version != checkpoint_version:
        step.checkpoint_version = checkpoint_version
        changed_fields.append("checkpoint_version")

    datetime_updates = {
        "available_at": available_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "last_heartbeat_at": last_heartbeat_at,
        "pause_requested_at": pause_requested_at,
        "paused_at": paused_at,
        "cancel_requested_at": cancel_requested_at,
        "canceled_at": canceled_at,
    }
    for field_name, field_value in datetime_updates.items():
        if field_value is not None and getattr(step, field_name) != field_value:
            setattr(step, field_name, field_value)
            changed_fields.append(field_name)

    if status == ProcessStepRun.Status.RUNNING and step.started_at is None:
        step.started_at = now
        changed_fields.append("started_at")
    if status in TERMINAL_STEP_STATUSES and step.finished_at is None:
        step.finished_at = finished_at or now
        if "finished_at" not in changed_fields:
            changed_fields.append("finished_at")
    if status == ProcessStepRun.Status.CANCELED and step.canceled_at is None:
        step.canceled_at = canceled_at or now
        changed_fields.append("canceled_at")
    if last_heartbeat_at is None and status in {ProcessStepRun.Status.RUNNING, ProcessStepRun.Status.PAUSED}:
        step.last_heartbeat_at = now
        if "last_heartbeat_at" not in changed_fields:
            changed_fields.append("last_heartbeat_at")

    if changed_fields:
        changed_fields.append("updated_at")
        step.save(update_fields=list(dict.fromkeys(changed_fields)))
    return step


@transaction.atomic
def recompute_run_progress(
    *,
    run: ProcessRun,
    status: str | None = None,
    current_step_key: str | None = None,
    current_stage: str | None = None,
    status_message: str | None = None,
    control_state: str | None = None,
    result_payload: dict | None = None,
    error_payload: dict | None = None,
    job_id: str | None = None,
    pause_requested_at=None,
    paused_at=None,
    resumed_at=None,
    pause_reason: str | None = None,
    cancel_requested_at=None,
    canceled_at=None,
    started_at=None,
    finished_at=None,
) -> ProcessRun:
    now = timezone.now()
    steps = list(run.steps.order_by("sequence", "id"))
    changed_fields: list[str] = []

    total_weight = sum(max(int(step.weight or 0), 1) for step in steps)
    if total_weight > 0:
        weighted_progress = sum(
            Decimal(max(int(step.weight or 0), 1)) * _effective_step_progress(step)
            for step in steps
        ) / Decimal(total_weight)
    else:
        weighted_progress = Decimal("0")
    weighted_progress = weighted_progress.quantize(Decimal("0.01"))

    if status in {ProcessRun.Status.COMPLETED, ProcessRun.Status.COMPLETED_WITH_ERRORS}:
        weighted_progress = Decimal("100.00")
    if weighted_progress < _to_decimal_percent(run.progress_percent):
        weighted_progress = _to_decimal_percent(run.progress_percent)
    if run.progress_percent != weighted_progress:
        run.progress_percent = weighted_progress
        changed_fields.append("progress_percent")

    inferred_status = status or _infer_run_status(run, steps)
    if run.status != inferred_status:
        run.status = inferred_status
        changed_fields.append("status")

    active_step = _pick_active_step(steps)
    resolved_step_key = current_step_key if current_step_key is not None else (active_step.step_key if active_step else run.current_step_key)
    resolved_stage = current_stage if current_stage is not None else (active_step.step_key if active_step else run.current_stage)
    resolved_message = status_message if status_message is not None else (
        active_step.status_message or active_step.worker_step if active_step else run.status_message
    )

    if run.current_step_key != (resolved_step_key or ""):
        run.current_step_key = resolved_step_key or ""
        changed_fields.append("current_step_key")
    if run.current_stage != (resolved_stage or ""):
        run.current_stage = resolved_stage or ""
        changed_fields.append("current_stage")
    if run.status_message != (resolved_message or ""):
        run.status_message = resolved_message or ""
        changed_fields.append("status_message")
    if control_state is not None and run.control_state != control_state:
        run.control_state = control_state
        changed_fields.append("control_state")
    if result_payload is not None and run.result_payload != result_payload:
        run.result_payload = result_payload
        changed_fields.append("result_payload")
    if error_payload is not None and run.error_payload != error_payload:
        run.error_payload = error_payload
        changed_fields.append("error_payload")
    if job_id is not None and run.job_id != job_id:
        run.job_id = job_id
        changed_fields.append("job_id")

    datetime_updates = {
        "pause_requested_at": pause_requested_at,
        "paused_at": paused_at,
        "resumed_at": resumed_at,
        "cancel_requested_at": cancel_requested_at,
        "canceled_at": canceled_at,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    for field_name, field_value in datetime_updates.items():
        if field_value is not None and getattr(run, field_name) != field_value:
            setattr(run, field_name, field_value)
            changed_fields.append(field_name)

    if pause_reason is not None and run.pause_reason != pause_reason:
        run.pause_reason = pause_reason
        changed_fields.append("pause_reason")

    if changed_fields:
        run.last_progress_at = now
        changed_fields.append("last_progress_at")
        if run.status == ProcessRun.Status.RUNNING and run.started_at is None:
            run.started_at = now
            changed_fields.append("started_at")
        if run.status in TERMINAL_RUN_STATUSES and run.finished_at is None:
            run.finished_at = finished_at or now
            changed_fields.append("finished_at")
        if run.status == ProcessRun.Status.CANCELED and run.canceled_at is None:
            run.canceled_at = canceled_at or now
            changed_fields.append("canceled_at")
        run.save(update_fields=list(dict.fromkeys(changed_fields + ["updated_at"])))
    return run


def build_process_run_event(run: ProcessRun, *, event: str = "process_run.updated") -> dict:
    return {
        "event": event,
        "run_id": str(run.run_id),
        "status": run.status,
        "progress": float(_to_decimal_percent(run.progress_percent)),
    }


def publish_run_event(run: ProcessRun, *, event: str = "process_run.updated") -> dict:
    payload = build_process_run_event(run, event=event)
    # Placeholder publisher. The websocket/notification bridge can call this
    # contract later without changing workflow state write paths again.
    logger.info("workflow_run_event event=%s run_id=%s status=%s progress=%s", event, run.run_id, run.status, payload["progress"])
    return payload

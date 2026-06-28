from __future__ import annotations

from celery import shared_task

from api.services.workflow_progress_consumer import consume_hope_progress_for_run


@shared_task(bind=True, ignore_result=True, queue="workflow-progress")
def consume_hope_progress_task(self, run_id: str, job_id: str) -> None:
    consume_hope_progress_for_run(run_id=run_id, job_id=job_id)

# Workflow Progress Validation Checklist

Use this checklist to validate the first real end-to-end workflow progress path:

- Django starts a workflow run
- Hope executes the generation job
- Hope emits Redis progress
- Django Celery ingests progress
- `ProcessStepRun` and `ProcessRun` update live
- Hope calls Django finalize callback

## 1. Prerequisites

- Hope stack is running from `hope/docker-compose.yml`
- `hope_default` Docker network exists
- Django dependencies include Celery
- Django database is reachable from the `anko_api` containers

## 2. Start Services

Start Hope first:

```bash
docker compose -f hope/docker-compose.yml up --build
```

Start Django API and workflow worker:

```bash
docker compose -f anko_api/docker-compose.yml up --build
```

Expected:

- `hope-api` is reachable on port `8080`
- `hope-worker` is healthy
- `anko-api` is reachable on port `8000`
- `anko-workflow-progress-worker` starts without Celery import errors

## 3. Confirm Runtime Wiring

Check these effective container-to-container URLs:

- Django -> Hope HTTP:
  - `PROCESS_REQUEST_BASE_URL=http://hope-api:8080`
- Hope -> Django callback:
  - `INTERNAL_API_BASE_URL=http://anko-api:8000`
- Frontend/user websocket URL:
  - `WS_PROCESS_REQUEST_BASE_URL=http://localhost:8080`
- Hope progress Redis:
  - `WORKFLOW_PROGRESS_REDIS_URL=redis://hope-redis:6379/2`

## 4. Trigger One Real Run

Create one battery generation run using the existing Django endpoint:

- `POST /api/batteries/start-generate/`

Use a payload that references real project and section ids already present in your DB.

Expected immediate response:

- `battery`
- `process_run.id`
- `process_run.run_id`
- `process_run.status`
- `job_id`
- `ws_url`

## 5. Validate Initial Workflow State

Open:

- `GET /api/process-runs/{run_id}/`
- `GET /api/process-runs/{run_id}/steps/`
- `GET /api/process-runs/{run_id}/artifacts/`

Expected right after dispatch:

- run status is `queued` or `running`
- current stage is the generation step
- prepare step is `completed`
- generate step is `queued`
- finalize step is `pending`

## 6. Validate Hope Progress Ingestion

Watch:

- Django API logs
- `anko-workflow-progress-worker` logs
- Hope worker logs

Expected:

- Hope emits progress for `progress:{job_id}`
- Django worker subscribes or falls back to polling
- generate step `progress_percent` increases over time
- generate step `worker_step` changes with Hope progress
- run `progress_percent` increases monotonically

## 7. Validate Finalization

Expected when Hope completes:

- Hope calls Django `finalize-from-service`
- generate step becomes `completed`
- finalize step becomes `completed` or `failed`
- run becomes `completed` or `failed`
- battery status becomes `Ready` when questions were created

Check:

- `GET /api/process-runs/{run_id}/`
- `GET /api/process-runs/{run_id}/steps/`
- `GET /api/batteries/{battery_id}/`

## 8. Validate Failure Path

If the Hope job fails:

- generate step should become `failed`
- finalize step should become `blocked`
- run should become `failed`
- `error_payload` should be populated

This is important to confirm run status does not remain `queued`.

## 9. Validate Artifacts

Check:

- `GET /api/process-runs/{run_id}/artifacts/`

Expected:

- input artifacts reference documents/sections/tag groups used
- output artifacts update after finalize

## 10. If Something Breaks

Check these first:

- `PROCESS_REQUEST_BASE_URL` points to `hope-api`, not a public URL
- `INTERNAL_API_BASE_URL` points to `anko-api`, not `localhost`
- Django worker can reach `hope-redis`
- Hope callback token matches Django internal token
- `workflow-progress` Celery worker is running

## 11. Success Criteria

This slice is done when one real run proves all of the following:

- Django creates `ProcessRun`
- Hope job is dispatched
- Django ingests Hope progress while job is still running
- Django recomputes workflow progress live
- Django finalize callback completes the run
- workflow read endpoints reflect the final state correctly

## 12. Next Slice After Validation

Implement workflow control endpoints and behavior:

- `POST /api/process-runs/{run_id}/pause/`
- `POST /api/process-runs/{run_id}/resume/`
- `POST /api/process-runs/{run_id}/cancel/`

Then add checkpoint-aware task stop/restart behavior.

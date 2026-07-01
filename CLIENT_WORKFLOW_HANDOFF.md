# Client Workflow Handoff

This document is for the person working on the client/frontend side.

It explains:

- what changed in the backend workflow
- what effect those changes have on the client
- what is already implemented
- what should be treated as source of truth


## Summary

Battery generation and tracked flashcard generation are no longer just fire-and-forget requests to Hope.

Now Django (`anko_api`) creates and owns a workflow record for the generation process, tracks progress, and finalizes the run when Hope finishes or fails.

Hope still executes the heavy generation work, but Django is now the workflow orchestrator and should be the main source of truth for client state.


## Main Architecture Change

Before:

- Client called Django
- Django called Hope
- Client mainly depended on Hope job progress or final battery state

Now:

- Client calls Django
- Django creates a `ProcessRun`
- Django dispatches work to Hope
- Hope emits progress through Redis
- Django consumes that progress and updates the `ProcessRun`
- Hope calls Django back on finalization
- Django marks the workflow as completed or failed

Rule for client:

- Trust Django workflow state first
- Do not treat Hope websocket state as the final business state


## What Is Implemented Right Now

### 1. Battery generation creates a workflow run

Endpoint already in use:

- `POST /api/batteries/start-generate/`

That endpoint now:

- creates the battery draft
- creates a `ProcessRun`
- creates workflow steps
- dispatches the Hope job
- returns both battery info and process run info

Current response includes:

- `battery`
- `process_run`
- `job_id`
- `ws_url`
- `microservice_response`

Important:

- `ws_url` still points to Hope progress websocket
- it can still be used for diagnostics
- but the intended source of truth for workflow state is Django `process_run`


### 1b. Flashcard generation creates a workflow run

New tracked endpoint:

- `POST /api/decks/start-generate/`

That endpoint now:

- creates the deck container
- creates a `ProcessRun`
- creates workflow steps
- dispatches the Hope flashcard job
- returns both deck info and process run info

Current response includes:

- `deck`
- `process_run`
- `job_id`
- `ws_url`
- `microservice_response`

Important:

- this is the tracked flashcard generation path for new client screens
- older deck/flashcard endpoints still exist for legacy/manual flows
- the intended source of truth for workflow state is Django `process_run`


### 2. Read-only workflow endpoints exist

Available endpoints:

- `GET /api/process-runs/`
- `GET /api/process-runs/{run_id}/`
- `GET /api/process-runs/{run_id}/steps/`
- `GET /api/process-runs/{run_id}/artifacts/`

These are read-only.

The client should not mutate workflow steps, progress, or artifacts directly.


### 3. Django now tracks overall and per-step progress

`ProcessRun` tracks overall workflow state such as:

- `status`
- `progress_percent`
- `current_step_key`
- `current_stage`
- `status_message`
- timestamps for pause/cancel/start/finish

`ProcessStepRun` tracks step-level state such as:

- `step_key`
- `item_key`
- `status`
- `progress_percent`
- `status_message`
- `worker_step`
- `external_job_id`
- `checkpoint_payload`

This means the client can show:

- one overall workflow progress bar
- current stage label
- step-by-step status
- later, per-item or per-document progress if needed


### 4. Hope finalization callback is wired

Hope now calls Django back through:

- `POST /api/batteries/{battery_id}/finalize-from-service/`
- `POST /api/decks/{deck_id}/finalize-from-service/`

That callback now works correctly inside Docker.

Relevant backend fix:

- internal container hostnames such as `anko-api` are allowed in Django `ALLOWED_HOSTS`

Effect:

- the workflow no longer gets stuck waiting for a final state just because the internal callback was rejected
- tracked deck runs now also close from Django callback finalization after flashcards are synced into the deck


### 5. Hope startup no longer blocks API readiness

Relevant backend fix:

- Hope Argos preload was moved off the blocking startup path

Effect:

- Hope API can become ready and accept requests faster
- Django can dispatch to Hope without hitting the previous startup connection failure


## Backend Model Changes

The frontend developer should know that this work was not only endpoint-level.
Some model assumptions changed too.

### Workflow models added

New workflow tracking models:

- `ProcessRun`
- `ProcessStepRun`
- `ProcessStepDependency`
- `ProcessArtifact`

What they do:

- `ProcessRun`: one workflow instance
- `ProcessStepRun`: one tracked stage or fan-out item inside the workflow
- `ProcessStepDependency`: explicit ordering/dependency edges between steps
- `ProcessArtifact`: normalized inputs/outputs/references produced during the workflow

Effect on frontend:

- workflow progress is now a first-class backend entity
- client can query progress/history directly from Django
- client no longer has to infer lifecycle only from battery/deck records


### Battery model changes relevant to frontend

`Battery` is now more workflow-friendly and less hard-coupled.

Important points:

- `project` is nullable
- `rule` is nullable
- `collection` exists and is nullable
- `generation_profile` exists and is nullable
- `config` exists as JSON
- `external_job_id` exists for Hope job linkage

Effect:

- frontend should not assume every battery always has a project/rule
- generated batteries can be linked through workflow/source records instead of one hard parent dependency


### Deck model changes relevant to frontend

Important points:

- `project` is nullable
- `collection` exists and is nullable
- `sections` relation is optional
- `config` exists as JSON
- `external_job_id` exists for Hope job linkage

Effect:

- frontend should not assume deck creation always depends on one required project-section chain
- future automatic workflows can create decks from grouped workflow outputs


### Explicit source link models added

Relevant models:

- `BatterySourceDocument`
- `BatterySourceSection`
- `BatterySourceTagGroup`
- `DeckSourceDocument`
- `DeckSourceSection`
- `DeckSourceTagGroup`

Effect:

- the source of a generated battery is now explicit
- the source of a generated deck is now explicit too
- frontend and admin views can later show provenance such as:
  - which documents were used
  - which sections were used
  - which tag groups were used


### Generated title behavior

Frontend should not require the user to provide the final title for generated content.

Current direction:

- request title can be omitted
- backend can derive a concise title during processing
- if LLM title generation is unavailable, backend can use fallback heuristics

Effect:

- frontend should treat returned `battery.name` or `deck.title` as authoritative
- frontend should not assume the submission title is always final


## Endpoint Examples

All examples below assume:

- header `Authorization: Token <USER_TOKEN>`
- JSON requests unless noted otherwise


### 1. Start battery generation with workflow tracking

Endpoint:

- `POST /api/batteries/start-generate/`

Example request:

```json
{
  "project": 1,
  "sections": [1],
  "quantity": 15,
  "difficulty": "medium",
  "question_format": "true_false",
  "query_text": "Validation Topic"
}
```

Example response:

```json
{
  "battery": {
    "id": 3,
    "project": 1,
    "rule": null,
    "name": "Validation Assessment Overview",
    "status": "Draft",
    "difficulty": "Medium",
    "external_job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99"
  },
  "process_run": {
    "id": 3,
    "run_id": "f19ccc2c-eb1c-4ba2-96d8-9f44283b1434",
    "status": "queued"
  },
  "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
  "ws_url": "ws://localhost:8080/ws/progress/7ec5d43c-78fb-4e8e-8117-e18428831c99",
  "microservice_response": {
    "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
    "task_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
    "status": "queued",
    "title": "Validation Assessment Overview",
    "document_ids": ["1"],
    "battery_id": 3
  }
}
```


### 2. List workflow runs

Endpoint:

- `GET /api/process-runs/`

Useful query params:

- `workflow_key`
- `status`
- `scope_type`
- `scope_id`
- `resource_type`
- `resource_id`

Example request:

- `GET /api/process-runs/?resource_type=battery&resource_id=3`

Example response shape:

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 3,
      "run_id": "f19ccc2c-eb1c-4ba2-96d8-9f44283b1434",
      "workflow_key": "battery_generate",
      "status": "running",
      "resource_type": "battery",
      "resource_id": "3",
      "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
      "current_step_key": "generate_questions",
      "current_stage": "generate_questions",
      "progress_percent": 90.0,
      "status_message": "load_embeddings",
      "control_state": "active"
    }
  ]
}
```


### 3. Read one workflow run

Endpoint:

- `GET /api/process-runs/{run_id}/`

Example response shape:

```json
{
  "id": 3,
  "run_id": "f19ccc2c-eb1c-4ba2-96d8-9f44283b1434",
  "workflow_key": "battery_generate",
  "workflow_version": 1,
  "status": "failed",
  "resource_type": "battery",
  "resource_id": "3",
  "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
  "current_step_key": "finalize_battery",
  "current_stage": "finalize_battery",
  "progress_percent": 90.0,
  "status_message": "Finalization produced no questions",
  "result_payload": {
    "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
    "battery_id": 3,
    "qa_pairs_found": 0,
    "options_created": 0,
    "questions_created": 0
  },
  "error_payload": {
    "error": "No questions were created during finalization"
  },
  "steps": [],
  "artifacts": []
}
```

Notes:

- detail response can include `steps` and `artifacts`
- frontend may still call dedicated `/steps/` and `/artifacts/` endpoints separately


### 4. Read workflow steps

Endpoint:

- `GET /api/process-runs/{run_id}/steps/`

Example response shape:

```json
[
  {
    "id": 11,
    "step_key": "prepare_sources",
    "item_key": "",
    "status": "completed",
    "progress_percent": 100.0,
    "status_message": "Sources prepared"
  },
  {
    "id": 12,
    "step_key": "generate_questions",
    "item_key": "",
    "status": "completed",
    "progress_percent": 100.0,
    "status_message": "Generation completed",
    "external_job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99"
  },
  {
    "id": 13,
    "step_key": "finalize_battery",
    "item_key": "",
    "status": "failed",
    "progress_percent": 0.0,
    "status_message": "Finalization produced no questions"
  }
]
```


### 5. Read workflow artifacts

Endpoint:

- `GET /api/process-runs/{run_id}/artifacts/`

Example response shape:

```json
[
  {
    "id": 21,
    "artifact_key": "battery:3",
    "artifact_type": "battery",
    "role": "output",
    "status": "active",
    "resource_type": "battery",
    "resource_id": "3",
    "payload": {
      "battery_id": 3
    }
  }
]
```


### 6. Internal finalize callback

Endpoint:

- `POST /api/batteries/{battery_id}/finalize-from-service/`

This endpoint is internal.

Frontend should know it exists because it is part of the workflow lifecycle, but frontend should not call it.

Example callback payload sent from Hope:

```json
{
  "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
  "battery_id": 3,
  "status": "completed",
  "title": "Validation Assessment Overview",
  "question_format": "true_false",
  "source_bundle": {
    "document_ids": ["1"],
    "section_ids": ["1"],
    "tags": ["Validation Topic"]
  },
  "error": null
}
```

Why frontend should care:

- this callback is what moves the run from in-flight state to final state
- if it fails, user can see stuck or outdated workflow state


### 7. Start tracked flashcard generation

Endpoint:

- `POST /api/decks/start-generate/`

This is the recommended endpoint for any new client screen that wants deck generation plus workflow tracking.

Example minimum request:

```json
{
  "document_ids": [1, 2],
  "cards_count": 20,
  "difficulty": "medium"
}
```

Example full request:

```json
{
  "project": 1,
  "collection_id": null,
  "document_ids": [1, 2],
  "section_ids": [],
  "tag_group_ids": [],
  "tags": [],
  "cards_count": 20,
  "difficulty": "medium",
  "title": "",
  "description": "",
  "visibility": "private"
}
```

Example response:

```json
{
  "deck": {
    "id": 12,
    "ownerId": 5,
    "title": "Cocktail Safety Flashcards",
    "visibility": "private",
    "description": "",
    "cardsCount": 0,
    "project": 1,
    "sections": [],
    "external_job_id": "de5d6c2e-2f7b-4f0d-8dc3-b33b76568f9a"
  },
  "process_run": {
    "id": 15,
    "run_id": "7a6bf07e-2b51-41d3-8f75-b6abec50f326",
    "status": "queued"
  },
  "job_id": "de5d6c2e-2f7b-4f0d-8dc3-b33b76568f9a",
  "ws_url": "ws://localhost:8080/ws/progress/de5d6c2e-2f7b-4f0d-8dc3-b33b76568f9a",
  "microservice_response": {
    "job_id": "de5d6c2e-2f7b-4f0d-8dc3-b33b76568f9a",
    "task_id": "de5d6c2e-2f7b-4f0d-8dc3-b33b76568f9a",
    "status": "queued",
    "title": "Cocktail Safety Flashcards"
  }
}
```

Notes:

- `title` is optional
- backend may return a better final `deck.title`
- cards are attached to the deck during finalization callback
- do not assume the deck already contains cards immediately after create


### 8. Internal deck finalize callback

Endpoint:

- `POST /api/decks/{deck_id}/finalize-from-service/`

This endpoint is internal.

Frontend should know it exists because it is part of the tracked lifecycle, but frontend should not call it.

Why frontend should care:

- this callback is what moves a tracked deck run from in-flight state to final state
- this callback is what syncs generated cards into the deck
- if it fails, user can see stuck or outdated workflow state


## Current Client Contract

### Create request

Current implemented generation entry point:

- `POST /api/batteries/start-generate/`
- `POST /api/decks/start-generate/`

Example response shape:

```json
{
  "battery": {
    "id": 3,
    "name": "Validation Assessment Overview",
    "status": "Draft",
    "external_job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99"
  },
  "process_run": {
    "id": 3,
    "run_id": "f19ccc2c-eb1c-4ba2-96d8-9f44283b1434",
    "status": "queued"
  },
  "job_id": "7ec5d43c-78fb-4e8e-8117-e18428831c99",
  "ws_url": "ws://localhost:8080/ws/progress/7ec5d43c-78fb-4e8e-8117-e18428831c99"
}
```

Client recommendation:

1. Save `battery.id`
2. Save `process_run.run_id`
3. Navigate UI using the Django workflow state, not only the Hope job id

For tracked flashcard generation:

1. Save `deck.id`
2. Save `process_run.run_id`
3. Navigate UI using the Django workflow state, not only the Hope job id


### Read workflow state

Primary endpoint:

- `GET /api/process-runs/{run_id}/`

This should drive:

- run status badge
- overall progress bar
- current workflow stage
- error state
- completion state

For tracked deck generation:

- treat `completed` as the point where cards are already synced into the deck
- after `completed`, fetch the deck or deck cards if the screen needs the final content

If detailed UI is needed:

- `GET /api/process-runs/{run_id}/steps/`

Use that for:

- stage list
- per-step status
- expanded debug panel


## Status Meaning for Client

Expected run-level statuses to support in UI:

- `queued`
- `running`
- `completed`
- `failed`
- `canceled`
- `paused`
- `completed_with_errors` later if introduced in the workflow path

Current real example:

- a run can fail even after progress reached `90%`
- this can happen when Hope finished execution but produced no usable questions

That means:

- progress percent is not enough
- final UI must always check final `status`


## Important Effect on Client Logic

### 1. Progress is no longer only transport-level

Do not assume:

- websocket progress reaching high percent means success

Do assume:

- final success comes from Django `process_run.status == completed`


### 2. Client should be resilient to partial progress

A run may show:

- progress updates from Hope
- then a final Django failure state

Example already observed:

- Hope job executed
- no embeddings were found
- callback succeeded
- Django finalized the run as failed

This is correct behavior.


### 3. Client should separate transport from business state

Use Hope websocket only as optional live signal.

Use Django process run for:

- what the stage is
- whether the process succeeded
- whether the process failed
- what artifacts exist


## Notifications / Live Updates

The backend now has a minimal workflow event contract:

```json
{
  "event": "process_run.updated",
  "run_id": "f19ccc2c-eb1c-4ba2-96d8-9f44283b1434",
  "status": "running",
  "progress": 37
}
```

Current state:

- this contract exists in Django
- it is logged/published at the service layer
- a full frontend delivery bridge is not yet exposed as a final client transport

Client recommendation for now:

- use polling against `GET /api/process-runs/{run_id}/`
- if a workflow event transport is later exposed, use it only as an invalidation trigger
- after receiving an update event, refetch the run from Django

This same polling contract applies to both:

- battery tracked generation
- deck tracked generation


## Recommended Client Flow

1. Call `POST /api/batteries/start-generate/`
2. Save `battery.id` and `process_run.run_id`
3. Show initial state as `queued`
4. Poll `GET /api/process-runs/{run_id}/`
5. Optionally fetch `/steps/` for detailed progress UI
6. Stop polling when run becomes terminal:
   - `completed`
   - `failed`
   - `canceled`
7. If completed, fetch or display final battery data
8. If failed, show the workflow error from Django

Tracked deck flow:

1. Call `POST /api/decks/start-generate/`
2. Save `deck.id` and `process_run.run_id`
3. Show initial state as `queued`
4. Poll `GET /api/process-runs/{run_id}/`
5. Optionally fetch `/steps/` for detailed progress UI
6. Stop polling when run becomes terminal
7. If completed, fetch:
   - `GET /api/decks/{deck_id}/`
   - `GET /api/decks/{deck_id}/cards/`
8. If failed, show the workflow error from Django


## Automatic Multi-Document Process

This is not yet the main exposed client entry point, but it is the intended next workflow.

Target behavior:

1. User selects one or more documents
2. Client sends only `document_ids` as required input
3. Django creates one workflow run for the whole automatic process
4. Django dispatches document processing in parallel
5. User receives workflow progress while documents are being processed
6. When document processing finishes, Django aggregates unique tags
7. Django partitions tags into groups
8. Django dispatches flashcard generation per group
9. Django dispatches battery generation per group
10. Django finalizes outputs and exposes resulting artifacts

Important client rule:

- the client should treat this as one workflow with many stages
- not as unrelated independent Hope jobs

Important after the latest backend change:

- the flashcard branch of auto-generate now uses the same deck finalization callback path
- auto-generate flashcard steps are closed by Django only after deck card sync is complete
- standalone tracked deck generation and auto-generated deck outputs now follow the same completion rule

Expected future entry point:

- `POST /api/process-runs/auto-generate/`

Expected minimum request:

```json
{
  "document_ids": [1, 2, 3, 4]
}
```

Optional inputs later:

- `workspace_id`
- `tag_group_size`
- `flashcard_options`
- `battery_options`


## How The User Gets Feedback

There are two different feedback layers and the client should not confuse them.

### 1. Workflow feedback from Django

This is the main user-facing feedback channel.

The client should show:

- overall progress percent
- current stage
- current status
- final success or failure

Source:

- `GET /api/process-runs/{run_id}/`

Detailed source:

- `GET /api/process-runs/{run_id}/steps/`

This is what the UI should trust.


### 2. Execution feedback from Hope

Hope emits live execution progress for the running job.

Current sources:

- Redis progress state
- Redis pubsub progress events
- Hope websocket `ws://.../ws/progress/{job_id}`

Today, Django consumes that execution progress and maps it into workflow progress.

Client rule:

- do not build final business UI directly from Hope progress
- Hope progress is useful for transport/live execution updates
- Django workflow state is the final mapped state

For tracked flashcard generation specifically:

- Hope emits `flashcard_generation` execution progress
- Django maps that into the workflow step `generate_flashcards`
- Hope then calls Django finalization
- Django syncs the generated cards into the deck
- only then should the client treat the deck as fully generated


## Frontend Developer Notes

This section is specifically for the frontend developer implementing the UI.

### Minimum data to persist in client state

After creation, store:

- `battery.id`
- `process_run.run_id`
- `job_id`

For tracked deck generation, store:

- `deck.id`
- `process_run.run_id`
- `job_id`

Only `process_run.run_id` is required to keep tracking workflow state from Django.


### Fields the UI should read from `ProcessRun`

Most important fields:

- `run_id`
- `status`
- `progress_percent`
- `current_step_key`
- `current_stage`
- `status_message`
- `created_at`
- `started_at`
- `finished_at`
- `error_payload`

Use these as:

- `status`: badge and terminal-state logic
- `progress_percent`: progress bar value
- `current_stage` or `current_step_key`: current phase label
- `status_message`: short detail text under the progress bar
- `error_payload`: failure details view


### Fields the UI should read from `ProcessStepRun`

Most useful fields:

- `step_key`
- `item_key`
- `status`
- `progress_percent`
- `status_message`
- `worker_step`
- `external_job_id`
- `checkpoint_payload`

Use these as:

- `step_key`: stable stage identifier
- `status`: per-step badge
- `progress_percent`: detailed progress row value
- `status_message`: human-readable detail
- `worker_step`: optional debug info for developer/admin view
- `checkpoint_payload`: do not expose directly to end users unless needed for admin/debug UI


### Recommended frontend state model

Suggested state split:

- `runSummary`
- `runSteps`
- `isPolling`
- `lastUpdatedAt`
- `terminalStateReached`

Suggested derived flags:

- `isQueued = status === "queued"`
- `isRunning = status === "running"`
- `isPaused = status === "paused"`
- `isFailed = status === "failed"`
- `isCompleted = status === "completed"`
- `isCanceled = status === "canceled"`
- `isTerminal = ["completed", "failed", "canceled"].includes(status)`


### Recommended polling strategy

Simple default:

- poll every `2s` while `queued`
- poll every `2s` while `running`
- poll every `5s` while `paused`
- stop polling on terminal state

If the page loses focus, it is reasonable to slow polling to `5s` to `10s`.

If a future Django event transport is exposed:

- subscribe to event
- use event as invalidation
- immediately refetch `/api/process-runs/{run_id}/`


### Recommended UI states

At minimum support these screens or components:

#### 1. Submission success state

After `POST /api/batteries/start-generate/`:

- show request accepted
- show initial `queued` state
- start tracking `process_run.run_id`

#### 2. In-progress state

Show:

- progress bar
- current stage label
- status message
- optional step list

#### 3. Completed state

Show:

- success message
- final battery ready state
- navigation action to open battery

#### 4. Failed state

Show:

- failure message
- backend error text if present
- retry action if product wants it

Important:

- failed does not always mean infrastructure failure
- it may mean content generation produced no usable output


### Recommended stage label mapping

Frontend should not hardcode user-facing labels from raw backend keys without a mapping layer.

Suggested mapping pattern:

- `prepare_sources` -> `Preparing sources`
- `generate_questions` -> `Generating questions`
- `finalize_battery` -> `Finalizing battery`

Future automatic workflow mapping:

- `prepare_inputs` -> `Preparing input`
- `preflight_reconciliation` -> `Checking existing data`
- `process_document` -> `Processing documents`
- `aggregate_unique_tags` -> `Collecting tags`
- `partition_tags` -> `Grouping tags`
- `generate_flashcards` -> `Generating flashcards`
- `generate_battery` -> `Generating questions`
- `finalize_outputs` -> `Finalizing results`

Standalone tracked deck workflow mapping:

- `prepare_sources` -> `Preparing sources`
- `generate_flashcards` -> `Generating flashcards`
- `finalize_deck` -> `Finalizing deck`

Keep this in one frontend constants file so labels stay maintainable.


### Recommended TypeScript shape

Example minimal types:

```ts
type ProcessRunStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "canceled";

type ProcessRun = {
  run_id: string;
  status: ProcessRunStatus;
  progress_percent: number;
  current_step_key: string | null;
  current_stage: string | null;
  status_message: string;
  error_payload?: Record<string, unknown> | null;
  started_at?: string | null;
  finished_at?: string | null;
};

type ProcessStepRun = {
  id: number;
  step_key: string;
  item_key: string;
  status: string;
  progress_percent: number;
  status_message: string;
  worker_step: string;
  external_job_id: string;
};
```


### API integration recommendation

Recommended client sequence:

1. `POST /api/batteries/start-generate/`
2. Read `process_run.run_id`
3. `GET /api/process-runs/{run_id}/`
4. Optionally `GET /api/process-runs/{run_id}/steps/`
5. If terminal and successful, navigate to battery detail

Tracked deck generation sequence:

1. `POST /api/decks/start-generate/`
2. Read `deck.id` and `process_run.run_id`
3. `GET /api/process-runs/{run_id}/`
4. Optionally `GET /api/process-runs/{run_id}/steps/`
5. If terminal and successful, navigate to deck detail or load `GET /api/decks/{deck_id}/cards/`

Do not use `job_id` as the main client route identifier.

Use `run_id` for workflow tracking.


### Error handling recommendation

Handle these separately:

- request creation failure
- workflow running failure
- completed with no output
- transport failure while polling

Suggested UX behavior:

- if polling fails once, keep previous UI state and retry
- if polling fails repeatedly, show a non-blocking warning
- do not mark workflow failed only because one poll request failed


### Debug / admin UI suggestion

If you build an internal debug drawer, it is useful to expose:

- `run_id`
- `job_id`
- raw `status`
- raw `current_step_key`
- raw `status_message`
- raw step payloads

This helps when backend and frontend need to debug workflow behavior together.


## Recommended Feedback UX

For the client person, the cleanest UI model is:

### Overall run feedback

Show:

- `Queued`
- `Running`
- `Paused`
- `Canceled`
- `Completed`
- `Failed`

Also show:

- one progress bar from `process_run.progress_percent`
- one stage label from `current_stage` or `current_step_key`
- one short status line from `status_message`


### Detailed feedback

If the screen supports details, show workflow steps from `/steps/`:

- `prepare_sources`
- `generate_questions`
- `finalize_battery`

Later, for the automatic multi-document workflow, this can expand to:

- `prepare_inputs`
- `preflight_reconciliation`
- `process_document`
- `aggregate_unique_tags`
- `partition_tags`
- `generate_flashcards`
- `generate_battery`
- `finalize_outputs`

For standalone tracked deck generation, the detailed list is:

- `prepare_sources`
- `generate_flashcards`
- `finalize_deck`


### Polling behavior

For now, recommended client behavior is:

1. Start polling after create request succeeds
2. Poll `GET /api/process-runs/{run_id}/`
3. Optionally poll `/steps/` only for expanded detail view
4. Stop polling when status is terminal:
   - `completed`
   - `failed`
   - `canceled`

If a future event channel is exposed from Django:

- use it as an invalidation trigger
- then refetch `process_run` from Django


## What The Client Should Not Do

- Do not write to `process-runs`
- Do not write to workflow steps
- Do not assume Hope websocket completion means workflow completion
- Do not infer success only from `battery.status`
- Do not depend on internal callback endpoints


## Known Current Limitation

The end-to-end wiring is working, but content generation can still fail if upstream document processing did not create embeddings.

Observed real case:

- Hope received the job
- Hope progress ran
- Hope final callback succeeded
- Django finalized correctly
- final state was `failed` because `questions_created = 0`

So if the client sees a failed workflow after dispatch, it does not automatically mean the workflow system is broken.
It may mean the source documents were not yet fully processable for question generation.


## What Is Planned Next

Not yet the main client contract, but already part of the direction:

- automatic multi-document workflow with only `document_ids` required
- grouped flashcard and battery generation
- workflow-level pause/cancel/restart from checkpoint
- minimal event notifications from Django
- per-document and per-stage progress visualization

When that larger workflow is exposed, the same client rule should still hold:

- Django workflow state is the source of truth
- Hope websocket state is only diagnostic/secondary
- for flashcards, final content should be read from the deck after workflow completion

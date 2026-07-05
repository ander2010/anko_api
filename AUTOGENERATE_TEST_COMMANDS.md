# Auto-generate test commands

Run these inside the `anko_api` dev container.

## 1. Start the focused workflow test

```bash
python manage.py test api.tests.AutoGenerateWorkflowCallbackTests
```

## 2. Get a token for manual API testing

```bash
python manage.py debug_process_runs --email andersanchez1987@gmail.com --workflow collection_auto_generate
```

Copy the `Authorization: Token ...` value from the output.

## 3. Trigger one auto-generate run

Replace `<YOUR_TOKEN>` and the document id as needed.

```bash
curl -X POST http://localhost:8000/api/process-runs/auto-generate/ \
  -H "Authorization: Token <YOUR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "document_ids": [1],
    "flashcard_options": {
      "cards_per_group": 5,
      "difficulty": "medium"
    },
    "battery_options": {
      "questions_per_group": 5,
      "difficulty": "medium",
      "question_format": "multiple_choice"
    }
  }'
```

## 4. Inspect the run

Replace `<RUN_ID>` with the `process_run.run_id` returned by the POST response.

```bash
curl -H "Authorization: Token <YOUR_TOKEN>" http://localhost:8000/api/process-runs/<RUN_ID>/
curl -H "Authorization: Token <YOUR_TOKEN>" http://localhost:8000/api/process-runs/<RUN_ID>/steps/
curl -H "Authorization: Token <YOUR_TOKEN>" http://localhost:8000/api/process-runs/<RUN_ID>/artifacts/
```

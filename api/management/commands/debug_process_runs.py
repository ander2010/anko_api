"""
Management command: debug_process_runs

Usage:
    python manage.py debug_process_runs
    python manage.py debug_process_runs --email otro@email.com
    python manage.py debug_process_runs --run-id 3fa85f64-5717-4562-b3fc-2c963f66afa6
    python manage.py debug_process_runs --workflow collection_auto_generate
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from api.models import ProcessArtifact, ProcessRun, ProcessStepRun, User
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = "Muestra token de auth y estado de process-runs para debugging en Postman."

    def add_arguments(self, parser):
        parser.add_argument("--email", default="andersanchez1987@gmail.com")
        parser.add_argument("--run-id", dest="run_id", default=None, help="UUID de un run específico")
        parser.add_argument("--workflow", default=None, help="Filtrar por workflow_key")
        parser.add_argument("--limit", type=int, default=5, help="Cuántos runs mostrar (default 5)")

    def handle(self, *args, **options):
        sep = "─" * 60

        # ── TOKEN ──────────────────────────────────────────────────
        self.stdout.write(self.style.HTTP_INFO(f"\n{sep}"))
        self.stdout.write(self.style.HTTP_INFO("  AUTH TOKEN"))
        self.stdout.write(self.style.HTTP_INFO(sep))

        try:
            user = User.objects.get(email=options["email"])
        except User.DoesNotExist:
            self.stderr.write(self.style.ERROR(f"Usuario no encontrado: {options['email']}"))
            return

        token, created = Token.objects.get_or_create(user=user)
        created_label = " (nuevo)" if created else ""
        self.stdout.write(f"  Usuario : {user.username} <{user.email}>")
        self.stdout.write(self.style.SUCCESS(f"  Token   : {token.key}{created_label}"))
        self.stdout.write("")
        self.stdout.write("  Header para Postman:")
        self.stdout.write(f"    Authorization: Token {token.key}")

        # ── ENDPOINTS ──────────────────────────────────────────────
        self.stdout.write(self.style.HTTP_INFO(f"\n{sep}"))
        self.stdout.write(self.style.HTTP_INFO("  ENDPOINTS DE PRUEBA"))
        self.stdout.write(self.style.HTTP_INFO(sep))
        self.stdout.write("  GET  http://localhost:8000/api/process-runs/")
        self.stdout.write("  POST http://localhost:8000/api/process-runs/auto-generate/")
        self.stdout.write('       Body: {"document_ids": [<id>]}')

        # ── RUN ESPECÍFICO ─────────────────────────────────────────
        run_id = options["run_id"]
        if run_id:
            self.stdout.write(self.style.HTTP_INFO(f"\n{sep}"))
            self.stdout.write(self.style.HTTP_INFO(f"  DETALLE RUN: {run_id}"))
            self.stdout.write(self.style.HTTP_INFO(sep))

            try:
                run = ProcessRun.objects.prefetch_related(
                    "artifacts", "steps__dependencies", "steps__dependents"
                ).get(run_id=run_id, initiated_by=user)
            except ProcessRun.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"  Run no encontrado para este usuario: {run_id}"))
                return

            self._print_run(run, verbose=True)
            return

        # ── LISTAR RUNS ────────────────────────────────────────────
        self.stdout.write(self.style.HTTP_INFO(f"\n{sep}"))
        self.stdout.write(self.style.HTTP_INFO("  PROCESS RUNS RECIENTES"))
        self.stdout.write(self.style.HTTP_INFO(sep))

        qs = ProcessRun.objects.filter(initiated_by=user).order_by("-created_at")
        if options["workflow"]:
            qs = qs.filter(workflow_key=options["workflow"])

        runs = list(qs[: options["limit"]])

        if not runs:
            self.stdout.write(self.style.WARNING("  No hay process runs para este usuario."))
            self.stdout.write("  Lanza uno con:")
            self.stdout.write(f"    POST http://localhost:8000/api/process-runs/auto-generate/")
            self.stdout.write(f"    Authorization: Token {token.key}")
            self.stdout.write('    Body: {"document_ids": [1]}')
        else:
            for run in runs:
                self._print_run(run)

        self.stdout.write("")

    # ── helpers ───────────────────────────────────────────────────

    def _status_style(self, status: str):
        mapping = {
            "pending": self.style.WARNING,
            "running": self.style.HTTP_INFO,
            "success": self.style.SUCCESS,
            "failed": self.style.ERROR,
            "cancelled": self.style.WARNING,
        }
        fn = mapping.get(status, str)
        return fn(status.upper())

    def _print_run(self, run: ProcessRun, verbose: bool = False):
        sep2 = "·" * 40
        self.stdout.write(f"\n  {sep2}")
        self.stdout.write(f"  run_id    : {self.style.SUCCESS(str(run.run_id))}")
        self.stdout.write(f"  workflow  : {run.workflow_key}")
        self.stdout.write(f"  status    : {self._status_style(run.status)}")
        self.stdout.write(f"  progress  : {run.progress_percent}%")
        self.stdout.write(f"  stage     : {run.current_stage or '—'}")
        self.stdout.write(f"  msg       : {run.status_message or '—'}")
        self.stdout.write(f"  creado    : {run.created_at}")
        self.stdout.write(f"  finalizado: {run.finished_at or '—'}")

        endpoint = f"http://localhost:8000/api/process-runs/{run.run_id}/"
        self.stdout.write(f"  GET       : {endpoint}")

        if verbose:
            # steps
            steps = list(ProcessStepRun.objects.filter(run=run).order_by("id"))
            self.stdout.write(f"\n  STEPS ({len(steps)}):")
            for s in steps:
                self.stdout.write(
                    f"    [{self._status_style(s.status)}] {s.step_key} — {s.status_message or '—'}"
                )

            # artifacts
            artifacts = list(ProcessArtifact.objects.filter(run=run).order_by("id"))
            self.stdout.write(f"\n  ARTIFACTS ({len(artifacts)}):")
            if not artifacts:
                self.stdout.write("    (ninguno todavía)")
            for a in artifacts:
                payload_preview = json.dumps(a.payload)[:120] if a.payload else "—"
                self.stdout.write(
                    f"    [{a.artifact_type}] {a.resource_type} id={a.resource_id}"
                )
                self.stdout.write(f"      payload: {payload_preview}")

            # error
            if run.error_payload:
                self.stdout.write(self.style.ERROR("\n  ERROR PAYLOAD:"))
                self.stdout.write(f"    {json.dumps(run.error_payload, indent=2)}")

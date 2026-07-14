"""
Enterprise Learning Service — Phase 2

All business logic for Learning Paths, Assignments, and Progress tracking.
ViewSets call these methods; they never contain business logic themselves.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from django.db import transaction
from django.utils import timezone

from api.enterprise_learning_models import (
    LearningPath,
    LearningModule,
    LearningModuleProgress,
    LearningPathAssignment,
    TrainingProgram,
    TrainingProgramVersion,
)
from api.enterprise_models import Company, CompanyMembership, LearningEvent, Team


class EnterpriseLearningService:

    # ------------------------------------------------------------------
    # Assignment helpers
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def assign_to_user(
        user,
        assigned_by,
        company: Company,
        learning_path: LearningPath = None,
        learning_module=None,
        due_date=None,
    ) -> LearningPathAssignment:
        """Create a user-level assignment for a learning path or a proceso."""
        assignment = LearningPathAssignment.objects.create(
            company=company,
            learning_path=learning_path,
            learning_module=learning_module,
            user=user,
            assigned_by=assigned_by,
            status="pending",
            due_date=due_date,
        )
        LearningEvent.objects.create(
            company=company,
            user=user,
            event_type="learning_path_assigned",
            learning_path=learning_path,
            metadata={
                "assignment_id": assignment.id,
                "learning_module_id": learning_module.id if learning_module else None,
            },
        )
        return assignment

    @staticmethod
    @transaction.atomic
    def assign_to_team(
        team: Team,
        assigned_by,
        company: Company,
        learning_path: LearningPath = None,
        learning_module=None,
        due_date=None,
    ) -> list[LearningPathAssignment]:
        """
        Create one individual (user-level) assignment per team member.

        A single shared team-level row (user=None, team=team) can't represent
        each member's own progress/status independently — LearningModuleProgress
        and completion tracking are keyed by (assignment, user), and "My
        Assignments" only ever queries by user=request.user, so a team-only row
        was never visible to anyone. metadata records which team this came
        from for traceability, without violating the model's own "exactly one
        of user or team" invariant.

        Members who already have a non-completed assignment for this same
        content are skipped, so re-running "assign to team" doesn't duplicate
        their in-progress work. A member whose prior assignment is already
        "completed" gets a fresh one (e.g. recurring/annual training).
        """
        assignments = []
        for membership in team.memberships.select_related("user"):
            has_active_assignment = LearningPathAssignment.objects.filter(
                company=company,
                learning_path=learning_path,
                learning_module=learning_module,
                user=membership.user,
            ).exclude(status="completed").exists()
            if has_active_assignment:
                continue
            assignment = LearningPathAssignment.objects.create(
                company=company,
                learning_path=learning_path,
                learning_module=learning_module,
                user=membership.user,
                assigned_by=assigned_by,
                status="pending",
                due_date=due_date,
                metadata={"assigned_via_team_id": team.id, "assigned_via_team_name": team.name},
            )
            LearningEvent.objects.create(
                company=company,
                user=membership.user,
                event_type="learning_path_assigned",
                learning_path=learning_path,
                metadata={
                    "assignment_id": assignment.id,
                    "team_id": team.id,
                    "learning_module_id": learning_module.id if learning_module else None,
                },
            )
            assignments.append(assignment)
        return assignments

    @staticmethod
    @transaction.atomic
    def backfill_team_assignments(team: Team, user, assigned_by=None) -> list[LearningPathAssignment]:
        """
        When a user joins a team, give them the same content the team was
        already assigned before they joined (via assign_to_team), so they
        don't miss out on it.

        Only backfills assignments whose metadata marks them as team-sourced
        (assigned_via_team_id == team.id) — assignments made directly to
        individual users are never touched. Skips any content the user
        already has a non-completed assignment for (same rule as
        assign_to_team, to avoid duplicates).
        """
        source_assignments = (
            LearningPathAssignment.objects.filter(
                company=team.company, metadata__assigned_via_team_id=team.id
            )
            .exclude(user=user)
            .order_by("-created_at")
        )
        seen_content = set()
        assignments = []
        for src in source_assignments:
            content_key = (src.learning_path_id, src.learning_module_id)
            if content_key in seen_content:
                continue
            seen_content.add(content_key)

            has_active_assignment = LearningPathAssignment.objects.filter(
                company=team.company,
                learning_path_id=src.learning_path_id,
                learning_module_id=src.learning_module_id,
                user=user,
            ).exclude(status="completed").exists()
            if has_active_assignment:
                continue

            assignment = LearningPathAssignment.objects.create(
                company=team.company,
                learning_path_id=src.learning_path_id,
                learning_module_id=src.learning_module_id,
                user=user,
                assigned_by=assigned_by or src.assigned_by,
                status="pending",
                due_date=src.due_date,
                metadata={"assigned_via_team_id": team.id, "assigned_via_team_name": team.name},
            )
            LearningEvent.objects.create(
                company=team.company,
                user=user,
                event_type="learning_path_assigned",
                learning_path_id=src.learning_path_id,
                metadata={
                    "assignment_id": assignment.id,
                    "team_id": team.id,
                    "learning_module_id": src.learning_module_id,
                    "backfilled": True,
                },
            )
            assignments.append(assignment)
        return assignments

    # ------------------------------------------------------------------
    # Progress tracking
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def start_assignment(assignment: LearningPathAssignment, user) -> LearningPathAssignment:
        """
        Mark the assignment as in_progress for the given user.
        Creates LearningModuleProgress rows (not_started) for every module.
        """
        if assignment.status == "completed":
            return assignment

        now = timezone.now()

        if assignment.status == "pending":
            assignment.status = "in_progress"
            assignment.started_at = now
            assignment.save(update_fields=["status", "started_at", "updated_at"])

        modules = assignment.learning_path.modules.all()
        for module in modules:
            LearningModuleProgress.objects.get_or_create(
                assignment=assignment,
                module=module,
                user=user,
                defaults={"status": "not_started"},
            )

        LearningEvent.objects.create(
            company=assignment.company,
            user=user,
            event_type="module_started",
            learning_path=assignment.learning_path,
            metadata={"assignment_id": assignment.id},
        )
        return assignment

    @staticmethod
    @transaction.atomic
    def complete_module(
        assignment: LearningPathAssignment,
        module: LearningModule,
        user,
        score: Optional[Decimal] = None,
    ) -> LearningModuleProgress:
        """
        Mark a specific module as completed for the user.
        Automatically completes the assignment if all required modules are done.
        """
        now = timezone.now()

        progress, _ = LearningModuleProgress.objects.get_or_create(
            assignment=assignment,
            module=module,
            user=user,
            defaults={"status": "not_started"},
        )

        if progress.status == "completed":
            return progress

        progress.status = "completed"
        progress.completed_at = now
        if score is not None:
            progress.score = score
        if progress.started_at is None:
            progress.started_at = now
        progress.save(update_fields=["status", "completed_at", "score", "started_at", "updated_at"])

        LearningEvent.objects.create(
            company=assignment.company,
            user=user,
            event_type="module_completed",
            learning_path=assignment.learning_path,
            learning_module=module,
            score=score,
            metadata={"assignment_id": assignment.id, "module_id": module.id},
        )

        EnterpriseLearningService._check_and_complete_assignment(assignment, user)
        return progress

    @staticmethod
    def _check_and_complete_assignment(assignment: LearningPathAssignment, user) -> None:
        """Complete the assignment if all required modules are done."""
        required_modules = assignment.learning_path.modules.filter(is_required=True)
        if not required_modules.exists():
            return

        completed_ids = set(
            LearningModuleProgress.objects.filter(
                assignment=assignment,
                user=user,
                status="completed",
            ).values_list("module_id", flat=True)
        )

        required_ids = set(required_modules.values_list("id", flat=True))
        if not required_ids.issubset(completed_ids):
            return

        now = timezone.now()
        assignment.status = "completed"
        assignment.completed_at = now
        assignment.save(update_fields=["status", "completed_at", "updated_at"])

        LearningEvent.objects.create(
            company=assignment.company,
            user=user,
            event_type="learning_path_completed",
            learning_path=assignment.learning_path,
            metadata={"assignment_id": assignment.id},
        )

        # Auto-issue any certificate templates whose requirements include this
        # learning path (best-effort — a failure here must not roll back the
        # assignment completion itself).
        try:
            from api.enterprise.services.certification_service import CertificationService
            CertificationService.auto_issue_on_path_completion(
                user=user,
                company=assignment.company,
                learning_path=assignment.learning_path,
                issued_by=None,
            )
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Auto-issue on learning completion failed for assignment %s", assignment.id
            )

    # ------------------------------------------------------------------
    # Progress calculation
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_progress(assignment: LearningPathAssignment, user) -> dict:
        """
        Return a progress summary dict for the (assignment, user) pair.

        {
          "total_modules": int,
          "required_modules": int,
          "completed_modules": int,
          "percent_total": Decimal,    # of all modules
          "percent_required": Decimal, # of required modules only
          "status": str,
        }
        """
        all_modules = list(assignment.learning_path.modules.all())
        required_modules = [m for m in all_modules if m.is_required]

        completed_ids = set(
            LearningModuleProgress.objects.filter(
                assignment=assignment,
                user=user,
                status="completed",
            ).values_list("module_id", flat=True)
        )

        completed_total = sum(1 for m in all_modules if m.id in completed_ids)
        completed_required = sum(1 for m in required_modules if m.id in completed_ids)

        total = len(all_modules)
        required = len(required_modules)

        percent_total = (
            Decimal(completed_total) / Decimal(total) * 100
            if total else Decimal("0")
        )
        percent_required = (
            Decimal(completed_required) / Decimal(required) * 100
            if required else Decimal("0")
        )

        return {
            "total_modules": total,
            "required_modules": required,
            "completed_modules": completed_total,
            "completed_module_ids": sorted(completed_ids),
            "completed_required_modules": completed_required,
            "percent_total": round(percent_total, 2),
            "percent_required": round(percent_required, 2),
            "status": assignment.status,
        }

    @staticmethod
    def calculate_readiness_score(user, company: Company) -> Decimal:
        """
        Simple readiness score: % of user's assignments that are completed.
        Returns 0-100.
        """
        assignments = LearningPathAssignment.objects.filter(
            company=company, user=user
        )
        total = assignments.count()
        if not total:
            return Decimal("0")
        completed = assignments.filter(status="completed").count()
        return round(Decimal(completed) / Decimal(total) * 100, 2)

    # ------------------------------------------------------------------
    # Training Program helpers
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def publish_training_program(program: TrainingProgram, learning_path: LearningPath, created_by, notes: str = "") -> TrainingProgramVersion:
        """
        Publish a new version of a training program.
        Marks all previous versions as not current.
        """
        program.versions.update(is_current=False)

        last_version = program.versions.order_by("-version_number").first()
        next_number = (last_version.version_number + 1) if last_version else 1

        version = TrainingProgramVersion.objects.create(
            program=program,
            version_number=next_number,
            learning_path=learning_path,
            is_current=True,
            notes=notes,
            created_by=created_by,
        )

        if program.status != "published":
            program.status = "published"
            program.save(update_fields=["status", "updated_at"])

        LearningEvent.objects.create(
            company=program.company,
            user=created_by,
            event_type="training_generated",
            learning_path=learning_path,
            metadata={"program_id": program.id, "version": next_number},
        )
        return version

    @staticmethod
    @transaction.atomic
    def publish_learning_path(path: LearningPath, user) -> LearningPath:
        path.status = "published"
        path.save(update_fields=["status", "updated_at"])
        LearningEvent.objects.create(
            company=path.company,
            user=user,
            event_type="training_generated",
            learning_path=path,
            metadata={"action": "published"},
        )
        return path

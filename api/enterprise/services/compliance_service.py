"""
Enterprise Compliance Service — Phase 4

Handles the full compliance lifecycle:
  - Program assignment (user / team)
  - Progress evaluation
  - Compliance status & risk
  - Renewals
  - Expiry detection
  - Audit report generation
"""

from __future__ import annotations

import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import List, Optional

from django.db import transaction
from django.utils import timezone

from api.enterprise_compliance_models import (
    ComplianceAssignment,
    ComplianceProgram,
    ComplianceRequirement,
    ComplianceReview,
)
from api.enterprise_learning_models import LearningPathAssignment
from api.enterprise_models import Company, LearningEvent, Team


# ---------------------------------------------------------------------------
# Warning thresholds (days before expiry)
# ---------------------------------------------------------------------------
WARNING_DAYS = 90
REMINDER_DAYS = 60
CRITICAL_DAYS = 30


class ComplianceService:

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def assign_to_user(
        program: ComplianceProgram,
        user,
        assigned_by,
        company: Company,
        due_date: Optional[datetime.date] = None,
    ) -> ComplianceAssignment:
        """Assign a compliance program to an individual user."""
        if due_date is None:
            due_date = datetime.date.today() + datetime.timedelta(days=30)

        assignment = ComplianceAssignment.objects.create(
            company=company,
            program=program,
            user=user,
            assigned_by=assigned_by,
            status="pending",
            due_date=due_date,
        )

        LearningEvent.objects.create(
            company=company,
            user=user,
            event_type="compliance_assigned",
            metadata={
                "assignment_id": assignment.id,
                "program_code": program.code,
            },
        )

        ComplianceService._ensure_requirement_assignments(
            program=program, user=user, assigned_by=assigned_by,
            company=company, due_date=due_date,
        )
        return assignment

    @staticmethod
    @transaction.atomic
    def assign_to_team(
        program: ComplianceProgram,
        team: Team,
        assigned_by,
        company: Company,
        due_date: Optional[datetime.date] = None,
    ) -> ComplianceAssignment:
        """Assign a compliance program to an entire team."""
        if due_date is None:
            due_date = datetime.date.today() + datetime.timedelta(days=30)

        assignment = ComplianceAssignment.objects.create(
            company=company,
            program=program,
            team=team,
            assigned_by=assigned_by,
            status="pending",
            due_date=due_date,
        )

        for membership in team.memberships.select_related("user"):
            LearningEvent.objects.create(
                company=company,
                user=membership.user,
                event_type="compliance_assigned",
                metadata={
                    "assignment_id": assignment.id,
                    "program_code": program.code,
                    "team_id": team.id,
                },
            )
            ComplianceService._ensure_requirement_assignments(
                program=program, user=membership.user, assigned_by=assigned_by,
                company=company, due_date=due_date,
            )
        return assignment

    @staticmethod
    def _ensure_requirement_assignments(program, user, assigned_by, company, due_date) -> None:
        """
        So a user assigned to a Compliance Program can complete it through the
        same Learning Path experience used everywhere else: make sure they
        have a LearningPathAssignment for each of the program's required
        Learning Paths. Reuses an existing one (any status) instead of
        creating a duplicate.
        """
        from api.enterprise.services.learning_service import EnterpriseLearningService

        learning_paths = {
            req.learning_path_id: req.learning_path
            for req in program.requirements.filter(learning_path__isnull=False).select_related("learning_path")
        }
        for learning_path in learning_paths.values():
            already_has = LearningPathAssignment.objects.filter(
                company=company, learning_path=learning_path, user=user,
            ).exists()
            if already_has:
                continue
            EnterpriseLearningService.assign_to_user(
                user=user, assigned_by=assigned_by, company=company,
                learning_path=learning_path, due_date=due_date,
            )

    # ------------------------------------------------------------------
    # Completing / reviewing
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def complete_assignment(
        assignment: ComplianceAssignment,
        user,
        score: Optional[Decimal] = None,
        reviewer=None,
        notes: str = "",
        review_type: str = "initial",
    ) -> ComplianceAssignment:
        """
        Mark a compliance assignment as completed.
        Determines is_compliant based on program.requires_score / passing_score.
        Creates a ComplianceReview record and a LearningEvent.
        """
        now = timezone.now()
        program = assignment.program

        # Determine pass/fail
        if program.requires_score and program.passing_score is not None:
            is_compliant = (score is not None and score >= program.passing_score)
        else:
            is_compliant = True

        # Expiry date = today + validity_days
        expires_at = datetime.date.today() + datetime.timedelta(days=program.validity_days)
        valid_until = expires_at

        review_status = "passed" if is_compliant else "failed"

        ComplianceReview.objects.create(
            company=assignment.company,
            user=user,
            program=program,
            assignment=assignment,
            review_type=review_type,
            status=review_status,
            score=score,
            reviewer=reviewer,
            notes=notes,
            reviewed_at=now,
            valid_until=valid_until,
        )

        assignment.status = "completed" if is_compliant else "non_compliant"
        assignment.is_compliant = is_compliant
        assignment.completed_at = now
        assignment.last_reviewed_at = now
        assignment.score = score
        assignment.expires_at = expires_at if is_compliant else None
        assignment.save(update_fields=[
            "status", "is_compliant", "completed_at",
            "last_reviewed_at", "score", "expires_at", "updated_at",
        ])

        event_type = "compliance_completed" if is_compliant else "compliance_completed"
        LearningEvent.objects.create(
            company=assignment.company,
            user=user,
            event_type=event_type,
            metadata={
                "assignment_id": assignment.id,
                "program_code": program.code,
                "is_compliant": is_compliant,
                "score": str(score) if score is not None else None,
            },
        )

        if is_compliant:
            # Auto-issue any certificate templates whose requirements include
            # this compliance program (best-effort — must not roll back the
            # assignment completion itself).
            try:
                from api.enterprise.services.certification_service import CertificationService
                CertificationService.auto_issue_on_compliance_completion(
                    user=user,
                    company=assignment.company,
                    compliance_program=program,
                    score=score,
                    issued_by=None,
                )
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "Auto-issue on compliance completion failed for assignment %s", assignment.id
                )

        return assignment

    @staticmethod
    def auto_complete_on_path_completion(user, company: Company, learning_path) -> None:
        """
        Called (best-effort) whenever a user finishes a Learning Path.

        If that path was a Requirement of a Compliance Program the user has
        a pending/in-progress assignment for, and all of that program's other
        required Learning Paths are also already completed, the Compliance
        Assignment is completed automatically — the same way manually
        completing it via `complete_assignment` works.
        """
        requirements = ComplianceRequirement.objects.filter(
            learning_path=learning_path, program__company=company,
        ).select_related("program")

        for req in requirements:
            assignment = ComplianceAssignment.objects.filter(
                company=company, program=req.program, user=user,
            ).exclude(status="completed").first()
            if not assignment:
                continue

            required_path_ids = set(
                req.program.requirements.filter(learning_path__isnull=False)
                .values_list("learning_path_id", flat=True)
            )
            if not required_path_ids:
                continue

            completed_path_ids = set(
                LearningPathAssignment.objects.filter(
                    company=company, user=user,
                    learning_path_id__in=required_path_ids, status="completed",
                ).values_list("learning_path_id", flat=True)
            )

            if required_path_ids.issubset(completed_path_ids):
                ComplianceService.complete_assignment(
                    assignment,
                    user=user,
                    score=None,
                    reviewer=None,
                    notes="Auto-completed: all required learning paths finished.",
                )

    # ------------------------------------------------------------------
    # Renewals
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_renewal(
        assignment: ComplianceAssignment,
        assigned_by,
        due_date: Optional[datetime.date] = None,
    ) -> ComplianceAssignment:
        """
        Create a new ComplianceAssignment as a renewal of an expired one.
        The original assignment is kept intact (audit trail).
        """
        program = assignment.program
        if due_date is None:
            due_date = datetime.date.today() + datetime.timedelta(days=30)

        renewal = ComplianceAssignment.objects.create(
            company=assignment.company,
            program=program,
            user=assignment.user,
            team=assignment.team,
            assigned_by=assigned_by,
            status="pending",
            due_date=due_date,
            renewal_count=assignment.renewal_count + 1,
            renewed_from=assignment,
        )

        user = assignment.user
        if user:
            LearningEvent.objects.create(
                company=assignment.company,
                user=user,
                event_type="compliance_assigned",
                metadata={
                    "assignment_id": renewal.id,
                    "renewed_from": assignment.id,
                    "program_code": program.code,
                    "renewal_number": renewal.renewal_count,
                },
            )
        return renewal

    # ------------------------------------------------------------------
    # Evaluation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def evaluate_compliance(user, company: Company) -> dict:
        """
        Returns compliance status summary for a user within a company.

        {
          total_programs: int,
          compliant: int,
          non_compliant: int,
          pending: int,
          expired: int,
          compliance_rate: Decimal (0-100),
          assignments: [...]
        }
        """
        assignments = ComplianceAssignment.objects.filter(
            company=company, user=user
        ).select_related("program")

        total = assignments.count()
        if total == 0:
            return {
                "user_id": user.id,
                "total_programs": 0,
                "compliant": 0,
                "non_compliant": 0,
                "pending": 0,
                "expired": 0,
                "compliance_rate": Decimal("0"),
            }

        compliant = assignments.filter(is_compliant=True, status="completed").count()
        non_compliant = assignments.filter(status="non_compliant").count()
        pending = assignments.filter(status__in=("pending", "in_progress")).count()

        today = datetime.date.today()
        expired = assignments.filter(
            expires_at__lt=today, status__in=("completed",)
        ).count()

        rate = Decimal(compliant) / Decimal(total) * 100
        rate = rate.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        return {
            "user_id": user.id,
            "total_programs": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "pending": pending,
            "expired": expired,
            "compliance_rate": rate,
        }

    @staticmethod
    def calculate_compliance_risk(user, company: Company) -> Decimal:
        """
        Compliance risk score 0-100.
        High risk = non-compliant mandatory programs or expiring soon.
        """
        assignments = ComplianceAssignment.objects.filter(
            company=company,
            user=user,
            program__is_mandatory=True,
        ).select_related("program")

        total = assignments.count()
        if total == 0:
            return Decimal("0")

        risk_points = Decimal("0")
        for a in assignments:
            if a.status == "non_compliant":
                risk_points += Decimal("40")
            elif a.status == "expired" or a.is_expired():
                risk_points += Decimal("35")
            elif a.is_expiring_soon(CRITICAL_DAYS):
                risk_points += Decimal("20")
            elif a.is_expiring_soon(WARNING_DAYS):
                risk_points += Decimal("10")

        risk = risk_points / Decimal(total)
        risk = min(Decimal("100"), risk)
        return risk.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def check_expiring_assignments(
        company: Company,
        days: int = WARNING_DAYS,
    ) -> List[ComplianceAssignment]:
        """
        Return assignments expiring within `days` days.
        Used by the daily compliance job.
        """
        today = datetime.date.today()
        threshold = today + datetime.timedelta(days=days)
        return list(
            ComplianceAssignment.objects.filter(
                company=company,
                status="completed",
                is_compliant=True,
                expires_at__gte=today,
                expires_at__lte=threshold,
            ).select_related("user", "team", "program")
        )

    @staticmethod
    def get_team_compliance(team: Team, company: Company) -> dict:
        """Aggregate compliance metrics for a team."""
        from api.enterprise_models import TeamMembership

        members = TeamMembership.objects.filter(team=team).select_related("user")
        if not members.exists():
            return {
                "team_id": team.id,
                "team_name": team.name,
                "member_count": 0,
                "avg_compliance_rate": Decimal("0"),
                "fully_compliant_count": 0,
                "at_risk_count": 0,
            }

        rates = []
        risks = []
        for m in members:
            result = ComplianceService.evaluate_compliance(m.user, company)
            rates.append(result["compliance_rate"])
            risk = ComplianceService.calculate_compliance_risk(m.user, company)
            risks.append(risk)

        n = Decimal(str(len(rates)))
        avg_rate = sum(rates) / n
        fully_compliant = sum(1 for r in rates if r >= Decimal("100"))
        at_risk = sum(1 for risk in risks if risk >= Decimal("50"))

        return {
            "team_id": team.id,
            "team_name": team.name,
            "member_count": int(n),
            "avg_compliance_rate": avg_rate.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "fully_compliant_count": fully_compliant,
            "at_risk_count": at_risk,
        }

    @staticmethod
    def get_company_compliance(company: Company) -> dict:
        """Aggregate compliance metrics for the whole company."""
        from api.enterprise_models import CompanyMembership

        members = CompanyMembership.objects.filter(
            company=company, status="active"
        ).select_related("user")

        if not members.exists():
            return {
                "company_id": company.id,
                "employee_count": 0,
                "avg_compliance_rate": Decimal("0"),
                "fully_compliant_count": 0,
                "at_risk_count": 0,
                "open_non_compliant": 0,
            }

        rates = []
        risks = []
        for m in members:
            result = ComplianceService.evaluate_compliance(m.user, company)
            rates.append(result["compliance_rate"])
            risk = ComplianceService.calculate_compliance_risk(m.user, company)
            risks.append(risk)

        n = Decimal(str(len(rates)))
        avg_rate = sum(rates) / n
        fully_compliant = sum(1 for r in rates if r >= Decimal("100"))
        at_risk = sum(1 for risk in risks if risk >= Decimal("50"))
        open_nc = ComplianceAssignment.objects.filter(
            company=company, status="non_compliant"
        ).count()

        return {
            "company_id": company.id,
            "company_name": company.name,
            "employee_count": int(n),
            "avg_compliance_rate": avg_rate.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "fully_compliant_count": fully_compliant,
            "at_risk_count": at_risk,
            "open_non_compliant": open_nc,
        }

    @staticmethod
    def generate_audit_report(company: Company, program: ComplianceProgram) -> dict:
        """
        Return a structured audit report for a compliance program.
        Used by auditors.
        """
        assignments = ComplianceAssignment.objects.filter(
            company=company, program=program
        ).select_related("user", "team")

        reviews = ComplianceReview.objects.filter(
            company=company, program=program
        ).select_related("user", "reviewer").order_by("-created_at")

        total = assignments.count()
        compliant = assignments.filter(is_compliant=True).count()
        non_compliant = assignments.filter(status="non_compliant").count()
        pending = assignments.filter(status__in=("pending", "in_progress")).count()
        expired = assignments.filter(is_compliant=False, status="expired").count()

        return {
            "program_code": program.code,
            "program_name": program.name,
            "compliance_type": program.compliance_type,
            "total_assignments": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "pending": pending,
            "expired": expired,
            "compliance_rate": (
                (Decimal(compliant) / Decimal(total) * 100).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                ) if total else Decimal("0")
            ),
            "total_reviews": reviews.count(),
            "passed_reviews": reviews.filter(status="passed").count(),
            "failed_reviews": reviews.filter(status="failed").count(),
        }

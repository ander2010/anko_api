"""
Enterprise Analytics Service — Phase 6

Aggregates data from all enterprise phases to produce dashboard payloads.
No new models — reads only from Phases 1-5.
"""

from __future__ import annotations

import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import List, Optional

from django.db.models import Avg, Count, Q
from django.utils import timezone

from api.enterprise_models import Company, CompanyMembership, LearningEvent, Team
from api.enterprise_learning_models import (
    LearningModule,
    LearningPath,
    LearningPathAssignment,
    LearningModuleProgress,
    TrainingProgram,
)
from api.enterprise_retention_models import (
    KnowledgeAssessment,
    KnowledgeGap,
    RetentionSnapshot,
    ReviewSchedule,
)
from api.enterprise_compliance_models import (
    ComplianceAssignment,
    ComplianceProgram,
)
from api.enterprise_certification_models import Certification, CertificateTemplate


def _pct(num: int, den: int) -> Decimal:
    if den == 0:
        return Decimal("0.00")
    return (Decimal(num) / Decimal(den) * 100).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )


class AnalyticsService:

    # ==================================================================
    # Employee Dashboard
    # ==================================================================

    @staticmethod
    def get_employee_dashboard(user, company: Company) -> dict:
        """
        Full dashboard for an individual employee.
        Aggregates: learning progress, retention, compliance, certs, reviews.
        """
        today = timezone.now().date()
        week_ahead = today + datetime.timedelta(days=7)

        # --- Learning ---
        assignments = LearningPathAssignment.objects.filter(
            company=company, user=user
        )
        lp_total = assignments.count()
        lp_completed = assignments.filter(status="completed").count()
        lp_in_progress = assignments.filter(status="in_progress").count()
        lp_pending = assignments.filter(status="pending").count()
        lp_overdue = assignments.filter(status="overdue").count()

        # --- Retention ---
        from api.enterprise.services.retention_service import RetentionService
        retention_score = RetentionService.calculate_user_retention(user, company)
        risk_score = RetentionService.calculate_risk_score(user, company)
        open_gaps = KnowledgeGap.objects.filter(
            company=company, user=user, status="open"
        ).count()

        # --- Review schedules ---
        reviews_overdue = ReviewSchedule.objects.filter(
            company=company, user=user, status="pending",
            due_date__lt=today,
        ).count()
        reviews_this_week = ReviewSchedule.objects.filter(
            company=company, user=user, status="pending",
            due_date__gte=today, due_date__lte=week_ahead,
        ).count()

        # --- Compliance ---
        from api.enterprise.services.compliance_service import ComplianceService
        compliance_data = ComplianceService.evaluate_compliance(user, company)
        expiring_compliance = ComplianceAssignment.objects.filter(
            company=company, user=user, status="completed", is_compliant=True,
            expires_at__gte=today,
            expires_at__lte=today + datetime.timedelta(days=30),
        ).count()

        # --- Certifications ---
        certs = Certification.objects.filter(company=company, user=user)
        cert_active = certs.filter(status="active").count()
        cert_expiring = certs.filter(
            status="active",
            expires_at__isnull=False,
            expires_at__gte=timezone.now(),
            expires_at__lte=timezone.now() + datetime.timedelta(days=30),
        ).count()

        # --- Recent activity ---
        recent_events = (
            LearningEvent.objects.filter(company=company, user=user)
            .order_by("-created_at")
            .values("event_type", "created_at")[:10]
        )

        return {
            "user_id": user.id,
            "username": user.username,
            "learning": {
                "total_assigned": lp_total,
                "completed": lp_completed,
                "in_progress": lp_in_progress,
                "pending": lp_pending,
                "overdue": lp_overdue,
                "completion_rate": _pct(lp_completed, lp_total),
            },
            "retention": {
                "score": retention_score,
                "risk_score": risk_score,
                "open_gaps": open_gaps,
            },
            "reviews": {
                "overdue": reviews_overdue,
                "due_this_week": reviews_this_week,
            },
            "compliance": {
                "total": compliance_data["total_programs"],
                "compliant": compliance_data["compliant"],
                "non_compliant": compliance_data["non_compliant"],
                "pending": compliance_data["pending"],
                "rate": compliance_data["compliance_rate"],
                "expiring_soon": expiring_compliance,
            },
            "certifications": {
                "active": cert_active,
                "total": certs.count(),
                "expiring_soon": cert_expiring,
            },
            "recent_activity": list(recent_events),
        }

    # ==================================================================
    # Manager Dashboard
    # ==================================================================

    @staticmethod
    def get_manager_dashboard(manager, company: Company, team: Optional[Team] = None) -> dict:
        """
        Dashboard for a manager — team-level view.
        If `team` is provided, scoped to that team; otherwise all members.
        """
        from api.enterprise_models import TeamMembership

        if team:
            memberships = TeamMembership.objects.filter(team=team).select_related("user")
            members = [m.user for m in memberships]
            context_name = team.name
            context_id = team.id
        else:
            memberships = CompanyMembership.objects.filter(
                company=company, status="active", role__in=("employee", "trainer", "manager")
            ).select_related("user")
            members = [m.user for m in memberships]
            context_name = company.name
            context_id = company.id

        total_members = len(members)
        if total_members == 0:
            return {
                "context": context_name,
                "total_members": 0,
                "learning": {},
                "retention": {},
                "compliance": {},
                "certifications": {},
                "at_risk_members": [],
            }

        # --- Learning aggregates ---
        assignments_qs = LearningPathAssignment.objects.filter(
            company=company, user__in=members
        )
        lp_total = assignments_qs.count()
        lp_completed = assignments_qs.filter(status="completed").count()
        lp_overdue = assignments_qs.filter(status="overdue").count()

        # --- Retention aggregates ---
        from api.enterprise.services.retention_service import RetentionService
        retention_scores = []
        risk_scores = []
        at_risk = []

        for u in members:
            r = RetentionService.calculate_user_retention(u, company)
            risk = RetentionService.calculate_risk_score(u, company)
            retention_scores.append(r)
            risk_scores.append(risk)
            if risk >= Decimal("60") or r < Decimal("40"):
                at_risk.append({
                    "user_id": u.id,
                    "username": u.username,
                    "retention_score": str(r),
                    "risk_score": str(risk),
                })

        n = Decimal(str(total_members))
        avg_retention = (sum(retention_scores) / n).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        ) if retention_scores else Decimal("0")
        avg_risk = (sum(risk_scores) / n).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        ) if risk_scores else Decimal("0")

        # --- Compliance aggregates ---
        from api.enterprise.services.compliance_service import ComplianceService
        comp_rates = []
        for u in members:
            c = ComplianceService.evaluate_compliance(u, company)
            comp_rates.append(c["compliance_rate"])
        avg_compliance = (sum(comp_rates) / n).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        ) if comp_rates else Decimal("0")

        # --- Knowledge gaps ---
        gap_filter = Q(company=company, user__in=members, status="open")
        open_gaps = KnowledgeGap.objects.filter(gap_filter).count()
        critical_gaps = KnowledgeGap.objects.filter(
            gap_filter, severity="critical"
        ).count()

        # --- Certifications ---
        cert_active = Certification.objects.filter(
            company=company, user__in=members, status="active"
        ).count()

        # --- Open review schedules ---
        overdue_reviews = ReviewSchedule.objects.filter(
            company=company, user__in=members,
            status="pending", due_date__lt=timezone.now().date(),
        ).count()

        return {
            "context": context_name,
            "context_id": context_id,
            "total_members": total_members,
            "learning": {
                "total_assignments": lp_total,
                "completed": lp_completed,
                "overdue": lp_overdue,
                "completion_rate": _pct(lp_completed, lp_total),
            },
            "retention": {
                "avg_score": avg_retention,
                "avg_risk": avg_risk,
                "open_gaps": open_gaps,
                "critical_gaps": critical_gaps,
                "overdue_reviews": overdue_reviews,
            },
            "compliance": {
                "avg_rate": avg_compliance,
            },
            "certifications": {
                "active_total": cert_active,
            },
            "at_risk_members": at_risk,
        }

    # ==================================================================
    # Trainer Dashboard
    # ==================================================================

    @staticmethod
    def get_trainer_dashboard(trainer, company: Company) -> dict:
        """
        Dashboard for a trainer — content and learner progress view.
        """
        # --- Learning paths owned or in company ---
        paths = LearningPath.objects.filter(company=company)
        path_count = paths.count()
        active_paths = paths.filter(status="active").count()

        # --- Assignments across all paths ---
        assignments = LearningPathAssignment.objects.filter(company=company)
        assigned_total = assignments.count()
        completed = assignments.filter(status="completed").count()
        in_progress = assignments.filter(status="in_progress").count()
        overdue = assignments.filter(status="overdue").count()

        # --- Module completions ---
        module_progress = LearningModuleProgress.objects.filter(
            assignment__company=company
        )
        modules_completed = module_progress.filter(status="completed").count()
        modules_total = module_progress.count()

        # --- Assessment averages per path ---
        path_assessments = (
            KnowledgeAssessment.objects.filter(
                company=company,
                learning_path__isnull=False,
            )
            .values("learning_path__id", "learning_path__name")
            .annotate(avg_score=Avg("score"), count=Count("id"))
            .order_by("-count")[:10]
        )

        # --- Training programs ---
        programs = TrainingProgram.objects.filter(company=company)

        # --- Learners needing attention (overdue or low score) ---
        overdue_qs = (
            assignments.filter(status="overdue")
            .values("user__id", "user__username")
            .annotate(overdue_count=Count("id"))
            .order_by("-overdue_count")[:10]
        )

        return {
            "learning_paths": {
                "total": path_count,
                "active": active_paths,
            },
            "assignments": {
                "total": assigned_total,
                "completed": completed,
                "in_progress": in_progress,
                "overdue": overdue,
                "completion_rate": _pct(completed, assigned_total),
            },
            "modules": {
                "total": modules_total,
                "completed": modules_completed,
                "completion_rate": _pct(modules_completed, modules_total),
            },
            "training_programs": {
                "total": programs.count(),
                "active": programs.filter(status="active").count(),
            },
            "top_paths_by_assessment": list(path_assessments),
            "learners_needing_attention": list(overdue_qs),
        }

    # ==================================================================
    # Auditor Dashboard
    # ==================================================================

    @staticmethod
    def get_auditor_dashboard(auditor, company: Company) -> dict:
        """
        Compliance and risk overview for auditors.
        """
        today = timezone.now().date()

        # --- Compliance overview ---
        all_programs = ComplianceProgram.objects.filter(company=company, status="active")
        mandatory_programs = all_programs.filter(is_mandatory=True)

        all_assignments = ComplianceAssignment.objects.filter(company=company)
        compliant = all_assignments.filter(is_compliant=True, status="completed").count()
        non_compliant = all_assignments.filter(status="non_compliant").count()
        pending = all_assignments.filter(status__in=("pending", "in_progress")).count()

        total_assignments = all_assignments.count()
        compliance_rate = _pct(compliant, total_assignments)

        # --- Expiring compliance (next 90 days) ---
        expiring_90 = all_assignments.filter(
            is_compliant=True, status="completed",
            expires_at__gte=today,
            expires_at__lte=today + datetime.timedelta(days=90),
        ).count()
        expiring_30 = all_assignments.filter(
            is_compliant=True, status="completed",
            expires_at__gte=today,
            expires_at__lte=today + datetime.timedelta(days=30),
        ).count()

        # --- By program ---
        program_breakdown = []
        for prog in all_programs.order_by("code")[:20]:
            pa = all_assignments.filter(program=prog)
            prog_total = pa.count()
            prog_compliant = pa.filter(is_compliant=True).count()
            program_breakdown.append({
                "program_code": prog.code,
                "program_name": prog.name,
                "total": prog_total,
                "compliant": prog_compliant,
                "rate": _pct(prog_compliant, prog_total),
            })

        # --- Certifications ---
        cert_active = Certification.objects.filter(company=company, status="active").count()
        cert_expiring_30 = Certification.objects.filter(
            company=company, status="active",
            expires_at__isnull=False,
            expires_at__gte=timezone.now(),
            expires_at__lte=timezone.now() + datetime.timedelta(days=30),
        ).count()

        # --- Knowledge gaps ---
        open_gaps = KnowledgeGap.objects.filter(company=company, status="open")
        critical_gaps = open_gaps.filter(severity="critical").count()
        high_gaps = open_gaps.filter(severity="high").count()

        # --- Recent audit events ---
        recent_events = (
            LearningEvent.objects.filter(
                company=company,
                event_type__in=(
                    "compliance_completed", "compliance_assigned",
                    "certificate_issued", "certificate_revoked",
                ),
            )
            .order_by("-created_at")
            .values("event_type", "user__username", "created_at")[:20]
        )

        return {
            "compliance": {
                "active_programs": all_programs.count(),
                "mandatory_programs": mandatory_programs.count(),
                "total_assignments": total_assignments,
                "compliant": compliant,
                "non_compliant": non_compliant,
                "pending": pending,
                "compliance_rate": compliance_rate,
                "expiring_30_days": expiring_30,
                "expiring_90_days": expiring_90,
            },
            "program_breakdown": program_breakdown,
            "certifications": {
                "active": cert_active,
                "expiring_30_days": cert_expiring_30,
            },
            "knowledge_gaps": {
                "open": open_gaps.count(),
                "critical": critical_gaps,
                "high": high_gaps,
            },
            "recent_audit_events": list(recent_events),
        }

    # ==================================================================
    # Executive Dashboard
    # ==================================================================

    @staticmethod
    def get_executive_dashboard(company: Company) -> dict:
        """
        Top-level KPIs for company owners and executives.
        Combines all phases into a health overview.
        """
        # --- Headcount ---
        active_members = CompanyMembership.objects.filter(
            company=company, status="active"
        )
        total_employees = active_members.count()

        # --- Learning ---
        assignments = LearningPathAssignment.objects.filter(company=company)
        lp_completed = assignments.filter(status="completed").count()
        lp_total = assignments.count()

        # --- Retention average (latest snapshot per user) ---
        from django.db.models import Max
        latest_snap_dates = (
            RetentionSnapshot.objects.filter(
                company=company, topic=None, learning_path=None
            )
            .values("user")
            .annotate(latest=Max("snapshot_date"))
        )
        avg_retention = Decimal("0")
        if latest_snap_dates.exists():
            # Pull all latest snapshots
            snap_filter = Q()
            for entry in latest_snap_dates:
                snap_filter |= Q(user=entry["user"], snapshot_date=entry["latest"])
            snaps = RetentionSnapshot.objects.filter(
                company=company, topic=None, learning_path=None
            ).filter(snap_filter)
            agg = snaps.aggregate(avg=Avg("retention_score"))
            if agg["avg"] is not None:
                avg_retention = Decimal(str(agg["avg"])).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )

        # --- Compliance ---
        all_assignments = ComplianceAssignment.objects.filter(company=company)
        comp_total = all_assignments.count()
        comp_compliant = all_assignments.filter(is_compliant=True, status="completed").count()
        comp_non_compliant = all_assignments.filter(status="non_compliant").count()
        compliance_rate = _pct(comp_compliant, comp_total)

        # --- Certifications ---
        cert_active = Certification.objects.filter(company=company, status="active").count()

        # --- Knowledge gaps ---
        open_gaps = KnowledgeGap.objects.filter(company=company, status="open").count()
        critical_gaps = KnowledgeGap.objects.filter(
            company=company, status="open", severity="critical"
        ).count()

        # --- Health score ---
        health_score = AnalyticsService.get_company_health_score(company)

        # --- Department/team breakdown ---
        from api.enterprise_models import BusinessUnit
        from api.enterprise.services.compliance_service import ComplianceService

        teams = Team.objects.filter(company=company)[:10]
        team_breakdown = []
        for team in teams:
            tc = ComplianceService.get_team_compliance(team, company)
            team_breakdown.append({
                "team_id": team.id,
                "team_name": team.name,
                "member_count": tc["member_count"],
                "avg_compliance_rate": tc["avg_compliance_rate"],
            })

        # --- Retention trend (last 30 days of snapshots) ---
        retention_trend = AnalyticsService.get_retention_trends(company, days=30)

        return {
            "company_id": company.id,
            "company_name": company.name,
            "health_score": health_score,
            "headcount": total_employees,
            "learning": {
                "total_assignments": lp_total,
                "completed": lp_completed,
                "completion_rate": _pct(lp_completed, lp_total),
            },
            "retention": {
                "avg_score": avg_retention,
                "open_gaps": open_gaps,
                "critical_gaps": critical_gaps,
            },
            "compliance": {
                "total": comp_total,
                "compliant": comp_compliant,
                "non_compliant": comp_non_compliant,
                "rate": compliance_rate,
            },
            "certifications": {
                "active": cert_active,
            },
            "team_breakdown": team_breakdown,
            "retention_trend": retention_trend,
        }

    # ==================================================================
    # Cross-cutting helpers
    # ==================================================================

    @staticmethod
    def get_company_health_score(company: Company) -> Decimal:
        """
        Composite health score 0-100 combining:
          - Avg compliance rate (40% weight)
          - Avg retention score (30% weight)
          - Certification coverage (20% weight)
          - No critical gaps (10% weight)
        """
        # Compliance (40%)
        assignments = ComplianceAssignment.objects.filter(company=company)
        total = assignments.count()
        compliant = assignments.filter(is_compliant=True, status="completed").count()
        compliance_score = _pct(compliant, total) if total else Decimal("0")

        # Retention (30%) — avg of latest retention snapshots
        from django.db.models import Max
        latest = (
            RetentionSnapshot.objects.filter(
                company=company, topic=None, learning_path=None
            )
            .values("user")
            .annotate(latest=Max("snapshot_date"))
        )
        retention_score = Decimal("0")
        if latest.exists():
            snap_filter = Q()
            for entry in latest:
                snap_filter |= Q(user=entry["user"], snapshot_date=entry["latest"])
            agg = RetentionSnapshot.objects.filter(
                company=company, topic=None, learning_path=None
            ).filter(snap_filter).aggregate(avg=Avg("retention_score"))
            if agg["avg"] is not None:
                retention_score = Decimal(str(agg["avg"])).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )

        # Certification coverage (20%) — % of active members with ≥1 cert
        active_members = CompanyMembership.objects.filter(
            company=company, status="active"
        ).count()
        certified_members = (
            Certification.objects.filter(company=company, status="active")
            .values("user")
            .distinct()
            .count()
        )
        cert_score = _pct(certified_members, active_members) if active_members else Decimal("0")

        # No critical gaps (10%)
        critical_gaps = KnowledgeGap.objects.filter(
            company=company, status="open", severity="critical"
        ).count()
        gap_score = Decimal("100") if critical_gaps == 0 else max(
            Decimal("0"), Decimal("100") - Decimal(str(critical_gaps * 20))
        )

        health = (
            compliance_score * Decimal("0.40")
            + retention_score * Decimal("0.30")
            + cert_score * Decimal("0.20")
            + gap_score * Decimal("0.10")
        )
        return health.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def get_retention_trends(company: Company, days: int = 90) -> List[dict]:
        """
        Returns avg retention score per snapshot_date over the past `days` days.
        """
        cutoff = timezone.now().date() - datetime.timedelta(days=days)
        rows = (
            RetentionSnapshot.objects.filter(
                company=company,
                snapshot_date__gte=cutoff,
                topic=None,
                learning_path=None,
            )
            .values("snapshot_date")
            .annotate(
                avg_retention=Avg("retention_score"),
                avg_risk=Avg("risk_score"),
                count=Count("id"),
            )
            .order_by("snapshot_date")
        )
        return [
            {
                "date": row["snapshot_date"].isoformat(),
                "avg_retention": Decimal(str(row["avg_retention"] or 0)).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                ),
                "avg_risk": Decimal(str(row["avg_risk"] or 0)).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                ),
                "snapshot_count": row["count"],
            }
            for row in rows
        ]

    @staticmethod
    def get_compliance_trends(company: Company, days: int = 90) -> List[dict]:
        """
        Returns compliance rate sampled from ComplianceAssignment completed_at
        bucketed by month.
        """
        from django.db.models.functions import TruncMonth
        cutoff = timezone.now() - datetime.timedelta(days=days)
        rows = (
            ComplianceAssignment.objects.filter(
                company=company,
                status__in=("completed", "non_compliant"),
                completed_at__gte=cutoff,
            )
            .annotate(month=TruncMonth("completed_at"))
            .values("month")
            .annotate(
                total=Count("id"),
                compliant=Count("id", filter=Q(is_compliant=True)),
            )
            .order_by("month")
        )
        return [
            {
                "month": row["month"].date().isoformat() if row["month"] else None,
                "total": row["total"],
                "compliant": row["compliant"],
                "rate": _pct(row["compliant"], row["total"]),
            }
            for row in rows
        ]

    @staticmethod
    def get_learning_trends(company: Company, days: int = 90) -> List[dict]:
        """
        Learning completions over the past `days` days, bucketed by week.
        """
        from django.db.models.functions import TruncWeek
        cutoff = timezone.now() - datetime.timedelta(days=days)
        rows = (
            LearningPathAssignment.objects.filter(
                company=company,
                completed_at__gte=cutoff,
                status="completed",
            )
            .annotate(week=TruncWeek("completed_at"))
            .values("week")
            .annotate(completions=Count("id"))
            .order_by("week")
        )
        return [
            {
                "week": row["week"].date().isoformat() if row["week"] else None,
                "completions": row["completions"],
            }
            for row in rows
        ]

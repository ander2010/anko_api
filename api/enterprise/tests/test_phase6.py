"""
Enterprise Phase 6 — Analytics & Dashboards Tests

Covers:
  - AnalyticsService: employee, manager, trainer, auditor, executive dashboards
  - Health score calculation
  - Retention, compliance, learning trends
  - API endpoints with role-based access control
  - Tenant isolation
"""

import datetime
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership, Team, TeamMembership
from api.enterprise_learning_models import LearningPath, LearningPathAssignment
from api.enterprise_retention_models import KnowledgeGap, RetentionSnapshot, ReviewSchedule
from api.enterprise_compliance_models import ComplianceAssignment, ComplianceProgram
from api.enterprise_certification_models import CertificateTemplate, Certification
from api.enterprise.services.analytics_service import AnalyticsService
from api.enterprise.services.compliance_service import ComplianceService
from api.enterprise.services.certification_service import CertificationService

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username):
    return User.objects.create_user(
        username=username, email=f"{username}@anlt.test", password="Pass123!"
    )


def make_company(owner, name="AnalyticsCo", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status="active"
    )


def make_lp(company, owner, name="Path A"):
    return LearningPath.objects.create(
        company=company, name=name, status="active", created_by=owner
    )


def make_assignment(company, user, lp, owner, status="pending"):
    return LearningPathAssignment.objects.create(
        company=company, user=user, learning_path=lp,
        assigned_by=owner, status=status
    )


def make_compliance_program(company, code, created_by=None):
    return ComplianceProgram.objects.create(
        company=company, name=f"Prog {code}", code=code,
        compliance_type="regulatory", status="active", created_by=created_by
    )


def make_compliance_assignment(company, program, user, status="pending"):
    return ComplianceAssignment.objects.create(
        company=company, program=program, user=user,
        status=status, due_date=datetime.date.today() + datetime.timedelta(days=30)
    )


def make_cert_template(company, code="CERT-A"):
    return CertificateTemplate.objects.create(
        company=company, name=f"Cert {code}", code=code,
        template_type="course_completion", validity_days=365, is_active=True
    )


def make_retention_snapshot(company, user, score=Decimal("70"), risk=Decimal("30")):
    return RetentionSnapshot.objects.create(
        company=company, user=user,
        snapshot_date=datetime.date.today(),
        retention_score=score,
        risk_score=risk,
        confidence_score=Decimal("80"),
    )


# ---------------------------------------------------------------------------
# Service: Employee Dashboard
# ---------------------------------------------------------------------------

class EmployeeDashboardServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_owner")
        self.employee = make_user("anlt_emp")
        self.company = make_company(self.owner, slug="anlt-emp-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_basic_structure(self):
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertIn("user_id", data)
        self.assertIn("learning", data)
        self.assertIn("retention", data)
        self.assertIn("compliance", data)
        self.assertIn("certifications", data)
        self.assertIn("reviews", data)
        self.assertIn("recent_activity", data)

    def test_learning_counts(self):
        lp = make_lp(self.company, self.owner)
        make_assignment(self.company, self.employee, lp, self.owner, status="completed")
        make_assignment(self.company, self.employee, lp, self.owner, status="in_progress")
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertEqual(data["learning"]["completed"], 1)
        self.assertEqual(data["learning"]["in_progress"], 1)
        self.assertEqual(data["learning"]["total_assigned"], 2)

    def test_compliance_in_dashboard(self):
        prog = make_compliance_program(self.company, "EMP-COMP-001", self.owner)
        a = make_compliance_assignment(self.company, prog, self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertEqual(data["compliance"]["compliant"], 1)

    def test_certifications_in_dashboard(self):
        template = make_cert_template(self.company, "EMP-CERT-A")
        CertificationService.issue_certificate(self.employee, self.company, template)
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertEqual(data["certifications"]["active"], 1)

    def test_overdue_reviews(self):
        ReviewSchedule.objects.create(
            company=self.company, user=self.employee,
            review_type="flashcard", status="pending",
            due_date=datetime.date.today() - datetime.timedelta(days=1),
        )
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertEqual(data["reviews"]["overdue"], 1)

    def test_open_gaps_in_retention(self):
        KnowledgeGap.objects.create(
            company=self.company, user=self.employee,
            severity="high", status="open",
            retention_score_at_detection=Decimal("30"),
        )
        data = AnalyticsService.get_employee_dashboard(self.employee, self.company)
        self.assertEqual(data["retention"]["open_gaps"], 1)


# ---------------------------------------------------------------------------
# Service: Manager Dashboard
# ---------------------------------------------------------------------------

class ManagerDashboardServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_mgr_owner")
        self.manager = make_user("anlt_mgr")
        self.emp1 = make_user("anlt_mgr_emp1")
        self.emp2 = make_user("anlt_mgr_emp2")
        self.company = make_company(self.owner, slug="anlt-mgr-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.emp1, self.company, role="employee")
        make_membership(self.emp2, self.company, role="employee")

    def test_basic_structure(self):
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company)
        self.assertIn("total_members", data)
        self.assertIn("learning", data)
        self.assertIn("retention", data)
        self.assertIn("compliance", data)
        self.assertIn("at_risk_members", data)

    def test_total_members(self):
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company)
        # manager + emp1 + emp2 = 3 (owner role excluded from employee view)
        self.assertEqual(data["total_members"], 3)

    def test_team_scoped(self):
        team = Team.objects.create(company=self.company, name="Alpha Team")
        TeamMembership.objects.create(team=team, user=self.emp1, role="member")
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company, team)
        self.assertEqual(data["total_members"], 1)

    def test_completion_rate(self):
        lp = make_lp(self.company, self.owner)
        make_assignment(self.company, self.emp1, lp, self.owner, status="completed")
        make_assignment(self.company, self.emp2, lp, self.owner, status="pending")
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company)
        self.assertEqual(data["learning"]["completed"], 1)
        self.assertEqual(data["learning"]["total_assignments"], 2)

    def test_at_risk_detected(self):
        # Make emp1 have a very low retention (no assessments → score=0 → risk high)
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company)
        # Members with 0 retention score appear in at_risk list
        user_ids = [m["user_id"] for m in data["at_risk_members"]]
        self.assertIn(self.emp1.id, user_ids)

    def test_empty_team(self):
        team = Team.objects.create(company=self.company, name="Empty Team")
        data = AnalyticsService.get_manager_dashboard(self.manager, self.company, team)
        self.assertEqual(data["total_members"], 0)


# ---------------------------------------------------------------------------
# Service: Trainer Dashboard
# ---------------------------------------------------------------------------

class TrainerDashboardServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_trn_owner")
        self.trainer = make_user("anlt_trn")
        self.emp = make_user("anlt_trn_emp")
        self.company = make_company(self.owner, slug="anlt-trn-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.emp, self.company, role="employee")

    def test_basic_structure(self):
        data = AnalyticsService.get_trainer_dashboard(self.trainer, self.company)
        self.assertIn("learning_paths", data)
        self.assertIn("assignments", data)
        self.assertIn("modules", data)
        self.assertIn("training_programs", data)
        self.assertIn("top_paths_by_assessment", data)
        self.assertIn("learners_needing_attention", data)

    def test_learning_path_count(self):
        make_lp(self.company, self.owner, name="Path 1")
        make_lp(self.company, self.owner, name="Path 2")
        data = AnalyticsService.get_trainer_dashboard(self.trainer, self.company)
        self.assertEqual(data["learning_paths"]["total"], 2)
        self.assertEqual(data["learning_paths"]["active"], 2)

    def test_assignment_counts(self):
        lp = make_lp(self.company, self.owner)
        make_assignment(self.company, self.emp, lp, self.owner, status="completed")
        make_assignment(self.company, self.emp, lp, self.owner, status="overdue")
        data = AnalyticsService.get_trainer_dashboard(self.trainer, self.company)
        self.assertEqual(data["assignments"]["completed"], 1)
        self.assertEqual(data["assignments"]["overdue"], 1)


# ---------------------------------------------------------------------------
# Service: Auditor Dashboard
# ---------------------------------------------------------------------------

class AuditorDashboardServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_aud_owner")
        self.auditor = make_user("anlt_aud")
        self.emp = make_user("anlt_aud_emp")
        self.company = make_company(self.owner, slug="anlt-aud-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.auditor, self.company, role="auditor")
        make_membership(self.emp, self.company, role="employee")

    def test_basic_structure(self):
        data = AnalyticsService.get_auditor_dashboard(self.auditor, self.company)
        self.assertIn("compliance", data)
        self.assertIn("program_breakdown", data)
        self.assertIn("certifications", data)
        self.assertIn("knowledge_gaps", data)
        self.assertIn("recent_audit_events", data)

    def test_compliance_counts(self):
        prog = make_compliance_program(self.company, "AUD-COMP-001", self.owner)
        a1 = make_compliance_assignment(self.company, prog, self.emp)
        ComplianceService.complete_assignment(a1, self.emp)
        data = AnalyticsService.get_auditor_dashboard(self.auditor, self.company)
        self.assertEqual(data["compliance"]["compliant"], 1)
        self.assertGreater(data["compliance"]["compliance_rate"], Decimal("0"))

    def test_program_breakdown(self):
        prog = make_compliance_program(self.company, "AUD-BRK-001", self.owner)
        make_compliance_assignment(self.company, prog, self.emp)
        data = AnalyticsService.get_auditor_dashboard(self.auditor, self.company)
        codes = [p["program_code"] for p in data["program_breakdown"]]
        self.assertIn("AUD-BRK-001", codes)

    def test_critical_gaps_counted(self):
        KnowledgeGap.objects.create(
            company=self.company, user=self.emp,
            severity="critical", status="open",
            retention_score_at_detection=Decimal("20"),
        )
        data = AnalyticsService.get_auditor_dashboard(self.auditor, self.company)
        self.assertEqual(data["knowledge_gaps"]["critical"], 1)


# ---------------------------------------------------------------------------
# Service: Executive Dashboard & Health Score
# ---------------------------------------------------------------------------

class ExecutiveDashboardServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_exec_owner")
        self.emp = make_user("anlt_exec_emp")
        self.company = make_company(self.owner, slug="anlt-exec-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.emp, self.company, role="employee")

    def test_basic_structure(self):
        data = AnalyticsService.get_executive_dashboard(self.company)
        self.assertIn("company_id", data)
        self.assertIn("health_score", data)
        self.assertIn("headcount", data)
        self.assertIn("learning", data)
        self.assertIn("retention", data)
        self.assertIn("compliance", data)
        self.assertIn("certifications", data)
        self.assertIn("team_breakdown", data)
        self.assertIn("retention_trend", data)

    def test_headcount(self):
        data = AnalyticsService.get_executive_dashboard(self.company)
        self.assertEqual(data["headcount"], 2)  # owner + emp

    def test_health_score_is_decimal(self):
        score = AnalyticsService.get_company_health_score(self.company)
        self.assertIsInstance(score, Decimal)
        self.assertGreaterEqual(score, Decimal("0"))
        self.assertLessEqual(score, Decimal("100"))

    def test_health_score_improves_with_compliance(self):
        prog = make_compliance_program(self.company, "HEALTH-001", self.owner)
        a = make_compliance_assignment(self.company, prog, self.emp)
        ComplianceService.complete_assignment(a, self.emp)
        score = AnalyticsService.get_company_health_score(self.company)
        self.assertGreater(score, Decimal("0"))

    def test_health_score_improves_with_cert(self):
        template = make_cert_template(self.company, "HEALTH-CERT")
        CertificationService.issue_certificate(self.emp, self.company, template)
        score = AnalyticsService.get_company_health_score(self.company)
        self.assertGreater(score, Decimal("0"))


# ---------------------------------------------------------------------------
# Service: Trends
# ---------------------------------------------------------------------------

class TrendsServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("anlt_trend_owner")
        self.emp = make_user("anlt_trend_emp")
        self.company = make_company(self.owner, slug="anlt-trend-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.emp, self.company, role="employee")

    def test_retention_trends_empty(self):
        data = AnalyticsService.get_retention_trends(self.company, days=90)
        self.assertIsInstance(data, list)

    def test_retention_trends_with_snapshots(self):
        make_retention_snapshot(self.company, self.emp, score=Decimal("75"))
        data = AnalyticsService.get_retention_trends(self.company, days=90)
        self.assertEqual(len(data), 1)
        self.assertIn("date", data[0])
        self.assertIn("avg_retention", data[0])

    def test_compliance_trends_empty(self):
        data = AnalyticsService.get_compliance_trends(self.company, days=90)
        self.assertIsInstance(data, list)

    def test_compliance_trends_with_data(self):
        prog = make_compliance_program(self.company, "TREND-001", self.owner)
        a = make_compliance_assignment(self.company, prog, self.emp)
        ComplianceService.complete_assignment(a, self.emp)
        data = AnalyticsService.get_compliance_trends(self.company, days=90)
        self.assertGreaterEqual(len(data), 1)
        self.assertIn("rate", data[0])

    def test_learning_trends_empty(self):
        data = AnalyticsService.get_learning_trends(self.company, days=90)
        self.assertIsInstance(data, list)

    def test_learning_trends_with_data(self):
        lp = make_lp(self.company, self.owner)
        a = make_assignment(self.company, self.emp, lp, self.owner, status="completed")
        a.completed_at = timezone.now()
        a.save()
        data = AnalyticsService.get_learning_trends(self.company, days=90)
        self.assertGreaterEqual(len(data), 1)
        self.assertIn("completions", data[0])


# ---------------------------------------------------------------------------
# API Tests
# ---------------------------------------------------------------------------

class AnalyticsDashboardAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_anlt_owner")
        self.manager = make_user("api_anlt_mgr")
        self.trainer = make_user("api_anlt_trn")
        self.auditor = make_user("api_anlt_aud")
        self.employee = make_user("api_anlt_emp")
        self.company = make_company(self.owner, slug="api-anlt-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.auditor, self.company, role="auditor")
        make_membership(self.employee, self.company, role="employee")

    def _url(self, action):
        return f"/api/enterprise/analytics/{action}/"

    def _params(self, **extra):
        return {"company_id": self.company.id, **extra}

    # --- Employee Dashboard ---

    def test_employee_dashboard_accessible_by_all_roles(self):
        for user in (self.owner, self.manager, self.trainer, self.employee):
            self.client.force_authenticate(user)
            r = self.client.get(self._url("employee-dashboard"), self._params())
            self.assertEqual(r.status_code, status.HTTP_200_OK, msg=f"Failed for {user.username}")
            self.assertIn("learning", r.data)

    def test_employee_dashboard_unauthenticated_denied(self):
        r = self.client.get(self._url("employee-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    # --- Manager Dashboard ---

    def test_manager_dashboard_accessible_by_manager(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url("manager-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("total_members", r.data)

    def test_manager_dashboard_denied_for_employee(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("manager-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_manager_dashboard_denied_for_trainer(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url("manager-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_manager_dashboard_with_team_filter(self):
        team = Team.objects.create(company=self.company, name="API Team")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url("manager-dashboard"),
            self._params(team_id=team.id),
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["total_members"], 1)

    # --- Trainer Dashboard ---

    def test_trainer_dashboard_accessible_by_trainer(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url("trainer-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("learning_paths", r.data)

    def test_trainer_dashboard_denied_for_employee(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("trainer-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_trainer_dashboard_denied_for_auditor(self):
        self.client.force_authenticate(self.auditor)
        r = self.client.get(self._url("trainer-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    # --- Auditor Dashboard ---

    def test_auditor_dashboard_accessible_by_auditor(self):
        self.client.force_authenticate(self.auditor)
        r = self.client.get(self._url("auditor-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("compliance", r.data)

    def test_auditor_dashboard_accessible_by_admin(self):
        self.client.force_authenticate(self.owner)
        r = self.client.get(self._url("auditor-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_auditor_dashboard_denied_for_employee(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("auditor-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_auditor_dashboard_denied_for_manager(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url("auditor-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    # --- Executive Dashboard ---

    def test_executive_dashboard_accessible_by_owner(self):
        self.client.force_authenticate(self.owner)
        r = self.client.get(self._url("executive-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("health_score", r.data)
        self.assertIn("headcount", r.data)

    def test_executive_dashboard_denied_for_manager(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url("executive-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_executive_dashboard_denied_for_auditor(self):
        self.client.force_authenticate(self.auditor)
        r = self.client.get(self._url("executive-dashboard"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    # --- Company Health ---

    def test_company_health_endpoint(self):
        self.client.force_authenticate(self.owner)
        r = self.client.get(self._url("company-health"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("health_score", r.data)

    def test_company_health_denied_for_employee(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("company-health"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    # --- Trends ---

    def test_retention_trends_accessible_by_manager(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url("retention-trends"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIsInstance(r.data, list)

    def test_retention_trends_denied_for_employee(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("retention-trends"), self._params())
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_compliance_trends_accessible_by_auditor(self):
        self.client.force_authenticate(self.auditor)
        r = self.client.get(self._url("compliance-trends"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_learning_trends_accessible_by_trainer(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url("learning-trends"), self._params())
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_trends_days_param(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url("retention-trends"),
            self._params(days=30),
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    # --- Missing company_id ---

    def test_missing_company_id_returns_400(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("employee-dashboard"))
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    # --- Tenant isolation ---

    def test_cross_company_isolation(self):
        owner2 = make_user("anlt_owner2")
        company2 = make_company(owner2, slug="api-anlt-co2")
        make_membership(owner2, company2, role="owner")
        # owner2 cannot access company data without membership
        self.client.force_authenticate(owner2)
        r = self.client.get(
            self._url("employee-dashboard"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

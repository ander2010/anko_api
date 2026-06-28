"""
Enterprise Phase 4 — Compliance Engine Tests

Covers:
  - Model constraints and validation
  - ComplianceService: assign, complete, renew, evaluate, risk, aggregation, audit
  - API endpoints: programs, requirements, assignments, reviews
  - Tenant isolation
"""

import datetime
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from api.enterprise_compliance_models import (
    ComplianceAssignment,
    ComplianceProgram,
    ComplianceRequirement,
    ComplianceReview,
)
from api.enterprise_models import Company, CompanyMembership, Team, TeamMembership
from api.enterprise.services.compliance_service import ComplianceService

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username):
    return User.objects.create_user(
        username=username, email=f"{username}@test.com", password="Pass123!"
    )


def make_company(owner, name="Acme", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee", status="active"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status=status
    )


def make_program(company, name="Safety Compliance", code="SAF-001", created_by=None, **kwargs):
    kwargs.setdefault("compliance_type", "safety")
    kwargs.setdefault("status", "active")
    kwargs.setdefault("validity_days", 365)
    kwargs.setdefault("is_mandatory", True)
    return ComplianceProgram.objects.create(
        company=company,
        name=name,
        code=code,
        created_by=created_by,
        **kwargs,
    )


def make_assignment(company, program, user=None, team=None, status="pending"):
    return ComplianceAssignment.objects.create(
        company=company,
        program=program,
        user=user,
        team=team,
        status=status,
        due_date=datetime.date.today() + datetime.timedelta(days=30),
    )


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class ComplianceProgramModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("cp_owner")
        self.company = make_company(self.owner, slug="cp-co")

    def test_create_program(self):
        prog = make_program(self.company)
        self.assertEqual(prog.status, "active")
        self.assertTrue(prog.is_mandatory)

    def test_unique_code_per_company(self):
        make_program(self.company, code="FAA-001")
        with self.assertRaises(Exception):
            make_program(self.company, name="Other", code="FAA-001")

    def test_same_code_different_companies(self):
        owner2 = make_user("cp_owner2")
        company2 = make_company(owner2, slug="cp-co2")
        make_program(self.company, code="FAA-001")
        prog2 = make_program(company2, code="FAA-001")
        self.assertEqual(prog2.code, "FAA-001")

    def test_str(self):
        prog = make_program(self.company, code="FAA-001")
        self.assertIn("FAA-001", str(prog))

    def test_default_validity_days(self):
        prog = make_program(self.company, code="DEF-001")
        self.assertEqual(prog.validity_days, 365)


class ComplianceRequirementModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("cr_owner")
        self.company = make_company(self.owner, slug="cr-co")
        self.program = make_program(self.company, code="CR-001")

    def test_create_requirement(self):
        req = ComplianceRequirement.objects.create(
            program=self.program,
            name="Initial Training",
            order=0,
        )
        self.assertEqual(req.order, 0)
        self.assertTrue(req.is_mandatory)

    def test_ordering(self):
        ComplianceRequirement.objects.create(program=self.program, name="B", order=1)
        ComplianceRequirement.objects.create(program=self.program, name="A", order=0)
        names = list(self.program.requirements.values_list("name", flat=True))
        self.assertEqual(names, ["A", "B"])


class ComplianceAssignmentModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("ca_owner")
        self.employee = make_user("ca_emp")
        self.company = make_company(self.owner, slug="ca-co")
        self.program = make_program(self.company, code="CA-001")

    def test_user_assignment(self):
        a = make_assignment(self.company, self.program, user=self.employee)
        self.assertEqual(a.user, self.employee)
        self.assertIsNone(a.team)

    def test_team_assignment(self):
        team = Team.objects.create(company=self.company, name="Team A")
        a = make_assignment(self.company, self.program, team=team)
        self.assertEqual(a.team, team)
        self.assertIsNone(a.user)

    def test_clean_rejects_both(self):
        from django.core.exceptions import ValidationError
        team = Team.objects.create(company=self.company, name="Team B")
        a = ComplianceAssignment(
            company=self.company, program=self.program,
            user=self.employee, team=team
        )
        with self.assertRaises(ValidationError):
            a.clean()

    def test_clean_rejects_neither(self):
        from django.core.exceptions import ValidationError
        a = ComplianceAssignment(company=self.company, program=self.program)
        with self.assertRaises(ValidationError):
            a.clean()

    def test_is_expiring_soon(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        a.is_compliant = True
        a.expires_at = datetime.date.today() + datetime.timedelta(days=15)
        a.save()
        self.assertTrue(a.is_expiring_soon(30))
        self.assertFalse(a.is_expiring_soon(10))

    def test_is_expired(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        a.expires_at = datetime.date.today() - datetime.timedelta(days=1)
        a.save()
        self.assertTrue(a.is_expired())

    def test_days_until_expiry(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        a.expires_at = datetime.date.today() + datetime.timedelta(days=45)
        a.save()
        self.assertEqual(a.days_until_expiry(), 45)


# ---------------------------------------------------------------------------
# Service Tests
# ---------------------------------------------------------------------------

class ComplianceServiceAssignTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_c_owner")
        self.employee = make_user("svc_c_emp")
        self.company = make_company(self.owner, slug="svc-comp-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")
        self.program = make_program(self.company, code="SVC-001", created_by=self.owner)

    def test_assign_to_user(self):
        a = ComplianceService.assign_to_user(
            self.program, self.employee, self.owner, self.company
        )
        self.assertEqual(a.user, self.employee)
        self.assertEqual(a.status, "pending")

    def test_assign_to_user_emits_event(self):
        from api.enterprise_models import LearningEvent
        ComplianceService.assign_to_user(
            self.program, self.employee, self.owner, self.company
        )
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.employee, event_type="compliance_assigned"
            ).exists()
        )

    def test_assign_to_team(self):
        team = Team.objects.create(company=self.company, name="SVC Team")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        a = ComplianceService.assign_to_team(
            self.program, team, self.owner, self.company
        )
        self.assertEqual(a.team, team)
        self.assertIsNone(a.user)

    def test_assign_to_team_emits_events_per_member(self):
        from api.enterprise_models import LearningEvent
        team = Team.objects.create(company=self.company, name="SVC Team 2")
        emp2 = make_user("svc_c_emp2")
        make_membership(emp2, self.company, role="employee")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        TeamMembership.objects.create(team=team, user=emp2, role="member")
        ComplianceService.assign_to_team(
            self.program, team, self.owner, self.company
        )
        count = LearningEvent.objects.filter(event_type="compliance_assigned").count()
        self.assertEqual(count, 2)


class ComplianceServiceCompleteTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_cc_owner")
        self.employee = make_user("svc_cc_emp")
        self.company = make_company(self.owner, slug="svc-compc-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_complete_without_score_requirement(self):
        program = make_program(self.company, code="NO-SCORE", requires_score=False)
        a = make_assignment(self.company, program, user=self.employee)
        result = ComplianceService.complete_assignment(a, self.employee)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.is_compliant)

    def test_complete_with_passing_score(self):
        program = make_program(
            self.company, code="SCORE-PASS",
            requires_score=True, passing_score=Decimal("70")
        )
        a = make_assignment(self.company, program, user=self.employee)
        result = ComplianceService.complete_assignment(
            a, self.employee, score=Decimal("85")
        )
        self.assertTrue(result.is_compliant)
        self.assertEqual(result.status, "completed")

    def test_complete_with_failing_score(self):
        program = make_program(
            self.company, code="SCORE-FAIL",
            requires_score=True, passing_score=Decimal("70")
        )
        a = make_assignment(self.company, program, user=self.employee)
        result = ComplianceService.complete_assignment(
            a, self.employee, score=Decimal("50")
        )
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.status, "non_compliant")

    def test_complete_sets_expires_at(self):
        program = make_program(self.company, code="EXP-001", validity_days=180)
        a = make_assignment(self.company, program, user=self.employee)
        result = ComplianceService.complete_assignment(a, self.employee)
        expected = datetime.date.today() + datetime.timedelta(days=180)
        self.assertEqual(result.expires_at, expected)

    def test_complete_creates_review_record(self):
        program = make_program(self.company, code="REV-001")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        self.assertEqual(
            ComplianceReview.objects.filter(assignment=a).count(), 1
        )

    def test_complete_emits_event(self):
        from api.enterprise_models import LearningEvent
        program = make_program(self.company, code="EVT-001")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.employee, event_type="compliance_completed"
            ).exists()
        )


class ComplianceServiceRenewalTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_ren_owner")
        self.employee = make_user("svc_ren_emp")
        self.company = make_company(self.owner, slug="svc-ren-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")
        self.program = make_program(self.company, code="REN-001")

    def test_create_renewal(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        renewal = ComplianceService.create_renewal(a, self.owner)
        self.assertEqual(renewal.status, "pending")
        self.assertEqual(renewal.renewal_count, 1)
        self.assertEqual(renewal.renewed_from, a)

    def test_renewal_increments_count(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        r1 = ComplianceService.create_renewal(a, self.owner)
        r2 = ComplianceService.create_renewal(r1, self.owner)
        self.assertEqual(r2.renewal_count, 2)


class ComplianceServiceEvaluationTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_ev_owner")
        self.employee = make_user("svc_ev_emp")
        self.company = make_company(self.owner, slug="svc-eval-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_evaluate_no_assignments(self):
        result = ComplianceService.evaluate_compliance(self.employee, self.company)
        self.assertEqual(result["total_programs"], 0)
        self.assertEqual(result["compliance_rate"], Decimal("0"))

    def test_evaluate_one_compliant(self):
        program = make_program(self.company, code="EVAL-001")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        result = ComplianceService.evaluate_compliance(self.employee, self.company)
        self.assertEqual(result["compliant"], 1)
        self.assertEqual(result["compliance_rate"], Decimal("100.00"))

    def test_evaluate_mixed(self):
        p1 = make_program(self.company, code="EVAL-P1")
        p2 = make_program(self.company, code="EVAL-P2", requires_score=True, passing_score=Decimal("70"))
        a1 = make_assignment(self.company, p1, user=self.employee)
        a2 = make_assignment(self.company, p2, user=self.employee)
        ComplianceService.complete_assignment(a1, self.employee)
        ComplianceService.complete_assignment(a2, self.employee, score=Decimal("50"))
        result = ComplianceService.evaluate_compliance(self.employee, self.company)
        self.assertEqual(result["compliant"], 1)
        self.assertEqual(result["non_compliant"], 1)
        self.assertEqual(result["compliance_rate"], Decimal("50.00"))

    def test_risk_score_zero_no_assignments(self):
        risk = ComplianceService.calculate_compliance_risk(self.employee, self.company)
        self.assertEqual(risk, Decimal("0"))

    def test_risk_high_non_compliant(self):
        program = make_program(
            self.company, code="RISK-001",
            requires_score=True, passing_score=Decimal("70"), is_mandatory=True
        )
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee, score=Decimal("40"))
        risk = ComplianceService.calculate_compliance_risk(self.employee, self.company)
        self.assertGreater(risk, Decimal("0"))

    def test_team_compliance(self):
        team = Team.objects.create(company=self.company, name="Eval Team")
        emp2 = make_user("svc_ev_emp2")
        make_membership(emp2, self.company, role="employee")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        TeamMembership.objects.create(team=team, user=emp2, role="member")
        result = ComplianceService.get_team_compliance(team, self.company)
        self.assertEqual(result["member_count"], 2)
        self.assertIn("avg_compliance_rate", result)

    def test_company_compliance(self):
        result = ComplianceService.get_company_compliance(self.company)
        self.assertEqual(result["company_id"], self.company.id)
        self.assertIn("avg_compliance_rate", result)

    def test_audit_report(self):
        program = make_program(self.company, code="AUD-001")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        report = ComplianceService.generate_audit_report(self.company, program)
        self.assertEqual(report["program_code"], "AUD-001")
        self.assertEqual(report["total_assignments"], 1)
        self.assertEqual(report["compliant"], 1)

    def test_check_expiring_assignments(self):
        program = make_program(self.company, code="EXP-SOON")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        # Override expires_at to 15 days from now
        a.refresh_from_db()
        a.expires_at = datetime.date.today() + datetime.timedelta(days=15)
        a.save()
        expiring = ComplianceService.check_expiring_assignments(self.company, days=30)
        self.assertGreaterEqual(len(expiring), 1)


# ---------------------------------------------------------------------------
# API Tests
# ---------------------------------------------------------------------------

class ComplianceProgramAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_cp_owner")
        self.trainer = make_user("api_cp_trainer")
        self.employee = make_user("api_cp_emp")
        self.company = make_company(self.owner, slug="api-cp-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.employee, self.company, role="employee")

    def _url(self, suffix=""):
        return f"/api/enterprise/compliance-programs/{suffix}"

    def test_trainer_can_create_program(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "FAA Safety",
            "code": "FAA-001",
            "compliance_type": "safety",
            "frequency": "annual",
            "validity_days": 365,
        })
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["code"], "FAA-001")

    def test_employee_cannot_create_program(self):
        self.client.force_authenticate(self.employee)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Unauthorized",
            "code": "UNAUTH-001",
        })
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_programs(self):
        make_program(self.company, code="LST-001")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data.get("results", r.data)), 1)

    def test_assign_to_user_action(self):
        program = make_program(self.company, code="ASGN-001", created_by=self.owner)
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{program.id}/assign-to-user/"),
            {"company_id": self.company.id, "user_id": self.employee.id},
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["user"], self.employee.id)

    def test_assign_to_team_action(self):
        program = make_program(self.company, code="TEAM-001", created_by=self.owner)
        team = Team.objects.create(company=self.company, name="API Team")
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{program.id}/assign-to-team/"),
            {"company_id": self.company.id, "team_id": team.id},
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["team"], team.id)

    def test_activate_action(self):
        program = ComplianceProgram.objects.create(
            company=self.company, name="Draft", code="DRF-001", status="draft"
        )
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{program.id}/activate/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "active")

    def test_archive_action(self):
        program = make_program(self.company, code="ARC-001")
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{program.id}/archive/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_audit_report_action(self):
        program = make_program(self.company, code="AUD-API-001")
        a = make_assignment(self.company, program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        self.client.force_authenticate(self.owner)
        r = self.client.get(
            self._url(f"{program.id}/audit-report/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("compliance_rate", r.data)

    def test_cross_company_isolation(self):
        owner2 = make_user("api_cp_owner2")
        company2 = make_company(owner2, slug="api-cp-co2")
        make_program(company2, code="SECRET-001")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        codes = [item["code"] for item in r.data.get("results", r.data)]
        self.assertNotIn("SECRET-001", codes)


class ComplianceAssignmentAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_ca_owner")
        self.manager = make_user("api_ca_mgr")
        self.employee = make_user("api_ca_emp")
        self.company = make_company(self.owner, slug="api-ca-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.employee, self.company, role="employee")
        self.program = make_program(self.company, code="API-CA-001", created_by=self.owner)

    def _url(self, suffix=""):
        return f"/api/enterprise/compliance-assignments/{suffix}"

    def test_my_compliance_action(self):
        a = make_assignment(self.company, self.program, user=self.employee)
        ComplianceService.complete_assignment(a, self.employee)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("my-compliance/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("compliance_rate", r.data)

    def test_complete_action(self):
        a = make_assignment(self.company, self.program, user=self.employee)
        self.client.force_authenticate(self.manager)
        r = self.client.post(
            self._url(f"{a.id}/complete/"),
            {"company_id": self.company.id, "score": "90"},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "completed")

    def test_renew_action(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        a.is_compliant = True
        a.expires_at = datetime.date.today() + datetime.timedelta(days=5)
        a.save()
        self.client.force_authenticate(self.manager)
        r = self.client.post(
            self._url(f"{a.id}/renew/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["renewal_count"], 1)

    def test_expiring_action(self):
        a = make_assignment(self.company, self.program, user=self.employee, status="completed")
        a.is_compliant = True
        a.expires_at = datetime.date.today() + datetime.timedelta(days=10)
        a.save()
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url("expiring/"),
            {"company_id": self.company.id, "days": 30},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_company_compliance_action(self):
        self.client.force_authenticate(self.owner)
        r = self.client.get(
            self._url("company-compliance/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("avg_compliance_rate", r.data)

    def test_team_compliance_action(self):
        team = Team.objects.create(company=self.company, name="API Comp Team")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url("team-compliance/"),
            {"company_id": self.company.id, "team_id": team.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("avg_compliance_rate", r.data)

    def test_employee_only_sees_own_assignments(self):
        make_assignment(self.company, self.program, user=self.employee)
        other = make_user("api_ca_other")
        make_membership(other, self.company, role="employee")
        make_assignment(self.company, self.program, user=other)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        user_ids = [item["user"] for item in r.data.get("results", r.data)]
        for uid in user_ids:
            self.assertEqual(uid, self.employee.id)

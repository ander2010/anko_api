"""
Enterprise Phase 1 — Foundation Tests

Covers:
  - Model creation and constraints
  - Tenant isolation (cross-company access denied)
  - Security service helpers
  - Permission classes
"""

import datetime
from django.test import TestCase
from django.contrib.auth import get_user_model

from api.enterprise_models import (
    Company,
    BusinessUnit,
    CompanyMembership,
    Team,
    TeamMembership,
    EnterpriseProfile,
    LearningEvent,
    KnowledgeHealthSnapshot,
)
from api.enterprise.services.security_service import (
    validate_company_access,
    validate_team_access,
    validate_business_unit_access,
    validate_dashboard_access,
)
from api.enterprise.permissions import (
    HasCompanyAccess,
    IsCompanyOwner,
    IsCompanyAdmin,
    IsCompanyManager,
    IsCompanyTrainer,
    IsCompanyEmployee,
    IsCompanyAuditor,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username, email=None):
    email = email or f"{username}@test.com"
    return User.objects.create_user(username=username, email=email, password="Pass123!")


def make_company(owner, name="Acme Corp", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee", status="active", stage="active_employee"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status=status, employee_stage=stage
    )


# ---------------------------------------------------------------------------
# Company model tests
# ---------------------------------------------------------------------------

class CompanyModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("comp_owner")

    def test_create_company(self):
        c = make_company(self.owner)
        self.assertEqual(c.name, "Acme Corp")
        self.assertTrue(c.is_active)

    def test_slug_unique(self):
        make_company(self.owner, slug="my-slug")
        with self.assertRaises(Exception):
            make_company(self.owner, name="Other", slug="my-slug")

    def test_str(self):
        c = make_company(self.owner)
        self.assertIn("Acme Corp", str(c))

    def test_default_settings_json(self):
        c = make_company(self.owner)
        self.assertIsInstance(c.settings, dict)


# ---------------------------------------------------------------------------
# BusinessUnit tests
# ---------------------------------------------------------------------------

class BusinessUnitTest(TestCase):
    def setUp(self):
        self.owner = make_user("bu_owner")
        self.company = make_company(self.owner)

    def test_create_bu(self):
        bu = BusinessUnit.objects.create(
            company=self.company, name="Engineering", code="ENG"
        )
        self.assertEqual(bu.code, "ENG")
        self.assertTrue(bu.is_active)

    def test_unique_code_per_company(self):
        BusinessUnit.objects.create(company=self.company, name="Engineering", code="ENG")
        with self.assertRaises(Exception):
            BusinessUnit.objects.create(
                company=self.company, name="Other", code="ENG"
            )

    def test_unique_name_per_company(self):
        BusinessUnit.objects.create(company=self.company, name="Engineering", code="ENG")
        with self.assertRaises(Exception):
            BusinessUnit.objects.create(
                company=self.company, name="Engineering", code="ENG2"
            )

    def test_same_code_different_companies(self):
        owner2 = make_user("bu_owner2")
        company2 = make_company(owner2, name="Other Corp", slug="other-corp")
        BusinessUnit.objects.create(company=self.company, name="Engineering", code="ENG")
        # Should NOT raise — different company
        bu2 = BusinessUnit.objects.create(
            company=company2, name="Engineering", code="ENG"
        )
        self.assertEqual(bu2.code, "ENG")


# ---------------------------------------------------------------------------
# CompanyMembership tests
# ---------------------------------------------------------------------------

class CompanyMembershipTest(TestCase):
    def setUp(self):
        self.owner = make_user("mem_owner")
        self.employee = make_user("mem_emp")
        self.company = make_company(self.owner)

    def test_create_membership(self):
        m = make_membership(self.employee, self.company)
        self.assertEqual(m.role, "employee")
        self.assertEqual(m.status, "active")

    def test_unique_per_company(self):
        make_membership(self.employee, self.company)
        with self.assertRaises(Exception):
            make_membership(self.employee, self.company)

    def test_is_active_member(self):
        m = make_membership(self.employee, self.company, status="active")
        self.assertTrue(m.is_active_member())

    def test_suspended_not_active(self):
        m = make_membership(self.employee, self.company, status="suspended")
        self.assertFalse(m.is_active_member())

    def test_role_and_stage_independent(self):
        m = make_membership(
            self.employee, self.company, role="employee", stage="onboarding"
        )
        self.assertEqual(m.role, "employee")
        self.assertEqual(m.employee_stage, "onboarding")
        m.role = "manager"
        m.employee_stage = "active_employee"
        m.save()
        m.refresh_from_db()
        self.assertEqual(m.role, "manager")
        self.assertEqual(m.employee_stage, "active_employee")


# ---------------------------------------------------------------------------
# Team + TeamMembership tests
# ---------------------------------------------------------------------------

class TeamTest(TestCase):
    def setUp(self):
        self.owner = make_user("team_owner")
        self.company = make_company(self.owner)

    def test_create_team(self):
        t = Team.objects.create(company=self.company, name="Engine Team")
        self.assertEqual(t.company, self.company)
        self.assertTrue(t.is_active)

    def test_unique_name_per_company(self):
        Team.objects.create(company=self.company, name="Engine Team")
        with self.assertRaises(Exception):
            Team.objects.create(company=self.company, name="Engine Team")

    def test_same_name_different_companies(self):
        owner2 = make_user("team_owner2")
        company2 = make_company(owner2, "Beta Corp", "beta-corp")
        Team.objects.create(company=self.company, name="Engine Team")
        t2 = Team.objects.create(company=company2, name="Engine Team")
        self.assertEqual(t2.name, "Engine Team")


class TeamMembershipTest(TestCase):
    def setUp(self):
        self.owner = make_user("tm_owner")
        self.member = make_user("tm_member")
        self.company = make_company(self.owner)
        self.team = Team.objects.create(company=self.company, name="Alpha")

    def test_add_member(self):
        tm = TeamMembership.objects.create(team=self.team, user=self.member)
        self.assertEqual(tm.role, "member")

    def test_unique_member_per_team(self):
        TeamMembership.objects.create(team=self.team, user=self.member)
        with self.assertRaises(Exception):
            TeamMembership.objects.create(team=self.team, user=self.member)


# ---------------------------------------------------------------------------
# EnterpriseProfile tests
# ---------------------------------------------------------------------------

class EnterpriseProfileTest(TestCase):
    def setUp(self):
        self.user = make_user("profile_user")
        self.owner = make_user("profile_owner")
        self.company = make_company(self.owner)

    def test_create_profile(self):
        p = EnterpriseProfile.objects.create(
            user=self.user,
            default_company=self.company,
            job_title="Aircraft Technician",
            employee_code="EMP001",
        )
        self.assertEqual(p.job_title, "Aircraft Technician")

    def test_one_to_one_enforced(self):
        EnterpriseProfile.objects.create(user=self.user)
        with self.assertRaises(Exception):
            EnterpriseProfile.objects.create(user=self.user)


# ---------------------------------------------------------------------------
# LearningEvent tests
# ---------------------------------------------------------------------------

class LearningEventTest(TestCase):
    def setUp(self):
        self.owner = make_user("ev_owner")
        self.user = make_user("ev_user")
        self.company = make_company(self.owner)

    def test_create_event(self):
        ev = LearningEvent.objects.create(
            company=self.company,
            user=self.user,
            event_type="battery_completed",
            score=85.5,
        )
        self.assertEqual(ev.event_type, "battery_completed")
        self.assertIsNotNone(ev.created_at)

    def test_event_without_score(self):
        ev = LearningEvent.objects.create(
            company=self.company,
            user=self.user,
            event_type="employee_activated",
        )
        self.assertIsNone(ev.score)


# ---------------------------------------------------------------------------
# KnowledgeHealthSnapshot tests
# ---------------------------------------------------------------------------

class KnowledgeHealthSnapshotTest(TestCase):
    def setUp(self):
        self.owner = make_user("snap_owner")
        self.company = make_company(self.owner)

    def test_create_snapshot(self):
        snap = KnowledgeHealthSnapshot.objects.create(
            company=self.company,
            snapshot_date=datetime.date.today(),
            global_retention_score=87.5,
            global_risk_score=12.0,
            active_employees=100,
            employees_at_risk=5,
        )
        self.assertEqual(snap.active_employees, 100)

    def test_unique_per_day(self):
        today = datetime.date.today()
        KnowledgeHealthSnapshot.objects.create(
            company=self.company, snapshot_date=today
        )
        with self.assertRaises(Exception):
            KnowledgeHealthSnapshot.objects.create(
                company=self.company, snapshot_date=today
            )

    def test_different_companies_same_day(self):
        owner2 = make_user("snap_owner2")
        company2 = make_company(owner2, "Snap Corp 2", "snap-corp-2")
        today = datetime.date.today()
        KnowledgeHealthSnapshot.objects.create(company=self.company, snapshot_date=today)
        snap2 = KnowledgeHealthSnapshot.objects.create(
            company=company2, snapshot_date=today
        )
        self.assertEqual(snap2.company, company2)


# ---------------------------------------------------------------------------
# Security service — tenant isolation tests
# ---------------------------------------------------------------------------

class SecurityServiceTenantTest(TestCase):
    def setUp(self):
        self.owner = make_user("sec_owner")
        self.employee = make_user("sec_emp")
        self.outsider = make_user("sec_out")
        self.company = make_company(self.owner)
        make_membership(self.employee, self.company, role="employee")

    def test_active_member_can_access(self):
        m = validate_company_access(self.employee, self.company.id)
        self.assertEqual(m.role, "employee")

    def test_outsider_cannot_access(self):
        with self.assertRaises(PermissionError):
            validate_company_access(self.outsider, self.company.id)

    def test_cross_company_blocked(self):
        owner2 = make_user("sec_owner2")
        company2 = make_company(owner2, "Other Corp", "other-corp-sec")
        with self.assertRaises(PermissionError):
            validate_company_access(self.employee, company2.id)

    def test_suspended_member_blocked(self):
        suspended = make_user("sec_suspended")
        make_membership(suspended, self.company, status="suspended")
        with self.assertRaises(PermissionError):
            validate_company_access(suspended, self.company.id)

    def test_removed_member_blocked(self):
        removed = make_user("sec_removed")
        make_membership(removed, self.company, status="removed")
        with self.assertRaises(PermissionError):
            validate_company_access(removed, self.company.id)


class SecurityServiceTeamTest(TestCase):
    def setUp(self):
        self.owner = make_user("sec_team_owner")
        self.company = make_company(self.owner)
        self.manager = make_user("sec_team_manager")
        self.member = make_user("sec_team_member")
        self.outsider = make_user("sec_team_out")

        make_membership(self.manager, self.company, role="manager")
        make_membership(self.member, self.company, role="employee")

        self.team = Team.objects.create(company=self.company, name="Engine Team")
        TeamMembership.objects.create(team=self.team, user=self.manager, role="manager")
        TeamMembership.objects.create(team=self.team, user=self.member, role="member")

    def test_admin_can_access_any_team(self):
        admin = make_user("sec_team_admin")
        make_membership(admin, self.company, role="admin")
        team, m = validate_team_access(admin, self.team.id)
        self.assertEqual(team.id, self.team.id)

    def test_assigned_manager_can_access(self):
        team, m = validate_team_access(self.manager, self.team.id)
        self.assertEqual(team.id, self.team.id)

    def test_unassigned_manager_blocked(self):
        other_manager = make_user("sec_team_mgr2")
        make_membership(other_manager, self.company, role="manager")
        # Not added to any TeamMembership for this team
        with self.assertRaises(PermissionError):
            validate_team_access(other_manager, self.team.id)

    def test_outsider_blocked(self):
        with self.assertRaises(PermissionError):
            validate_team_access(self.outsider, self.team.id)


class SecurityServiceDashboardTest(TestCase):
    def setUp(self):
        self.owner = make_user("dash_owner")
        self.company = make_company(self.owner)
        self.admin = make_user("dash_admin")
        self.manager = make_user("dash_manager")
        self.employee = make_user("dash_emp")

        make_membership(self.admin, self.company, role="admin")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.employee, self.company, role="employee")

    def test_employee_can_access_own_dashboard(self):
        m = validate_dashboard_access(self.employee, self.company.id, "employee")
        self.assertEqual(m.role, "employee")

    def test_employee_cannot_access_executive_dashboard(self):
        with self.assertRaises(PermissionError):
            validate_dashboard_access(self.employee, self.company.id, "executive")

    def test_manager_can_access_manager_dashboard(self):
        m = validate_dashboard_access(self.manager, self.company.id, "manager")
        self.assertEqual(m.role, "manager")

    def test_admin_can_access_executive_dashboard(self):
        m = validate_dashboard_access(self.admin, self.company.id, "executive")
        self.assertEqual(m.role, "admin")


# ---------------------------------------------------------------------------
# Permission class tests (using DRF's APIRequestFactory)
# ---------------------------------------------------------------------------

class _MockRequest:
    """Minimal request object sufficient for permission tests."""

    def __init__(self, user, company_id=None):
        self.user = user
        self.query_params = {"company_id": company_id} if company_id else {}
        self.data = {}


class _MockView:
    def __init__(self, kwargs=None):
        self.kwargs = kwargs or {}


class PermissionClassTest(TestCase):
    def setUp(self):
        self.owner = make_user("perm_owner")
        self.employee = make_user("perm_emp")
        self.outsider = make_user("perm_out")
        self.company = make_company(self.owner)
        make_membership(self.employee, self.company, role="employee")

    def _check(self, permission_class, user):
        """Helper: returns True if permission grants access."""
        request = _MockRequest(user)
        view = _MockView(kwargs={"company_pk": self.company.id})
        perm = permission_class()
        return perm.has_permission(request, view)

    def test_has_company_access_active_member(self):
        self.assertTrue(self._check(HasCompanyAccess, self.employee))

    def test_has_company_access_outsider_denied(self):
        self.assertFalse(self._check(HasCompanyAccess, self.outsider))

    def test_is_company_owner_only_owner(self):
        make_membership(self.owner, self.company, role="owner")
        self.assertTrue(self._check(IsCompanyOwner, self.owner))
        self.assertFalse(self._check(IsCompanyOwner, self.employee))

    def test_is_company_admin_includes_owner(self):
        make_membership(self.owner, self.company, role="owner")
        self.assertTrue(self._check(IsCompanyAdmin, self.owner))

    def test_is_company_admin_excludes_employee(self):
        self.assertFalse(self._check(IsCompanyAdmin, self.employee))

    def test_is_company_manager_includes_manager(self):
        mgr = make_user("perm_mgr")
        make_membership(mgr, self.company, role="manager")
        self.assertTrue(self._check(IsCompanyManager, mgr))

    def test_is_company_employee_any_member(self):
        self.assertTrue(self._check(IsCompanyEmployee, self.employee))

    def test_is_company_auditor_excludes_employee(self):
        self.assertFalse(self._check(IsCompanyAuditor, self.employee))

    def test_is_company_auditor_includes_auditor(self):
        auditor = make_user("perm_auditor")
        make_membership(auditor, self.company, role="auditor")
        self.assertTrue(self._check(IsCompanyAuditor, auditor))

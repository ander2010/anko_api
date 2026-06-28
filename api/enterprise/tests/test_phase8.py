"""
Phase 8 — Company Management API Tests

Tests cover:
  - Company CRUD + invite + member management
  - BusinessUnit CRUD
  - Team CRUD + add/remove members
  - LearningModule new fields (process_type, difficulty, minimum_passing_score)
  - LearningPath final_battery field
  - LearningModuleItem ViewSet
  - Tenant isolation
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from api.enterprise_models import (
    BusinessUnit,
    Company,
    CompanyMembership,
    Team,
    TeamMembership,
)
from api.enterprise_learning_models import (
    LearningModule,
    LearningModuleItem,
    LearningPath,
)

User = get_user_model()

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

_uid = 0


def _next_uid():
    global _uid
    _uid += 1
    return _uid


def make_user(username=None, **kwargs):
    uid = _next_uid()
    username = username or f"user_p8_{uid}"
    kwargs.setdefault("email", f"{username}@test8.com")
    return User.objects.create_user(username=username, password="pass1234", **kwargs)


def make_company(owner, name=None):
    uid = _next_uid()
    name = name or f"Company P8 {uid}"
    slug = name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(company, user, role="employee", status="active"):
    return CompanyMembership.objects.create(
        company=company,
        user=user,
        role=role,
        status=status,
        employee_stage="active_employee",
    )


def make_business_unit(company, name=None, code=None):
    uid = _next_uid()
    return BusinessUnit.objects.create(
        company=company,
        name=name or f"BU {uid}",
        code=code or f"BU{uid}",
    )


def make_team(company, name=None):
    uid = _next_uid()
    return Team.objects.create(
        company=company,
        name=name or f"Team {uid}",
    )


def make_learning_path(company, created_by, **kwargs):
    uid = _next_uid()
    return LearningPath.objects.create(
        company=company,
        name=kwargs.get("name", f"Path {uid}"),
        status="draft",
        created_by=created_by,
    )


def make_module(path, **kwargs):
    uid = _next_uid()
    return LearningModule.objects.create(
        learning_path=path,
        name=kwargs.get("name", f"Module {uid}"),
        order=kwargs.get("order", 0),
        process_type=kwargs.get("process_type", "course"),
        difficulty=kwargs.get("difficulty", "medium"),
        minimum_passing_score=kwargs.get("minimum_passing_score", 70),
    )


# ---------------------------------------------------------------------------
# CompanyModel Tests
# ---------------------------------------------------------------------------

class CompanyModelTest(TestCase):

    def test_company_creation(self):
        owner = make_user()
        company = make_company(owner)
        self.assertEqual(company.owner, owner)
        self.assertTrue(company.is_active)

    def test_owner_membership_created_via_service(self):
        from api.enterprise.services.company_service import CompanyService
        owner = make_user()
        company = CompanyService.create_company(
            owner,
            {"name": "My Corp", "slug": "my-corp"},
        )
        membership = CompanyMembership.objects.get(company=company, user=owner)
        self.assertEqual(membership.role, "owner")
        self.assertEqual(membership.status, "active")


# ---------------------------------------------------------------------------
# CompanyService Tests
# ---------------------------------------------------------------------------

class CompanyServiceTest(TestCase):

    def setUp(self):
        from api.enterprise.services.company_service import CompanyService
        self.service = CompanyService
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")

    def test_add_new_user_by_email(self):
        membership = self.service.add_user(
            company=self.company,
            email="newuser@example.com",
            role="employee",
            employee_stage="onboarding",
            added_by=self.owner,
        )
        self.assertEqual(membership.status, "active")
        self.assertEqual(membership.role, "employee")
        self.assertEqual(membership.user.email, "newuser@example.com")
        self.assertIsNotNone(membership.joined_at)

    def test_add_existing_user(self):
        existing = make_user()
        membership = self.service.add_user(
            company=self.company,
            email=existing.email,
            role="trainer",
            employee_stage="trainee",
            added_by=self.owner,
        )
        self.assertEqual(membership.user, existing)
        self.assertEqual(membership.role, "trainer")
        self.assertEqual(membership.status, "active")

    def test_add_duplicate_raises(self):
        member = make_user()
        make_membership(self.company, member, role="employee")
        from rest_framework.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            self.service.add_user(
                company=self.company,
                email=member.email,
                role="employee",
                employee_stage="onboarding",
                added_by=self.owner,
            )

    def test_change_member_role(self):
        member = make_user()
        m = make_membership(self.company, member, role="employee")
        updated = self.service.change_member_role(
            company=self.company,
            membership_id=m.id,
            new_role="trainer",
            changed_by=self.owner,
        )
        self.assertEqual(updated.role, "trainer")

    def test_change_owner_role_raises(self):
        owner_membership = CompanyMembership.objects.get(
            company=self.company, user=self.owner
        )
        from rest_framework.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            self.service.change_member_role(
                company=self.company,
                membership_id=owner_membership.id,
                new_role="admin",
                changed_by=self.owner,
            )

    def test_remove_member(self):
        member = make_user()
        m = make_membership(self.company, member, role="employee")
        self.service.remove_member(
            company=self.company,
            membership_id=m.id,
            removed_by=self.owner,
        )
        m.refresh_from_db()
        self.assertEqual(m.status, "removed")

    def test_remove_owner_raises(self):
        owner_m = CompanyMembership.objects.get(company=self.company, user=self.owner)
        from rest_framework.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            self.service.remove_member(
                company=self.company,
                membership_id=owner_m.id,
                removed_by=self.owner,
            )


# ---------------------------------------------------------------------------
# Company API Tests
# ---------------------------------------------------------------------------

class CompanyAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.client.force_authenticate(user=self.owner)

    def test_create_company_requires_staff(self):
        # Regular user cannot create companies
        resp = self.client.post("/api/enterprise/companies/", {
            "name": "Test Corp",
            "slug": "test-corp",
        })
        self.assertEqual(resp.status_code, 403)

    def test_create_company_as_staff(self):
        self.owner.is_staff = True
        self.owner.save()
        resp = self.client.post("/api/enterprise/companies/", {
            "name": "Test Corp",
            "slug": "test-corp",
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["name"], "Test Corp")
        company = Company.objects.get(id=resp.data["id"])
        self.assertTrue(
            CompanyMembership.objects.filter(
                company=company, user=self.owner, role="owner", status="active"
            ).exists()
        )

    def test_list_only_own_companies(self):
        from api.enterprise.services.company_service import CompanyService
        CompanyService.create_company(self.owner, {"name": "Corp A", "slug": "corp-a"})
        CompanyService.create_company(self.owner, {"name": "Corp B", "slug": "corp-b"})
        # Another user's company
        other = make_user()
        CompanyService.create_company(other, {"name": "Corp Other", "slug": "corp-other"})

        resp = self.client.get("/api/enterprise/companies/")
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        names = [c["name"] for c in results]
        self.assertIn("Corp A", names)
        self.assertIn("Corp B", names)
        self.assertNotIn("Corp Other", names)

    def test_retrieve_company(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        resp = self.client.get(f"/api/enterprise/companies/{company.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["name"], company.name)

    def test_retrieve_requires_membership(self):
        other_owner = make_user()
        other_company = make_company(other_owner)
        resp = self.client.get(f"/api/enterprise/companies/{other_company.id}/")
        self.assertEqual(resp.status_code, 403)

    def test_add_user(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        resp = self.client.post(
            f"/api/enterprise/companies/{company.id}/add-user/",
            {"email": "newperson@example.com", "role": "employee", "employee_stage": "onboarding"},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["status"], "active")   # immediate access
        self.assertEqual(resp.data["role"], "employee")

    def test_members_list(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        emp = make_user()
        make_membership(company, emp, role="employee")
        resp = self.client.get(f"/api/enterprise/companies/{company.id}/members/")
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 2)

    def test_change_member_role(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        emp = make_user()
        m = make_membership(company, emp, role="employee")
        resp = self.client.post(
            f"/api/enterprise/companies/{company.id}/change-member-role/",
            {"membership_id": m.id, "role": "trainer"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["role"], "trainer")

    def test_remove_member(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        emp = make_user()
        m = make_membership(company, emp, role="employee")
        resp = self.client.post(
            f"/api/enterprise/companies/{company.id}/remove-member/",
            {"membership_id": m.id},
        )
        self.assertEqual(resp.status_code, 204)
        m.refresh_from_db()
        self.assertEqual(m.status, "removed")

    def test_non_admin_cannot_add_user(self):
        company = make_company(self.owner)
        make_membership(company, self.owner, role="owner")
        employee = make_user()
        make_membership(company, employee, role="employee")
        self.client.force_authenticate(user=employee)
        resp = self.client.post(
            f"/api/enterprise/companies/{company.id}/add-user/",
            {"email": "x@x.com", "role": "employee", "employee_stage": "onboarding"},
        )
        self.assertEqual(resp.status_code, 403)


# ---------------------------------------------------------------------------
# BusinessUnit API Tests
# ---------------------------------------------------------------------------

class BusinessUnitAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")
        self.client.force_authenticate(user=self.owner)

    def test_create_business_unit(self):
        resp = self.client.post(
            "/api/enterprise/business-units/",
            {
                "name": "Engineering",
                "code": "ENG",
                "company_id": self.company.id,
            },
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["name"], "Engineering")
        self.assertEqual(resp.data["code"], "ENG")

    def test_list_business_units(self):
        make_business_unit(self.company, name="Sales")
        make_business_unit(self.company, name="HR")
        resp = self.client.get(
            f"/api/enterprise/business-units/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 2)

    def test_update_business_unit(self):
        bu = make_business_unit(self.company)
        resp = self.client.patch(
            f"/api/enterprise/business-units/{bu.id}/",
            {"name": "Updated BU"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["name"], "Updated BU")

    def test_delete_business_unit(self):
        bu = make_business_unit(self.company)
        resp = self.client.delete(f"/api/enterprise/business-units/{bu.id}/")
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(BusinessUnit.objects.filter(id=bu.id).exists())

    def test_employee_cannot_create_bu(self):
        emp = make_user()
        make_membership(self.company, emp, role="employee")
        self.client.force_authenticate(user=emp)
        resp = self.client.post(
            "/api/enterprise/business-units/",
            {"name": "Dept X", "code": "DX", "company_id": self.company.id},
        )
        self.assertEqual(resp.status_code, 403)


# ---------------------------------------------------------------------------
# Team API Tests
# ---------------------------------------------------------------------------

class TeamAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")
        self.client.force_authenticate(user=self.owner)

    def test_create_team(self):
        resp = self.client.post(
            "/api/enterprise/teams/",
            {"name": "Alpha Team", "company_id": self.company.id},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["name"], "Alpha Team")

    def test_list_teams(self):
        make_team(self.company, name="Team A")
        make_team(self.company, name="Team B")
        resp = self.client.get(f"/api/enterprise/teams/?company_id={self.company.id}")
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 2)

    def test_add_member_to_team(self):
        team = make_team(self.company)
        emp = make_user()
        make_membership(self.company, emp, role="employee")
        resp = self.client.post(
            f"/api/enterprise/teams/{team.id}/add-member/",
            {"user_id": emp.id, "role": "member"},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(TeamMembership.objects.filter(team=team, user=emp).exists())

    def test_add_member_not_in_company_fails(self):
        team = make_team(self.company)
        outsider = make_user()
        resp = self.client.post(
            f"/api/enterprise/teams/{team.id}/add-member/",
            {"user_id": outsider.id, "role": "member"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_remove_member_from_team(self):
        team = make_team(self.company)
        emp = make_user()
        make_membership(self.company, emp, role="employee")
        TeamMembership.objects.create(team=team, user=emp, role="member")
        resp = self.client.post(
            f"/api/enterprise/teams/{team.id}/remove-member/",
            {"user_id": emp.id},
        )
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(TeamMembership.objects.filter(team=team, user=emp).exists())

    def test_list_team_members(self):
        team = make_team(self.company)
        for _ in range(3):
            emp = make_user()
            make_membership(self.company, emp, role="employee")
            TeamMembership.objects.create(team=team, user=emp, role="member")
        resp = self.client.get(f"/api/enterprise/teams/{team.id}/members/")
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 3)

    def test_filter_teams_by_business_unit(self):
        bu = make_business_unit(self.company)
        t1 = make_team(self.company, name="BU Team")
        t1.business_unit = bu
        t1.save()
        make_team(self.company, name="Other Team")
        resp = self.client.get(
            f"/api/enterprise/teams/?company_id={self.company.id}&business_unit_id={bu.id}"
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "BU Team")


# ---------------------------------------------------------------------------
# LearningModule New Fields Tests
# ---------------------------------------------------------------------------

class LearningModuleFieldsTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")
        self.client.force_authenticate(user=self.owner)
        self.path = make_learning_path(self.company, self.owner)

    def test_module_has_process_type(self):
        module = make_module(self.path, process_type="tutorial")
        self.assertEqual(module.process_type, "tutorial")

    def test_module_has_difficulty(self):
        module = make_module(self.path, difficulty="hard")
        self.assertEqual(module.difficulty, "hard")

    def test_module_has_minimum_passing_score(self):
        module = make_module(self.path, minimum_passing_score=80)
        self.assertEqual(module.minimum_passing_score, 80)

    def test_module_defaults(self):
        module = LearningModule.objects.create(
            learning_path=self.path,
            name="Default Module",
        )
        self.assertEqual(module.process_type, "course")
        self.assertEqual(module.difficulty, "medium")
        self.assertEqual(module.minimum_passing_score, 70)

    def test_create_module_via_api_with_new_fields(self):
        resp = self.client.post(
            "/api/enterprise/learning-modules/",
            {
                "learning_path": self.path.id,
                "name": "API Module",
                "process_type": "tutorial",
                "difficulty": "easy",
                "minimum_passing_score": 60,
            },
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["process_type"], "tutorial")
        self.assertEqual(resp.data["difficulty"], "easy")
        self.assertEqual(resp.data["minimum_passing_score"], 60)

    def test_module_serializer_includes_new_fields(self):
        module = make_module(self.path, process_type="course", difficulty="hard")
        resp = self.client.get(f"/api/enterprise/learning-modules/{module.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("process_type", resp.data)
        self.assertIn("difficulty", resp.data)
        self.assertIn("minimum_passing_score", resp.data)


# ---------------------------------------------------------------------------
# LearningPath final_battery Tests
# ---------------------------------------------------------------------------

class LearningPathFinalBatteryTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")
        self.client.force_authenticate(user=self.owner)

    def test_learning_path_has_final_battery_field(self):
        path = make_learning_path(self.company, self.owner)
        self.assertIsNone(path.final_battery)

    def test_path_serializer_includes_final_battery(self):
        path = make_learning_path(self.company, self.owner)
        resp = self.client.get(
            f"/api/enterprise/learning-paths/{path.id}/",
            {"company_id": self.company.id},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("final_battery", resp.data)

    def test_path_list_includes_final_battery(self):
        make_learning_path(self.company, self.owner)
        resp = self.client.get(
            "/api/enterprise/learning-paths/",
            {"company_id": self.company.id},
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertGreater(len(results), 0)
        self.assertIn("final_battery", results[0])


# ---------------------------------------------------------------------------
# LearningModuleItem ViewSet Tests
# ---------------------------------------------------------------------------

class LearningModuleItemAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner = make_user()
        self.company = make_company(self.owner)
        make_membership(self.company, self.owner, role="owner")
        self.client.force_authenticate(user=self.owner)
        self.path = make_learning_path(self.company, self.owner)
        self.module = make_module(self.path)

    def _make_project(self):
        from api.models import Project
        return Project.objects.create(title="Test Project", owner=self.owner)

    def _make_document(self):
        from api.models import Document
        uid = _next_uid()
        project = self._make_project()
        return Document.objects.create(
            project=project,
            filename=f"test_{uid}.pdf",
            type="pdf",
            size=1000,
            hash=f"hash_{uid}",
            uploaded_by=self.owner,
        )

    def test_create_document_item(self):
        doc = self._make_document()
        resp = self.client.post("/api/enterprise/learning-module-items/", {
            "module": self.module.id,
            "item_type": "document",
            "order": 1,
            "document": doc.id,
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["item_type"], "document")
        self.assertEqual(resp.data["document"], doc.id)

    def test_list_items_filter_by_module(self):
        doc1 = self._make_document()
        doc2 = self._make_document()
        LearningModuleItem.objects.create(
            module=self.module, item_type="document", order=1, document=doc1
        )
        LearningModuleItem.objects.create(
            module=self.module, item_type="document", order=2, document=doc2
        )
        resp = self.client.get(
            f"/api/enterprise/learning-module-items/?module_id={self.module.id}"
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 2)

    def test_list_items_filter_by_learning_path(self):
        doc = self._make_document()
        LearningModuleItem.objects.create(
            module=self.module, item_type="document", order=1, document=doc
        )
        resp = self.client.get(
            f"/api/enterprise/learning-module-items/?learning_path_id={self.path.id}"
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 1)

    def test_delete_item(self):
        doc = self._make_document()
        item = LearningModuleItem.objects.create(
            module=self.module, item_type="document", order=1, document=doc
        )
        resp = self.client.delete(f"/api/enterprise/learning-module-items/{item.id}/")
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(LearningModuleItem.objects.filter(id=item.id).exists())

    def test_create_item_requires_exactly_one_fk(self):
        # POST without any FK (topic/battery/deck/document) should fail validation
        resp = self.client.post("/api/enterprise/learning-module-items/", {
            "module": self.module.id,
            "item_type": "document",
            "order": 1,
            # no document / topic / battery / deck → should fail
        })
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# Tenant Isolation Tests
# ---------------------------------------------------------------------------

class Phase8TenantIsolationTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.owner_a = make_user()
        self.owner_b = make_user()
        self.company_a = make_company(self.owner_a)
        self.company_b = make_company(self.owner_b)
        make_membership(self.company_a, self.owner_a, role="owner")
        make_membership(self.company_b, self.owner_b, role="owner")

    def test_cannot_list_other_company_members(self):
        self.client.force_authenticate(user=self.owner_a)
        resp = self.client.get(
            f"/api/enterprise/companies/{self.company_b.id}/members/"
        )
        self.assertEqual(resp.status_code, 403)

    def test_cannot_add_user_to_other_company(self):
        self.client.force_authenticate(user=self.owner_a)
        resp = self.client.post(
            f"/api/enterprise/companies/{self.company_b.id}/add-user/",
            {"email": "hacker@evil.com", "role": "owner", "employee_stage": "active_employee"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_cannot_see_other_company_business_units(self):
        make_business_unit(self.company_b, name="Secret BU")
        self.client.force_authenticate(user=self.owner_a)
        resp = self.client.get(
            f"/api/enterprise/business-units/?company_id={self.company_b.id}"
        )
        # Returns empty — not 403 — because the user doesn't have access to the company
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 0)

    def test_cannot_see_other_company_teams(self):
        make_team(self.company_b, name="Secret Team")
        self.client.force_authenticate(user=self.owner_a)
        resp = self.client.get(
            f"/api/enterprise/teams/?company_id={self.company_b.id}"
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.data["results"] if "results" in resp.data else resp.data
        self.assertEqual(len(results), 0)

    def test_cannot_add_member_to_other_company_team(self):
        team = make_team(self.company_b)
        self.client.force_authenticate(user=self.owner_a)
        intruder = make_user()
        resp = self.client.post(
            f"/api/enterprise/teams/{team.id}/add-member/",
            {"user_id": intruder.id, "role": "member"},
        )
        # team is in company_b — owner_a has no access
        self.assertIn(resp.status_code, [403, 404])

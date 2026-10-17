"""F-02: assigning with a due date must not 500, must not duplicate, and emails can't break it."""
import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APITestCase

from api.enterprise.services.assignment_dedup import consolidate, revert
from api.enterprise_compliance_models import ComplianceAssignment, ComplianceProgram
from api.enterprise_learning_models import LearningModuleProgress, LearningPath, LearningPathAssignment
from api.enterprise_models import Company, CompanyMembership, Team, TeamMembership
from api.models import Permission, Resource, Role

User = get_user_model()


def grant(role_name, resource_key, action="manage"):
    resource, _ = Resource.objects.get_or_create(key=resource_key, defaults={"name": resource_key})
    permission, _ = Permission.objects.get_or_create(resource=resource, action=action)
    role, _ = Role.objects.get_or_create(name=f"enterprise.{role_name}")
    role.permissions.add(permission)


class AssignmentApiTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_user("f02_admin", "admin@f02.test", "Pass123!")
        self.employee = User.objects.create_user("f02_emp", "emp@f02.test", "Pass123!")
        self.company = Company.objects.create(name="F02 Co", slug="f02-co", owner=self.admin)
        CompanyMembership.objects.create(user=self.admin, company=self.company, role="admin", status="active")
        CompanyMembership.objects.create(user=self.employee, company=self.company, role="employee", status="active")
        grant("admin", "enterprise.ent-manage-assignments")
        self.path = LearningPath.objects.create(company=self.company, name="Onboarding", status="published", created_by=self.admin)
        self.client.force_authenticate(self.admin)
        self.due = (timezone.localdate() + datetime.timedelta(days=10)).isoformat()

    def assign(self, **body):
        return self.client.post(
            f"/api/enterprise/learning-paths/{self.path.id}/assign-to-user/?company_id={self.company.id}",
            {"user_id": self.employee.id, **body}, format="json",
        )

    def test_assign_with_due_date_returns_201_and_same_date(self):
        response = self.assign(due_date=self.due)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(str(response.data["due_date"]).startswith(self.due))
        self.assertEqual(LearningPathAssignment.objects.filter(user=self.employee, learning_path=self.path).count(), 1)

    def test_repeating_the_assignment_returns_409_without_duplicate(self):
        self.assertEqual(self.assign(due_date=self.due).status_code, 201)
        response = self.assign(due_date=self.due)
        self.assertEqual(response.status_code, 409)
        self.assertIn("already assigned", response.data["detail"])
        self.assertEqual(LearningPathAssignment.objects.filter(user=self.employee, learning_path=self.path).count(), 1)

    def test_completed_assignment_can_be_assigned_again(self):
        LearningPathAssignment.objects.create(company=self.company, learning_path=self.path, user=self.employee, status="completed")
        self.assertEqual(self.assign().status_code, 201)

    def test_past_or_malformed_due_date_is_400_and_nothing_saved(self):
        past = (timezone.localdate() - datetime.timedelta(days=1)).isoformat()
        for value in (past, "2026-13-40", "2026-10-30T00:00:00Z"):
            response = self.assign(due_date=value)
            self.assertEqual(response.status_code, 400, value)
            self.assertIn("due_date", response.data)
        self.assertFalse(LearningPathAssignment.objects.filter(user=self.employee).exists())

    def test_failing_notification_does_not_break_the_response(self):
        with patch(
            "api.enterprise.services.email_service.send_assignment_notification",
            side_effect=RuntimeError("smtp down"),
        ):
            with self.captureOnCommitCallbacks(execute=True):
                response = self.assign(due_date=self.due)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(LearningPathAssignment.objects.filter(user=self.employee, learning_path=self.path).exists())

    def test_assign_to_team_twice_returns_409(self):
        team = Team.objects.create(company=self.company, name="Ops")
        TeamMembership.objects.create(team=team, user=self.employee)
        url = f"/api/enterprise/learning-paths/{self.path.id}/assign-to-team/?company_id={self.company.id}"
        self.assertEqual(self.client.post(url, {"team_id": team.id}, format="json").status_code, 201)
        self.assertEqual(self.client.post(url, {"team_id": team.id}, format="json").status_code, 409)
        self.assertEqual(LearningPathAssignment.objects.filter(user=self.employee, learning_path=self.path).count(), 1)


class ComplianceAssignmentApiTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user("f02_cowner", "o@f02c.test", "Pass123!")
        self.employee = User.objects.create_user("f02_cemp", "e@f02c.test", "Pass123!")
        self.company = Company.objects.create(name="F02 C", slug="f02-c", owner=self.owner)
        CompanyMembership.objects.create(user=self.owner, company=self.company, role="owner", status="active")
        CompanyMembership.objects.create(user=self.employee, company=self.company, role="employee", status="active")
        self.program = ComplianceProgram.objects.create(company=self.company, name="Safety", code="SAF-1", created_by=self.owner, status="active")
        self.client.force_authenticate(self.owner)

    def test_duplicate_compliance_assignment_returns_409(self):
        url = f"/api/enterprise/compliance-programs/{self.program.id}/assign-to-user/?company_id={self.company.id}"
        due = (timezone.localdate() + datetime.timedelta(days=5)).isoformat()
        self.assertEqual(self.client.post(url, {"user_id": self.employee.id, "due_date": due}, format="json").status_code, 201)
        self.assertEqual(self.client.post(url, {"user_id": self.employee.id, "due_date": due}, format="json").status_code, 409)
        self.assertEqual(ComplianceAssignment.objects.filter(user=self.employee, program=self.program).count(), 1)

    def test_renewing_an_active_assignment_returns_409(self):
        active = ComplianceAssignment.objects.create(company=self.company, program=self.program, user=self.employee, status="pending")
        response = self.client.post(
            f"/api/enterprise/compliance-assignments/{active.id}/renew/?company_id={self.company.id}", {}, format="json",
        )
        self.assertEqual(response.status_code, 409)


class ConsolidateDuplicatesTests(TestCase):
    """Existing duplicates (created before the constraint) are superseded, not deleted, and reversible."""

    def setUp(self):
        # Simulate pre-migration data: drop the constraint inside this test's transaction.
        with connection.schema_editor() as editor:
            for constraint in LearningPathAssignment._meta.constraints:
                editor.remove_constraint(LearningPathAssignment, constraint)
        owner = User.objects.create_user("f02_dedup", "d@f02.test", "Pass123!")
        self.user = User.objects.create_user("f02_dedup_emp", "de@f02.test", "Pass123!")
        company = Company.objects.create(name="Dedup", slug="dedup", owner=owner)
        path = LearningPath.objects.create(company=company, name="P", created_by=owner)
        module = path.modules.create(name="M1", order=0) if hasattr(path, "modules") else None
        self.rows = [
            LearningPathAssignment.objects.create(company=company, learning_path=path, user=self.user, status="pending")
            for _ in range(3)
        ]
        # The newest one has progress: it must be the one kept.
        if module is not None:
            LearningModuleProgress.objects.create(assignment=self.rows[2], module=module, user=self.user, status="completed")

    def test_dry_run_changes_nothing(self):
        report = consolidate(LearningPathAssignment, LearningModuleProgress, ComplianceAssignment, apply=False)
        self.assertEqual(report["learning"]["rows"], 2)
        self.assertEqual(LearningPathAssignment.objects.filter(status="superseded").count(), 0)

    def test_apply_supersedes_keeps_one_and_is_idempotent_and_reversible(self):
        consolidate(LearningPathAssignment, LearningModuleProgress, ComplianceAssignment, apply=True)
        kept = LearningPathAssignment.objects.exclude(status="superseded")
        self.assertEqual(kept.count(), 1)
        self.assertEqual(kept.get().id, self.rows[2].id)
        self.assertEqual(LearningPathAssignment.objects.count(), 3)  # nothing deleted

        again = consolidate(LearningPathAssignment, LearningModuleProgress, ComplianceAssignment, apply=True)
        self.assertEqual(again["learning"]["changed"], 0)

        revert(LearningPathAssignment, ComplianceAssignment, apply=True)
        self.assertEqual(LearningPathAssignment.objects.filter(status="pending").count(), 3)

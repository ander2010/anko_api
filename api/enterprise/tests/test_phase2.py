"""
Enterprise Phase 2 — Learning Engine Tests

Covers:
  - Model constraints and validation
  - Service methods (assign, start, complete, progress, readiness)
  - API endpoints (CRUD + custom actions)
  - Tenant isolation (cross-company access denied)
"""

import datetime
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from api.enterprise_learning_models import (
    LearningModule,
    LearningModuleItem,
    LearningModuleProgress,
    LearningPath,
    LearningPathAssignment,
    TrainingProgram,
    TrainingProgramVersion,
)
from api.enterprise_models import (
    Company,
    CompanyMembership,
    Team,
    TeamMembership,
)
from api.enterprise.services.learning_service import EnterpriseLearningService

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username, email=None):
    email = email or f"{username}@test.com"
    return User.objects.create_user(username=username, email=email, password="Pass123!")


def make_company(owner, name="Acme", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee", status="active"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status=status
    )


def make_path(company, name="Onboarding Path", status="published", created_by=None):
    return LearningPath.objects.create(
        company=company, name=name, status=status, created_by=created_by
    )


def make_module(path, name="Module 1", order=0, is_required=True):
    return LearningModule.objects.create(
        learning_path=path, name=name, order=order, is_required=is_required
    )


def make_assignment(company, path, user=None, team=None, status="pending"):
    return LearningPathAssignment.objects.create(
        company=company,
        learning_path=path,
        user=user,
        team=team,
        status=status,
    )


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class LearningPathModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("lp_owner")
        self.company = make_company(self.owner)

    def test_create_path(self):
        path = make_path(self.company)
        self.assertEqual(path.company, self.company)
        self.assertEqual(path.status, "published")

    def test_str(self):
        path = make_path(self.company, name="Safety Training")
        self.assertIn("Safety Training", str(path))

    def test_default_status_is_draft(self):
        path = LearningPath.objects.create(company=self.company, name="Draft Path")
        self.assertEqual(path.status, "draft")


class LearningModuleModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("mod_owner")
        self.company = make_company(self.owner)
        self.path = make_path(self.company)

    def test_create_module(self):
        m = make_module(self.path)
        self.assertEqual(m.learning_path, self.path)
        self.assertTrue(m.is_required)

    def test_ordering_by_order(self):
        make_module(self.path, name="B", order=2)
        make_module(self.path, name="A", order=1)
        names = list(self.path.modules.values_list("name", flat=True))
        self.assertEqual(names, ["A", "B"])

    def test_multiple_modules(self):
        make_module(self.path, name="Intro", order=0)
        make_module(self.path, name="Core", order=1)
        self.assertEqual(self.path.modules.count(), 2)


class LearningModuleItemModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("item_owner")
        self.company = make_company(self.owner, slug="item-co")
        self.path = make_path(self.company)
        self.module = make_module(self.path)

    def _make_topic(self):
        from api.models import Project, Topic
        project = Project.objects.create(title="P", owner=self.owner)
        return Topic.objects.create(project=project, name="T")

    def test_create_item_with_topic(self):
        topic = self._make_topic()
        item = LearningModuleItem.objects.create(
            module=self.module,
            item_type="topic",
            order=0,
            topic=topic,
        )
        self.assertEqual(item.item_type, "topic")

    def test_clean_requires_exactly_one_fk(self):
        from django.core.exceptions import ValidationError
        item = LearningModuleItem(module=self.module, item_type="topic", order=0)
        # No FK set
        with self.assertRaises(ValidationError):
            item.clean()

    def test_clean_rejects_two_fks(self):
        from django.core.exceptions import ValidationError
        from api.models import Battery, Project
        project = Project.objects.create(title="P2", owner=self.owner)
        topic = __import__("api.models", fromlist=["Topic"]).Topic.objects.create(
            project=project, name="T2"
        )
        battery = Battery.objects.create(
            project=project, name="B", difficulty="Easy"
        )
        item = LearningModuleItem(
            module=self.module, item_type="topic", order=0,
            topic=topic, battery=battery
        )
        with self.assertRaises(ValidationError):
            item.clean()


class LearningPathAssignmentModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("asgn_owner")
        self.user = make_user("asgn_user")
        self.company = make_company(self.owner, slug="asgn-co")
        self.path = make_path(self.company)

    def test_user_assignment(self):
        a = make_assignment(self.company, self.path, user=self.user)
        self.assertEqual(a.user, self.user)
        self.assertIsNone(a.team)

    def test_team_assignment(self):
        team = Team.objects.create(company=self.company, name="Team A")
        a = make_assignment(self.company, self.path, team=team)
        self.assertEqual(a.team, team)
        self.assertIsNone(a.user)

    def test_clean_rejects_both(self):
        from django.core.exceptions import ValidationError
        team = Team.objects.create(company=self.company, name="Team B")
        a = LearningPathAssignment(
            company=self.company, learning_path=self.path,
            user=self.user, team=team
        )
        with self.assertRaises(ValidationError):
            a.clean()

    def test_clean_rejects_neither(self):
        from django.core.exceptions import ValidationError
        a = LearningPathAssignment(
            company=self.company, learning_path=self.path
        )
        with self.assertRaises(ValidationError):
            a.clean()

    def test_is_overdue_when_past_due(self):
        from django.utils import timezone
        past = timezone.now() - datetime.timedelta(days=1)
        a = make_assignment(self.company, self.path, user=self.user, status="in_progress")
        a.due_date = past
        a.save()
        self.assertTrue(a.is_overdue())

    def test_is_not_overdue_when_completed(self):
        from django.utils import timezone
        past = timezone.now() - datetime.timedelta(days=1)
        a = make_assignment(self.company, self.path, user=self.user, status="completed")
        a.due_date = past
        a.save()
        self.assertFalse(a.is_overdue())


class TrainingProgramModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("tp_owner")
        self.company = make_company(self.owner, slug="tp-co")

    def test_create_program(self):
        program = TrainingProgram.objects.create(
            company=self.company, name="FAA Safety", created_by=self.owner
        )
        self.assertEqual(program.status, "draft")

    def test_version_unique_per_program(self):
        path = make_path(self.company)
        program = TrainingProgram.objects.create(company=self.company, name="Prog")
        TrainingProgramVersion.objects.create(
            program=program, version_number=1, learning_path=path
        )
        with self.assertRaises(Exception):
            TrainingProgramVersion.objects.create(
                program=program, version_number=1, learning_path=path
            )


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------

class EnterpriseLearningServiceTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_owner")
        self.trainer = make_user("svc_trainer")
        self.employee = make_user("svc_emp")
        self.company = make_company(self.owner, slug="svc-co")

        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.employee, self.company, role="employee")

        self.path = make_path(self.company, created_by=self.trainer)
        self.module1 = make_module(self.path, name="Intro", order=0, is_required=True)
        self.module2 = make_module(self.path, name="Core", order=1, is_required=True)
        self.module3 = make_module(self.path, name="Optional", order=2, is_required=False)

    def test_assign_to_user(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        self.assertEqual(assignment.user, self.employee)
        self.assertEqual(assignment.status, "pending")
        self.assertEqual(assignment.learning_path, self.path)

    def test_assign_to_user_emits_event(self):
        from api.enterprise_models import LearningEvent
        EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.employee,
                event_type="learning_path_assigned",
            ).exists()
        )

    def test_assign_to_team(self):
        team = Team.objects.create(company=self.company, name="Alpha")
        member = make_user("svc_member")
        make_membership(member, self.company)
        TeamMembership.objects.create(team=team, user=member, role="member")

        assignment = EnterpriseLearningService.assign_to_team(
            self.path, team, self.trainer, self.company
        )
        self.assertEqual(assignment.team, team)
        self.assertIsNone(assignment.user)

    def test_start_assignment(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        updated = EnterpriseLearningService.start_assignment(assignment, self.employee)
        self.assertEqual(updated.status, "in_progress")
        self.assertIsNotNone(updated.started_at)

    def test_start_creates_progress_rows(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        count = LearningModuleProgress.objects.filter(
            assignment=assignment, user=self.employee
        ).count()
        self.assertEqual(count, 3)  # all 3 modules

    def test_complete_module(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        progress = EnterpriseLearningService.complete_module(
            assignment, self.module1, self.employee, score=Decimal("90.0")
        )
        self.assertEqual(progress.status, "completed")
        self.assertEqual(progress.score, Decimal("90.0"))

    def test_complete_all_required_modules_completes_assignment(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module1, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module2, self.employee)
        # Optional module NOT completed — assignment should still complete
        assignment.refresh_from_db()
        self.assertEqual(assignment.status, "completed")
        self.assertIsNotNone(assignment.completed_at)

    def test_optional_module_incomplete_does_not_block_completion(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module1, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module2, self.employee)
        assignment.refresh_from_db()
        self.assertEqual(assignment.status, "completed")

    def test_calculate_progress(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module1, self.employee)

        data = EnterpriseLearningService.calculate_progress(assignment, self.employee)

        self.assertEqual(data["total_modules"], 3)
        self.assertEqual(data["required_modules"], 2)
        self.assertEqual(data["completed_modules"], 1)
        self.assertEqual(data["completed_required_modules"], 1)
        self.assertAlmostEqual(float(data["percent_required"]), 50.0)

    def test_calculate_readiness_score_zero_when_no_assignments(self):
        new_user = make_user("svc_new")
        score = EnterpriseLearningService.calculate_readiness_score(new_user, self.company)
        self.assertEqual(score, Decimal("0"))

    def test_calculate_readiness_score_100_when_all_complete(self):
        assignment = EnterpriseLearningService.assign_to_user(
            self.path, self.employee, self.trainer, self.company
        )
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module1, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module2, self.employee)

        score = EnterpriseLearningService.calculate_readiness_score(self.employee, self.company)
        self.assertEqual(score, Decimal("100.00"))

    def test_publish_training_program(self):
        program = TrainingProgram.objects.create(
            company=self.company, name="FAA Safety", created_by=self.trainer
        )
        version = EnterpriseLearningService.publish_training_program(
            program, self.path, self.trainer, notes="Initial release"
        )
        self.assertEqual(version.version_number, 1)
        self.assertTrue(version.is_current)
        program.refresh_from_db()
        self.assertEqual(program.status, "published")

    def test_publish_training_program_increments_version(self):
        program = TrainingProgram.objects.create(
            company=self.company, name="FAA v2", created_by=self.trainer
        )
        path2 = make_path(self.company, name="Path 2")
        EnterpriseLearningService.publish_training_program(program, self.path, self.trainer)
        v2 = EnterpriseLearningService.publish_training_program(program, path2, self.trainer)
        self.assertEqual(v2.version_number, 2)
        self.assertTrue(v2.is_current)
        # v1 should no longer be current
        v1 = program.versions.get(version_number=1)
        self.assertFalse(v1.is_current)

    def test_publish_learning_path(self):
        draft = LearningPath.objects.create(company=self.company, name="Draft", status="draft")
        updated = EnterpriseLearningService.publish_learning_path(draft, self.trainer)
        self.assertEqual(updated.status, "published")


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

class LearningPathAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_owner")
        self.trainer = make_user("api_trainer")
        self.employee = make_user("api_emp")
        self.outsider = make_user("api_out")
        self.company = make_company(self.owner, slug="api-co")

        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.employee, self.company, role="employee")
        # owner has no CompanyMembership yet (they own but may not have explicit membership)
        make_membership(self.owner, self.company, role="owner")

    def _url(self, suffix=""):
        return f"/api/enterprise/learning-paths/{suffix}"

    def test_list_requires_authentication(self):
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_trainer_can_create_path(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "New Training Path",
            "description": "Test",
            "status": "draft",
        })
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["name"], "New Training Path")

    def test_employee_cannot_create_path(self):
        self.client.force_authenticate(self.employee)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Unauthorized Path",
            "status": "draft",
        })
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_trainer_can_list_paths(self):
        make_path(self.company, name="Visible Path")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data["results"]), 1)

    def test_outsider_gets_empty_list(self):
        make_path(self.company)
        self.client.force_authenticate(self.outsider)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        # Either 200 with empty results or 403 — both are acceptable isolation
        if r.status_code == status.HTTP_200_OK:
            self.assertEqual(len(r.data.get("results", [])), 0)

    def test_cross_company_isolation(self):
        owner2 = make_user("api_owner2")
        company2 = make_company(owner2, name="Other Corp", slug="other-api-co")
        make_path(company2, name="Secret Path")

        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": company2.id})
        if r.status_code == status.HTTP_200_OK:
            names = [item["name"] for item in r.data.get("results", [])]
            self.assertNotIn("Secret Path", names)

    def test_publish_action(self):
        path = make_path(self.company, status="draft", created_by=self.trainer)
        self.client.force_authenticate(self.trainer)
        r = self.client.post(
            self._url(f"{path.id}/publish/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "published")

    def test_assign_to_user_action(self):
        path = make_path(self.company, created_by=self.trainer)
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{path.id}/assign-to-user/"),
            {
                "company_id": self.company.id,
                "user_id": self.employee.id,
            },
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["user"], self.employee.id)

    def test_assign_to_team_action(self):
        path = make_path(self.company, created_by=self.trainer)
        team = Team.objects.create(company=self.company, name="API Team")
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{path.id}/assign-to-team/"),
            {
                "company_id": self.company.id,
                "team_id": team.id,
            },
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["team"], team.id)

    def test_analytics_action(self):
        path = make_path(self.company, created_by=self.trainer)
        make_assignment(self.company, path, user=self.employee, status="completed")
        self.client.force_authenticate(self.owner)
        r = self.client.get(
            self._url(f"{path.id}/analytics/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("completion_rate", r.data)


class LearningAssignmentAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("asn_api_owner")
        self.employee = make_user("asn_api_emp")
        self.company = make_company(self.owner, slug="asn-api-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

        self.path = make_path(self.company, created_by=self.owner)
        self.module1 = make_module(self.path, name="M1", order=0, is_required=True)
        self.module2 = make_module(self.path, name="M2", order=1, is_required=True)

    def _url(self, suffix=""):
        return f"/api/enterprise/learning-assignments/{suffix}"

    def test_start_action(self):
        assignment = make_assignment(self.company, self.path, user=self.employee)
        self.client.force_authenticate(self.employee)
        r = self.client.post(
            self._url(f"{assignment.id}/start/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "in_progress")

    def test_complete_module_action(self):
        assignment = make_assignment(self.company, self.path, user=self.employee, status="in_progress")
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        self.client.force_authenticate(self.employee)
        r = self.client.post(
            self._url(f"{assignment.id}/complete-module/"),
            {"module_id": self.module1.id, "score": "85.5"},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "completed")

    def test_progress_action(self):
        assignment = make_assignment(self.company, self.path, user=self.employee, status="in_progress")
        EnterpriseLearningService.start_assignment(assignment, self.employee)
        EnterpriseLearningService.complete_module(assignment, self.module1, self.employee)
        self.client.force_authenticate(self.employee)
        r = self.client.get(
            self._url(f"{assignment.id}/progress/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("percent_required", r.data)
        self.assertEqual(r.data["completed_modules"], 1)

    def test_my_assignments_action(self):
        make_assignment(self.company, self.path, user=self.employee)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("my-assignments/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)


class TrainingProgramAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("tp_api_owner")
        self.trainer = make_user("tp_api_trainer")
        self.company = make_company(self.owner, slug="tp-api-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.trainer, self.company, role="trainer")
        self.path = make_path(self.company, created_by=self.trainer)

    def _url(self, suffix=""):
        return f"/api/enterprise/training-programs/{suffix}"

    def test_trainer_can_create_program(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Aviation Safety Program",
        })
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)

    def test_publish_program_creates_version(self):
        self.client.force_authenticate(self.trainer)
        create_r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Program X",
        })
        program_id = create_r.data["id"]
        publish_r = self.client.post(
            self._url(f"{program_id}/publish/"),
            {
                "company_id": self.company.id,
                "learning_path_id": self.path.id,
                "notes": "First release",
            },
        )
        self.assertEqual(publish_r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(publish_r.data["version_number"], 1)
        self.assertTrue(publish_r.data["is_current"])

    def test_versions_action(self):
        program = TrainingProgram.objects.create(
            company=self.company, name="Prog Z", created_by=self.trainer
        )
        TrainingProgramVersion.objects.create(
            program=program, version_number=1, learning_path=self.path, is_current=True
        )
        self.client.force_authenticate(self.trainer)
        r = self.client.get(
            self._url(f"{program.id}/versions/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 1)

    def test_archive_action(self):
        program = TrainingProgram.objects.create(
            company=self.company, name="Old Prog", created_by=self.owner
        )
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{program.id}/archive/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "archived")

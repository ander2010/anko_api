"""F-10: publishing a Training Program version."""
from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise_learning_models import LearningPath, TrainingProgram, TrainingProgramVersion
from api.enterprise_models import Company, CompanyMembership
from api.models import User


class PublishVersionTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("f10", "f10@test.com", "Pass123!")
        cls.company = Company.objects.create(name="F10", slug="f10", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        other_owner = User.objects.create_user("f10b", "f10b@test.com", "Pass123!")
        cls.other = Company.objects.create(name="Other", slug="f10-other", owner=other_owner)

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.program = TrainingProgram.objects.create(company=self.company, name="QA-TEST Programa", created_by=self.owner)
        self.path = LearningPath.objects.create(company=self.company, name="QA-TEST Ruta", status="published", created_by=self.owner)
        self.url = f"/api/enterprise/training-programs/{self.program.id}/publish/?company_id={self.company.id}"

    def publish(self, **body):
        return self.client.post(self.url, body, format="json")

    def test_two_versions_and_current_flag(self):
        self.assertEqual(self.publish(learning_path_id=self.path.id, notes="v1").status_code, 201)
        second = self.publish(learning_path_id=self.path.id, notes="v2")
        self.assertEqual(second.status_code, 201, second.content)
        self.assertEqual(second.data["version_number"], 2)
        current = TrainingProgramVersion.objects.filter(program=self.program, is_current=True)
        self.assertEqual([v.version_number for v in current], [2])

        listed = self.client.get(f"/api/enterprise/training-programs/?company_id={self.company.id}").data
        item = next(p for p in (listed.get("results", listed) if isinstance(listed, dict) else listed) if p["id"] == self.program.id)
        self.assertEqual((item["version_count"], item["current_version_number"]), (2, 2))

        history = self.client.get(f"/api/enterprise/training-programs/{self.program.id}/versions/?company_id={self.company.id}")
        self.assertEqual(history.status_code, 200)
        self.assertEqual({v["notes"] for v in history.data}, {"v1", "v2"})
        self.assertEqual({v["created_by_username"] for v in history.data}, {"f10"})

    def test_validation_errors_name_the_field(self):
        missing = self.publish(notes="x")
        self.assertEqual(missing.status_code, 400)
        self.assertIn("learning_path_id", missing.data)

        draft = LearningPath.objects.create(company=self.company, name="Draft", status="draft", created_by=self.owner)
        self.assertIn("published", str(self.publish(learning_path_id=draft.id).data["learning_path_id"]))

        foreign = LearningPath.objects.create(company=self.other, name="Foreign", status="published")
        r = self.publish(learning_path_id=foreign.id)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(TrainingProgramVersion.objects.filter(program=self.program).exists())

    def test_other_company_cannot_publish(self):
        intruder = User.objects.create_user("f10x", "x@f10.test", "Pass123!")
        CompanyMembership.objects.create(user=intruder, company=self.other, role="owner", status="active")
        self.client.force_authenticate(intruder)
        r = self.client.post(f"/api/enterprise/training-programs/{self.program.id}/publish/?company_id={self.other.id}",
                             {"learning_path_id": self.path.id}, format="json")
        self.assertIn(r.status_code, (403, 404))

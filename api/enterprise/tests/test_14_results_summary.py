"""14: one summary for the process counters/banner/completion, and the best attempt per battery."""
import datetime
from decimal import Decimal

from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_certification_models import Certification
from api.enterprise_models import Company, CompanyMembership
from api.models import Battery, BatteryAttempt, BatteryQuestion, BatterySourceTagGroup, User


class ResultsSummaryTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("d13", "d13@test.com", "Pass123!")
        cls.employee = User.objects.create_user("d13e", "d13e@test.com", "Pass123!")
        cls.company = Company.objects.create(name="D13", slug="d13", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        CompanyMembership.objects.create(user=cls.employee, company=cls.company, role="employee", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.q = f"?company_id={self.company.id}"

    def test_14_summary_and_best_attempt(self):
        ks, topic, _, _ = make_process_with_generated_topic(self.company, self.owner)
        ks.minimum_passing_score = 80
        ks.save(update_fields=["minimum_passing_score"])
        self.client.post(f"/api/enterprise/knowledge-sources/{ks.id}/topics/{topic.id}/decks/{self.q}",
                         {"title": "D", "flashcards": [{"front": "a", "back": "b"}, {"front": "c", "back": "d"}]}, format="json")
        batteries = []
        for name in ("B1", "B2"):
            b = Battery.objects.create(project=None, name=name, status="Ready", difficulty="Medium")
            BatterySourceTagGroup.objects.create(battery=b, tag_group=topic)
            BatteryQuestion.objects.create(battery=b, question="Q", type="singleChoice", order=0, points=1)
            batteries.append(b)
        now = timezone.now()
        BatteryAttempt.objects.create(battery=batteries[0], user=self.owner, status="finished", percent=Decimal("20"), finished_at=now)
        BatteryAttempt.objects.create(battery=batteries[0], user=self.owner, status="in_progress", percent=Decimal("0"))  # re-opened
        BatteryAttempt.objects.create(battery=batteries[1], user=self.owner, status="finished", percent=Decimal("90"), finished_at=now)
        res = self.client.get(f"/api/enterprise/knowledge-sources/{ks.id}/results/{self.q}").data
        b1 = next(b for b in res["batteries"] if b["name"] == "B1")
        self.assertEqual(float(b1["best_attempt"]["percent"]), 20.0)
        self.assertEqual(b1["last_attempt"]["status"], "in_progress")  # unchanged field
        self.assertEqual(res["summary"], {
            "topics": 1, "decks": 1, "batteries": 2, "questions": 2, "cards": 2,
            "passing_score": 80, "completed_batteries": 1, "completion_percent": 55,
        })

"""Regression: '+ Add deck -> Generate with AI' in a process topic, for a company owner who is not platform staff."""
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_models import Company, CompanyMembership
from api.models import BatterySourceTagGroup, DeckSourceTagGroup, TagGroup, User


class AIDeckInProcessTopicTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("aid", "aid@test.com", "Pass123!")  # NOT is_staff
        cls.company = Company.objects.create(name="AID", slug="aid", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        cls.employee = User.objects.create_user("aide", "aide@test.com", "Pass123!")
        CompanyMembership.objects.create(user=cls.employee, company=cls.company, role="employee", status="active")
        cls.stranger = User.objects.create_user("aidx", "aidx@test.com", "Pass123!")
        other = Company.objects.create(name="AIDX", slug="aidx", owner=cls.stranger)
        CompanyMembership.objects.create(user=cls.stranger, company=other, role="owner", status="active")

    def setUp(self):
        self.ks, self.topic, self.doc, self.section = make_process_with_generated_topic(self.company, self.owner)
        q = f"?company_id={self.company.id}"
        self.client.force_authenticate(self.owner)
        self.manual_topic_id = int(self.client.post(f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/{q}",
                                                    {"title": "Manual"}, format="json").data["id"])

    def generate(self, kind, topic_id):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"job_id": f"job-{kind}", "status": "queued"}
        body = {"sections": [self.section.id], "tag_group_ids": [topic_id], "quantity": 3}
        body.update({"title": "AI deck"} if kind == "decks" else {"name": "AI battery"})
        with patch("api.views.post_with_retry", return_value=fake), patch("api.views._post_with_logging", return_value=fake), \
             patch("requests.post", return_value=fake):
            return self.client.post(f"/api/{kind}/start-generate/", body, format="json")

    def test_owner_and_trainer_generate_ai_deck_and_battery_in_generated_and_manual_topics(self):
        # One generation per user: the personal plan allows 1 flashcard job per month (PlanGuard).
        trainer = User.objects.create_user("aidt", "aidt@test.com", "Pass123!")
        CompanyMembership.objects.create(user=trainer, company=self.company, role="trainer", status="active")
        for user, topic_id in ((self.owner, self.topic.id), (trainer, self.manual_topic_id)):
            self.client.force_authenticate(user)
            deck = self.generate("decks", topic_id)
            self.assertIn(deck.status_code, (200, 201, 202), deck.content)
            self.assertTrue(DeckSourceTagGroup.objects.filter(tag_group_id=topic_id).exists())
            battery = self.generate("batteries", topic_id)
            self.assertIn(battery.status_code, (200, 201, 202), battery.content)
            self.assertTrue(BatterySourceTagGroup.objects.filter(tag_group_id=topic_id).exists())

    def test_other_company_and_employee_cannot_attach_to_the_topic(self):
        for user in (self.stranger, self.employee):
            self.client.force_authenticate(user)
            for kind in ("decks", "batteries"):
                with self.subTest(user=user.username, kind=kind):
                    self.assertIn(self.generate(kind, self.topic.id).status_code, (403, 404))

    def test_other_company_cannot_generate_from_these_sections(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"job_id": "job-x", "status": "queued"}
        self.client.force_authenticate(self.stranger)
        with patch("api.views.post_with_retry", return_value=fake), patch("api.views._post_with_logging", return_value=fake), \
             patch("requests.post", return_value=fake):
            for kind, extra in (("batteries", {"name": "x"}), ("decks", {"title": "x"})):
                r = self.client.post(f"/api/{kind}/start-generate/", {"sections": [self.section.id], "quantity": 2, **extra}, format="json")
                with self.subTest(kind=kind):
                    self.assertIn(r.status_code, (403, 404), r.content)

    def test_unrelated_tag_group_still_404(self):
        loose = TagGroup.objects.create(name="loose")
        self.assertEqual(self.generate("decks", loose.id).status_code, 404)

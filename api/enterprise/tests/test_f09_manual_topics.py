"""F-09: topics created by hand inside a process ("+ Add topic")."""
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_document_intelligence_models import KnowledgeSource, KnowledgeSourceTopic
from api.enterprise_models import Company, CompanyMembership
from api.models import BatterySourceTagGroup, User


class ManualTopicTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("f09", "f09@test.com", "Pass123!")
        cls.company = Company.objects.create(name="F09", slug="f09", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.ks, self.generated, _, self.section = make_process_with_generated_topic(self.company, self.owner)
        self.q = f"?company_id={self.company.id}"
        self.base = f"/api/enterprise/knowledge-sources/{self.ks.id}"

    def add_topic(self, ks=None, **body):
        payload = {"title": "QA-TEST Tópico manual"}
        payload.update(body)
        return self.client.post(f"/api/enterprise/knowledge-sources/{(ks or self.ks).id}/topics/{self.q}", payload, format="json")

    def results(self, ks=None):
        return self.client.get(f"/api/enterprise/knowledge-sources/{(ks or self.ks).id}/results/{self.q}").data

    def test_create_topic_appears_in_results_after_generated_ones(self):
        r = self.add_topic(description="Hand-made", tags=["helmets", " Helmets ", "boots", ""])
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.data["title"], "QA-TEST Tópico manual")
        self.assertEqual(r.data["tags"], ["helmets", "boots"])
        self.assertTrue(r.data["manual"])
        topics = self.results()["topics"]
        self.assertEqual([t["id"] for t in topics], [str(self.generated.id), r.data["id"]])
        self.assertEqual(topics[0]["tags"], ["safety", "helmets"])  # generated topic unchanged

    def test_order_is_next_available_and_names_are_unique_case_insensitive(self):
        self.add_topic(title="Alpha")
        self.add_topic(title="Beta")
        self.assertEqual(list(KnowledgeSourceTopic.objects.filter(knowledge_source=self.ks).values_list("order", flat=True)), [1, 2])
        dup = self.add_topic(title="  alpha ")
        self.assertEqual(dup.status_code, 400)
        self.assertIn("title", dup.data)
        self.assertEqual(self.add_topic(title="topic 1").status_code, 400)  # clashes with the generated topic
        self.assertEqual(self.add_topic(title="  ").status_code, 400)

    def test_works_in_process_without_documents_or_runs(self):
        empty = KnowledgeSource.objects.create(company=self.company, title="QA-TEST empty", created_by=self.owner)
        self.assertEqual(self.results(empty)["topics"], [])
        r = self.add_topic(ks=empty)
        self.assertEqual(r.status_code, 201, r.content)
        res = self.results(empty)
        self.assertIsNone(res["run"])
        self.assertEqual([t["id"] for t in res["topics"]], [r.data["id"]])

    def test_manual_deck_and_ai_battery_in_manual_topic(self):
        topic_id = self.add_topic().data["id"]
        deck = self.client.post(f"{self.base}/topics/{topic_id}/decks/{self.q}", {
            "title": "QA-TEST deck", "flashcards": [{"front": "Q", "back": "A"}],
        }, format="json")
        self.assertEqual(deck.status_code, 201, deck.content)

        # AI generation in a process topic still needs a platform admin (pre-existing rule).
        User.objects.filter(pk=self.owner.pk).update(is_staff=True)
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"job_id": "job-f09", "status": "queued"}
        with patch("api.views.post_with_retry", return_value=fake), patch("api.views._post_with_logging", return_value=fake), \
             patch("requests.post", return_value=fake):
            battery = self.client.post("/api/batteries/start-generate/", {
                "name": "QA-TEST battery", "sections": [self.section.id], "tag_group_ids": [int(topic_id)], "quantity": 2,
            }, format="json")
        self.assertIn(battery.status_code, (200, 201, 202), battery.content)
        self.assertTrue(BatterySourceTagGroup.objects.filter(tag_group_id=topic_id).exists())

        res = self.results()
        self.assertIn(deck.data["id"], [d["id"] for d in res["decks"] if str(d["tag_group_id"]) == topic_id])
        self.assertTrue(any(str(b["tag_group_id"]) == topic_id for b in res["batteries"]))

    def test_patch_topic(self):
        topic_id = self.add_topic(tags=["a"]).data["id"]
        self.add_topic(title="Other")
        url = f"{self.base}/topics/{topic_id}/{self.q}"
        r = self.client.patch(url, {"description": "New", "tags": ["b", "c"]}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual((r.data["title"], r.data["description"], r.data["tags"]), ("QA-TEST Tópico manual", "New", ["b", "c"]))
        self.assertEqual(self.client.patch(url, {"title": "other"}, format="json").status_code, 400)
        self.assertEqual(self.client.patch(f"{self.base}/topics/{self.generated.id}/{self.q}", {"title": "X"}, format="json").status_code, 404)

    def test_other_company_cannot_add_topics(self):
        stranger = User.objects.create_user("f09x", "f09x@test.com", "Pass123!")
        other = Company.objects.create(name="F09X", slug="f09x", owner=stranger)
        CompanyMembership.objects.create(user=stranger, company=other, role="owner", status="active")
        self.client.force_authenticate(stranger)
        r = self.client.post(f"{self.base}/topics/?company_id={other.id}", {"title": "X"}, format="json")
        self.assertEqual(r.status_code, 404)
        self.assertFalse(KnowledgeSourceTopic.objects.exists())

    def test_employee_cannot_add_topics(self):
        employee = User.objects.create_user("f09e", "f09e@test.com", "Pass123!")
        CompanyMembership.objects.create(user=employee, company=self.company, role="employee", status="active")
        self.client.force_authenticate(employee)
        self.assertEqual(self.add_topic().status_code, 403)

"""15: a learning-path module that wraps a process shows the process's real numbers."""
from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_models import Company, CompanyMembership
from api.models import Battery, BatterySourceTagGroup, User


class PathProcessRowTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("p15", "p15@test.com", "Pass123!")
        cls.company = Company.objects.create(name="P15", slug="p15", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    def test_module_row_uses_process_items_and_passing_score(self):
        self.client.force_authenticate(self.owner)
        q = f"?company_id={self.company.id}"
        ks, topic, _, _ = make_process_with_generated_topic(self.company, self.owner, title="QA-TEST-Claude")
        ks.minimum_passing_score = 80
        ks.save(update_fields=["minimum_passing_score"])
        self.client.post(f"/api/enterprise/knowledge-sources/{ks.id}/topics/{topic.id}/decks/{q}",
                         {"title": "D", "flashcards": [{"front": "a", "back": "b"}]}, format="json")
        battery = Battery.objects.create(project=None, name="B", status="Ready", difficulty="Medium")
        BatterySourceTagGroup.objects.create(battery=battery, tag_group=topic)
        path = self.client.post(f"/api/enterprise/learning-paths/{q}", {"name": "QA-TEST Ruta"}, format="json").data
        module = self.client.post(f"/api/enterprise/learning-modules/{q}", {
            "learning_path": path["id"], "name": "copy", "knowledge_source": ks.id}, format="json")
        self.assertEqual(module.status_code, 201, module.content)
        self.assertEqual((module.data["minimum_passing_score"], module.data["item_count"]), (80, 2))
        self.assertEqual(module.data["content_counts"], {"topics": 1, "decks": 1, "batteries": 1})
        detail = self.client.get(f"/api/enterprise/learning-paths/{path['id']}/{q}").data
        row = next(m for m in detail["modules"] if m["id"] == module.data["id"])
        self.assertEqual((row["name"], row["minimum_passing_score"], row["item_count"]), ("QA-TEST-Claude", 80, 2))

    def test_plain_module_keeps_its_own_numbers(self):
        self.client.force_authenticate(self.owner)
        q = f"?company_id={self.company.id}"
        path = self.client.post(f"/api/enterprise/learning-paths/{q}", {"name": "Plain"}, format="json").data
        module = self.client.post(f"/api/enterprise/learning-modules/{q}", {"learning_path": path["id"], "name": "M"}, format="json").data
        self.assertEqual((module["minimum_passing_score"], module["item_count"]), (70, 0))
        self.assertNotIn("content_counts", module)

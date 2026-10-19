"""Finding 16 (anko_api side): language, short titles and the user's exact names."""
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import SimpleTestCase
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_models import Company, CompanyMembership
from api.models import Battery, Document, Section, User
from api.services.generation_text import (
    detect_language, generation_metadata, keep_user_casing, language_for_documents, short_title,
)

ES = "Las gafas de seguridad son obligatorias al cortar flejes. Use el casco en la zona de carga y descarga del almacén."
EN = "Safety goggles are mandatory when cutting straps. Wear a helmet in the loading and unloading area of the warehouse."


class HelperTests(SimpleTestCase):
    def test_language_detection(self):
        self.assertEqual(detect_language(ES), "es")
        self.assertEqual(detect_language(EN), "en")
        self.assertEqual(detect_language("ok"), "")

    def test_metadata_tells_the_service_the_language(self):
        meta = generation_metadata("es")
        self.assertEqual((meta["language"], meta["language_code"]), ("spanish", "es"))
        self.assertIn("Write ALL output", meta["output_language_instruction"])
        self.assertEqual(generation_metadata(""), {})

    def test_short_titles(self):
        tags = ["certified personnel requirements", "designated meeting points", "designated reporting forms"]
        title = short_title(tags=tags, kind="flashcards", index=1)
        self.assertEqual(title, "Certified Personnel Requirements")
        long_title = short_title(tags=["a " * 80], kind="battery", index=2)
        self.assertLessEqual(len(long_title), 60)
        self.assertEqual(short_title(tags=[], kind="battery", index=3), "Assessment 3")
        self.assertEqual(short_title(tags=["EPP and PPE"], kind="group", index=1), "EPP And PPE")

    def test_keep_user_casing(self):
        self.assertEqual(keep_user_casing("QA-TEST Bateria VF", "Qa-test Bateria VF"), "QA-TEST Bateria VF")
        self.assertEqual(keep_user_casing("Battery - Generated", "Hand Safety"), "Hand Safety")
        self.assertIsNone(keep_user_casing("X", None))


class GenerationRequestTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("g16", "g16@test.com", "Pass123!", is_staff=True)
        cls.company = Company.objects.create(name="G16", slug="g16", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.q = f"?company_id={self.company.id}"

    def test_process_language_is_validated_and_overrides_detection(self):
        url = f"/api/enterprise/knowledge-sources/{self.q}"
        self.assertEqual(self.client.post(url, {"title": "L", "source_type": "manual", "language": "xx"}, format="json").status_code, 400)
        created = self.client.post(url, {"title": "L", "source_type": "manual", "language": "es"}, format="json")
        self.assertEqual((created.status_code, created.data["language"]), (201, "es"))

    def test_documents_language_is_detected_and_stored(self):
        ks, _, doc, section = make_process_with_generated_topic(self.company, self.owner)
        Section.objects.filter(pk=section.pk).update(content=ES)
        self.assertEqual(language_for_documents([doc.id]), "es")
        self.assertEqual(Document.objects.get(pk=doc.pk).language, "es")
        ks.language = "en"
        self.assertEqual(language_for_documents([doc.id], ks), "en")  # the process setting wins
        detail = self.client.get(f"/api/enterprise/knowledge-sources/{ks.id}/{self.q}").data
        self.assertEqual(detail["detected_language"], "es")

    def test_battery_request_sends_language_and_keeps_the_typed_name(self):
        ks, topic, doc, section = make_process_with_generated_topic(self.company, self.owner)
        Section.objects.filter(pk=section.pk).update(content=ES)
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"job_id": "job-g16", "status": "queued", "title": "Qa-test Bateria VF"}
        with patch("api.views.post_with_retry", return_value=fake) as p1, patch("api.views._post_with_logging", return_value=fake) as p2, \
             patch("requests.post", return_value=fake) as p3:
            r = self.client.post("/api/batteries/start-generate/", {
                "name": "QA-TEST Bateria VF", "sections": [section.id], "tag_group_ids": [topic.id], "quantity": 2,
            }, format="json")
        self.assertIn(r.status_code, (200, 201, 202), r.content)
        battery = Battery.objects.filter(source_tag_groups__tag_group=topic).latest("id")
        self.assertEqual(battery.name, "QA-TEST Bateria VF")
        calls = [c for m in (p1, p2, p3) for c in m.call_args_list]
        payloads = [c.kwargs.get("json") or next((a for a in c.args if isinstance(a, dict)), None) for c in calls]
        payload = next(p for p in payloads if p and "metadata" in p)
        self.assertEqual(payload["metadata"]["language"], "spanish")
        self.assertNotIn(str(self.company.id), [str(v) for k, v in payload["metadata"].items() if k == "company_id"])

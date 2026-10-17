"""F-03: enum values are stable English keys; only labels are translated."""
from unittest.mock import patch

from django.apps import apps
from django.test import RequestFactory, TestCase
from rest_framework.test import APITestCase

from api import renderers
from api.enterprise_document_intelligence_models import KnowledgeSource
from api.enterprise_models import Company, CompanyMembership
from api.models import Document, EnumValueBackup, User
from api.services.enum_normalization import normalize, plan, restore


def fake_translate(data, **kwargs):
    # Same contract as the real service: {"0": text, ...} -> {"0": translated, ...}
    return {k: f"ES:{v}" for k, v in data.items()}


class RendererKeepsEnumKeysTests(TestCase):
    def setUp(self):
        renderers._translation_cache.clear()

    def test_spanish_response_translates_text_but_not_enum_keys(self):
        request = RequestFactory().get("/", HTTP_ACCEPT_LANGUAGE="es")
        payload = {
            "title": "Safety manual",
            "process_type": "course",
            "difficulty": "easy",
            "source_type": "other",
            "status": "pending",
            "question_format": "multiple_choice",
            "steps": [{"step_key": "process_document", "status_message": "Processing documents"}],
            "documents": [{"status": "ready", "label": "aggregate_unique_tags"}],
        }
        with patch("api.renderers.post_translate", side_effect=fake_translate):
            renderers.translate_data_if_needed(payload, request)

        self.assertEqual(payload["title"], "ES:Safety manual")  # human text is still translated
        self.assertEqual(payload["steps"][0]["status_message"], "ES:Processing documents")
        for key, value in (("process_type", "course"), ("difficulty", "easy"), ("source_type", "other"),
                           ("status", "pending"), ("question_format", "multiple_choice")):
            self.assertEqual(payload[key], value)
        self.assertEqual(payload["steps"][0]["step_key"], "process_document")
        self.assertEqual(payload["documents"][0]["status"], "ready")
        self.assertEqual(payload["documents"][0]["label"], "aggregate_unique_tags")  # identifier-shaped value


class KnowledgeSourceApiEnumTests(APITestCase):
    def setUp(self):
        renderers._translation_cache.clear()
        self.owner = User.objects.create_user("f03_owner", "o@f03.test", "Pass123!")
        self.company = Company.objects.create(name="F03", slug="f03", owner=self.owner)
        CompanyMembership.objects.create(user=self.owner, company=self.company, role="admin", status="active")
        self.client.force_authenticate(self.owner)

    def _create(self, **overrides):
        body = {"title": "Proc", "source_type": "other", "process_type": "course", "difficulty": "easy", **overrides}
        with patch("api.renderers.post_translate", side_effect=fake_translate):
            return self.client.post(
                f"/api/enterprise/knowledge-sources/?company_id={self.company.id}", body,
                format="json", HTTP_ACCEPT_LANGUAGE="es",
            )

    def test_create_returns_keys_even_in_spanish(self):
        response = self._create()
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data["process_type"], "course")
        self.assertEqual(response.data["difficulty"], "easy")
        ks = KnowledgeSource.objects.get(title="Proc")
        self.assertEqual((ks.process_type, ks.difficulty, ks.source_type), ("course", "easy", "other"))

    def test_translated_values_are_rejected(self):
        self.assertEqual(self._create(process_type="Claro.").status_code, 400)
        self.assertEqual(self._create(difficulty="fácil").status_code, 400)


class NormalizeEnumValuesTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("f03_norm", "n@f03.test", "Pass123!")
        company = Company.objects.create(name="Norm", slug="norm", owner=owner)
        seed = Document.objects.create(filename="s.txt", type="txt", size=1, hash="h", uploaded_by=owner, status="listo")
        self.ks = KnowledgeSource.objects.create(
            company=company, document=seed, title="Old", created_by=owner,
            process_type="Claro.", difficulty="mediano", source_type="otros", status="pendientes",
        )
        self.weird = KnowledgeSource.objects.create(
            company=company, document=seed, title="Weird", created_by=owner, process_type="zzz",
        )
        self.doc = seed
        self.get_model = lambda name: apps.get_model("api", name)

    def test_dry_run_reports_and_changes_nothing(self):
        findings = {(i["field"], i["value"]): i["target"] for i in plan(self.get_model)}
        self.assertEqual(findings[("process_type", "Claro.")], "course")
        self.assertEqual(findings[("difficulty", "mediano")], "medium")
        self.assertEqual(findings[("source_type", "otros")], "other")
        self.assertEqual(findings[("status", "pendientes")], "pending")
        self.assertEqual(findings[("status", "listo")], "ready")
        self.assertIsNone(findings[("process_type", "zzz")])  # unknown -> manual review
        self.ks.refresh_from_db()
        self.assertEqual(self.ks.process_type, "Claro.")

    def test_apply_then_restore(self):
        normalize(self.get_model, EnumValueBackup, apply=True)
        self.ks.refresh_from_db()
        self.doc.refresh_from_db()
        self.assertEqual(
            (self.ks.process_type, self.ks.difficulty, self.ks.source_type, self.ks.status, self.doc.status),
            ("course", "medium", "other", "pending", "ready"),
        )
        self.weird.refresh_from_db()
        self.assertEqual(self.weird.process_type, "zzz")  # untouched
        self.assertEqual(normalize(self.get_model, EnumValueBackup, apply=True)[0]["value"], "zzz")  # idempotent

        restore(self.get_model, EnumValueBackup)
        self.ks.refresh_from_db()
        self.assertEqual(self.ks.process_type, "Claro.")

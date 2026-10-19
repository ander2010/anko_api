"""Finding 17: validations with clear, per-field errors."""
import datetime

from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership
from api.models import User


class ValidationTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("v17", "v17@test.com", "Pass123!")
        cls.company = Company.objects.create(name="V17", slug="v17", owner=cls.owner)
        cls.other = Company.objects.create(name="V17 other", slug="v17-other", owner=cls.owner)
        for company in (cls.company, cls.other):
            CompanyMembership.objects.create(user=cls.owner, company=company, role="owner", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)

    def post(self, url, data, company=None):
        return self.client.post(f"{url}?company_id={(company or self.company).id}", data, format="json")

    def test_compliance_expiry_must_follow_effective(self):
        today = timezone.localdate()
        bad = self.post("/api/enterprise/compliance-programs/", {
            "name": "P", "code": "V-1", "effective_date": str(today), "expiry_date": str(today - datetime.timedelta(days=1))})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("expiry_date", bad.data)
        ok = self.post("/api/enterprise/compliance-programs/", {
            "name": "P", "code": "V-2", "effective_date": str(today), "expiry_date": str(today + datetime.timedelta(days=30))})
        self.assertEqual(ok.status_code, 201, ok.content)
        patch = self.client.patch(f"/api/enterprise/compliance-programs/{ok.data['id']}/?company_id={self.company.id}",
                                  {"expiry_date": str(today - datetime.timedelta(days=5))}, format="json")
        self.assertEqual(patch.status_code, 400)
        self.assertIn("expiry_date", patch.data)

    def test_expired_program_cannot_be_activated(self):
        from api.enterprise_compliance_models import ComplianceProgram
        program = self.post("/api/enterprise/compliance-programs/", {"name": "Old", "code": "V-OLD"}).data
        ComplianceProgram.objects.filter(pk=program["id"]).update(expiry_date=timezone.localdate() - datetime.timedelta(days=1))
        r = self.post(f"/api/enterprise/compliance-programs/{program['id']}/activate/", {})
        self.assertEqual(r.status_code, 400)
        self.assertIn("expiry_date", r.data)

    def test_scores_between_0_and_100(self):
        r = self.post("/api/enterprise/compliance-programs/", {"name": "S", "code": "V-S", "requires_score": True, "passing_score": 150})
        self.assertIn("passing_score", r.data)
        t = self.post("/api/enterprise/certificate-templates/", {"name": "T", "code": "V-T", "title": "T", "requires_score": True})
        self.assertIn("minimum_score", t.data)
        t = self.post("/api/enterprise/certificate-templates/", {"name": "T", "code": "V-T", "title": "T", "requires_score": True, "minimum_score": 150})
        self.assertIn("minimum_score", t.data)
        ok = self.post("/api/enterprise/certificate-templates/", {"name": "T", "code": "V-T", "title": "T", "requires_score": True, "minimum_score": 80})
        self.assertEqual(ok.status_code, 201, ok.content)

    def test_codes_are_unique_per_company(self):
        for url, body in (("/api/enterprise/compliance-programs/", {"name": "A", "code": "DUP"}),
                          ("/api/enterprise/certificate-templates/", {"name": "A", "code": "DUP", "title": "A"})):
            self.assertEqual(self.post(url, body).status_code, 201)
            dup = self.post(url, {**body, "code": "dup"})
            self.assertEqual(dup.status_code, 400, url)
            self.assertIn("already exists", str(dup.data["code"]))
            self.assertEqual(self.post(url, body, company=self.other).status_code, 201, url)

    def test_process_numbers_and_texts(self):
        url = "/api/enterprise/knowledge-sources/"
        base = {"title": "  QA-TEST  ", "source_type": "manual"}
        self.assertIn("minimum_passing_score", self.post(url, {**base, "minimum_passing_score": 150}).data)
        for field, value in (("cards_per_group", 0), ("cards_per_group", 501), ("questions_per_group", 7.5)):
            r = self.post(url, {**base, field: value})
            self.assertEqual(r.status_code, 400, (field, value))
            self.assertIn(field, r.data)
        self.assertIn("title", self.post(url, {**base, "title": "x" * 256}).data)
        ok = self.post(url, base)
        self.assertEqual(ok.status_code, 201, ok.content)
        self.assertEqual(ok.data["title"], "QA-TEST")

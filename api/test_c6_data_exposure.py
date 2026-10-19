"""C6: what public / member endpoints expose."""
import re

from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise_certification_models import Certification
from api.enterprise_models import Company, CompanyMembership
from api.models import Document, Project, User
from api.serializers import DocumentSerializer


class DataExposureTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("c6", "c6@test.com", "Pass123!")
        cls.emp = User.objects.create_user("c6e", "c6e@test.com", "Pass123!", first_name="Ana", last_name="QA")
        cls.company = Company.objects.create(name="C6", slug="c6", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        CompanyMembership.objects.create(user=cls.emp, company=cls.company, role="employee", status="active")

    def test_public_verification_is_minimal_and_codes_are_random(self):
        self.client.force_authenticate(self.owner)
        q = f"?company_id={self.company.id}"
        tpl = self.client.post(f"/api/enterprise/certificate-templates/{q}", {"name": "C", "code": "C6", "title": "C"}, format="json").data
        cert = self.client.post(f"/api/enterprise/certificate-templates/{tpl['id']}/issue/{q}", {"user_id": self.emp.id}, format="json").data
        code = Certification.objects.get(pk=cert["id"]).verification_code
        self.assertRegex(code, r"^[A-Z0-9]{12}$")
        self.client.force_authenticate(None)
        body = self.client.get(f"/api/enterprise/verify/{code}/").data
        self.assertTrue(body["valid"])
        self.assertEqual(body["holder_name"], "Ana QA")
        text = str(body)
        self.assertNotIn("c6e@test.com", text)
        for internal in ("user_id", "company_id", "email", "id"):
            self.assertNotIn(internal, body)

    def test_members_list_needs_permission_and_hides_internal_fields(self):
        self.client.force_authenticate(self.emp)
        self.assertEqual(self.client.get(f"/api/enterprise/companies/{self.company.id}/members/").status_code, 403)
        self.client.force_authenticate(self.owner)
        rows = self.client.get(f"/api/enterprise/companies/{self.company.id}/members/").data
        self.assertTrue(rows)
        for row in rows:
            for field in ("password", "last_login", "is_staff", "is_superuser"):
                self.assertNotIn(field, row)

    def test_document_serializer_hides_quarantine_internals(self):
        doc = Document.objects.create(project=Project.objects.create(title="P", owner=self.owner), filename="a.md",
                                      type="md", size=1, hash="c6", uploaded_by=self.owner,
                                      quarantine_original_key="documents/secret/key.exe", quarantine_reason="SUSPICIOUS")
        data = DocumentSerializer(doc).data
        self.assertNotIn("quarantine_original_key", data)
        self.assertNotIn("quarantine_reason", data)
        self.assertIn("filename", data)
        self.assertIn("hash", data)  # unchanged contract

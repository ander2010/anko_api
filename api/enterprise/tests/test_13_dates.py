"""13: certificate timestamps are exact and returned in full (no day shift)."""
import datetime
from decimal import Decimal

from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_certification_models import Certification
from api.enterprise_models import Company, CompanyMembership
from api.models import Battery, BatteryAttempt, BatteryQuestion, BatterySourceTagGroup, User


class CertificateDatesTests(APITestCase):
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

    def test_13_certificate_data_has_full_timestamps_and_30_day_expiry(self):
        tpl = self.client.post(f"/api/enterprise/certificate-templates/{self.q}", {"name": "C", "code": "D13", "title": "C", "validity_days": 30}, format="json").data
        cert = self.client.post(f"/api/enterprise/certificate-templates/{tpl['id']}/issue/{self.q}", {"user_id": self.employee.id}, format="json").data
        data = self.client.get(f"/api/enterprise/certifications/{cert['id']}/certificate-data/{self.q}").data
        row = Certification.objects.get(pk=cert["id"])
        self.assertEqual(data["issued_at"], row.issued_at.date().isoformat())  # unchanged contract
        self.assertEqual(data["issued_at_iso"], row.issued_at.isoformat())
        issued = datetime.datetime.fromisoformat(data["issued_at_iso"])
        expires = datetime.datetime.fromisoformat(data["expires_at_iso"])
        self.assertEqual(expires - issued, datetime.timedelta(days=30))

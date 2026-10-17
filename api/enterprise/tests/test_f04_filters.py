"""F-04: process list filters by type and difficulty (combinable, validated)."""
import itertools

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from api.enterprise_document_intelligence_models import KnowledgeSource
from api.enterprise_models import Company, CompanyMembership
from api.models import Document

TYPES = ("course", "tutorial", "study_material")
DIFFICULTIES = ("easy", "medium", "hard")


class ProcessListFilterTests(APITestCase):
    def setUp(self):
        owner = get_user_model().objects.create_user("f04", "f04@test.com", "Pass123!")
        self.company = Company.objects.create(name="F04", slug="f04", owner=owner)
        CompanyMembership.objects.create(user=owner, company=self.company, role="admin", status="active")
        seed = Document.objects.create(filename="s.txt", type="txt", size=1, hash="h", uploaded_by=owner, status="ready")
        for process_type, difficulty in itertools.product(TYPES, DIFFICULTIES):
            KnowledgeSource.objects.create(
                company=self.company, document=seed, created_by=owner,
                title=f"{process_type}-{difficulty}", process_type=process_type, difficulty=difficulty,
            )
        self.client.force_authenticate(owner)

    def titles(self, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        response = self.client.get(f"/api/enterprise/knowledge-sources/?company_id={self.company.id}&{query}")
        self.assertEqual(response.status_code, 200, response.content)
        return sorted(item["title"] for item in response.data)

    def test_every_combination_returns_exactly_the_matching_processes(self):
        for process_type, difficulty in itertools.product(("",) + TYPES, ("",) + DIFFICULTIES):
            params = {k: v for k, v in (("process_type", process_type), ("difficulty", difficulty)) if v}
            expected = sorted(
                f"{t}-{d}" for t, d in itertools.product(TYPES, DIFFICULTIES)
                if (not process_type or t == process_type) and (not difficulty or d == difficulty)
            )
            self.assertEqual(self.titles(**params), expected, params)

    def test_invalid_filter_value_is_400(self):
        response = self.client.get(f"/api/enterprise/knowledge-sources/?company_id={self.company.id}&process_type=Claro.")
        self.assertEqual(response.status_code, 400)

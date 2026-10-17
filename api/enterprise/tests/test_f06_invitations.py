"""F-06: the invitations endpoints the frontend now calls (no duplicated /api prefix)."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership
from api.models import Permission, Resource, Role


class CompanyInvitationsApiTests(APITestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user("f06", "f06@test.com", "Pass123!")
        self.company = Company.objects.create(name="F06", slug="f06", owner=self.admin)
        CompanyMembership.objects.create(user=self.admin, company=self.company, role="admin", status="active")
        resource = Resource.objects.create(key="enterprise.ent-invitations", name="Invitations")
        role = Role.objects.create(name="enterprise.admin")
        role.permissions.add(Permission.objects.create(resource=resource, action="manage"))
        self.client.force_authenticate(self.admin)
        self.base = f"/api/enterprise/companies/{self.company.id}/invitations/"

    def test_duplicated_prefix_is_not_a_route(self):
        self.assertEqual(self.client.get(f"/api{self.base}").status_code, 404)

    @patch("api.enterprise.views.invitations.send_invitation_email")
    def test_list_create_resend_cancel(self, _send):
        self.assertEqual(self.client.get(self.base).status_code, 200)

        created = self.client.post(self.base, {"email": "new@f06.test", "role": "employee"}, format="json")
        self.assertEqual(created.status_code, 201, created.content)
        invitation_id = created.data["id"]

        listed = self.client.get(self.base, {"status": "pending"})
        self.assertEqual([i["id"] for i in self._items(listed)], [invitation_id])
        self.assertEqual(self._items(self.client.get(self.base, {"status": "accepted"})), [])

        self.assertEqual(self.client.post(f"{self.base}{invitation_id}/resend/").status_code, 200)
        self.assertEqual(self.client.delete(f"{self.base}{invitation_id}/").status_code, 204)
        self.assertEqual(self._items(self.client.get(self.base, {"status": "cancelled"}))[0]["id"], invitation_id)
        self.assertEqual(self.client.delete(f"{self.base}{invitation_id}/").status_code, 400)

    @staticmethod
    def _items(response):
        data = response.data
        return data.get("results", data) if isinstance(data, dict) else data

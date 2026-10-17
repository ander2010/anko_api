"""/api/users/ is the platform-wide user directory: platform admins only."""
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership
from api.models import User


class UserDirectoryAccessTests(APITestCase):
    def setUp(self):
        self.staff = User.objects.create_user("plat_admin", "admin@plat.test", "Pass123!", is_staff=True)
        self.company_admin = User.objects.create_user("co_admin", "coadmin@a.test", "Pass123!")
        self.employee = User.objects.create_user("employee", "emp@b.test", "Pass123!")
        company = Company.objects.create(name="A", slug="a", owner=self.company_admin)
        CompanyMembership.objects.create(user=self.company_admin, company=company, role="admin", status="active")

    def test_anonymous_and_regular_users_cannot_list(self):
        self.assertEqual(self.client.get("/api/users/").status_code, 401)
        for user in (self.company_admin, self.employee):
            self.client.force_authenticate(user)
            self.assertEqual(self.client.get("/api/users/").status_code, 403, user.username)

    def test_regular_user_cannot_edit_others_or_escalate(self):
        self.client.force_authenticate(self.employee)
        r = self.client.patch(f"/api/users/{self.employee.id}/", {"is_staff": True}, format="json")
        self.assertEqual(r.status_code, 403)
        r = self.client.patch(f"/api/users/{self.company_admin.id}/", {"email": "x@x.test"}, format="json")
        self.assertEqual(r.status_code, 403)
        self.employee.refresh_from_db()
        self.assertFalse(self.employee.is_staff)

    def test_platform_admin_can_list_and_search(self):
        self.client.force_authenticate(self.staff)
        r = self.client.get("/api/users/", {"search": "coadmin@"})
        self.assertEqual(r.status_code, 200)
        emails = [u["email"] for u in (r.data.get("results", r.data) if isinstance(r.data, dict) else r.data)]
        self.assertEqual(emails, ["coadmin@a.test"])

    def test_own_profile_still_works_through_auth_me(self):
        self.client.force_authenticate(self.employee)
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 200)

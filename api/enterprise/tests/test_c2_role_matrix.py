"""
C2: role x action matrix inside one company, enforced by the backend.

Expected roles come from seed_routes_rbac (MANAGE_GATED_KEYS for writes, the
*_ALLOWED lists for views). Every action is tried by one user of each role;
allowed roles must not get 403, the others must get 403 (or 404).
"""
from unittest.mock import patch

from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_models import Company, CompanyMembership, Team
from api.models import Battery, BatteryQuestion, BatterySourceTagGroup, User

ROLES = ("owner", "admin", "manager", "trainer", "auditor", "employee")
CONTENT = {"owner", "admin", "manager", "trainer"}
ASSIGN = {"owner", "admin", "manager"}
TEAM_REPORTS = {"owner", "admin", "manager"}
COMPANY_RETENTION = {"owner", "admin", "manager", "auditor"}
COMPANY_COMPLIANCE = {"owner", "admin", "auditor"}
AUDIT_REPORT = {"owner", "admin", "auditor"}
MEMBERS = {"owner", "admin", "manager"}
INVITATIONS = {"owner", "admin"}


class RoleMatrixTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._no_throttle = patch("rest_framework.throttling.SimpleRateThrottle.allow_request", return_value=True)
        cls._no_throttle.start()

    @classmethod
    def tearDownClass(cls):
        cls._no_throttle.stop()
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.users = {}
        owner = User.objects.create_user("c2owner", "c2owner@test.com", "Pass123!")
        cls.company = Company.objects.create(name="C2", slug="c2", owner=owner)
        for role in ROLES:
            user = owner if role == "owner" else User.objects.create_user(f"c2{role}", f"c2{role}@test.com", "Pass123!")
            CompanyMembership.objects.create(user=user, company=cls.company, role=role, status="active")
            cls.users[role] = user
        cls.target = User.objects.create_user("c2target", "c2target@test.com", "Pass123!")
        CompanyMembership.objects.create(user=cls.target, company=cls.company, role="employee", status="active")

    def setUp(self):
        self.client.force_authenticate(self.users["owner"])
        self.q = f"?company_id={self.company.id}"
        post = lambda url, data=None: self.client.post(f"{url}{self.q}", data or {}, format="json").data  # noqa: E731
        self.ks, self.topic, _, _ = make_process_with_generated_topic(self.company, self.users["owner"])
        self.path = post("/api/enterprise/learning-paths/", {"name": "C2 path"})
        post(f"/api/enterprise/learning-paths/{self.path['id']}/publish/")
        self.module = post("/api/enterprise/learning-modules/", {"learning_path": self.path["id"], "name": "C2 module"})
        self.compliance = post("/api/enterprise/compliance-programs/", {"name": "C2 compliance", "code": "C2-1"})
        self.template = post("/api/enterprise/certificate-templates/", {"name": "C2 cert", "code": "C2-CERT", "title": "C2"})
        self.team = Team.objects.create(company=self.company, name="C2 team")
        self.battery = Battery.objects.create(project=None, name="C2 battery", status="Ready", difficulty="Medium")
        BatterySourceTagGroup.objects.create(battery=self.battery, tag_group=self.topic)
        BatteryQuestion.objects.create(battery=self.battery, question="Q", type="singleChoice", order=0, points=1)

    def check(self, allowed, method, url, data=None, label=None):
        for role in ROLES:
            self.client.force_authenticate(self.users[role])
            full = url + (("&" if "?" in url else "?") + f"company_id={self.company.id}")
            r = getattr(self.client, method)(full, data or {}, format="json")
            with self.subTest(action=label or url, role=role):
                if role in allowed:
                    self.assertNotIn(r.status_code, (401, 403), f"{role} should be allowed: {method.upper()} {url} -> {r.status_code} {str(getattr(r, 'data', ''))[:200]}")
                else:
                    self.assertIn(r.status_code, (403, 404), f"{role} must be denied: {method.upper()} {url} -> {r.status_code}")

    def test_content_creation(self):
        n = iter(range(1000))
        self.check(CONTENT, "post", "/api/enterprise/knowledge-sources/", {"title": "x", "source_type": "manual"}, "create process")
        self.check(CONTENT, "post", "/api/enterprise/learning-paths/", {"name": "x"}, "create path")
        self.check(CONTENT, "post", "/api/enterprise/learning-modules/", {"learning_path": self.path["id"], "name": "x"}, "create module")
        self.check(CONTENT, "post", "/api/enterprise/learning-module-items/", {"module": self.module["id"], "item_type": "battery", "battery": self.battery.id}, "create module item")
        self.check(CONTENT, "post", "/api/enterprise/training-programs/", {"name": "x"}, "create program")
        self.check(CONTENT, "post", "/api/enterprise/compliance-requirements/", {"program": self.compliance["id"], "learning_path": self.path["id"], "name": "x"}, "create compliance requirement")
        self.check(CONTENT, "post", "/api/enterprise/certification-requirements/", {"template": self.template["id"], "learning_path": self.path["id"]}, "create cert requirement")
        self.check(CONTENT, "post", f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/", {"title": f"t{next(n)}"}, "add topic")

    def test_content_edit_and_delete(self):
        self.check(CONTENT, "patch", f"/api/enterprise/learning-modules/{self.module['id']}/", {"name": "renamed"}, "edit module")
        self.check(CONTENT, "patch", f"/api/batteries/{self.battery.id}/", {"name": "renamed"}, "edit process battery")

    def test_compliance_and_certificate_codes_by_role(self):
        for role in ROLES:
            self.client.force_authenticate(self.users[role])
            r = self.client.post(f"/api/enterprise/compliance-programs/{self.q}", {"name": f"P {role}", "code": f"P-{role}"}, format="json")
            t = self.client.post(f"/api/enterprise/certificate-templates/{self.q}", {"name": f"T {role}", "code": f"T-{role}", "title": "T"}, format="json")
            with self.subTest(role=role):
                expected_ok = role in CONTENT
                self.assertEqual(r.status_code == 201, expected_ok, f"compliance {role}: {r.status_code}")
                self.assertEqual(t.status_code == 201, expected_ok, f"template {role}: {t.status_code}")

    def test_assign_and_reports(self):
        self.check(ASSIGN, "post", f"/api/enterprise/learning-paths/{self.path['id']}/assign-to-user/", {"user_id": self.target.id}, "assign path")
        self.check(TEAM_REPORTS, "get", f"/api/enterprise/retention/team-retention/?team_id={self.team.id}", label="team retention")
        self.check(TEAM_REPORTS, "get", f"/api/enterprise/compliance-assignments/team-compliance/?team_id={self.team.id}", label="team compliance")
        self.check(COMPANY_RETENTION, "get", "/api/enterprise/retention/company-retention/", label="company retention")
        self.check(COMPANY_COMPLIANCE, "get", "/api/enterprise/compliance-assignments/company-compliance/", label="company compliance")
        self.check(AUDIT_REPORT, "get", f"/api/enterprise/compliance-programs/{self.compliance['id']}/audit-report/", label="audit report")

    def test_members_and_invitations(self):
        self.check(MEMBERS, "post", f"/api/enterprise/teams/{self.team.id}/add-member/", {"user_id": self.target.id}, "add team member")
        self.check(INVITATIONS, "get", f"/api/enterprise/companies/{self.company.id}/invitations/", label="list invitations")
        self.check(INVITATIONS, "post", f"/api/enterprise/companies/{self.company.id}/invitations/",
                   {"email": "new@c2.test", "role": "employee", "employee_stage": "onboarding"}, "invite")

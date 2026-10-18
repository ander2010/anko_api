"""F-11: Team Retention / Team Compliance return per-member data for the chosen team."""
from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership, Team, TeamMembership
from api.enterprise_retention_models import KnowledgeAssessment
from api.models import User

RET = "/api/enterprise/retention/team-retention/"
COMP = "/api/enterprise/compliance-assignments/team-compliance/"
OLD_RET_KEYS = {"team_id", "team_name", "member_count", "avg_retention", "avg_risk", "at_risk_count"}
OLD_COMP_KEYS = {"team_id", "team_name", "member_count", "avg_compliance_rate", "fully_compliant_count", "at_risk_count"}


class TeamReportTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("f11", "f11@test.com", "Pass123!")
        cls.company = Company.objects.create(name="F11", slug="f11", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        cls.ana = User.objects.create_user("ana", "ana@test.com", "Pass123!", first_name="Ana", last_name="QA")
        CompanyMembership.objects.create(user=cls.ana, company=cls.company, role="employee", status="active")
        cls.team = Team.objects.create(company=cls.company, name="QA-TEST Team")
        TeamMembership.objects.create(team=cls.team, user=cls.ana)
        cls.empty_team = Team.objects.create(company=cls.company, name="QA-TEST Empty")
        KnowledgeAssessment.objects.create(company=cls.company, user=cls.ana, score=40, items_total=10, items_correct=4)

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.q = f"?company_id={self.company.id}"

    def test_team_retention_has_members_and_keeps_aggregates(self):
        r = self.client.get(f"{RET}{self.q}&team_id={self.team.id}")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertTrue(OLD_RET_KEYS <= set(r.data))
        self.assertEqual(r.data["member_count"], 1)
        [row] = r.data["members"]
        self.assertEqual((row["user_id"], row["name"], row["email"]), (self.ana.id, "Ana QA", "ana@test.com"))
        self.assertIsNotNone(row["last_assessment"])
        for key in ("retention_score", "risk_score", "risk_level", "open_gaps", "at_risk"):
            self.assertIn(key, row)
        self.assertEqual(sum(r.data["risk_distribution"].values()), 1)

    def test_team_compliance_has_members_and_keeps_aggregates(self):
        r = self.client.get(f"{COMP}{self.q}&team_id={self.team.id}")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertTrue(OLD_COMP_KEYS <= set(r.data))
        [row] = r.data["members"]
        self.assertEqual(row["user_name"], "Ana QA")
        for key in ("compliance_rate", "compliant", "non_compliant", "pending", "expired", "risk_level"):
            self.assertIn(key, row)
        for key in ("compliant", "non_compliant", "pending", "risk_distribution"):
            self.assertIn(key, r.data)

    def test_empty_team_is_200_with_empty_lists(self):
        for url in (RET, COMP):
            r = self.client.get(f"{url}{self.q}&team_id={self.empty_team.id}")
            self.assertEqual(r.status_code, 200, r.content)
            self.assertEqual((r.data["member_count"], r.data["members"]), (0, []))

    def test_missing_or_foreign_team_is_a_clear_400(self):
        other = Company.objects.create(name="F11X", slug="f11x", owner=self.owner)
        foreign = Team.objects.create(company=other, name="Foreign")
        for url in (RET, COMP):
            missing = self.client.get(f"{url}{self.q}")
            self.assertEqual(missing.status_code, 400)
            self.assertEqual(set(missing.data), {"team_id"})  # no longer blames company_id
            self.assertEqual(self.client.get(f"{url}{self.q}&team_id=abc").status_code, 400)
            self.assertEqual(self.client.get(f"{url}{self.q}&team_id={foreign.id}").status_code, 400)

    def test_employee_without_permission_is_403(self):
        self.client.force_authenticate(self.ana)
        for url in (RET, COMP):
            self.assertEqual(self.client.get(f"{url}{self.q}&team_id={self.team.id}").status_code, 403)

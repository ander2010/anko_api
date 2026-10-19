"""
C1: a user of company A can never read, change or delete anything of company B.

Company B's objects are created by B's owner; then A's owner attacks every
endpoint three ways: ?company_id=B (not a member), ?company_id=A with B's ids
(object of another tenant) and no company_id at all. Every attempt must be
403/404 (or an empty list), and nothing of B may change.
"""
import shutil
import tempfile
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APITestCase

from api.enterprise.services.knowledge_graph_builder import build_knowledge_graph
from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_document_intelligence_models import KnowledgeNode, KnowledgeSource
from api.enterprise_models import BusinessUnit, Company, CompanyMembership, Team, TeamMembership
from api.enterprise_retention_models import KnowledgeAssessment
from api.models import Deck, Flashcard, User

DENIED = (403, 404)
# Also not a leak: method not allowed, or "company_id is required" when it is omitted.
NOT_A_LEAK = DENIED + (405,)


def is_denied(response):
    if response.status_code in NOT_A_LEAK:
        return True
    data = getattr(response, "data", None)
    if response.status_code != 400 or not isinstance(data, dict):
        return False
    # "company_id is required", or "Team not found" (same answer whether the team exists or not).
    return set(data) == {"company_id"} or (set(data) == {"team_id"} and "not found" in str(data["team_id"]).lower())


class TenantIsolationTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media = tempfile.mkdtemp(prefix="anko-c1-")
        cls._storage = override_settings(DEFAULT_FILE_STORAGE="django.core.files.storage.FileSystemStorage", MEDIA_ROOT=cls._media)
        # Throttling is off here (throttle classes are bound at import time, so patch them):
        # a 429 must not be mistaken for an isolation check.
        cls._no_throttle = patch("rest_framework.throttling.SimpleRateThrottle.allow_request", return_value=True)
        cls._no_throttle.start()
        cls._storage.enable()

    @classmethod
    def tearDownClass(cls):
        cls._storage.disable()
        cls._no_throttle.stop()
        shutil.rmtree(cls._media, ignore_errors=True)
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.a_owner = User.objects.create_user("c1a", "c1a@test.com", "Pass123!")
        cls.b_owner = User.objects.create_user("c1b", "c1b@test.com", "Pass123!")
        cls.b_emp = User.objects.create_user("c1be", "c1be@test.com", "Pass123!")
        cls.A = Company.objects.create(name="C1 A", slug="c1-a", owner=cls.a_owner)
        cls.B = Company.objects.create(name="C1 B", slug="c1-b", owner=cls.b_owner)
        CompanyMembership.objects.create(user=cls.a_owner, company=cls.A, role="owner", status="active")
        CompanyMembership.objects.create(user=cls.b_owner, company=cls.B, role="owner", status="active")
        CompanyMembership.objects.create(user=cls.b_emp, company=cls.B, role="employee", status="active")

    # ------------------------------------------------------------------ helpers
    def as_b(self):
        self.client.force_authenticate(self.b_owner)

    def as_a(self):
        self.client.force_authenticate(self.a_owner)

    def b_post(self, url, data=None, fmt="json"):
        sep = "&" if "?" in url else "?"
        r = self.client.post(f"{url}{sep}company_id={self.B.id}", data or {}, format=fmt)
        self.assertIn(r.status_code, (200, 201), f"setup {url}: {r.status_code} {r.content[:300]}")
        return r.data

    def setUp(self):
        self.as_b()
        b = {}
        b["ks"], b["topic"], b["doc"], b["section"] = make_process_with_generated_topic(self.B, self.b_owner, title="C1 B process")
        b["deck"] = self.b_post(f"/api/enterprise/knowledge-sources/{b['ks'].id}/topics/{b['topic'].id}/decks/", {
            "title": "B deck", "flashcards": [{"front": "secret B front", "back": "secret B back"}],
        })["id"]
        b["manual_topic"] = self.b_post(f"/api/enterprise/knowledge-sources/{b['ks'].id}/topics/", {"title": "B topic"})["id"]
        build_knowledge_graph(b["ks"])
        b["node"] = KnowledgeNode.objects.filter(source=b["ks"]).first().id
        b["path"] = self.b_post("/api/enterprise/learning-paths/", {"name": "B path"})["id"]
        self.b_post(f"/api/enterprise/learning-paths/{b['path']}/publish/")
        b["module"] = self.b_post("/api/enterprise/learning-modules/", {"learning_path": b["path"], "name": "B module"})["id"]
        b["program"] = self.b_post("/api/enterprise/training-programs/", {"name": "B program"})["id"]
        self.b_post(f"/api/enterprise/training-programs/{b['program']}/publish/", {"learning_path_id": b["path"]})
        b["assignment"] = self.b_post(f"/api/enterprise/learning-paths/{b['path']}/assign-to-user/", {"user_id": self.b_emp.id})["id"]
        b["compliance"] = self.b_post("/api/enterprise/compliance-programs/", {"name": "B compliance", "code": "B-1"})["id"]
        b["requirement"] = self.b_post("/api/enterprise/compliance-requirements/", {
            "program": b["compliance"], "learning_path": b["path"], "name": "B req"})["id"]
        self.b_post(f"/api/enterprise/compliance-programs/{b['compliance']}/activate/")
        b["c_assignment"] = self.b_post(f"/api/enterprise/compliance-programs/{b['compliance']}/assign-to-user/", {"user_id": self.b_emp.id})["id"]
        b["template"] = self.b_post("/api/enterprise/certificate-templates/", {"name": "B cert", "code": "B-CERT", "title": "B"})["id"]
        b["cert"] = self.b_post(f"/api/enterprise/certificate-templates/{b['template']}/issue/", {"user_id": self.b_emp.id})["id"]
        b["team"] = Team.objects.create(company=self.B, name="B team").id
        TeamMembership.objects.create(team_id=b["team"], user=self.b_emp)
        b["bu"] = BusinessUnit.objects.create(company=self.B, name="B unit", code="BU").id
        with patch("api.enterprise.services.invitation_service.InvitationService._send_email", create=True):
            b["invitation"] = self.b_post(f"/api/enterprise/companies/{self.B.id}/invitations/", {
                "email": "new@b.test", "role": "employee", "employee_stage": "onboarding"})["id"]
        b["assessment"] = KnowledgeAssessment.objects.create(company=self.B, user=self.b_emp, score=50).id
        self.b = b
        self.as_a()

    def attempt(self, method, url, data=None):
        call = getattr(self.client, method)
        return call(url, data or {}, format="json") if method != "get" else call(url)

    def assert_denied(self, method, url, data=None, allow_empty_list=False):
        for suffix in (f"company_id={self.B.id}", f"company_id={self.A.id}", ""):
            full = url + (("&" if "?" in url else "?") + suffix if suffix else "")
            with self.subTest(method=method, url=full):
                r = self.attempt(method, full, data)
                if allow_empty_list and r.status_code == 200:
                    items = r.data.get("results", r.data) if isinstance(r.data, dict) else r.data
                    self.assertEqual(list(items or []), [], f"{method.upper()} {full} leaked {str(r.data)[:300]}")
                    continue
                self.assertTrue(is_denied(r), f"{method.upper()} {full} -> {r.status_code} {str(getattr(r, 'data', ''))[:300]}")

    # ------------------------------------------------------------------ tests
    def test_detail_routes_read_update_delete(self):
        b = self.b
        detail = {
            "knowledge-sources": b["ks"].id, "learning-paths": b["path"], "learning-modules": b["module"],
            "training-programs": b["program"], "learning-assignments": b["assignment"],
            "compliance-programs": b["compliance"], "compliance-requirements": b["requirement"],
            "compliance-assignments": b["c_assignment"], "certificate-templates": b["template"],
            "certifications": b["cert"], "teams": b["team"], "business-units": b["bu"], "companies": self.B.id,
            "assessments": b["assessment"],
        }
        for resource, pk in detail.items():
            url = f"/api/enterprise/{resource}/{pk}/"
            self.assert_denied("get", url)
            self.assert_denied("patch", url, {"name": "hacked", "title": "hacked"})
            self.assert_denied("delete", url)
        self.assertTrue(KnowledgeSource.objects.filter(pk=b["ks"].id, title="C1 B process").exists())
        self.assertTrue(Company.objects.filter(pk=self.B.id, name="C1 B").exists())

    def test_lists_do_not_leak(self):
        for resource in ("knowledge-sources", "learning-paths", "learning-modules", "training-programs",
                         "learning-assignments", "compliance-programs", "compliance-requirements",
                         "compliance-assignments", "certificate-templates", "certifications", "teams",
                         "business-units", "assessments", "retention-snapshots", "knowledge-gaps", "procedures"):
            for q in (f"?company_id={self.B.id}", ""):
                url = f"/api/enterprise/{resource}/{q}"
                with self.subTest(url=url):
                    r = self.client.get(url)
                    if is_denied(r):
                        continue
                    self.assertEqual(r.status_code, 200)
                    items = r.data.get("results", r.data) if isinstance(r.data, dict) else r.data
                    self.assertEqual(len(items), 0, f"GET {url} leaked {str(items)[:300]}")

    def test_nested_and_custom_actions(self):
        b = self.b
        ks, topic = b["ks"].id, b["topic"].id
        actions = [
            ("get", f"/api/enterprise/knowledge-sources/{ks}/results/"),
            ("get", f"/api/enterprise/knowledge-sources/{ks}/documents-with-sections/"),
            ("get", f"/api/enterprise/knowledge-sources/{ks}/status/"),
            ("post", f"/api/enterprise/knowledge-sources/{ks}/topics/", {"title": "x"}),
            ("patch", f"/api/enterprise/knowledge-sources/{ks}/topics/{b['manual_topic']}/", {"title": "x"}),
            ("post", f"/api/enterprise/knowledge-sources/{ks}/topics/{topic}/decks/", {"title": "x", "flashcards": [{"front": "a", "back": "b"}]}),
            ("post", f"/api/enterprise/knowledge-sources/{ks}/add-document/", {}),
            ("post", f"/api/enterprise/learning-paths/{b['path']}/assign-to-user/", {"user_id": self.a_owner.id}),
            ("post", f"/api/enterprise/learning-paths/{b['path']}/archive/"),
            ("get", f"/api/enterprise/training-programs/{b['program']}/versions/"),
            ("post", f"/api/enterprise/training-programs/{b['program']}/publish/", {"learning_path_id": b["path"]}),
            ("get", f"/api/enterprise/compliance-programs/{b['compliance']}/audit-report/"),
            ("post", f"/api/enterprise/compliance-programs/{b['compliance']}/assign-to-user/", {"user_id": self.a_owner.id}),
            ("post", f"/api/enterprise/compliance-programs/{b['compliance']}/archive/"),
            ("post", f"/api/enterprise/certificate-templates/{b['template']}/issue/", {"user_id": self.a_owner.id}),
            ("get", f"/api/enterprise/certifications/{b['cert']}/certificate-data/"),
            ("post", f"/api/enterprise/certifications/{b['cert']}/revoke/", {"reason": "x"}),
            ("get", f"/api/enterprise/teams/{b['team']}/members/"),
            ("post", f"/api/enterprise/teams/{b['team']}/add-member/", {"user_id": self.a_owner.id}),
            ("get", f"/api/enterprise/companies/{self.B.id}/members/"),
            ("get", f"/api/enterprise/companies/{self.B.id}/invitations/"),
            ("post", f"/api/enterprise/companies/{self.B.id}/invitations/{b['invitation']}/resend/"),
            ("get", f"/api/enterprise/retention/team-retention/?team_id={b['team']}"),
            ("get", f"/api/enterprise/compliance-assignments/team-compliance/?team_id={b['team']}"),
            ("post", f"/api/enterprise/knowledge-graph/rebuild/?knowledge_source_id={ks}"),
        ]
        for method, url, *data in actions:
            self.assert_denied(method, url, data[0] if data else None)

    def test_company_wide_reports_need_membership(self):
        for url in ("/api/enterprise/retention/company-retention/", "/api/enterprise/compliance-assignments/company-compliance/",
                    "/api/enterprise/analytics/company-dashboard/", "/api/enterprise/knowledge-graph/graph/",
                    "/api/enterprise/knowledge-graph/nodes/"):
            with self.subTest(url=url):
                r = self.client.get(f"{url}?company_id={self.B.id}")
                self.assertIn(r.status_code, DENIED + (400,), f"{url} -> {r.status_code} {str(getattr(r, 'data', ''))[:200]}")
        nodes = self.client.get(f"/api/enterprise/knowledge-graph/nodes/?company_id={self.A.id}&knowledge_source_id={self.b['ks'].id}")
        self.assertEqual(len(nodes.data) if nodes.status_code == 200 else 0, 0)

    def test_flashcards_and_batteries_of_another_company(self):
        deck_id = self.b["deck"]
        card = Flashcard.objects.filter(deck_id=deck_id).first()
        checks = [
            ("post", "/api/flashcards/ws-pull-card/", {"deck_id": deck_id, "job_id": "c1-attack"}),
            ("post", "/api/flashcards/ws-push-feedback/", {"deck_id": deck_id, "job_id": "c1-attack", "seq": 1, "card_id": card.card_id or str(card.id), "rating": 3}),
            ("get", f"/api/decks/{deck_id}/", None),
            ("patch", f"/api/decks/{deck_id}/", {"title": "hacked"}),
            ("delete", f"/api/decks/{deck_id}/", None),
            ("get", f"/api/flashcards/{card.id}/", None),
        ]
        for method, url, data in checks:
            with self.subTest(method=method, url=url):
                r = self.attempt(method, url, data)
                self.assertTrue(is_denied(r), f"{method.upper()} {url} -> {r.status_code} {str(getattr(r, 'data', ''))[:200]}")
        listed = self.client.get("/api/flashcards/", {"deck": deck_id})
        self.assertNotIn("secret B front", listed.content.decode(errors="ignore"))
        self.assertTrue(Deck.objects.filter(pk=deck_id, title="B deck").exists())


class CompanyContentAccessTests(TenantIsolationTests):
    """The C1 fix must not take content away from the company that owns it."""

    def _battery_in_b_topic(self):
        from api.models import Battery, BatteryOption, BatteryQuestion, BatterySourceTagGroup
        battery = Battery.objects.create(project=None, name="B battery", status="Ready", difficulty="Medium")
        BatterySourceTagGroup.objects.create(battery=battery, tag_group=self.b["topic"])
        q = BatteryQuestion.objects.create(battery=battery, question="B question", type="singleChoice", order=0, points=1)
        BatteryOption.objects.create(question=q, option_id="a", text="yes", correct=True)
        return battery

    def test_b_employee_still_learns_lists_and_answers(self):
        self.client.force_authenticate(self.b_emp)
        deck_id = self.b["deck"]
        start = self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": deck_id, "job_id": "c1-own"}, format="json")
        self.assertEqual(start.status_code, 200, start.content)
        self.assertIn("secret B front", self.client.get("/api/flashcards/", {"deck": deck_id}).content.decode())
        battery = self._battery_in_b_topic()
        self.assertEqual(self.client.get(f"/api/batteries/{battery.id}/questions/").status_code, 200)

    def test_a_cannot_answer_b_battery(self):
        battery = self._battery_in_b_topic()
        self.assertIn(self.client.get(f"/api/batteries/{battery.id}/questions/").status_code, DENIED)

    def test_deck_in_a_learning_module_is_reachable_by_that_company(self):
        from api.enterprise_learning_models import LearningModule, LearningModuleItem
        deck = Deck.objects.create(project=None, owner=self.b_owner, title="Path-only deck", visibility="private")
        Flashcard.objects.create(deck=deck, card_id="p1", front="path front", back="path back")
        module = LearningModule.objects.get(pk=self.b["module"])
        LearningModuleItem.objects.create(module=module, item_type="deck", deck=deck)
        self.client.force_authenticate(self.b_emp)
        self.assertEqual(self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": deck.id, "job_id": "c1-path"}, format="json").status_code, 200)
        self.as_a()
        self.assertIn(self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": deck.id, "job_id": "c1-path-a"}, format="json").status_code, DENIED)

    # The parent's attack tests are not repeated here.
    test_detail_routes_read_update_delete = None
    test_lists_do_not_leak = None
    test_nested_and_custom_actions = None
    test_company_wide_reports_need_membership = None
    test_flashcards_and_batteries_of_another_company = None


class GeneralListsTests(CompanyContentAccessTests):
    """Platform-wide /api/decks/ and /api/batteries/ must not expose another company's process content."""

    def test_general_lists_and_battery_actions(self):
        battery = self._battery_in_b_topic()
        for url in ("/api/decks/", "/api/decks/?tag_group=%d" % self.b["topic"].id, "/api/batteries/",
                    "/api/batteries/?tag_group=%d" % self.b["topic"].id, f"/api/flashcards/?deck={self.b['deck']}"):
            with self.subTest(url=url):
                r = self.client.get(url)
                body = r.content.decode(errors="ignore")
                if r.status_code == 200 and "_n" in body:
                    from api.test_f05_learn_mode import decrypt
                    from rest_framework.authtoken.models import Token
                    token = Token.objects.get_or_create(user=self.a_owner)[0].key
                    self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
                    body = str(decrypt(self.client.get(url).json(), token))
                for secret in ("secret B front", "B deck", "B battery", "B question"):
                    self.assertNotIn(secret, body, f"GET {url} leaked {secret!r}")
        for method, url in (("get", f"/api/batteries/{battery.id}/"), ("post", f"/api/batteries/{battery.id}/start_attempt/"),
                            ("patch", f"/api/batteries/{battery.id}/"), ("delete", f"/api/batteries/{battery.id}/")):
            with self.subTest(method=method, url=url):
                r = self.attempt(method, url, {"name": "hacked"} if method == "patch" else None)
                self.assertTrue(is_denied(r), f"{method.upper()} {url} -> {r.status_code}")

    test_b_employee_still_learns_lists_and_answers = None
    test_a_cannot_answer_b_battery = None
    test_deck_in_a_learning_module_is_reachable_by_that_company = None

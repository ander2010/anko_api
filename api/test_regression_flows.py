"""
Regression suite for flows verified in production (Oct 2026).
Must pass before and after any change on feat/inactive-features-oct-2026.

AI / anko_services calls are mocked: these tests check our API contract and
side effects, never the LLM.
"""
import datetime
import io
import shutil
import tempfile
from unittest.mock import MagicMock, patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone
from reportlab.pdfgen import canvas
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from api.enterprise_document_intelligence_models import KnowledgeSource
from api.enterprise_models import Company, CompanyMembership, Team
from api.models import (
    Battery, BatteryOption, BatteryQuestion, Deck, DeckSourceTagGroup, Document, Flashcard, ProcessRun, Project, Section, TagGroup, User,
)


def pdf_bytes():
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(72, 720, "Safety procedure")
    c.showPage()
    c.save()
    return buf.getvalue()


EXE = b"MZ\x90\x00" + b"\x00" * 200


class RegressionBase(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media = tempfile.mkdtemp(prefix="anko-regression-")
        cls._storage = override_settings(DEFAULT_FILE_STORAGE="django.core.files.storage.FileSystemStorage", MEDIA_ROOT=cls._media)
        cls._storage.enable()

    @classmethod
    def tearDownClass(cls):
        cls._storage.disable()
        shutil.rmtree(cls._media, ignore_errors=True)
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("reg_owner", "owner@reg.test", "Pass123!")
        cls.employee = User.objects.create_user("reg_emp", "emp@reg.test", "Pass123!")
        cls.company = Company.objects.create(name="Reg Co", slug="reg-co", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")
        CompanyMembership.objects.create(user=cls.employee, company=cls.company, role="employee", status="active")

    def setUp(self):
        self.token = Token.objects.get_or_create(user=self.owner)[0].key
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")
        self.q = f"?company_id={self.company.id}"

    def post(self, url, data=None, **kw):
        return self.client.post(url + (self.q if "?" not in url else f"&company_id={self.company.id}"), data or {}, format=kw.pop("format", "json"), **kw)

    def get(self, url, params=None):
        return self.client.get(url + self.q, params or {})

    def make_ks(self, **extra):
        r = self.post("/api/enterprise/knowledge-sources/", {
            "title": "Reg Process", "source_type": "manual", "process_type": "course", "difficulty": "medium",
            "cards_per_group": 7, "questions_per_group": 4, "question_format": "true_false", **extra,
        })
        self.assertEqual(r.status_code, 201, r.content)
        return r.data


class R01ProcessAndUploads(RegressionBase):
    def test_create_process_upload_valid_and_reject_exe(self):
        ks = self.make_ks()
        url = f"/api/enterprise/knowledge-sources/{ks['id']}/add-document/"
        ok = self.post(url, {"file": SimpleUploadedFile("manual.pdf", pdf_bytes())}, format="multipart")
        self.assertEqual(ok.status_code, 201, ok.content)
        bad = self.post(url, {"file": SimpleUploadedFile("program.exe", EXE)}, format="multipart")
        self.assertEqual(bad.status_code, 415)


class R02AutoGenerate(RegressionBase):
    def test_auto_generate_respects_group_sizes(self):
        doc = Document.objects.create(filename="d.txt", type="TXT", size=1, hash="r02", uploaded_by=self.owner, status="ready")
        with patch("api.tasks.orchestrate_auto_generate_run_task.delay") as delay:
            r = self.client.post("/api/process-runs/auto-generate/", {
                "document_ids": [doc.id], "tag_group_size": 10,
                "flashcard_options": {"cards_per_group": 7, "difficulty": "easy"},
                "battery_options": {"questions_per_group": 4, "difficulty": "easy", "question_format": "true_false"},
            }, format="json")
        self.assertIn(r.status_code, (200, 201, 202), r.content)
        run = ProcessRun.objects.filter(workflow_key="collection_auto_generate").latest("id")
        payload = str(run.input_payload)
        self.assertIn("'cards_per_group': 7", payload)
        self.assertIn("'questions_per_group': 4", payload)
        delay.assert_called_once()


class R03LearnStudySimulate(RegressionBase):
    def setUp(self):
        super().setUp()
        project = Project.objects.create(title="P", owner=self.owner)
        self.deck = Deck.objects.create(project=project, owner=self.owner, title="Deck", visibility="private")
        for i in range(1, 6):
            Flashcard.objects.create(deck=self.deck, card_id=f"r{i}", front=f"Q{i}", back=f"A{i}")
        self.project = project

    def _decrypt(self, response):
        from api.test_f05_learn_mode import decrypt
        body = response.json()
        body = decrypt(body, self.token) if "_n" in body else body
        return body.get("data", body)

    def test_learn_five_good_then_session_complete(self):
        data = self._decrypt(self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": self.deck.id, "job_id": "reg"}, format="json"))
        seen = []
        for seq in range(1, 6):
            seen.append(data["next_card"]["card_id"])
            data = self._decrypt(self.client.post("/api/flashcards/ws-push-feedback/", {
                "deck_id": self.deck.id, "job_id": "reg", "seq": seq, "card_id": seen[-1], "rating": 3,
            }, format="json"))
        self.assertEqual(len(set(seen)), 5)
        self.assertTrue(data["session"]["done"])

    def test_study_lists_every_card(self):
        r = self.client.get("/api/flashcards/", {"deck": self.deck.id, "page_size": 50})
        self.assertEqual(r.status_code, 200)
        body = self._decrypt(r)
        items = body.get("results", body) if isinstance(body, dict) else body
        self.assertEqual(len(items), 5)

    def test_simulate_scores_answers(self):
        battery = Battery.objects.create(project=self.project, name="B", status="Ready", difficulty="Medium")
        questions = []
        for i in range(2):
            q = BatteryQuestion.objects.create(battery=battery, question=f"Q{i}", type="singleChoice", order=i, points=1)
            right = BatteryOption.objects.create(question=q, option_id="a", text="yes", correct=True)
            wrong = BatteryOption.objects.create(question=q, option_id="b", text="no", correct=False)
            questions.append((q, right, wrong))
        start = self.client.post(f"/api/batteries/{battery.id}/start_attempt/", {}, format="json")
        self.assertEqual(start.status_code, 201, start.content)
        attempt_id = start.data["id"]
        for (q, right, wrong), chosen in zip(questions, ("right", "wrong")):
            r = self.client.post(f"/api/batteries/{battery.id}/answer/", {
                "attempt_id": attempt_id, "question_id": q.id,
                "selected_option_id": (right if chosen == "right" else wrong).id,
            }, format="json")
            self.assertEqual(r.status_code, 200, r.content)
            self.assertEqual(r.data["is_correct"], chosen == "right")
        # Same contract as the frontend: it sends the attempt summary (the API does not recompute it).
        finish = self.client.post(f"/api/batteries/{battery.id}/finish_attempt/", {
            "attempt_id": attempt_id, "total_score": 1, "max_score": 2, "correct_count": 1, "total_questions": 2,
        }, format="json")
        self.assertEqual(finish.status_code, 200, finish.content)
        self.assertEqual(finish.data["status"], "finished")
        self.assertEqual(float(finish.data["percent"]), 50.0)
        self.assertEqual(finish.data["correct_count"], 1)


class R04AddWithAIInGeneratedTopic(RegressionBase):
    """Generated topics have no Collection, so today only platform admins (like QA) can add AI content."""

    def setUp(self):
        super().setUp()
        User.objects.filter(pk=self.owner.pk).update(is_staff=True)
        self.doc = Document.objects.create(filename="d.txt", type="TXT", size=1, hash="r04", uploaded_by=self.owner, status="ready")
        self.section = Section.objects.create(document=self.doc, title="Safety", content="Wear helmets.", order=1)
        self.topic = TagGroup.objects.create(name="Topic 1")

    def test_add_deck_and_battery_with_ai_link_to_topic(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {"job_id": "job-reg", "status": "queued"}
        with patch("api.views.post_with_retry", return_value=fake), patch("api.views._post_with_logging", return_value=fake), \
             patch("requests.post", return_value=fake):
            deck = self.client.post("/api/decks/start-generate/", {
                "title": "AI deck", "sections": [self.section.id], "tag_group_ids": [self.topic.id], "quantity": 3,
            }, format="json")
            battery = self.client.post("/api/batteries/start-generate/", {
                "name": "AI battery", "sections": [self.section.id], "tag_group_ids": [self.topic.id], "quantity": 2,
            }, format="json")
        self.assertIn(deck.status_code, (200, 201, 202), deck.content)
        self.assertIn(battery.status_code, (200, 201, 202), battery.content)
        self.assertTrue(DeckSourceTagGroup.objects.filter(tag_group=self.topic).exists())


class R06LearningPaths(RegressionBase):
    def test_create_publish_assign_and_reassign_conflict(self):
        path = self.post("/api/enterprise/learning-paths/", {"name": "Reg Path"})
        self.assertEqual(path.status_code, 201, path.content)
        pid = path.data["id"]
        self.assertEqual(self.post(f"/api/enterprise/learning-paths/{pid}/publish/").status_code, 200)
        due = (timezone.localdate() + datetime.timedelta(days=7)).isoformat()
        body = {"user_id": self.employee.id, "due_date": due}
        self.assertEqual(self.post(f"/api/enterprise/learning-paths/{pid}/assign-to-user/", body).status_code, 201)
        self.assertEqual(self.post(f"/api/enterprise/learning-paths/{pid}/assign-to-user/", body).status_code, 409)


class R07TrainingPrograms(RegressionBase):
    def test_create_program(self):
        r = self.post("/api/enterprise/training-programs/", {"name": "Reg Program"})
        self.assertEqual(r.status_code, 201, r.content)


class R08Compliance(RegressionBase):
    def test_program_requirement_activate_assign_audit(self):
        path = self.post("/api/enterprise/learning-paths/", {"name": "Req Path"}).data
        program = self.post("/api/enterprise/compliance-programs/", {"name": "Reg Compliance", "code": "REG-1"})
        self.assertEqual(program.status_code, 201, program.content)
        prog_id = program.data["id"]
        req = self.post("/api/enterprise/compliance-requirements/", {"program": prog_id, "learning_path": path["id"], "name": "Path"})
        self.assertEqual(req.status_code, 201, req.content)
        self.assertIn(self.post(f"/api/enterprise/compliance-programs/{prog_id}/activate/").status_code, (200, 201))
        assign = self.post(f"/api/enterprise/compliance-programs/{prog_id}/assign-to-user/", {"user_id": self.employee.id})
        self.assertEqual(assign.status_code, 201, assign.content)
        self.assertEqual(self.get(f"/api/enterprise/compliance-programs/{prog_id}/audit-report/").status_code, 200)


class R09Certificates(RegressionBase):
    def test_template_issue_and_view(self):
        tpl = self.post("/api/enterprise/certificate-templates/", {
            "name": "Reg Cert", "code": "REG-CERT", "title": "Certificate", "body": "<script>alert(1)</script> Well done",
        })
        self.assertEqual(tpl.status_code, 201, tpl.content)
        if not tpl.data.get("is_active", True):
            self.post(f"/api/enterprise/certificate-templates/{tpl.data['id']}/activate/")
        issued = self.post(f"/api/enterprise/certificate-templates/{tpl.data['id']}/issue/", {"user_id": self.employee.id})
        self.assertIn(issued.status_code, (200, 201), issued.content)
        cert_id = issued.data["id"]
        view = self.get(f"/api/enterprise/certifications/{cert_id}/certificate-data/")
        self.assertEqual(view.status_code, 200, view.content)


class R10InvitationsAndTeams(RegressionBase):
    def test_invitations_load_and_teams_create(self):
        self.assertEqual(self.client.get(f"/api/enterprise/companies/{self.company.id}/invitations/").status_code, 200)
        team = self.post("/api/enterprise/teams/", {"name": "Reg Team", "company": self.company.id})
        self.assertEqual(team.status_code, 201, team.content)
        self.assertTrue(Team.objects.filter(name="Reg Team", company=self.company).exists())


# ---------------------------------------------------------------------------
# Round 3 (fix/data-quality-security-oct-2026): the 10 flows of the brief, extended.
# ---------------------------------------------------------------------------

class R01bRenamedExecutable(RegressionBase):
    def test_md_ok_and_exe_renamed_to_pdf_is_415(self):
        ks = self.make_ks()
        url = f"/api/enterprise/knowledge-sources/{ks['id']}/add-document/"
        ok = self.post(url, {"file": SimpleUploadedFile("guide.md", b"# Safety\n\nWear helmets.\n")}, format="multipart")
        self.assertEqual(ok.status_code, 201, ok.content)
        bad = self.post(url, {"file": SimpleUploadedFile("invoice.pdf", EXE)}, format="multipart")
        self.assertEqual(bad.status_code, 415)


class R03bLearnRatingsAndReview(R03LearnStudySimulate):
    def test_hard_card_returns_after_three_cards_marked_review(self):
        data = self._decrypt(self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": self.deck.id, "job_id": "reg-hard"}, format="json"))
        shown, reviews, seq = [], [], 0
        while data["next_card"] and seq < 20:
            card = data["next_card"]
            shown.append(card["card_id"])
            reviews.append(card.get("is_review"))
            seq += 1
            data = self._decrypt(self.client.post("/api/flashcards/ws-push-feedback/", {
                "deck_id": self.deck.id, "job_id": "reg-hard", "seq": seq, "card_id": card["card_id"],
                "rating": 2 if seq == 1 else 3,
            }, format="json"))
        first = shown[0]
        again = shown.index(first, 1)
        self.assertGreaterEqual(len(set(shown[1:again])), 3)
        self.assertTrue(reviews[again])
        self.assertTrue(data["session"]["done"])

    # Inherited flows already run in R03.
    test_learn_five_good_then_session_complete = None
    test_study_lists_every_card = None
    test_simulate_scores_answers = None


class R04bManualDeckInGeneratedAndManualTopics(RegressionBase):
    def test_manual_deck_in_both_kinds_of_topic(self):
        from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
        ks, generated, _, _ = make_process_with_generated_topic(self.company, self.owner, title="Reg topics")
        manual = self.post(f"/api/enterprise/knowledge-sources/{ks.id}/topics/", {"title": "Reg manual topic"})
        self.assertEqual(manual.status_code, 201, manual.content)
        for topic_id in (generated.id, manual.data["id"]):
            r = self.post(f"/api/enterprise/knowledge-sources/{ks.id}/topics/{topic_id}/decks/", {
                "title": f"Deck {topic_id}", "flashcards": [{"front": "Q", "back": "A"}]})
            self.assertEqual(r.status_code, 201, r.content)
        results = self.get(f"/api/enterprise/knowledge-sources/{ks.id}/results/").data
        self.assertEqual(len(results["decks"]), 2)


class R07bTrainingProgramVersion(RegressionBase):
    def test_publish_version(self):
        path = self.post("/api/enterprise/learning-paths/", {"name": "Reg Version Path"}).data
        self.post(f"/api/enterprise/learning-paths/{path['id']}/publish/")
        program = self.post("/api/enterprise/training-programs/", {"name": "Reg Versioned"}).data
        r = self.post(f"/api/enterprise/training-programs/{program['id']}/publish/", {"learning_path_id": path["id"]})
        self.assertEqual(r.status_code, 201, r.content)


class R10bReportsLoad(RegressionBase):
    def test_invitations_team_reports_and_graph_load(self):
        team = Team.objects.create(company=self.company, name="Reg Report Team")
        for url in (
            f"/api/enterprise/companies/{self.company.id}/invitations/",
            f"/api/enterprise/retention/team-retention/?team_id={team.id}",
            f"/api/enterprise/compliance-assignments/team-compliance/?team_id={team.id}",
            "/api/enterprise/knowledge-graph/graph/",
        ):
            sep = "&" if "?" in url else "?"
            r = self.client.get(f"{url}{sep}company_id={self.company.id}")
            self.assertEqual(r.status_code, 200, f"{url}: {r.status_code} {r.content[:200]}")

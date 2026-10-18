"""F-08: manual deck inside a process topic."""
from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_models import Company, CompanyMembership
from api.models import Deck, DeckSourceTagGroup, Flashcard, TagGroup, User


class ManualDeckTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("f08", "f08@test.com", "Pass123!")
        cls.company = Company.objects.create(name="F08", slug="f08", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.ks, self.topic, _, _ = make_process_with_generated_topic(self.company, self.owner)
        self.url = f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/{self.topic.id}/decks/?company_id={self.company.id}"

    def create(self, **body):
        payload = {"title": "QA Manual", "flashcards": [{"front": "Q1", "back": "A1"}, {"front": "Q2", "back": "A2"}]}
        payload.update(body)
        return self.client.post(self.url, payload, format="json")

    def test_creates_deck_with_cards_linked_to_topic(self):
        r = self.create(flashcards=[{"front": "  Q1  ", "back": " A1 ", "notes": ""}, {"front": "Q2", "back": "A2"}])
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.data["title"], "QA Manual")
        self.assertEqual(r.data["cardsCount"], 2)
        self.assertEqual(str(r.data["tag_group_id"]), str(self.topic.id))
        self.assertEqual([c["front"] for c in r.data["flashcards"]], ["Q1", "Q2"])  # trimmed
        self.assertTrue(DeckSourceTagGroup.objects.filter(deck_id=r.data["id"], tag_group=self.topic).exists())

        results = self.client.get(f"/api/enterprise/knowledge-sources/{self.ks.id}/results/?company_id={self.company.id}")
        deck = next(d for d in results.data["decks"] if d["id"] == r.data["id"])
        self.assertEqual(deck["cardsCount"], 2)

    def test_manual_deck_works_in_learn(self):
        deck_id = self.create().data["id"]
        start = self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": deck_id, "job_id": "f08"}, format="json")
        self.assertEqual(start.status_code, 200)
        data = start.data
        seen = []
        for seq in (1, 2):
            seen.append(data["next_card"]["card_id"])
            data = self.client.post("/api/flashcards/ws-push-feedback/", {
                "deck_id": deck_id, "job_id": "f08", "seq": seq, "card_id": seen[-1], "rating": 3,
            }, format="json").data
        self.assertEqual(len(set(seen)), 2)
        self.assertTrue(data["session"]["done"])

    def test_validation(self):
        before = Deck.objects.count()
        self.assertIn("title", self.create(title="   ").data)
        self.assertEqual(self.create(flashcards=[]).status_code, 400)
        self.assertIn("flashcards", self.create(flashcards=[{"front": "Q", "back": "  "}]).data)
        self.assertEqual(self.create(flashcards=[{"front": "Q", "back": "A"}] * 501).status_code, 400)
        self.assertEqual(Deck.objects.count(), before)
        self.assertFalse(Flashcard.objects.filter(front="Q").exists())

    def test_topic_must_belong_to_the_process(self):
        stray = TagGroup.objects.create(name="Other")
        r = self.client.post(
            f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/{stray.id}/decks/?company_id={self.company.id}",
            {"title": "x", "flashcards": [{"front": "a", "back": "b"}]}, format="json",
        )
        self.assertEqual(r.status_code, 404)

    def test_other_company_is_denied(self):
        intruder = User.objects.create_user("f08x", "x@f08.test", "Pass123!")
        other = Company.objects.create(name="Other", slug="f08-other", owner=intruder)
        CompanyMembership.objects.create(user=intruder, company=other, role="owner", status="active")
        self.client.force_authenticate(intruder)
        r = self.client.post(
            f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/{self.topic.id}/decks/?company_id={other.id}",
            {"title": "x", "flashcards": [{"front": "a", "back": "b"}]}, format="json",
        )
        self.assertEqual(r.status_code, 404)
        r = self.client.post(self.url, {"title": "x", "flashcards": [{"front": "a", "back": "b"}]}, format="json")
        self.assertEqual(r.status_code, 403)

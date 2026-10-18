"""F-05: Learn mode sessions are DB-backed, strictly ordered by seq and idempotent."""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from api.models import Deck, Flashcard, FlashcardSchedule, LearnAnswer, LearnRating, Project, User

AGAIN, HARD, GOOD, EASY = (int(r) for r in (LearnRating.AGAIN, LearnRating.HARD, LearnRating.GOOD, LearnRating.EASY))


def decrypt(body, token):
    def b64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    key = hashlib.sha256(token.encode()).digest()
    return json.loads(AESGCM(key).decrypt(b64(body["_n"]), b64(body["_t"]), None))


class LearnModeTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("f05", "f05@test.com", "Pass123!")
        self.token = Token.objects.create(user=self.user).key
        project = Project.objects.create(title="P", owner=self.user)
        self.deck = Deck.objects.create(project=project, owner=self.user, title="Deck", visibility="private")
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")

    def make_cards(self, n):
        return [Flashcard.objects.create(deck=self.deck, card_id=f"c{i}", front=f"Q{i}", back=f"A{i}") for i in range(1, n + 1)]

    def call(self, path, body):
        r = self.client.post(path, body, format="json")
        data = r.json()
        if "_n" in data:
            data = decrypt(data, self.token)
            data = data.get("data", data)
        return r.status_code, data

    def start(self, job_id="job-1"):
        return self.call("/api/flashcards/ws-pull-card/", {"deck_id": self.deck.id, "job_id": job_id})

    def answer(self, job_id, seq, card_id, rating=None, action=None):
        body = {"deck_id": self.deck.id, "job_id": job_id, "seq": seq, "card_id": card_id, "time_to_answer_ms": 900}
        if rating is not None:
            body["rating"] = rating
        if action:
            body["action"] = action
        return self.call("/api/flashcards/ws-push-feedback/", body)

    def run_session(self, job_id, ratings=None, max_steps=30):
        """Answer until done; returns (card ids shown, last payload)."""
        ratings = ratings or {}
        _, data = self.start(job_id)
        shown, seq = [], 0
        while data["next_card"] and len(shown) < max_steps:
            card_id = data["next_card"]["card_id"]
            shown.append(card_id)
            seq += 1
            code, data = self.answer(job_id, seq, card_id, ratings.get(len(shown), GOOD))
            self.assertEqual(code, 200, data)
            self.assertEqual(data["ack_seq"], seq)
        return shown, data

    def test_all_good_returns_five_distinct_cards_then_done(self):
        self.make_cards(5)
        shown, last = self.run_session("job-good")
        self.assertEqual(shown, ["c1", "c2", "c3", "c4", "c5"])
        self.assertIsNone(last["next_card"])
        self.assertTrue(last["session"]["done"])
        self.assertEqual(last["session"]["reviewed"], 5)

    def test_again_card_returns_after_at_least_three_distinct_cards(self):
        self.make_cards(5)
        shown, last = self.run_session("job-again", ratings={1: AGAIN})
        self.assertEqual(shown[0], "c1")
        again_at = shown.index("c1", 1)
        self.assertGreaterEqual(len(set(shown[1:again_at])), 3)
        self.assertTrue(last["session"]["done"])

    def test_repeated_card_is_flagged_as_review(self):
        self.make_cards(5)
        _, data = self.start("job-review")
        self.assertFalse(data["next_card"]["is_review"])
        seq, flags = 0, {}
        while data["next_card"]:
            seq += 1
            card = data["next_card"]
            flags.setdefault(card["card_id"], []).append(card["is_review"])
            _, data = self.answer("job-review", seq, card["card_id"], HARD if seq == 1 else GOOD)
        self.assertEqual(flags["c1"], [False, True])
        self.assertTrue(all(v == [False] for k, v in flags.items() if k != "c1"))

    def test_last_pending_card_can_repeat(self):
        self.make_cards(1)
        self.start("job-single")
        _, data = self.answer("job-single", 1, "c1", AGAIN)
        self.assertEqual(data["next_card"]["card_id"], "c1")
        self.assertTrue(data["next_card"]["is_review"])

    def test_same_seq_twice_returns_same_response_and_applies_once(self):
        cards = self.make_cards(3)
        _, data = self.start("job-dup")
        first = self.answer("job-dup", 1, data["next_card"]["card_id"], GOOD)
        second = self.answer("job-dup", 1, data["next_card"]["card_id"], GOOD)
        self.assertEqual(first[0], 200)
        self.assertEqual(first, second)
        self.assertEqual(LearnAnswer.objects.filter(session__job_id="job-dup").count(), 1)
        self.assertEqual(FlashcardSchedule.objects.get(user=self.user, card=cards[0]).reps, 1)

    def test_seq_gap_returns_409_with_expected_seq(self):
        self.make_cards(3)
        _, data = self.start("job-gap")
        code, body = self.answer("job-gap", 3, data["next_card"]["card_id"], GOOD)
        self.assertEqual(code, 409)
        self.assertEqual(body["expected_seq"], 1)

    def test_rating_out_of_range_is_400(self):
        self.make_cards(2)
        _, data = self.start("job-400")
        for rating in (0, 5):
            code, _ = self.answer("job-400", 1, data["next_card"]["card_id"], rating)
            self.assertEqual(code, 400, rating)
        self.assertEqual(self.answer("job-400", 1, data["next_card"]["card_id"], action="nope")[0], 400)
        self.assertEqual(self.answer("job-400", 1, data["next_card"]["card_id"])[0], 400)  # neither rating nor action

    def test_two_sessions_do_not_mix_seq(self):
        self.make_cards(3)
        _, a = self.start("job-A")
        _, b = self.start("job-B")
        self.assertEqual(self.answer("job-A", 1, a["next_card"]["card_id"], GOOD)[0], 200)
        self.assertEqual(self.answer("job-A", 2, "c2", GOOD)[0], 200)
        code, body = self.answer("job-B", 1, b["next_card"]["card_id"], GOOD)  # B keeps its own seq
        self.assertEqual(code, 200)
        self.assertEqual(body["ack_seq"], 1)
        self.assertEqual(body["next_card"]["card_id"], "c2")

    def test_skip_does_not_schedule_and_requeues(self):
        cards = self.make_cards(3)
        self.start("job-skip")
        code, data = self.answer("job-skip", 1, "c1", action="skip")
        self.assertEqual(code, 200)
        self.assertEqual(data["next_card"]["card_id"], "c2")
        self.assertFalse(FlashcardSchedule.objects.filter(card=cards[0]).exists())
        self.assertEqual(data["session"]["reviewed"], 0)

    def test_resume_returns_current_card_and_wrong_card_is_409(self):
        self.make_cards(3)
        self.start("job-resume")
        self.answer("job-resume", 1, "c1", GOOD)
        _, resumed = self.start("job-resume")
        self.assertEqual((resumed["ack_seq"], resumed["next_card"]["card_id"]), (1, "c2"))
        code, body = self.answer("job-resume", 2, "c3", GOOD)
        self.assertEqual(code, 409)
        self.assertEqual(body["expected_card_id"], "c2")

    def test_good_schedules_next_review_in_days(self):
        cards = self.make_cards(1)
        self.start("job-sched")
        self.answer("job-sched", 1, "c1", GOOD)
        schedule = FlashcardSchedule.objects.get(user=self.user, card=cards[0])
        self.assertEqual(schedule.state, "review")
        self.assertGreater((schedule.due_at - schedule.last_reviewed_at).days, 2)

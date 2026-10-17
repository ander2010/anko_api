"""
F-05: Learn mode must advance after feedback.

A fake flashcard WebSocket service reproduces the real protocol of
anko_services (per-connection seq, in-flight card, "seq mismatch" rejection,
"ack" after applying feedback) so the anko_api client is exercised end to end.
"""
import asyncio
import base64
import hashlib
import json
import threading
from unittest.mock import patch

import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from api.models import Deck, Project, User
from api.services import flashcards_ws
from api.services.flashcards_ws import RATING_EASY, RATING_GOOD, RATING_HARD


class FakeFlashcardService:
    """In-memory imitation of anko_services' /ws/flashcards/{job_id} endpoint."""

    def __init__(self, card_ids):
        self.queue = list(card_ids)   # due cards, in order
        self.inflight = None          # {"seq": int, "card_id": int}
        self.loop = asyncio.new_event_loop()
        self.port = None
        ready = threading.Event()

        async def start():
            self.server = await websockets.serve(self.handler, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        self.thread = threading.Thread(target=lambda: (self.loop.run_until_complete(start()), self.loop.run_forever()), daemon=True)
        self.thread.start()
        ready.wait(5)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)

    async def handler(self, ws):
        sub = json.loads(await ws.recv())
        session = {"seq": int(sub.get("last_seq") or 0)}
        await ws.send(json.dumps({"message_type": "accepted"}))

        async def send_next():
            if not self.queue:
                await ws.send(json.dumps({"message_type": "idle"}))
                await ws.send(json.dumps({"message_type": "done"}))
                return False
            session["seq"] += 1
            card_id = self.queue[0]
            self.inflight = {"seq": session["seq"], "card_id": card_id}
            await ws.send(json.dumps({"message_type": "card", "seq": session["seq"], "kind": "new",
                                      "card": {"id": card_id, "card_id": card_id, "front": f"Q{card_id}"}}))
            return True

        if self.inflight:  # reconnect: resend in-flight card with its seq
            await ws.send(json.dumps({"message_type": "card", "seq": self.inflight["seq"], "kind": "new",
                                      "card": {"id": self.inflight["card_id"], "card_id": self.inflight["card_id"]}}))
        elif not await send_next():
            return

        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("message_type") != "card_feedback":
                    continue
                if msg["seq"] != session["seq"]:
                    await ws.send(json.dumps({"error": "seq mismatch"}))
                    continue
                if not self.inflight or msg["card_id"] != self.inflight["card_id"]:
                    await ws.send(json.dumps({"error": "card mismatch"}))
                    continue
                card_id = self.queue.pop(0)
                if msg["rating"] == RATING_HARD:
                    self.queue.append(card_id)  # rescheduled: comes back later in the session
                self.inflight = None
                await ws.send(json.dumps({"message_type": "ack", "seq": msg["seq"], "card_id": card_id}))
                if not await send_next():
                    return
        except websockets.ConnectionClosed:
            return


def decrypt(body, token):
    def b64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    key = hashlib.sha256(token.encode()).digest()
    return json.loads(AESGCM(key).decrypt(b64(body["_n"]), b64(body["_t"]), None))


class LearnModeTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("f05", "f05@test.com", "Pass123!")
        self.token = Token.objects.create(user=self.user).key
        project = Project.objects.create(title="P", owner=self.user)
        self.deck = Deck.objects.create(project=project, owner=self.user, title="Deck", visibility="private", external_job_id="job-f05")
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")

    def start_service(self, cards):
        self.service = FakeFlashcardService(cards)
        self.addCleanup(self.service.stop)
        patcher = patch.object(flashcards_ws, "BASE_WS", f"ws://127.0.0.1:{self.service.port}/ws/flashcards")
        patcher.start()
        self.addCleanup(patcher.stop)

    def pull(self, last_seq):
        r = self.client.post("/api/flashcards/ws-pull-card/", {"deck_id": self.deck.id, "last_seq": last_seq}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        body = r.json()
        body = decrypt(body, self.token) if "_n" in body else body
        return body.get("data", body)  # encrypted envelope wraps the payload in {"data": ...}

    def rate(self, card, rating):
        return self.client.post("/api/flashcards/ws-push-feedback/", {
            "deck_id": self.deck.id, "seq": card["seq"], "card_id": card["card"]["card_id"], "rating": rating,
        }, format="json")

    def run_session(self, ratings):
        seen, last_seq = [], 0
        for _ in range(20):
            data = self.pull(last_seq)
            if data["message_type"] == "done":
                return seen, True
            card = data
            seen.append(card["card"]["card_id"])
            rating = ratings.get(len(seen), RATING_GOOD)
            self.assertEqual(self.rate(card, rating).status_code, 200)
            last_seq = card["seq"]
        return seen, False

    def test_all_good_walks_every_card_once_and_ends(self):
        self.start_service([1, 2, 3, 4, 5])
        seen, finished = self.run_session({})
        self.assertEqual(seen, [1, 2, 3, 4, 5])
        self.assertTrue(finished)

    def test_hard_card_comes_back_later(self):
        self.start_service([1, 2, 3])
        seen, finished = self.run_session({1: RATING_HARD})
        self.assertEqual(seen, [1, 2, 3, 1])
        self.assertTrue(finished)

    def test_repeated_or_older_seq_is_rejected(self):
        self.start_service([1, 2])
        card = self.pull(0)
        self.assertEqual(self.rate(card, RATING_GOOD).status_code, 200)
        self.assertEqual(self.rate(card, RATING_GOOD).status_code, 409)  # same seq again

    def test_invalid_rating_is_400(self):
        self.start_service([1])
        card = self.pull(0)
        self.assertEqual(self.rate(card, 3).status_code, 400)
        self.assertEqual(self.rate(card, RATING_EASY).status_code, 200)

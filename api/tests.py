from django.core.management import call_command
from rest_framework import status
from rest_framework.test import APITestCase

from api.models import (
    Deck,
    DeckShare,
    Flashcard,
    Project,
    Resource,
    SavedDeck,
    User,
)
from api.urls import router


class RbacAdminPanelTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_user(
            username="admin_user",
            email="admin@example.com",
            password="StrongPass123!",
            is_staff=True,
        )
        cls.user_a = User.objects.create_user(
            username="user_a",
            email="user_a@example.com",
            password="StrongPass123!",
        )
        cls.user_b = User.objects.create_user(
            username="user_b",
            email="user_b@example.com",
            password="StrongPass123!",
        )

        cls.project_a = Project.objects.create(title="Project A", owner=cls.user_a)
        cls.project_b = Project.objects.create(title="Project B", owner=cls.user_b)

        cls.deck_a = Deck.objects.create(
            project=cls.project_a,
            owner=cls.user_a,
            title="Deck A",
            visibility="private",
        )
        cls.deck_b = Deck.objects.create(
            project=cls.project_b,
            owner=cls.user_b,
            title="Deck B",
            visibility="private",
        )
        cls.deck_c = Deck.objects.create(
            project=cls.project_b,
            owner=cls.user_b,
            title="Deck C",
            visibility="private",
        )

        cls.share_b_to_a = DeckShare.objects.create(
            deck=cls.deck_b,
            shared_with=cls.user_a,
            access="view",
        )
        cls.share_c_to_admin = DeckShare.objects.create(
            deck=cls.deck_c,
            shared_with=cls.admin,
            access="view",
        )

        cls.saved_a = SavedDeck.objects.create(user=cls.user_a, deck=cls.deck_a)
        cls.saved_b = SavedDeck.objects.create(user=cls.user_b, deck=cls.deck_b)

        cls.card_a = Flashcard.objects.create(deck=cls.deck_a, front="A1", back="A1B")
        cls.card_b = Flashcard.objects.create(deck=cls.deck_b, front="B1", back="B1B")
        cls.card_c = Flashcard.objects.create(deck=cls.deck_c, front="C1", back="C1B")

        call_command("seed_routes_rbac")

    def _extract_ids(self, response):
        payload = response.data
        if isinstance(payload, dict) and "results" in payload:
            payload = payload["results"]
        if not isinstance(payload, list):
            return []
        return [item.get("id") for item in payload if isinstance(item, dict)]

    def test_admin_rbac_resources_exist(self):
        required = [
            "dashboard.admin.batteries",
            "dashboard.admin.decks",
            "dashboard.admin.flashcards",
            "dashboard.admin.deck-shares",
            "dashboard.admin.saved-decks",
        ]
        for key in required:
            self.assertTrue(Resource.objects.filter(key=key).exists(), key)

    def test_admin_panels_are_registered_in_router(self):
        expected_prefixes = {
            "users",
            "resources",
            "permissions",
            "roles",
            "plans",
            "plan-limits",
            "subscriptions",
            "battery-shares",
            "saved-batteries",
            "invites",
            "batteries",
            "decks",
            "flashcards",
            "deck-shares",
            "saved-decks",
        }
        registered = {prefix for prefix, _, _ in router.registry}
        missing = expected_prefixes - registered
        self.assertFalse(missing, f"Missing API routes for admin panels: {sorted(missing)}")

    def test_decks_requires_authentication(self):
        response = self.client.get("/api/decks/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_decks_non_admin_is_scoped(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.get("/api/decks/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.deck_a.id, ids)  # owner
        self.assertIn(self.deck_b.id, ids)  # shared
        self.assertNotIn(self.deck_c.id, ids)  # not owned or shared

    def test_decks_admin_is_global(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/decks/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.deck_a.id, ids)
        self.assertIn(self.deck_b.id, ids)
        self.assertIn(self.deck_c.id, ids)

    def test_flashcards_non_admin_requires_deck_filter(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.get("/api/flashcards/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self._extract_ids(response), [])

    def test_flashcards_non_admin_checks_access(self):
        self.client.force_authenticate(user=self.user_a)

        own_response = self.client.get(f"/api/flashcards/?deck={self.deck_a.id}")
        self.assertEqual(own_response.status_code, status.HTTP_200_OK)
        own_ids = set(self._extract_ids(own_response))
        self.assertIn(self.card_a.id, own_ids)

        shared_response = self.client.get(f"/api/flashcards/?deck={self.deck_b.id}")
        self.assertEqual(shared_response.status_code, status.HTTP_200_OK)
        shared_ids = set(self._extract_ids(shared_response))
        self.assertIn(self.card_b.id, shared_ids)

        forbidden_response = self.client.get(f"/api/flashcards/?deck={self.deck_c.id}")
        self.assertEqual(forbidden_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_flashcards_admin_is_global(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/flashcards/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.card_a.id, ids)
        self.assertIn(self.card_b.id, ids)
        self.assertIn(self.card_c.id, ids)

    def test_deck_shares_non_admin_is_scoped(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.get("/api/deck-shares/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.share_b_to_a.id, ids)
        self.assertNotIn(self.share_c_to_admin.id, ids)

    def test_deck_shares_admin_is_global(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/deck-shares/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.share_b_to_a.id, ids)
        self.assertIn(self.share_c_to_admin.id, ids)

    def test_saved_decks_non_admin_is_scoped(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.get("/api/saved-decks/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.saved_a.id, ids)
        self.assertNotIn(self.saved_b.id, ids)

    def test_saved_decks_admin_is_global(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/saved-decks/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        ids = set(self._extract_ids(response))
        self.assertIn(self.saved_a.id, ids)
        self.assertIn(self.saved_b.id, ids)

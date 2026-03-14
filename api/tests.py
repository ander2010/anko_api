import io
import shutil
import tempfile

from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import override_settings
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
    def setUpClass(cls):
        super().setUpClass()
        cls._media_root = tempfile.mkdtemp(prefix="anko-test-media-")
        cls._override = override_settings(
            DEFAULT_FILE_STORAGE="django.core.files.storage.FileSystemStorage",
            MEDIA_ROOT=cls._media_root,
        )
        cls._override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        shutil.rmtree(cls._media_root, ignore_errors=True)
        super().tearDownClass()

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

    def _make_test_image(self, *, width=600, height=600, fmt="PNG", color=(32, 128, 192)):
        buffer = io.BytesIO()
        image = Image.new("RGB", (width, height), color)
        image.save(buffer, format=fmt)
        return SimpleUploadedFile(
            name=f"card-back.{fmt.lower()}",
            content=buffer.getvalue(),
            content_type=f"image/{fmt.lower()}",
        )

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

    def test_deck_owner_can_add_rich_card_with_back_image(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image()

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Question with image",
                "back": "Explanation under image",
                "notes": "teacher note",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.deck_a.refresh_from_db()
        self.assertTrue(self.deck_a.external_job_id)

        card = Flashcard.objects.exclude(id=self.card_a.id).get(deck=self.deck_a, front="Question with image")
        self.assertEqual(card.back, "Explanation under image")
        self.assertEqual(card.notes, "teacher note")
        self.assertTrue(card.back_image)
        self.assertTrue(card.back_image_size_bytes)
        self.assertEqual(card.back_image_original_size_bytes, card.back_image_size_bytes)
        self.assertFalse(card.back_image_was_optimized)
        self.assertEqual(card.back_image_width, 600)
        self.assertEqual(card.back_image_height, 600)
        self.assertEqual(card.job_id, self.deck_a.external_job_id)
        self.assertEqual(card.user_id, str(self.user_a.id))
        self.assertTrue(card.card_id)
        self.assertEqual(response.data["card"]["backImageRenderHint"], "image_top_text_bottom")
        self.assertEqual(response.data["card"]["backImageWarnings"], [])
        self.assertEqual(response.data["card"]["back_image_width"], 600)
        self.assertEqual(response.data["card"]["back_image_height"], 600)
        self.assertEqual(response.data["card"]["back_image_size_bytes"], card.back_image_size_bytes)
        self.assertIn("image_constraints", response.data)

    def test_deck_owner_can_add_rich_card_with_image_only_back(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image()

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Image-only answer",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        card = Flashcard.objects.get(deck=self.deck_a, front="Image-only answer")
        self.assertEqual(card.back, "")
        self.assertTrue(card.back_image)

    def test_add_rich_card_auto_optimizes_large_image(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image(width=2600, height=2600)

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Needs optimization",
                "back": "Optimized explanation",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        card = Flashcard.objects.get(deck=self.deck_a, front="Needs optimization")
        self.assertTrue(card.back_image_was_optimized)
        self.assertTrue(card.back_image_original_size_bytes)
        self.assertTrue(card.back_image_size_bytes)
        self.assertLessEqual(card.back_image_width, 2000)
        self.assertLessEqual(card.back_image_height, 2000)
        self.assertEqual(response.data["card"]["backImageRenderHint"], "optimized_image")
        self.assertIn("automatically optimized", " ".join(response.data["card"]["backImageWarnings"]).lower())

    def test_add_rich_card_returns_tall_image_warning(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image(width=500, height=1300)

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Tall image",
                "back": "Short explanation",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["card"]["backImageRenderHint"], "tall_image")
        self.assertTrue(response.data["card"]["backImageWarnings"])

    def test_add_rich_card_returns_small_text_space_warning(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image()
        long_back = "A" * 260

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Long explanation",
                "back": long_back,
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["card"]["backImageRenderHint"], "small_text_space")
        self.assertTrue(response.data["card"]["backImageWarnings"])

    def test_add_rich_card_requires_owner(self):
        self.client.force_authenticate(user=self.user_b)
        image = self._make_test_image()

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Forbidden",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_rich_card_requires_back_text_or_image(self):
        self.client.force_authenticate(user=self.user_a)

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Missing answer",
                "back": "",
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rich_card_config_returns_constraints(self):
        self.client.force_authenticate(user=self.user_a)

        response = self.client.get("/api/decks/rich-card-config/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["image_constraints"]["max_file_size_mb"], 3.0)
        self.assertEqual(response.data["render_guidance"]["image_fit"], "contain")
        self.assertTrue(response.data["image_constraints"]["auto_optimize_when_needed"])

    def test_add_rich_card_rejects_small_image(self):
        self.client.force_authenticate(user=self.user_a)
        image = self._make_test_image(width=200, height=200)

        response = self.client.post(
            f"/api/decks/{self.deck_a.id}/add-rich-card/",
            {
                "front": "Too small",
                "back_image": image,
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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

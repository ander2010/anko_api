import io
import os
import requests
import shutil
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PIL import Image
from botocore.exceptions import ClientError
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from api.models import (
    Battery,
    BatteryQuestion,
    Deck,
    DeckShare,
    Document,
    Flashcard,
    ProcessArtifact,
    ProcessRun,
    ProcessStepRun,
    Project,
    Resource,
    SavedDeck,
    User,
)
from api.services.auto_generate_workflow import (
    AUTO_STAGE_KEYS,
    cleanup_empty_generated_battery,
    cleanup_empty_generated_deck,
    _finalize_completed_battery_step,
    _finalize_completed_flashcard_step,
    _document_has_inflight_processing,
    _step_finalize_callback_status,
    _step_requires_finalize_callback,
)
from api.services.hope_broker import (
    dispatch_battery_generation,
    dispatch_flashcard_generation,
    dispatch_process_document,
)
from api.services.http_retry import post_with_retry
from api.throttles import (
    BurstAnonRateThrottle,
    BurstUserRateThrottle,
    SustainedAnonRateThrottle,
    SustainedUserRateThrottle,
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

    def test_project_documents_infers_type_from_uploaded_filename(self):
        self.client.force_authenticate(user=self.user_a)
        upload = SimpleUploadedFile("study-notes.txt", b"plain text", content_type="text/plain")

        with patch("api.views.ProjectViewSet._process_document_external", return_value=({"success": True}, None)):
            response = self.client.post(
                f"/api/projects/{self.project_a.id}/documents/",
                {"files": [upload]},
                format="multipart",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, filename="study-notes.txt")
        self.assertEqual(document.type, "TXT")
        self.assertEqual(response.data["uploaded"][0]["type"], "TXT")

    def test_project_documents_infers_supported_pptx_type_from_uploaded_filename(self):
        self.client.force_authenticate(user=self.user_a)
        upload = SimpleUploadedFile(
            "deck-slides.pptx",
            b"presentation-bytes",
            content_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )

        with patch("api.views.ProjectViewSet._process_document_external", return_value=({"success": True}, None)):
            response = self.client.post(
                f"/api/projects/{self.project_a.id}/documents/",
                {"files": [upload]},
                format="multipart",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, filename="deck-slides.pptx")
        self.assertEqual(document.type, "PPTX")
        self.assertEqual(response.data["uploaded"][0]["type"], "PPTX")

    def test_document_register_infers_supported_doc_type_from_filename_over_payload(self):
        self.client.force_authenticate(user=self.user_a)
        fake_response = Mock()
        fake_response.json.return_value = {"job_id": "job-doc-register"}

        with patch("api.views._post_with_logging", return_value=fake_response):
            response = self.client.post(
                "/api/documents/register/",
                {
                    "project_id": self.project_a.id,
                    "filename": "report.doc",
                    "file_key": "documents/1/1/report.doc",
                    "size": 1234,
                    "type": "PDF",
                    "hash": "hash-doc-register",
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, hash="hash-doc-register")
        self.assertEqual(document.type, "DOC")
        self.assertEqual(response.data["document"]["type"], "DOC")

    def test_project_documents_infers_supported_docx_type_from_uploaded_filename(self):
        self.client.force_authenticate(user=self.user_a)
        upload = SimpleUploadedFile(
            "chapter-notes.docx",
            b"wordprocessing-bytes",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

        with patch("api.views.ProjectViewSet._process_document_external", return_value=({"success": True}, None)):
            response = self.client.post(
                f"/api/projects/{self.project_a.id}/documents/",
                {"files": [upload]},
                format="multipart",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, filename="chapter-notes.docx")
        self.assertEqual(document.type, "DOCX")
        self.assertEqual(response.data["uploaded"][0]["type"], "DOCX")

    def test_document_register_infers_supported_pptx_type_from_filename_over_payload(self):
        self.client.force_authenticate(user=self.user_a)
        fake_response = Mock()
        fake_response.json.return_value = {"job_id": "job-pptx-register"}

        with patch("api.views._post_with_logging", return_value=fake_response):
            response = self.client.post(
                "/api/documents/register/",
                {
                    "project_id": self.project_a.id,
                    "filename": "slides.pptx",
                    "file_key": "documents/1/1/slides.pptx",
                    "size": 4321,
                    "type": "PDF",
                    "hash": "hash-pptx-register",
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, hash="hash-pptx-register")
        self.assertEqual(document.type, "PPTX")
        self.assertEqual(response.data["document"]["type"], "PPTX")

    def test_document_register_infers_supported_docx_type_from_filename_over_payload(self):
        self.client.force_authenticate(user=self.user_a)
        fake_response = Mock()
        fake_response.json.return_value = {"job_id": "job-docx-register"}

        with patch("api.views._post_with_logging", return_value=fake_response):
            response = self.client.post(
                "/api/documents/register/",
                {
                    "project_id": self.project_a.id,
                    "filename": "report.docx",
                    "file_key": "documents/1/1/report.docx",
                    "size": 1234,
                    "type": "PDF",
                    "hash": "hash-docx-register",
                },
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = Document.objects.get(project=self.project_a, hash="hash-docx-register")
        self.assertEqual(document.type, "DOCX")
        self.assertEqual(response.data["document"]["type"], "DOCX")

    def test_project_documents_rejects_unsupported_xlsx_type(self):
        self.client.force_authenticate(user=self.user_a)
        upload = SimpleUploadedFile(
            "financial-model.xlsx",
            b"spreadsheet-bytes",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        response = self.client.post(
            f"/api/projects/{self.project_a.id}/documents/",
            {"files": [upload]},
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Supported document types", response.data["detail"])

    def test_document_delete_removes_converted_source_and_pdf_variants(self):
        self.client.force_authenticate(user=self.user_a)
        document = Document.objects.create(
            project=self.project_a,
            filename="New Microsoft Word Document.docx",
            type="DOC",
            size=639640,
            hash="hash-delete-doc-variants",
            uploaded_by=self.user_a,
        )
        document.file.name = "documents/1/4/New_Microsoft_Word_Document.docx"
        document.save(update_fields=["file"])

        existing_keys = {
            "documents/1/4/New_Microsoft_Word_Document.docx",
            "documents/1/4/New_Microsoft_Word_Document.pdf",
        }
        mock_client = Mock()

        def head_object_side_effect(*, Bucket, Key):
            if Key not in existing_keys:
                raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        mock_client.head_object.side_effect = head_object_side_effect
        mock_client.get_paginator.return_value.paginate.return_value = []

        with patch("api.views.DocumentViewSet._build_supabase_s3_client", return_value=(mock_client, "anko")):
            response = self.client.delete(f"/api/documents/{document.id}/")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Document.objects.filter(id=document.id).exists())
        deleted_keys = [call.kwargs["Key"] for call in mock_client.delete_object.call_args_list]
        self.assertEqual(
            deleted_keys,
            [
                "documents/1/4/New_Microsoft_Word_Document.docx",
                "documents/1/4/New_Microsoft_Word_Document.pdf",
            ],
        )

    def test_document_delete_uses_non_pdf_extension_even_if_row_type_is_stale_pdf(self):
        self.client.force_authenticate(user=self.user_a)
        document = Document.objects.create(
            project=self.project_a,
            filename="slides.pptx",
            type="PDF",
            size=4321,
            hash="hash-delete-pptx-stale-pdf",
            uploaded_by=self.user_a,
        )
        document.file.name = "documents/1/1/slides.pptx"
        document.save(update_fields=["file"])

        existing_keys = {
            "documents/1/1/slides.pptx",
            "documents/1/1/slides.pdf",
        }
        mock_client = Mock()

        def head_object_side_effect(*, Bucket, Key):
            if Key not in existing_keys:
                raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        mock_client.head_object.side_effect = head_object_side_effect
        mock_client.get_paginator.return_value.paginate.return_value = []

        with patch("api.views.DocumentViewSet._build_supabase_s3_client", return_value=(mock_client, "anko")):
            response = self.client.delete(f"/api/documents/{document.id}/")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        deleted_keys = [call.kwargs["Key"] for call in mock_client.delete_object.call_args_list]
        self.assertEqual(
            deleted_keys,
            [
                "documents/1/1/slides.pptx",
                "documents/1/1/slides.pdf",
            ],
        )

    def test_authenticated_requests_are_globally_throttled(self):
        throttle_rates = {
            "user_burst": "2/min",
            "user_sustained": "100/hour",
            "anon_burst": "100/min",
            "anon_sustained": "100/hour",
        }
        with patch.object(BurstUserRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(SustainedUserRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(BurstAnonRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(SustainedAnonRateThrottle, "THROTTLE_RATES", throttle_rates):
            cache.clear()
            self.client.force_authenticate(user=self.user_a)

            first = self.client.get("/api/decks/")
            second = self.client.get("/api/decks/")
            third = self.client.get("/api/decks/")

            self.assertEqual(first.status_code, status.HTTP_200_OK)
            self.assertEqual(second.status_code, status.HTTP_200_OK)
            self.assertEqual(third.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_anonymous_requests_are_globally_throttled(self):
        throttle_rates = {
            "anon_burst": "2/min",
            "anon_sustained": "100/hour",
            "user_burst": "100/min",
            "user_sustained": "100/hour",
        }
        with patch.object(BurstUserRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(SustainedUserRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(BurstAnonRateThrottle, "THROTTLE_RATES", throttle_rates), \
             patch.object(SustainedAnonRateThrottle, "THROTTLE_RATES", throttle_rates):
            cache.clear()

            first = self.client.get("/api/plans/")
            second = self.client.get("/api/plans/")
            third = self.client.get("/api/plans/")

            self.assertEqual(first.status_code, status.HTTP_200_OK)
            self.assertEqual(second.status_code, status.HTTP_200_OK)
            self.assertEqual(third.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

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

    def test_flashcards_list_prioritizes_new_cards_when_older_rows_have_null_created_at(self):
        self.client.force_authenticate(user=self.user_a)

        Flashcard.objects.filter(id=self.card_a.id).update(created_at=None)
        for index in range(9):
            Flashcard.objects.create(
                deck=self.deck_a,
                front=f"Legacy {index}",
                back="Older imported card",
                created_at=None,
            )

        image_card = Flashcard.objects.create(
            deck=self.deck_a,
            front="Newest rich card",
            back="Has image",
            back_image=self._make_test_image(),
            back_image_original_size_bytes=1,
            back_image_size_bytes=1,
            back_image_width=600,
            back_image_height=600,
        )

        response = self.client.get(f"/api/flashcards/?deck={self.deck_a.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = response.data["results"] if isinstance(response.data, dict) else response.data
        ids = [item["id"] for item in payload]
        self.assertIn(image_card.id, ids)
        image_payload = next(item for item in payload if item["id"] == image_card.id)
        self.assertEqual(image_payload["backImageRenderHint"], "image_top_text_bottom")
        self.assertIsNotNone(image_payload["backImageUrl"])

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

    def test_download_flashcards_pdf_supports_back_image(self):
        self.client.force_authenticate(user=self.user_a)
        card = Flashcard.objects.create(
            deck=self.deck_a,
            front="Front with image back",
            back="Explanation under exported image",
            back_image=self._make_test_image(width=900, height=700),
            back_image_original_size_bytes=1,
            back_image_size_bytes=1,
            back_image_width=900,
            back_image_height=700,
        )

        response = self.client.get(f"/api/decks/{self.deck_a.id}/download-flashcards-pdf/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertTrue(len(response.content) > 0)

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

    def test_ws_pull_card_enriches_learning_payload_with_image_metadata(self):
        self.client.force_authenticate(user=self.user_a)
        self.deck_a.external_job_id = "job-learn-1"
        self.deck_a.save(update_fields=["external_job_id"])

        image_card = Flashcard.objects.create(
            deck=self.deck_a,
            front="Learn with image",
            back="Answer",
            job_id="job-learn-1",
            card_id="pipeline-card-1",
            back_image=self._make_test_image(),
            back_image_original_size_bytes=1234,
            back_image_size_bytes=987,
            back_image_width=600,
            back_image_height=600,
        )

        with patch("api.views.async_to_sync") as async_to_sync_mock:
            async_to_sync_mock.return_value = lambda **kwargs: {
                "message_type": "card",
                "seq": 4,
                "card": {
                    "card_id": "pipeline-card-1",
                    "front": "Learn with image",
                    "back": "Answer",
                },
            }

            response = self.client.post(
                "/api/flashcards/ws-pull-card/",
                {"deck_id": self.deck_a.id},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = response.data["card"]
        self.assertEqual(payload["id"], image_card.id)
        self.assertEqual(payload["back_image_size_bytes"], 987)
        self.assertEqual(payload["back_image_original_size_bytes"], 1234)
        self.assertEqual(payload["back_image_width"], 600)
        self.assertEqual(payload["back_image_height"], 600)
        self.assertIsNotNone(payload["backImageUrl"])

    def test_admin_delete_flashcard_removes_image_and_empty_folder(self):
        self.client.force_authenticate(user=self.admin)
        image_card = Flashcard.objects.create(
            deck=self.deck_a,
            front="Delete me",
            back="Cleanup image",
            card_id="folder-cleanup-card",
            back_image=self._make_test_image(),
        )
        image_path = image_card.back_image.path
        folder_path = os.path.dirname(image_path)

        self.assertTrue(os.path.exists(image_path))
        self.assertTrue(os.path.isdir(folder_path))

        response = self.client.delete(f"/api/admin/flashcards/{image_card.id}/")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Flashcard.objects.filter(id=image_card.id).exists())
        self.assertFalse(os.path.exists(image_path))
        self.assertFalse(os.path.exists(folder_path))

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


class AutoGenerateWorkflowCallbackTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="workflow_user",
            email="workflow@example.com",
            password="StrongPass123!",
        )
        self.project = Project.objects.create(title="Workflow Project", owner=self.user)
        self.deck = Deck.objects.create(project=self.project, owner=self.user, title="Workflow Deck")
        self.battery = Battery.objects.create(name="Workflow Battery", status="Draft")

    def test_flashcard_step_requires_finalize_callback(self):
        step = SimpleNamespace(step_key=AUTO_STAGE_KEYS["generate_flashcards"])
        self.assertTrue(_step_requires_finalize_callback(step))

    def test_flashcard_finalize_status_reads_deck_callback_state(self):
        step = SimpleNamespace(
            step_key=AUTO_STAGE_KEYS["generate_flashcards"],
            result_payload={"deck_id": self.deck.id},
            input_payload={},
        )

        self.assertEqual(_step_finalize_callback_status(step), "")

        self.deck.config = {"last_generation_status": "completed"}
        self.deck.save(update_fields=["config"])

        self.assertEqual(_step_finalize_callback_status(step), "completed")

    def test_battery_finalize_status_reads_battery_callback_state(self):
        step = SimpleNamespace(
            step_key=AUTO_STAGE_KEYS["generate_battery"],
            result_payload={"battery_id": self.battery.id},
            input_payload={},
        )

        self.assertEqual(_step_finalize_callback_status(step), "")

        self.battery.config = {"last_generation_status": "completed"}
        self.battery.save(update_fields=["config"])

        self.assertEqual(_step_finalize_callback_status(step), "completed")

    @patch("api.views.time.sleep", return_value=None)
    @patch("api.views._fetch_generated_flashcards_from_hope")
    def test_sync_generated_flashcards_retries_empty_fetches(self, fetch_mock, _sleep_mock):
        from api.views import DeckViewSet

        fetch_mock.side_effect = [
            [],
            [],
            [
                {
                    "card_id": "card-1",
                    "front": "Front",
                    "back": "Back",
                    "tags": ["tag-1"],
                }
            ],
        ]

        result = DeckViewSet._sync_generated_flashcards(deck=self.deck, job_id="hope-job-1")

        self.assertEqual(fetch_mock.call_count, 3)
        self.assertEqual(result["card_count"], 1)
        self.assertEqual(result["cards_synced"], 1)
        saved_card = Flashcard.objects.get(deck=self.deck)
        self.assertEqual(saved_card.job_id, "hope-job-1")
        self.assertEqual(saved_card.front, "Front")
        self.assertEqual(saved_card.back, "Back")

    def test_document_with_active_job_reuses_existing_processing(self):
        document = Document.objects.create(
            project=self.project,
            filename="active.pdf",
            type="PDF",
            size=1,
            hash="hash-active",
            status="processing",
            job_id="hope-job-1",
            uploaded_by=self.user,
        )

        self.assertTrue(_document_has_inflight_processing(document))

    def test_document_without_job_does_not_reuse_processing(self):
        document = Document.objects.create(
            project=self.project,
            filename="pending.pdf",
            type="PDF",
            size=1,
            hash="hash-pending",
            status="pending",
            uploaded_by=self.user,
        )

        self.assertFalse(_document_has_inflight_processing(document))

    def test_cleanup_empty_generated_battery_deletes_placeholder_and_artifacts(self):
        run = ProcessRun.objects.create(workflow_key="test-workflow")
        artifact = ProcessArtifact.objects.create(
            run=run,
            artifact_key=f"battery:{self.battery.id}",
            artifact_type="battery",
            resource_type="battery",
            resource_id=str(self.battery.id),
        )

        deleted = cleanup_empty_generated_battery(battery=self.battery)

        self.assertTrue(deleted)
        self.assertFalse(Battery.objects.filter(id=self.battery.id).exists())
        self.assertFalse(ProcessArtifact.objects.filter(id=artifact.id).exists())

    def test_cleanup_empty_generated_deck_deletes_placeholder_and_artifacts(self):
        run = ProcessRun.objects.create(workflow_key="test-workflow")
        artifact = ProcessArtifact.objects.create(
            run=run,
            artifact_key=f"deck:{self.deck.id}",
            artifact_type="deck",
            resource_type="deck",
            resource_id=str(self.deck.id),
        )

        deleted = cleanup_empty_generated_deck(deck=self.deck)

        self.assertTrue(deleted)
        self.assertFalse(Deck.objects.filter(id=self.deck.id).exists())
        self.assertFalse(ProcessArtifact.objects.filter(id=artifact.id).exists())

    @patch("api.views.BatteryViewSet.save_questions_from_qa_pairs")
    def test_finalize_completed_battery_step_deletes_empty_battery(self, save_questions_mock):
        save_questions_mock.return_value = {
            "battery_id": self.battery.id,
            "job_id": "battery-job-1",
            "qa_pairs_found": 0,
            "questions_created": 0,
            "options_created": 0,
        }
        run = ProcessRun.objects.create(
            workflow_key="collection_auto_generate",
            input_payload={"battery_options": {"question_format": "true_false"}},
        )
        step = ProcessStepRun.objects.create(
            run=run,
            step_key=AUTO_STAGE_KEYS["generate_battery"],
            external_job_id="battery-job-1",
            result_payload={"battery_id": self.battery.id},
        )

        completed = _finalize_completed_battery_step(run_id=run.id, step=step)

        self.assertFalse(completed)
        self.assertFalse(Battery.objects.filter(id=self.battery.id).exists())

    @patch("api.views.DeckViewSet._sync_generated_flashcards")
    def test_finalize_completed_flashcard_step_deletes_empty_deck(self, sync_flashcards_mock):
        sync_flashcards_mock.return_value = {"cards_synced": 0, "card_count": 0}
        run = ProcessRun.objects.create(workflow_key="collection_auto_generate")
        step = ProcessStepRun.objects.create(
            run=run,
            step_key=AUTO_STAGE_KEYS["generate_flashcards"],
            external_job_id="deck-job-1",
            result_payload={"deck_id": self.deck.id},
        )

        completed = _finalize_completed_flashcard_step(run_id=run.id, step=step)

        self.assertFalse(completed)
        self.assertFalse(Deck.objects.filter(id=self.deck.id).exists())


class HttpRetryTests(TestCase):
    @patch("api.services.http_retry.random.uniform", return_value=0.0)
    @patch("api.services.http_retry.time.sleep", return_value=None)
    @patch("api.services.http_retry.requests.post")
    def test_post_with_retry_retries_request_exception(self, post_mock, _sleep_mock, _uniform_mock):
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.headers = {}
        response.content = b"{}"
        post_mock.side_effect = [
            requests.ConnectionError("connection dropped"),
            response,
        ]

        result = post_with_retry(
            "http://hope.test/endpoint",
            payload={"job_id": "job-1"},
            timeout=30,
            label="test_retry_exception",
            logger=Mock(),
            max_attempts=2,
        )

        self.assertIs(result, response)
        self.assertEqual(post_mock.call_count, 2)

    @patch("api.services.http_retry.random.uniform", return_value=0.0)
    @patch("api.services.http_retry.time.sleep", return_value=None)
    @patch("api.services.http_retry.requests.post")
    def test_post_with_retry_retries_retryable_status(self, post_mock, _sleep_mock, _uniform_mock):
        retry_response = Mock()
        retry_response.ok = False
        retry_response.status_code = 503
        retry_response.headers = {}
        retry_response.content = b"busy"
        retry_response.raise_for_status.side_effect = requests.HTTPError("503 busy")

        success_response = Mock()
        success_response.ok = True
        success_response.status_code = 200
        success_response.headers = {}
        success_response.content = b"{}"

        post_mock.side_effect = [retry_response, success_response]

        result = post_with_retry(
            "http://hope.test/endpoint",
            payload={"job_id": "job-2"},
            timeout=30,
            label="test_retry_status",
            logger=Mock(),
            max_attempts=2,
        )

        self.assertIs(result, success_response)
        self.assertEqual(post_mock.call_count, 2)


class HopeBrokerDispatchTests(TestCase):
    @patch("api.services.hope_broker.Redis.from_url")
    @patch("api.services.hope_broker._celery_app")
    def test_dispatch_process_document_enqueues_hope_task_and_progress(self, celery_app_mock, redis_from_url_mock):
        task_result = SimpleNamespace(id="job-doc-1")
        celery_app_mock.return_value.send_task.return_value = task_result
        redis_client = Mock()
        redis_from_url_mock.return_value = redis_client

        result = dispatch_process_document(
            {
                "job_id": "job-doc-1",
                "doc_id": 42,
                "file_path": "media/test.pdf",
                "metadata": {"run_id": "run-1"},
            }
        )

        celery_app_mock.return_value.send_task.assert_called_once_with(
            "pipeline.prepare.dispatch_document",
            args=[
                {
                    "job_id": "job-doc-1",
                    "doc_id": 42,
                    "file_path": "media/test.pdf",
                    "metadata": {"run_id": "run-1"},
                },
                {"run_id": "run-1", "job_id": "job-doc-1", "document_id": 42},
            ],
            task_id="job-doc-1",
            queue="celery",
        )
        redis_client.hset.assert_any_call(
            "job:job-doc-1",
            mapping={
                "doc_id": "42",
                "progress": "0",
                "status": "QUEUED",
                "current_step": "ingestion",
                "process": "process_pdf",
                "task_id": "job-doc-1",
            },
        )
        self.assertEqual(result["job_id"], "job-doc-1")
        self.assertEqual(result["document_id"], 42)

    @patch("api.services.hope_broker.Redis.from_url")
    @patch("api.services.hope_broker._celery_app")
    def test_dispatch_battery_generation_uses_hope_queue_and_progress_doc_ids(self, celery_app_mock, redis_from_url_mock):
        task_result = SimpleNamespace(id="job-battery-1")
        celery_app_mock.return_value.send_task.return_value = task_result
        redis_client = Mock()
        redis_from_url_mock.return_value = redis_client

        result = dispatch_battery_generation(
            {
                "job_id": "job-battery-1",
                "battery_id": 7,
                "title": "Biology Assessment",
                "source_bundle": {"document_ids": ["10", "11"]},
                "metadata": {"callback_url": "http://anko/api/callback"},
            }
        )

        celery_app_mock.return_value.send_task.assert_called_once_with(
            "pipeline.llm.generate_questions",
            args=[
                {
                    "job_id": "job-battery-1",
                    "battery_id": 7,
                    "title": "Biology Assessment",
                    "source_bundle": {"document_ids": ["10", "11"]},
                    "metadata": {"callback_url": "http://anko/api/callback"},
                },
                {"callback_url": "http://anko/api/callback"},
            ],
            task_id="job-battery-1",
            queue="celery",
        )
        redis_client.hset.assert_any_call(
            "job:job-battery-1",
            mapping={
                "doc_id": "10,11",
                "progress": "0",
                "status": "QUEUED",
                "current_step": "generate_question",
                "process": "generate_question",
                "task_id": "job-battery-1",
            },
        )
        self.assertEqual(result["title"], "Biology Assessment")

    @patch("api.services.hope_broker.Redis.from_url")
    @patch("api.services.hope_broker._celery_app")
    def test_dispatch_flashcard_generation_uses_existing_title(self, celery_app_mock, redis_from_url_mock):
        task_result = SimpleNamespace(id="job-deck-1")
        celery_app_mock.return_value.send_task.return_value = task_result
        redis_client = Mock()
        redis_from_url_mock.return_value = redis_client

        result = dispatch_flashcard_generation(
            {
                "job_id": "job-deck-1",
                "deck_id": 5,
                "title": "Biology Flashcards",
                "source_bundle": {"document_ids": ["10"]},
                "metadata": {"callback_url": "http://anko/api/callback"},
            }
        )

        celery_app_mock.return_value.send_task.assert_called_once_with(
            "flashcards.generate",
            args=[
                "job-deck-1",
                {
                    "job_id": "job-deck-1",
                    "deck_id": 5,
                    "title": "Biology Flashcards",
                    "source_bundle": {"document_ids": ["10"]},
                    "metadata": {"callback_url": "http://anko/api/callback"},
                },
            ],
            task_id="job-deck-1",
            queue="celery",
        )
        redis_client.hset.assert_any_call(
            "job:job-deck-1",
            mapping={
                "doc_id": "10",
                "progress": "0",
                "status": "QUEUED",
                "current_step": "flashcard_generation",
                "task_id": "job-deck-1",
                "title": "Biology Flashcards",
            },
        )
        self.assertEqual(result["deck_id"], 5)

"""Phase 7 — Document Intelligence ViewSets."""

from __future__ import annotations

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.document_intelligence_service import (
    DocumentIntelligenceService,
)
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise.serializers.document_intelligence import (
    ChangeImpactAnalysisSerializer,
    DocumentVersionSerializer,
    KnowledgeGraphSerializer,
    KnowledgeNodeSerializer,
    KnowledgeRelationshipSerializer,
    KnowledgeSourceCreateSerializer,
    KnowledgeSourceSerializer,
    ProcessingStatusSerializer,
    ProcedureSerializer,
)


def _ks_generated_topics(ks, doc_ids=None):
    """
    Topics (tag groups) produced by Auto-generate for a KnowledgeSource.

    Every auto-generate run ever launched for a subset of this KS's currently
    linked documents "belongs" to this process — not just the one matching the
    exact current document set. Re-running Auto-generar after adding a new
    document changes that exact-match key (e.g. "75" -> "75,76"), so matching
    only the latest run made earlier topics — and anything manually added
    under them via "+ Agregar deck/batería" — vanish from view even though
    nothing was actually deleted. Aggregating every qualifying run keeps old
    topics and manual content visible forever while still layering in
    whatever a fresh Auto-generar run produces.

    Returns (runs, tag_group_ids, topics) where topics is [{"id", "tags"}].
    """
    from api.enterprise_document_intelligence_models import KnowledgeSourceDocument
    from api.models import ProcessRun

    if doc_ids is None:
        doc_ids = sorted(
            KnowledgeSourceDocument.objects.filter(knowledge_source=ks).values_list("document_id", flat=True)
        )
    doc_id_set = set(doc_ids)
    if not doc_id_set:
        return [], [], []

    candidate_runs = (
        ProcessRun.objects
        .filter(workflow_key="collection_auto_generate", resource_type="document_batch")
        .exclude(status__in=["canceled", "cancelled", "queued", "draft"])
        .order_by("created_at")
    )
    runs = []
    for candidate in candidate_runs:
        try:
            run_doc_ids = {int(v) for v in candidate.resource_id.split(",") if v.strip()}
        except ValueError:
            continue
        if run_doc_ids and run_doc_ids.issubset(doc_id_set):
            runs.append(candidate)

    # Tag-group artifacts across every qualifying run → used as "topics"
    tag_group_ids: list[int] = []
    topics = []
    seen_tag_group_ids = set()
    for run in runs:
        for a in run.artifacts.filter(artifact_type="tag_group").order_by("resource_id"):
            if a.resource_id in seen_tag_group_ids:
                continue
            seen_tag_group_ids.add(a.resource_id)
            tag_group_ids.append(int(a.resource_id))
            topics.append({"id": a.resource_id, "tags": a.payload.get("tags", [])})
    return runs, tag_group_ids, topics


def _manual_topic_payload(topic) -> dict:
    """A hand-made topic in the /results/ "topics" format (plus title/description/manual)."""
    return {
        "id": str(topic.tag_group_id),
        "tags": [item.value for item in topic.tag_group.items.all()],
        "title": topic.title,
        "description": topic.description,
        "manual": True,
    }


def _ks_manual_topics(ks):
    """Topics created by hand in this KnowledgeSource (F-09), in display order."""
    from api.enterprise_document_intelligence_models import KnowledgeSourceTopic
    return list(
        KnowledgeSourceTopic.objects.filter(knowledge_source=ks)
        .select_related("tag_group").prefetch_related("tag_group__items")
        .order_by("order", "id")
    )


def _ks_topic_ids(ks) -> set:
    """Every topic (TagGroup id) that belongs to this KnowledgeSource: generated + manual."""
    _, tag_group_ids, _ = _ks_generated_topics(ks)
    return set(tag_group_ids) | {t.tag_group_id for t in _ks_manual_topics(ks)}


def _ks_output_ids(runs, tag_group_ids):
    """
    Battery/deck artifacts across every qualifying run, unioned with anything
    linked afterward via "+ Agregar deck/batería" (which links through
    BatterySourceTagGroup/DeckSourceTagGroup to one of these tag_groups but
    was never registered as an artifact of any run). Returns (deck_ids, battery_ids).
    """
    from api.models import BatterySourceTagGroup, DeckSourceTagGroup

    battery_ids = set()
    deck_ids = set()
    for run in runs:
        battery_ids |= set(int(a.resource_id) for a in run.artifacts.filter(artifact_type="battery"))
        deck_ids |= set(int(a.resource_id) for a in run.artifacts.filter(artifact_type="deck"))
    if tag_group_ids:
        battery_ids |= set(
            BatterySourceTagGroup.objects
            .filter(tag_group_id__in=tag_group_ids)
            .values_list("battery_id", flat=True)
        )
        deck_ids |= set(
            DeckSourceTagGroup.objects
            .filter(tag_group_id__in=tag_group_ids)
            .values_list("deck_id", flat=True)
        )
    return deck_ids, battery_ids


def ks_content_counts(ks) -> dict:
    """15: {"topics", "decks", "batteries"} of a process — what its learning-path row shows."""
    from api.models import Battery, Deck

    runs, tag_group_ids, topics = _ks_generated_topics(ks)
    for manual in _ks_manual_topics(ks):
        if manual.tag_group_id not in tag_group_ids:
            tag_group_ids.append(manual.tag_group_id)
            topics.append(manual)
    deck_ids, battery_ids = _ks_output_ids(runs, tag_group_ids)
    return {
        "topics": len(topics),
        "decks": Deck.objects.filter(id__in=deck_ids).count() if deck_ids else 0,
        "batteries": Battery.objects.filter(id__in=battery_ids).count() if battery_ids else 0,
    }


def _results_summary(ks, topics, decks, batteries) -> dict:
    """
    14: the one source for the process header counters, the "Ready" banner and
    "Process completion". Completion averages the user's best finished attempt of
    every battery (0 when not attempted); a battery counts as completed when that
    best score is >= the process minimum_passing_score.
    """
    passing = ks.minimum_passing_score if ks.minimum_passing_score is not None else 70
    best = [float((b.get("best_attempt") or {}).get("percent") or 0) for b in batteries]
    return {
        "topics": len(topics),
        "decks": len(decks),
        "batteries": len(batteries),
        "questions": sum(int(b.get("question_count") or 0) for b in batteries),
        "cards": sum(int(d.get("cardsCount") or d.get("card_count") or 0) for d in decks),
        "passing_score": passing,
        "completed_batteries": sum(1 for pct in best if pct >= passing),
        "completion_percent": round(sum(best) / len(best)) if best else 0,
    }


def _resolve_ks(company_id, ks_id):
    from api.enterprise_document_intelligence_models import KnowledgeSource
    try:
        return KnowledgeSource.objects.select_related(
            "document", "company", "created_by"
        ).get(pk=ks_id, company_id=company_id)
    except KnowledgeSource.DoesNotExist:
        raise NotFound("KnowledgeSource not found.")


# ---------------------------------------------------------------------------
# KnowledgeSourceViewSet
# ---------------------------------------------------------------------------

class KnowledgeSourceViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    CRUD + processing actions for KnowledgeSource objects.

    Endpoints:
      GET    /enterprise/knowledge-sources/
      POST   /enterprise/knowledge-sources/
      GET    /enterprise/knowledge-sources/{id}/
      DELETE /enterprise/knowledge-sources/{id}/
      POST   /enterprise/knowledge-sources/{id}/process/
      GET    /enterprise/knowledge-sources/{id}/status/
      POST   /enterprise/knowledge-sources/{id}/generate-training/
      POST   /enterprise/knowledge-sources/{id}/detect-changes/
    """

    permission_classes = [IsAuthenticated]

    def _resolve_company_membership(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        return company, membership

    def _require_trainer(self, membership):
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

    def list(self, request):
        company, membership = self._resolve_company_membership()
        from api.enterprise_document_intelligence_models import KnowledgeSource
        qs = KnowledgeSource.objects.filter(company=company).select_related(
            "document", "created_by"
        ).order_by("-created_at")

        # Optional filters (combinable). Values must be valid enum keys.
        for param in ("status", "source_type", "process_type", "difficulty"):
            value = request.query_params.get(param)
            if not value:
                continue
            valid = {key for key, _ in KnowledgeSource._meta.get_field(param).choices}
            if value not in valid:
                raise ValidationError({param: f"Invalid value '{value}'. Allowed: {', '.join(sorted(valid))}."})
            qs = qs.filter(**{param: value})

        return Response(KnowledgeSourceSerializer(qs, many=True).data)

    def create(self, request):
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)

        ser = KnowledgeSourceCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        from api.enterprise_document_intelligence_models import KnowledgeSource
        from api.enterprise_models import BusinessUnit

        bu = None
        if d.get("business_unit_id"):
            try:
                bu = BusinessUnit.objects.get(pk=d["business_unit_id"], company=company)
            except BusinessUnit.DoesNotExist:
                raise ValidationError({"business_unit_id": "BusinessUnit not found."})

        ks = KnowledgeSource.objects.create(
            company=company,
            title=d["title"],
            description=d.get("description", ""),
            source_type=d["source_type"],
            business_unit=bu,
            process_type=d.get("process_type", "course"),
            difficulty=d.get("difficulty", "medium"),
            minimum_passing_score=d.get("minimum_passing_score", 70),
            estimated_duration_minutes=d.get("estimated_duration_minutes"),
            cards_per_group=d.get("cards_per_group", 20),
            questions_per_group=d.get("questions_per_group", 15),
            question_format=d.get("question_format", "multiple_choice"),
            language=d.get("language", ""),  # 16: "" = use the language detected in the documents
            status="pending",
            created_by=request.user,
        )
        return Response(KnowledgeSourceSerializer(ks).data, status=201)

    @action(detail=True, methods=["post"], url_path="add-document")
    def add_document(self, request, pk=None):
        """
        Uploads a file, creates a Document, and links it to this KnowledgeSource.
        Accepts multipart/form-data with:
          - file       : the uploaded file (required)
          - version_note: optional text describing this addition (e.g. "Actualización Q2")
        """
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        from api.services.file_validation import (
            FileValidationError, oversize_error, rejection_response, validate_uploaded_file,
        )
        from api.upload_handlers import oversize_uploads

        too_large = oversize_uploads(request)
        if too_large:
            return rejection_response(request, oversize_error(), filename=too_large[0], source="knowledge_source_add_document")
        if "file" not in request.FILES:
            raise ValidationError({"file": "A file is required."})

        uploaded_file = request.FILES["file"]
        # Validate name, size and real content before the Document exists.
        try:
            validated = validate_uploaded_file(uploaded_file)
        except FileValidationError as err:
            return rejection_response(
                request, err, filename=uploaded_file.name, size=uploaded_file.size,
                source="knowledge_source_add_document",
            )

        from api.models import Document
        from api.enterprise_document_intelligence_models import KnowledgeSourceDocument

        document = Document(
            filename=validated.original_name,
            file=uploaded_file,
            type=validated.extension,  # enterprise documents keep the lowercase extension as type
            size=validated.size,
            hash=validated.sha256,
            uploaded_by=request.user,
        )
        document._uploader_id = request.user.id
        document.save()

        KnowledgeSourceDocument.objects.get_or_create(
            knowledge_source=ks,
            document=document,
            defaults={
                "added_by": request.user,
                "version_note": request.data.get("version_note", ""),
            },
        )

        ks.refresh_from_db()
        return Response(KnowledgeSourceSerializer(ks).data, status=201)

    def retrieve(self, request, pk=None):
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)
        return Response(KnowledgeSourceSerializer(ks).data)

    def destroy(self, request, pk=None):
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)
        ks.delete()
        return Response(status=204)

    @action(detail=True, methods=["get"], url_path="results")
    def results(self, request, pk=None):
        """Returns the generated batteries, decks, and topics for this KnowledgeSource."""
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)

        from api.enterprise_document_intelligence_models import KnowledgeSourceDocument
        from api.models import ProcessRun, Battery, Deck, DeckSourceTagGroup, BatterySourceTagGroup
        from api.serializers import BatteryListSerializer, DeckListSerializer

        # Get document IDs linked to this KS (sorted to match resource_id in ProcessRun)
        doc_ids = sorted(
            KnowledgeSourceDocument.objects
            .filter(knowledge_source=ks)
            .values_list("document_id", flat=True)
        )
        manual_topics = _ks_manual_topics(ks)
        if not doc_ids and not manual_topics:
            return Response({"run": None, "batteries": [], "decks": [], "topics": []})

        runs, tag_group_ids, topics = _ks_generated_topics(ks, doc_ids)
        if not runs and not manual_topics:
            return Response({"run": None, "batteries": [], "decks": [], "topics": []})

        # Topics added by hand (F-09) come after the generated ones.
        for manual in manual_topics:
            if manual.tag_group_id not in tag_group_ids:
                tag_group_ids.append(manual.tag_group_id)
                topics.append(_manual_topic_payload(manual))

        deck_ids, battery_ids = _ks_output_ids(runs, tag_group_ids)

        # Respect manual display order set via /batteries/reorder/ and /decks/reorder/
        # (same convention as the /batteries/?tag_group= and /decks/?tag_group= querysets).
        batteries_qs = (
            Battery.objects.filter(id__in=battery_ids).order_by("order", "-created_at")
            if battery_ids else Battery.objects.none()
        )
        batteries_data = BatteryListSerializer(batteries_qs, many=True, context={"request": request}).data

        decks_qs = (
            Deck.objects.filter(id__in=deck_ids).order_by("order", "-created_at")
            if deck_ids else Deck.objects.none()
        )
        decks_data = DeckListSerializer(decks_qs, many=True, context={"request": request}).data

        latest_run = runs[-1] if runs else None
        return Response({
            "run": {
                "id": latest_run.id,
                "run_id": str(latest_run.run_id),
                "status": latest_run.status,
                "progress_percent": float(latest_run.progress_percent or 0),
                "status_message": latest_run.status_message or "",
            } if latest_run else None,
            "batteries": batteries_data,
            "decks": decks_data,
            "topics": topics,
            "summary": _results_summary(ks, topics, decks_data, batteries_data),  # 14 (additive)
        })

    def _save_manual_topic(self, ks, tag_group, d, *, exclude_id=None):
        """Applies validated ManualTopicSerializer data; titles are unique per process (case-insensitive)."""
        from api.enterprise_document_intelligence_models import KnowledgeSourceTopic
        from api.models import TagGroup, TagGroupItem

        title = d["title"]
        _, generated_ids, _ = _ks_generated_topics(ks)
        clash = (
            KnowledgeSourceTopic.objects.filter(knowledge_source=ks, title__iexact=title)
            .exclude(tag_group_id=exclude_id).exists()
            or TagGroup.objects.filter(id__in=generated_ids, name__iexact=title).exists()
        )
        if clash:
            raise ValidationError({"title": "A topic with this name already exists in this process."})

        tag_group.name = title
        tag_group.save(update_fields=["name", "updated_at"])
        if "tags" in d:
            tag_group.items.all().delete()
            TagGroupItem.objects.bulk_create([
                TagGroupItem(tag_group=tag_group, value=tag, order=i) for i, tag in enumerate(d["tags"])
            ])

    @action(detail=True, methods=["post"], url_path="topics")
    def create_topic(self, request, pk=None):
        """
        POST /api/enterprise/knowledge-sources/{id}/topics/?company_id=
        {"title", "description"?, "tags"?: [str]} -> 201 topic in the /results/ "topics" format.
        The topic is a TagGroup, so "+ Add deck/battery" link to it like any generated topic.
        """
        from django.db import transaction
        from django.db.models import Max
        from api.enterprise.serializers.document_intelligence import ManualTopicSerializer
        from api.enterprise_document_intelligence_models import KnowledgeSourceTopic
        from api.models import TagGroup

        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)
        ser = ManualTopicSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        with transaction.atomic():
            last = KnowledgeSourceTopic.objects.filter(knowledge_source=ks).aggregate(m=Max("order"))["m"]
            tag_group = TagGroup.objects.create(name=d["title"], metadata={"knowledge_source_id": ks.id, "manual": True})
            self._save_manual_topic(ks, tag_group, d)
            topic = KnowledgeSourceTopic.objects.create(
                knowledge_source=ks, tag_group=tag_group, title=d["title"],
                description=d.get("description", ""), order=(last or 0) + 1, created_by=request.user,
            )
        from api.enterprise.services.knowledge_graph_builder import safe_build
        safe_build(ks)  # F-13
        return Response(_manual_topic_payload(topic), status=201)

    @action(detail=True, methods=["patch"], url_path=r"topics/(?P<topic_id>\d+)")
    def update_topic(self, request, pk=None, topic_id=None):
        """PATCH /api/enterprise/knowledge-sources/{id}/topics/{topic_id}/ — edits a hand-made topic."""
        from django.db import transaction
        from api.enterprise.serializers.document_intelligence import ManualTopicSerializer
        from api.enterprise_document_intelligence_models import KnowledgeSourceTopic

        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)
        topic = (
            KnowledgeSourceTopic.objects.select_related("tag_group")
            .filter(knowledge_source=ks, tag_group_id=int(topic_id)).first()
        )
        if topic is None:
            raise NotFound("Topic not found in this process (only hand-made topics can be edited).")

        ser = ManualTopicSerializer(data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        d = dict(ser.validated_data)
        d.setdefault("title", topic.title)
        with transaction.atomic():
            self._save_manual_topic(ks, topic.tag_group, d, exclude_id=topic.tag_group_id)
            topic.title = d["title"]
            if "description" in d:
                topic.description = d["description"]
            topic.save(update_fields=["title", "description", "updated_at"])
        from api.enterprise.services.knowledge_graph_builder import safe_build
        safe_build(ks)  # F-13
        topic = KnowledgeSourceTopic.objects.prefetch_related("tag_group__items").get(pk=topic.pk)
        return Response(_manual_topic_payload(topic))

    @action(detail=True, methods=["post"], url_path=r"topics/(?P<topic_id>\d+)/decks")
    def create_topic_deck(self, request, pk=None, topic_id=None):
        """
        POST /api/enterprise/knowledge-sources/{id}/topics/{topic_id}/decks/?company_id=
        Manual deck (F-08): {"title", "description"?, "is_public"?, "flashcards": [{"front", "back", "notes"?}]}
        Same Deck/Flashcard models and topic link (DeckSourceTagGroup) as AI decks.
        201 -> deck in the /results/ format (DeckListSerializer) + "flashcards".
        """
        from django.db import transaction
        from api.enterprise.serializers.document_intelligence import ManualDeckCreateSerializer
        from api.models import Deck, Flashcard, TagGroup
        from api.serializers import DeckListSerializer, FlashcardSerializer
        from api.services.auto_generate_workflow import sync_deck_source_links

        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)
        topic_id = int(topic_id)
        if topic_id not in _ks_topic_ids(ks):
            raise NotFound("Topic not found in this process.")

        data = ManualDeckCreateSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        d = data.validated_data
        if d.get("knowledge_source_id") not in (None, ks.id) or d.get("topic_id") not in (None, topic_id):
            raise ValidationError({"detail": "knowledge_source_id/topic_id do not match the URL."})

        topic = TagGroup.objects.get(pk=topic_id)
        with transaction.atomic():
            deck = Deck.objects.create(
                project=None,
                collection=None,
                owner=request.user,
                title=d["title"],
                description=d.get("description", ""),
                visibility="public" if d.get("is_public") else "private",
            )
            Flashcard.objects.bulk_create([
                Flashcard(deck=deck, front=c["front"], back=c["back"], notes=c.get("notes", ""))
                for c in d["flashcards"]
            ])
            sync_deck_source_links(deck=deck, source_bundle={"tag_group_ids": [str(topic.id)]})

        payload = DeckListSerializer(deck, context={"request": request}).data
        payload["flashcards"] = FlashcardSerializer(
            deck.cards.order_by("created_at", "id"), many=True, context={"request": request}
        ).data
        return Response(payload, status=201)

    @action(detail=True, methods=["get"], url_path="documents-with-sections")
    def documents_with_sections(self, request, pk=None):
        """Returns this KnowledgeSource's documents with their extracted sections.

        Documents added via `add-document` are linked to the KnowledgeSource only
        through KnowledgeSourceDocument (not Document.project), so the project-scoped
        `/projects/{id}/documents-with-sections/` endpoint can never see them.
        """
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)

        from django.db.models import Prefetch
        from api.models import Document, Section
        from api.serializers import DocumentWithSectionsSerializer
        from api.enterprise_document_intelligence_models import KnowledgeSourceDocument

        doc_ids = (
            KnowledgeSourceDocument.objects
            .filter(knowledge_source=ks)
            .values_list("document_id", flat=True)
        )
        docs = (
            Document.objects.filter(id__in=list(doc_ids), quarantined_at__isnull=True)  # B2: never generate from quarantined files
            .prefetch_related(Prefetch("sections", queryset=Section.objects.all().order_by("order", "id")))
            .order_by("id")
        )
        ser = DocumentWithSectionsSerializer(docs, many=True, context={"request": request})
        return Response({"documents": ser.data})

    @action(detail=True, methods=["post"], url_path="process")
    def process(self, request, pk=None):
        """Triggers AI extraction pipeline synchronously (use Celery in prod)."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        if ks.status == "processing":
            raise ValidationError({"detail": "Already processing."})

        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()
        return Response(KnowledgeSourceSerializer(ks).data)

    @action(detail=True, methods=["get"], url_path="status")
    def status(self, request, pk=None):
        """Returns the current processing status."""
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)
        data = DocumentIntelligenceService.get_processing_status(ks.pk)
        return Response(ProcessingStatusSerializer(data).data)

    @action(detail=True, methods=["post"], url_path="generate-training")
    def generate_training(self, request, pk=None):
        """Generates a TrainingProgram from the processed KnowledgeSource."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        try:
            program = DocumentIntelligenceService.generate_training_program(ks.pk)
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})

        from api.enterprise.serializers.learning import TrainingProgramSerializer
        return Response(TrainingProgramSerializer(program).data, status=201)

    @action(detail=True, methods=["post"], url_path="detect-changes")
    def detect_changes(self, request, pk=None):
        """Checks for document content changes and creates a ChangeImpactAnalysis."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        changed, analysis = DocumentIntelligenceService.detect_document_changes(
            ks.pk, created_by=request.user
        )
        if not changed:
            return Response({"changed": False, "analysis": None})

        return Response({
            "changed": True,
            "analysis": ChangeImpactAnalysisSerializer(analysis).data,
        })


# ---------------------------------------------------------------------------
# ProcedureViewSet (read-only, scoped to company)
# ---------------------------------------------------------------------------

class ProcedureViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Read-only listing of extracted procedures.

    Endpoints:
      GET /enterprise/procedures/
      GET /enterprise/procedures/{id}/
    """

    permission_classes = [IsAuthenticated]

    def _get_company(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id)

    def list(self, request):
        company = self._get_company()
        from api.enterprise_document_intelligence_models import Procedure
        qs = Procedure.objects.filter(company=company).select_related(
            "knowledge_source"
        ).order_by("knowledge_source_id", "order")

        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(knowledge_source_id=ks_id)

        is_critical = request.query_params.get("is_critical")
        if is_critical is not None:
            qs = qs.filter(is_critical=is_critical.lower() == "true")

        return Response(ProcedureSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        company = self._get_company()
        from api.enterprise_document_intelligence_models import Procedure
        try:
            proc = Procedure.objects.get(pk=pk, company=company)
        except Procedure.DoesNotExist:
            raise NotFound("Procedure not found.")
        return Response(ProcedureSerializer(proc).data)


# ---------------------------------------------------------------------------
# ChangeImpactAnalysisViewSet
# ---------------------------------------------------------------------------

class ChangeImpactAnalysisViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Impact analysis management.

    Endpoints:
      GET  /enterprise/change-impact/
      GET  /enterprise/change-impact/{id}/
      POST /enterprise/change-impact/{id}/analyze/
      POST /enterprise/change-impact/{id}/apply/
    """

    permission_classes = [IsAuthenticated]

    def _resolve_company_membership(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id), membership

    def _get_analysis(self, company, pk):
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        try:
            return ChangeImpactAnalysis.objects.select_related(
                "knowledge_source", "old_version", "new_version"
            ).get(pk=pk, company=company)
        except ChangeImpactAnalysis.DoesNotExist:
            raise NotFound("ChangeImpactAnalysis not found.")

    def list(self, request):
        company, _ = self._resolve_company_membership()
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        qs = ChangeImpactAnalysis.objects.filter(company=company).order_by("-created_at")

        status = request.query_params.get("status")
        if status:
            qs = qs.filter(status=status)
        impact_level = request.query_params.get("impact_level")
        if impact_level:
            qs = qs.filter(impact_level=impact_level)
        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(knowledge_source_id=ks_id)

        return Response(ChangeImpactAnalysisSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        company, _ = self._resolve_company_membership()
        analysis = self._get_analysis(company, pk)
        return Response(ChangeImpactAnalysisSerializer(analysis).data)

    @action(detail=True, methods=["post"], url_path="analyze")
    def analyze(self, request, pk=None):
        """Runs AI impact analysis comparing old vs new document versions."""
        company, membership = self._resolve_company_membership()
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

        analysis = self._get_analysis(company, pk)
        if analysis.status == "analyzing":
            raise ValidationError({"detail": "Analysis already in progress."})
        if analysis.status == "completed":
            raise ValidationError({"detail": "Analysis already completed."})

        DocumentIntelligenceService.analyze_change_impact(analysis.pk)
        analysis.refresh_from_db()
        return Response(ChangeImpactAnalysisSerializer(analysis).data)

    @action(detail=True, methods=["post"], url_path="apply")
    def apply(self, request, pk=None):
        """Regenerates training program based on the completed impact analysis."""
        company, membership = self._resolve_company_membership()
        if membership.role not in ("owner", "admin", "trainer"):
            raise PermissionDenied("Trainer role or higher required.")

        analysis = self._get_analysis(company, pk)
        if analysis.status != "completed":
            raise ValidationError(
                {"detail": "Impact analysis must be completed before applying."}
            )
        if analysis.training_regenerated:
            raise ValidationError({"detail": "Training already regenerated for this analysis."})

        try:
            new_program = DocumentIntelligenceService.regenerate_training(
                knowledge_source_id=analysis.knowledge_source_id,
                change_analysis_id=analysis.pk,
            )
        except Exception as exc:
            raise ValidationError({"detail": str(exc)})

        from api.enterprise.serializers.learning import TrainingProgramSerializer
        return Response({
            "message": "Training program regenerated successfully.",
            "training_program": TrainingProgramSerializer(new_program).data,
        })


# ---------------------------------------------------------------------------
# KnowledgeGraphViewSet
# ---------------------------------------------------------------------------

class KnowledgeGraphViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Knowledge graph retrieval.

    Endpoints:
      GET /enterprise/knowledge-graph/graph/
      GET /enterprise/knowledge-graph/nodes/
      GET /enterprise/knowledge-graph/relationships/
    """

    permission_classes = [IsAuthenticated]

    def _get_company(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id)

    @action(detail=False, methods=["get"], url_path="graph")
    def graph(self, request):
        """Returns the full knowledge graph (nodes + relationships)."""
        company = self._get_company()
        ks_id = request.query_params.get("knowledge_source_id")
        ks = None
        if ks_id:
            from api.enterprise_document_intelligence_models import KnowledgeSource
            try:
                ks = KnowledgeSource.objects.get(pk=ks_id, company=company)
            except KnowledgeSource.DoesNotExist:
                raise NotFound("KnowledgeSource not found.")

        data = DocumentIntelligenceService.get_knowledge_graph(company, ks)
        return Response(KnowledgeGraphSerializer(data).data)

    @action(detail=False, methods=["post"], url_path="rebuild")
    def rebuild(self, request):
        """
        POST /api/enterprise/knowledge-graph/rebuild/?company_id=[&knowledge_source_id=]
        F-13: rebuilds the structure graph (process, topics, tags, procedures) of one
        process or of every process in the company. Trainer role or higher.
        """
        company = self._get_company()
        membership = validate_company_access(request.user, company.id)
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")
        from api.enterprise.services.knowledge_graph_builder import build_knowledge_graph
        from api.enterprise_document_intelligence_models import KnowledgeSource

        qs = KnowledgeSource.objects.filter(company=company)
        ks_id = request.query_params.get("knowledge_source_id") or request.data.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(pk=ks_id)
            if not qs.exists():
                raise NotFound("KnowledgeSource not found.")
        results = [build_knowledge_graph(ks) for ks in qs]
        graph = DocumentIntelligenceService.get_knowledge_graph(company, qs.first() if ks_id else None)
        return Response({
            "processes": len(results),
            "nodes_created": sum(r["nodes_created"] for r in results),
            "nodes_updated": sum(r["nodes_updated"] for r in results),
            "nodes_deleted": sum(r["nodes_deleted"] for r in results),
            "node_count": graph["node_count"],
            "edge_count": graph["edge_count"],
        })

    @action(detail=False, methods=["get"], url_path="nodes")
    def nodes(self, request):
        """Lists knowledge nodes for the company."""
        company = self._get_company()
        from api.enterprise_document_intelligence_models import KnowledgeNode
        qs = KnowledgeNode.objects.filter(company=company).order_by("-importance_score")

        node_type = request.query_params.get("node_type")
        if node_type:
            qs = qs.filter(node_type=node_type)
        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(source_id=ks_id)

        return Response(KnowledgeNodeSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"], url_path="relationships")
    def relationships(self, request):
        """Lists knowledge relationships for the company."""
        company = self._get_company()
        from api.enterprise_document_intelligence_models import KnowledgeRelationship
        qs = KnowledgeRelationship.objects.filter(
            company=company
        ).select_related("source_node", "target_node")

        rel_type = request.query_params.get("relationship_type")
        if rel_type:
            qs = qs.filter(relationship_type=rel_type)

        return Response(KnowledgeRelationshipSerializer(qs, many=True).data)

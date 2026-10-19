"""Phase 7 — Document Intelligence Serializers."""

from __future__ import annotations

from rest_framework import serializers


# ---------------------------------------------------------------------------
# KnowledgeSource
# ---------------------------------------------------------------------------

class KnowledgeSourceCreateSerializer(serializers.Serializer):
    document_id = serializers.IntegerField(required=False, allow_null=True)
    title = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True, default="")
    source_type = serializers.ChoiceField(
        choices=[
            "policy", "procedure", "regulation",
            "manual", "training_material", "other",
        ],
        default="other",
    )
    business_unit_id = serializers.IntegerField(required=False, allow_null=True)
    # Proceso configuration — propagated to LearningModules when generate-training runs
    process_type = serializers.ChoiceField(
        choices=["study_material", "tutorial", "course"],
        default="course",
        required=False,
    )
    difficulty = serializers.ChoiceField(
        choices=["easy", "medium", "hard"],
        default="medium",
        required=False,
    )
    minimum_passing_score = serializers.IntegerField(
        required=False, allow_null=True, default=70, min_value=0, max_value=100
    )
    estimated_duration_minutes = serializers.IntegerField(
        required=False, allow_null=True, min_value=1
    )
    # Auto-generation preferences — used as defaults when auto-generate runs
    cards_per_group = serializers.IntegerField(
        required=False, default=20, min_value=1
    )
    questions_per_group = serializers.IntegerField(
        required=False, default=15, min_value=1
    )
    question_format = serializers.ChoiceField(
        choices=["true_false", "multiple_choice", "variety"],
        default="multiple_choice",
        required=False,
    )


class KnowledgeSourceSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    title = serializers.CharField()
    description = serializers.CharField()
    source_type = serializers.CharField()
    status = serializers.CharField()
    document_id = serializers.IntegerField(allow_null=True)
    document_filename = serializers.SerializerMethodField()
    documents = serializers.SerializerMethodField()
    business_unit_id = serializers.IntegerField(allow_null=True)
    process_type = serializers.CharField()
    difficulty = serializers.CharField()
    minimum_passing_score = serializers.IntegerField(allow_null=True)
    estimated_duration_minutes = serializers.IntegerField(allow_null=True)
    cards_per_group = serializers.IntegerField()
    questions_per_group = serializers.IntegerField()
    question_format = serializers.CharField()
    extracted_topics_count = serializers.IntegerField()
    extracted_procedures_count = serializers.IntegerField()
    generated_training_id = serializers.IntegerField(allow_null=True)
    metadata = serializers.DictField()
    error_message = serializers.CharField()
    processing_started_at = serializers.DateTimeField(allow_null=True)
    processing_completed_at = serializers.DateTimeField(allow_null=True)
    created_by_id = serializers.IntegerField(allow_null=True)
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()

    def get_document_filename(self, obj) -> str:
        return obj.document.filename if obj.document_id else ""

    def get_documents(self, obj) -> list:
        from api.enterprise_document_intelligence_models import KnowledgeSourceDocument
        links = (
            KnowledgeSourceDocument.objects
            .filter(knowledge_source=obj)
            .select_related("document", "added_by")
            .order_by("added_at")
        )
        return [
            {
                "id": link.document.id,
                "filename": link.document.filename,
                "type": link.document.type,
                "size": link.document.size,
                "status": link.document.status,
                "added_at": link.added_at.isoformat(),
                "added_by": link.added_by.username if link.added_by else None,
                "version_note": link.version_note,
                "quarantined": link.document.quarantined_at is not None,  # B2 (additive)
            }
            for link in links
        ]


class ProcessingStatusSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    status = serializers.CharField()
    processing_started_at = serializers.DateTimeField(allow_null=True)
    processing_completed_at = serializers.DateTimeField(allow_null=True)
    extracted_topics_count = serializers.IntegerField()
    extracted_procedures_count = serializers.IntegerField()
    error_message = serializers.CharField(allow_null=True)
    has_training = serializers.BooleanField()


# ---------------------------------------------------------------------------
# DocumentVersion
# ---------------------------------------------------------------------------

class DocumentVersionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    knowledge_source_id = serializers.IntegerField()
    document_id = serializers.IntegerField()
    version_number = serializers.IntegerField()
    file_hash = serializers.CharField()
    content_hash = serializers.CharField()
    extracted_at = serializers.DateTimeField(allow_null=True)
    summary = serializers.CharField()
    key_changes = serializers.ListField(child=serializers.CharField())
    topic_count = serializers.IntegerField()
    created_at = serializers.DateTimeField()


# ---------------------------------------------------------------------------
# Procedure
# ---------------------------------------------------------------------------

class ProcedureStepSerializer(serializers.Serializer):
    order = serializers.IntegerField()
    text = serializers.CharField()
    warning = serializers.CharField(required=False, allow_blank=True)


class ProcedureSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    knowledge_source_id = serializers.IntegerField()
    topic_id = serializers.IntegerField(allow_null=True)
    title = serializers.CharField()
    description = serializers.CharField()
    steps = serializers.ListField(child=serializers.DictField())
    warnings = serializers.ListField(child=serializers.CharField())
    references = serializers.ListField(child=serializers.CharField())
    order = serializers.IntegerField()
    is_critical = serializers.BooleanField()
    metadata = serializers.DictField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


# ---------------------------------------------------------------------------
# ChangeImpactAnalysis
# ---------------------------------------------------------------------------

class ChangeImpactAnalysisSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    knowledge_source_id = serializers.IntegerField()
    old_version_id = serializers.IntegerField(allow_null=True)
    new_version_id = serializers.IntegerField(allow_null=True)
    status = serializers.CharField()
    impact_level = serializers.CharField(allow_null=True)
    affected_topics = serializers.ListField(child=serializers.CharField())
    affected_learning_path_ids = serializers.ListField(child=serializers.IntegerField())
    affected_procedures = serializers.ListField(child=serializers.CharField())
    summary = serializers.CharField()
    recommendations = serializers.ListField(child=serializers.CharField())
    analyzed_at = serializers.DateTimeField(allow_null=True)
    error_message = serializers.CharField()
    training_regenerated = serializers.BooleanField()
    training_regenerated_at = serializers.DateTimeField(allow_null=True)
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


# ---------------------------------------------------------------------------
# Knowledge Graph
# ---------------------------------------------------------------------------

class KnowledgeNodeSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    title = serializers.CharField()
    node_type = serializers.CharField()
    description = serializers.CharField()
    source_id = serializers.IntegerField(allow_null=True)
    topic_id = serializers.IntegerField(allow_null=True)
    importance_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    metadata = serializers.DictField()
    created_at = serializers.DateTimeField()


class KnowledgeRelationshipSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    source_node_id = serializers.IntegerField()
    target_node_id = serializers.IntegerField()
    relationship_type = serializers.CharField()
    strength = serializers.DecimalField(max_digits=4, decimal_places=3)
    description = serializers.CharField()
    created_at = serializers.DateTimeField()


class KnowledgeGraphSerializer(serializers.Serializer):
    node_count = serializers.IntegerField()
    edge_count = serializers.IntegerField()
    nodes = serializers.ListField(child=serializers.DictField())
    relationships = serializers.ListField(child=serializers.DictField())


# ---------------------------------------------------------------------------
# Manual decks inside a process topic (F-08)
# ---------------------------------------------------------------------------

MAX_MANUAL_DECK_CARDS = 500  # same ceiling as /decks/start-generate/ (cards_count max 500)


class ManualFlashcardSerializer(serializers.Serializer):
    front = serializers.CharField(trim_whitespace=True, max_length=5000)
    back = serializers.CharField(trim_whitespace=True, max_length=5000)
    notes = serializers.CharField(trim_whitespace=True, required=False, allow_blank=True, default="", max_length=5000)


class ManualDeckCreateSerializer(serializers.Serializer):
    title = serializers.CharField(trim_whitespace=True, max_length=200)
    description = serializers.CharField(trim_whitespace=True, required=False, allow_blank=True, default="")
    is_public = serializers.BooleanField(required=False, default=False)
    flashcards = ManualFlashcardSerializer(many=True, allow_empty=False, max_length=MAX_MANUAL_DECK_CARDS)
    # Optional echo of the URL ids (kept for clients that send them in the body).
    knowledge_source_id = serializers.IntegerField(required=False)
    topic_id = serializers.IntegerField(required=False)


# ---------------------------------------------------------------------------
# Topics created by hand inside a process (F-09)
# ---------------------------------------------------------------------------

class ManualTopicSerializer(serializers.Serializer):
    title = serializers.CharField(trim_whitespace=True, max_length=255)
    description = serializers.CharField(trim_whitespace=True, required=False, allow_blank=True, default="")
    tags = serializers.ListField(
        child=serializers.CharField(trim_whitespace=True, allow_blank=True, max_length=255), required=False, default=list, max_length=50,
    )

    def validate_tags(self, value):
        # Drop blanks and case-insensitive duplicates, keeping the first spelling.
        seen, tags = set(), []
        for tag in value:
            if tag and tag.lower() not in seen:
                seen.add(tag.lower())
                tags.append(tag)
        return tags

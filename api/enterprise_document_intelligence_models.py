"""
Ankard Enterprise v1.0 — Phase 7 Document Intelligence Models

Tracks knowledge sources (enterprise documents), extracts topics/procedures,
builds knowledge graphs, and manages training regeneration on document changes.
All models belong to the `api` app migration graph.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models

from api.enterprise_models import BusinessUnit, Company, TenantMixin


# ==========================================================================
# KnowledgeSource
# ==========================================================================

class KnowledgeSource(TenantMixin):
    """
    A document designated as a company knowledge source.
    AI processing extracts topics, procedures, and a knowledge graph.
    """

    SOURCE_TYPE_CHOICES = [
        ("policy", "Policy"),
        ("procedure", "Procedure"),
        ("regulation", "Regulation"),
        ("manual", "Manual"),
        ("training_material", "Training Material"),
        ("other", "Other"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("processed", "Processed"),
        ("failed", "Failed"),
    ]

    PROCESS_TYPE_CHOICES = [
        ("study_material", "Study Material"),
        ("tutorial", "Tutorial"),
        ("course", "Course"),
    ]
    DIFFICULTY_CHOICES = [
        ("easy", "Easy"),
        ("medium", "Medium"),
        ("hard", "Hard"),
    ]

    document = models.ForeignKey(
        "api.Document",
        on_delete=models.CASCADE,
        related_name="knowledge_sources",
        null=True,
        blank=True,
    )
    # Proceso configuration — used when generate-training creates LearningModules
    process_type = models.CharField(
        max_length=20, choices=PROCESS_TYPE_CHOICES, default="course"
    )
    difficulty = models.CharField(
        max_length=10, choices=DIFFICULTY_CHOICES, default="medium"
    )
    minimum_passing_score = models.PositiveIntegerField(default=70, null=True, blank=True)
    estimated_duration_minutes = models.PositiveIntegerField(null=True, blank=True)

    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    source_type = models.CharField(
        max_length=30, choices=SOURCE_TYPE_CHOICES, default="other"
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending"
    )
    processing_started_at = models.DateTimeField(null=True, blank=True)
    processing_completed_at = models.DateTimeField(null=True, blank=True)
    extracted_topics_count = models.PositiveIntegerField(default=0)
    extracted_procedures_count = models.PositiveIntegerField(default=0)
    generated_training = models.ForeignKey(
        "api.TrainingProgram",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_sources",
    )
    metadata = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_knowledge_sources"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "source_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.company})"


# ==========================================================================
# KnowledgeSourceDocument  (many documents per KnowledgeSource)
# ==========================================================================

class KnowledgeSourceDocument(models.Model):
    """
    Links one or more Documents to a KnowledgeSource.
    Supports adding new document versions over time without replacing old ones.
    """
    knowledge_source = models.ForeignKey(
        KnowledgeSource,
        on_delete=models.CASCADE,
        related_name="source_documents",
    )
    document = models.ForeignKey(
        "api.Document",
        on_delete=models.CASCADE,
        related_name="knowledge_source_links",
    )
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    version_note = models.TextField(blank=True)

    class Meta:
        db_table = "enterprise_knowledge_source_documents"
        ordering = ["added_at"]
        unique_together = [("knowledge_source", "document")]

    def __str__(self) -> str:
        return f"{self.knowledge_source.title} → {self.document.filename}"


# ==========================================================================
# DocumentVersion
# ==========================================================================

class DocumentVersion(models.Model):
    """
    Snapshot of a KnowledgeSource document at a point in time.
    Used to detect content changes and trigger impact analysis.
    """

    knowledge_source = models.ForeignKey(
        KnowledgeSource,
        on_delete=models.CASCADE,
        related_name="versions",
    )
    document = models.ForeignKey(
        "api.Document",
        on_delete=models.CASCADE,
        related_name="document_versions",
    )
    version_number = models.PositiveIntegerField(default=1)
    file_hash = models.CharField(max_length=64, blank=True)
    content_hash = models.CharField(max_length=64, blank=True)
    extracted_at = models.DateTimeField(null=True, blank=True)
    summary = models.TextField(blank=True)
    key_changes = models.JSONField(default=list, blank=True)
    topic_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_document_versions"
        ordering = ["-version_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["knowledge_source", "version_number"],
                name="uniq_doc_version_per_source",
            )
        ]

    def __str__(self) -> str:
        return f"{self.knowledge_source.title} v{self.version_number}"


# ==========================================================================
# Procedure
# ==========================================================================

class Procedure(TenantMixin):
    """
    A step-by-step procedure extracted from a knowledge source.
    Represents an operational process the company wants employees to learn.
    """

    knowledge_source = models.ForeignKey(
        KnowledgeSource,
        on_delete=models.CASCADE,
        related_name="procedures",
    )
    topic = models.ForeignKey(
        "api.Topic",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="procedures",
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    steps = models.JSONField(default=list)
    warnings = models.JSONField(default=list)
    references = models.JSONField(default=list)
    order = models.PositiveIntegerField(default=0)
    is_critical = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_procedures"
        ordering = ["order"]
        indexes = [
            models.Index(fields=["company", "knowledge_source"]),
            models.Index(fields=["company", "is_critical"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.knowledge_source.title})"


# ==========================================================================
# ChangeImpactAnalysis
# ==========================================================================

class ChangeImpactAnalysis(TenantMixin):
    """
    Impact report when a knowledge source document is updated.
    Identifies which training, topics, and procedures are affected.
    """

    IMPACT_LEVEL_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("analyzing", "Analyzing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    knowledge_source = models.ForeignKey(
        KnowledgeSource,
        on_delete=models.CASCADE,
        related_name="change_analyses",
    )
    old_version = models.ForeignKey(
        DocumentVersion,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="impact_as_old",
    )
    new_version = models.ForeignKey(
        DocumentVersion,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="impact_as_new",
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending"
    )
    impact_level = models.CharField(
        max_length=10, choices=IMPACT_LEVEL_CHOICES, null=True, blank=True
    )
    affected_topics = models.JSONField(default=list)
    affected_learning_path_ids = models.JSONField(default=list)
    affected_procedures = models.JSONField(default=list)
    summary = models.TextField(blank=True)
    recommendations = models.JSONField(default=list)
    analyzed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    training_regenerated = models.BooleanField(default=False)
    training_regenerated_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_change_impact_analyses"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "impact_level"]),
        ]

    def __str__(self) -> str:
        return f"Impact for {self.knowledge_source.title} ({self.status})"


# ==========================================================================
# KnowledgeNode
# ==========================================================================

class KnowledgeNode(TenantMixin):
    """
    A node in the company knowledge graph.
    Represents a concept, procedure, regulation, skill, or topic.
    """

    NODE_TYPE_CHOICES = [
        ("concept", "Concept"),
        ("procedure", "Procedure"),
        ("regulation", "Regulation"),
        ("skill", "Skill"),
        ("topic", "Topic"),
        ("document", "Document"),
        ("rule", "Rule"),
    ]

    title = models.CharField(max_length=255)
    node_type = models.CharField(
        max_length=20, choices=NODE_TYPE_CHOICES, default="concept"
    )
    description = models.TextField(blank=True)
    source = models.ForeignKey(
        KnowledgeSource,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_nodes",
    )
    topic = models.ForeignKey(
        "api.Topic",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_nodes",
    )
    importance_score = models.DecimalField(
        max_digits=5, decimal_places=2, default=50
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_knowledge_nodes"
        ordering = ["-importance_score"]
        indexes = [
            models.Index(fields=["company", "node_type"]),
            models.Index(fields=["company", "importance_score"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.node_type})"


# ==========================================================================
# KnowledgeRelationship
# ==========================================================================

class KnowledgeRelationship(models.Model):
    """
    A directed relationship between two knowledge nodes.
    Strength ranges from 0 (weak) to 1 (strong dependency).
    """

    RELATIONSHIP_TYPE_CHOICES = [
        ("requires", "Requires"),
        ("related_to", "Related To"),
        ("contradicts", "Contradicts"),
        ("extends", "Extends"),
        ("supersedes", "Supersedes"),
        ("depends_on", "Depends On"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="+",
    )
    source_node = models.ForeignKey(
        KnowledgeNode,
        on_delete=models.CASCADE,
        related_name="outgoing",
    )
    target_node = models.ForeignKey(
        KnowledgeNode,
        on_delete=models.CASCADE,
        related_name="incoming",
    )
    relationship_type = models.CharField(
        max_length=20, choices=RELATIONSHIP_TYPE_CHOICES
    )
    strength = models.DecimalField(max_digits=4, decimal_places=3, default=0.5)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_knowledge_relationships"
        constraints = [
            models.UniqueConstraint(
                fields=["source_node", "target_node", "relationship_type"],
                name="uniq_knowledge_relationship",
            )
        ]

    def __str__(self) -> str:
        return (
            f"{self.source_node.title} "
            f"--{self.relationship_type}--> "
            f"{self.target_node.title}"
        )

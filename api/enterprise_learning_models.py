"""
Ankard Enterprise v1.0 — Phase 2 Learning Engine Models

Depends on Phase 1 foundation (enterprise_models.py must be applied first).
All models belong to the `api` app migration graph.
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from api.enterprise_models import BusinessUnit, Company, Team, TenantMixin


# ==========================================================================
# LearningPath
# ==========================================================================

class LearningPath(TenantMixin):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("archived", "Archived"),
    ]

    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="learning_paths",
    )
    project = models.ForeignKey(
        "api.Project",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="enterprise_learning_paths",
    )
    final_battery = models.ForeignKey(
        "api.Battery",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="final_battery_paths",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    estimated_duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_learning_paths",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_learning_paths"
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "created_at"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.company})"


# ==========================================================================
# LearningModule
# ==========================================================================

class LearningModule(models.Model):
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

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="learning_modules",
        null=True,
        blank=True,
    )
    # Optional — a proceso can exist standalone or be part of a learning path
    learning_path = models.ForeignKey(
        LearningPath,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="modules",
    )
    # The real, live KnowledgeSource this module represents. A KnowledgeSource can be
    # referenced by any number of LearningModule rows (one per LearningPath it's added
    # to, plus optionally a standalone one) — each is a separate "placement", but they
    # all point at the same underlying process. Deleting the KnowledgeSource cascades
    # to remove every placement of it (it disappears from every path); deleting a
    # LearningPath does NOT touch the KnowledgeSource (see LearningPathViewSet.perform_destroy,
    # which only orphans modules to standalone). Null on older modules created before this
    # field existed — those can't be resolved back to a KnowledgeSource and are treated as
    # unlinked/manual modules.
    knowledge_source = models.ForeignKey(
        "api.KnowledgeSource",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="learning_modules",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_required = models.BooleanField(default=True)
    estimated_duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    process_type = models.CharField(
        max_length=20, choices=PROCESS_TYPE_CHOICES, default="course"
    )
    difficulty = models.CharField(
        max_length=10, choices=DIFFICULTY_CHOICES, default="medium"
    )
    minimum_passing_score = models.PositiveIntegerField(default=70, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_learning_modules"
        ordering = ["order"]
        indexes = [
            models.Index(fields=["company", "created_at"]),
            models.Index(fields=["learning_path", "order"]),
        ]

    def __str__(self):
        path = self.learning_path.name if self.learning_path_id else "standalone"
        return f"{path} → {self.name}"


# ==========================================================================
# LearningModuleItem
# ==========================================================================

class LearningModuleItem(models.Model):
    ITEM_TYPE_CHOICES = [
        ("topic", "Topic"),
        ("battery", "Battery / Quiz"),
        ("deck", "Flashcard Deck"),
        ("document", "Document"),
    ]

    module = models.ForeignKey(
        LearningModule,
        on_delete=models.CASCADE,
        related_name="items",
    )
    item_type = models.CharField(max_length=20, choices=ITEM_TYPE_CHOICES)
    order = models.PositiveIntegerField(default=0)
    is_required = models.BooleanField(default=True)

    # Exactly one of these must be set (enforced in clean())
    topic = models.ForeignKey(
        "api.Topic",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="module_items",
    )
    battery = models.ForeignKey(
        "api.Battery",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="module_items",
    )
    deck = models.ForeignKey(
        "api.Deck",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="module_items",
    )
    document = models.ForeignKey(
        "api.Document",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="module_items",
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_learning_module_items"
        ordering = ["order"]

    def clean(self):
        active = [
            v for v in [self.topic_id, self.battery_id, self.deck_id, self.document_id]
            if v is not None
        ]
        if len(active) != 1:
            raise ValidationError(
                "Exactly one of topic, battery, deck, or document must be set."
            )

    def __str__(self):
        return f"{self.module.name} · item {self.order} ({self.item_type})"


# ==========================================================================
# TrainingProgram
# ==========================================================================

class TrainingProgram(TenantMixin):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("archived", "Archived"),
    ]

    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="training_programs",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_training_programs",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_training_programs"
        indexes = [
            models.Index(fields=["company", "status"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.company})"


# ==========================================================================
# TrainingProgramVersion
# ==========================================================================

class TrainingProgramVersion(models.Model):
    program = models.ForeignKey(
        TrainingProgram,
        on_delete=models.CASCADE,
        related_name="versions",
    )
    version_number = models.PositiveIntegerField(default=1)
    learning_path = models.ForeignKey(
        LearningPath,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="program_versions",
    )
    notes = models.TextField(blank=True)
    is_current = models.BooleanField(default=False, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_program_versions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_training_program_versions"
        ordering = ["-version_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["program", "version_number"],
                name="uniq_training_program_version_number",
            )
        ]

    def __str__(self):
        return f"{self.program.name} v{self.version_number}"


# ==========================================================================
# LearningPathAssignment
# ==========================================================================

class LearningPathAssignment(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
        ("overdue", "Overdue"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="learning_assignments",
    )
    # Exactly one of learning_path or learning_module must be set
    learning_path = models.ForeignKey(
        LearningPath,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="assignments",
    )
    learning_module = models.ForeignKey(
        LearningModule,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="assignments",
    )

    # Exactly one of user or team must be set (enforced in clean())
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="learning_assignments",
    )
    team = models.ForeignKey(
        Team,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="learning_assignments",
    )

    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_learning_paths",
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    due_date = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_learning_path_assignments"
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["team", "status"]),
            models.Index(fields=["due_date"]),
            models.Index(fields=["company", "due_date"]),
        ]

    def clean(self):
        if bool(self.user_id) == bool(self.team_id):
            raise ValidationError(
                "Exactly one of user or team must be set — not both, not neither."
            )

    def is_overdue(self) -> bool:
        return (
            self.due_date is not None
            and timezone.now() > self.due_date
            and self.status != "completed"
        )

    def __str__(self):
        target = f"user:{self.user_id}" if self.user_id else f"team:{self.team_id}"
        return f"{self.learning_path.name} → {target} ({self.status})"


# ==========================================================================
# LearningModuleProgress
# ==========================================================================

class LearningModuleProgress(models.Model):
    STATUS_CHOICES = [
        ("not_started", "Not Started"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
    ]

    assignment = models.ForeignKey(
        LearningPathAssignment,
        on_delete=models.CASCADE,
        related_name="module_progresses",
    )
    module = models.ForeignKey(
        LearningModule,
        on_delete=models.CASCADE,
        related_name="progresses",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="module_progresses",
    )

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="not_started"
    )
    score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_learning_module_progresses"
        constraints = [
            models.UniqueConstraint(
                fields=["assignment", "module", "user"],
                name="uniq_module_progress_assignment_module_user",
            )
        ]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["assignment", "status"]),
            models.Index(fields=["assignment", "user"]),
        ]

    def __str__(self):
        return f"{self.user} | {self.module.name} | {self.status}"

"""
Ankard Enterprise v1.0 — Phase 3 Retention Engine Models

KnowledgeAssessment  → single assessment event (battery/flashcard/review)
RetentionSnapshot    → historical snapshot per user/topic (never overwrite)
KnowledgeGap         → detected knowledge weakness for user or team
ReviewSchedule       → next scheduled review with spaced-repetition fields
"""

from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from api.enterprise_models import Company, Team


# ==========================================================================
# KnowledgeAssessment
# ==========================================================================

class KnowledgeAssessment(models.Model):
    """
    Records every meaningful assessment event.
    One row per battery attempt / flashcard session / manual review.
    Powers all retention calculations.
    """

    ASSESSMENT_TYPE_CHOICES = [
        ("battery", "Battery / Quiz"),
        ("flashcard_session", "Flashcard Session"),
        ("review", "Scheduled Review"),
        ("manual", "Manual Assessment"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="knowledge_assessments",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="knowledge_assessments",
    )

    # Content references — all optional; at least one should be set
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_assessments",
    )
    learning_module = models.ForeignKey(
        "api.LearningModule",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_assessments",
    )
    topic = models.ForeignKey(
        "api.Topic",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_assessments",
    )
    battery = models.ForeignKey(
        "api.Battery",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_assessments",
    )
    battery_attempt = models.ForeignKey(
        "api.BatteryAttempt",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_assessments",
    )

    assessment_type = models.CharField(
        max_length=30, choices=ASSESSMENT_TYPE_CHOICES, default="battery"
    )

    # Raw performance
    score = models.DecimalField(max_digits=6, decimal_places=2, default=0)  # 0-100
    max_score = models.DecimalField(max_digits=6, decimal_places=2, default=100)
    items_total = models.PositiveIntegerField(default=0)
    items_correct = models.PositiveIntegerField(default=0)

    # Derived scores (calculated by RetentionService at save time)
    retention_score = models.DecimalField(
        max_digits=6, decimal_places=2, default=0,
        help_text="0-100 retention score at the time of this assessment",
    )
    confidence_score = models.DecimalField(
        max_digits=6, decimal_places=2, default=0,
        help_text="0-100 confidence based on score consistency",
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_knowledge_assessments"
        indexes = [
            models.Index(fields=["company", "user"]),
            models.Index(fields=["company", "created_at"]),
            models.Index(fields=["user", "topic"]),
            models.Index(fields=["user", "battery"]),
            models.Index(fields=["company", "user", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} | {self.assessment_type} | {self.score:.1f}% ({self.created_at:%Y-%m-%d})"


# ==========================================================================
# RetentionSnapshot
# ==========================================================================

class RetentionSnapshot(models.Model):
    """
    Historical retention snapshot per (user, topic/path).
    NEVER overwrite — always create a new row.
    Used to visualize retention trends over time.
    """

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="retention_snapshots",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="retention_snapshots",
    )
    topic = models.ForeignKey(
        "api.Topic",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="retention_snapshots",
    )
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="retention_snapshots",
    )

    snapshot_date = models.DateField(default=timezone.now)

    retention_score = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    risk_score = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    confidence_score = models.DecimalField(max_digits=6, decimal_places=2, default=0)

    assessment_count = models.PositiveIntegerField(default=0)
    last_assessment_date = models.DateTimeField(null=True, blank=True)
    next_review_date = models.DateField(null=True, blank=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_retention_snapshots"
        indexes = [
            models.Index(fields=["company", "user"]),
            models.Index(fields=["company", "snapshot_date"]),
            models.Index(fields=["user", "topic"]),
            models.Index(fields=["user", "learning_path"]),
            models.Index(fields=["company", "user", "snapshot_date"]),
        ]
        ordering = ["-snapshot_date", "-created_at"]

    def __str__(self):
        target = f"topic:{self.topic_id}" if self.topic_id else f"path:{self.learning_path_id}"
        return f"{self.user} | {target} | {self.snapshot_date} | R:{self.retention_score}"


# ==========================================================================
# KnowledgeGap
# ==========================================================================

class KnowledgeGap(models.Model):
    """
    A detected knowledge weakness for a user or team.
    Created by RetentionService.detect_knowledge_gaps().
    Managers can acknowledge and resolve gaps.
    """

    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    STATUS_CHOICES = [
        ("open", "Open"),
        ("acknowledged", "Acknowledged"),
        ("resolved", "Resolved"),
        ("dismissed", "Dismissed"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="knowledge_gaps",
    )

    # Target: user OR team (at least one must be set)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.CASCADE,
        related_name="knowledge_gaps",
    )
    team = models.ForeignKey(
        Team,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_gaps",
    )

    # Content that has the gap
    topic = models.ForeignKey(
        "api.Topic",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_gaps",
    )
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="knowledge_gaps",
    )

    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="medium")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open")

    retention_score_at_detection = models.DecimalField(
        max_digits=6, decimal_places=2, default=0
    )

    detected_at = models.DateTimeField(default=timezone.now)

    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="acknowledged_gaps",
    )

    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="resolved_gaps",
    )

    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_knowledge_gaps"
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "severity"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["team", "status"]),
            models.Index(fields=["company", "user", "status"]),
        ]
        ordering = ["-detected_at"]

    def clean(self):
        if not self.user_id and not self.team_id:
            raise ValidationError("At least one of user or team must be set.")

    def __str__(self):
        target = f"user:{self.user_id}" if self.user_id else f"team:{self.team_id}"
        return f"Gap [{self.severity}] {target} | {self.status}"


# ==========================================================================
# ReviewSchedule
# ==========================================================================

class ReviewSchedule(models.Model):
    """
    Scheduled review for a user — powered by spaced repetition (SM-2).

    Fields ease_factor, interval_days, repetition_count drive the algorithm:
      - ease_factor: starts at 2.5, adjusts ±0.1–0.2 based on score
      - interval_days: days until next review (1 → 6 → 14 → ...)
      - repetition_count: how many times the card/topic has been reviewed
    """

    REVIEW_TYPE_CHOICES = [
        ("flashcard", "Flashcard Review"),
        ("battery", "Battery / Quiz"),
        ("reading", "Reading / Study"),
        ("assessment", "Assessment"),
    ]

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("completed", "Completed"),
        ("overdue", "Overdue"),
        ("skipped", "Skipped"),
    ]

    PRIORITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="review_schedules",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="review_schedules",
    )

    # What to review
    topic = models.ForeignKey(
        "api.Topic",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="review_schedules",
    )
    learning_module = models.ForeignKey(
        "api.LearningModule",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="review_schedules",
    )
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="review_schedules",
    )
    flashcard = models.ForeignKey(
        "api.Flashcard",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="review_schedules",
    )
    battery = models.ForeignKey(
        "api.Battery",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="review_schedules",
    )

    review_type = models.CharField(
        max_length=20, choices=REVIEW_TYPE_CHOICES, default="battery"
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending"
    )
    priority = models.CharField(
        max_length=20, choices=PRIORITY_CHOICES, default="medium"
    )

    due_date = models.DateField()
    completed_at = models.DateTimeField(null=True, blank=True)
    score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True,
        help_text="Score after completion (0-100)",
    )

    # SM-2 spaced repetition fields
    ease_factor = models.DecimalField(
        max_digits=4, decimal_places=2, default=2.50,
        help_text="SM-2 ease factor (1.3 – 2.5)",
    )
    interval_days = models.PositiveIntegerField(
        default=1,
        help_text="Days until next review",
    )
    repetition_count = models.PositiveIntegerField(
        default=0,
        help_text="How many times this item has been reviewed",
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_review_schedules"
        indexes = [
            models.Index(fields=["company", "user", "due_date"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["user", "due_date"]),
            models.Index(fields=["company", "status"]),
            models.Index(fields=["due_date"]),
        ]
        ordering = ["due_date"]

    def is_overdue(self) -> bool:
        from django.utils import timezone
        return (
            self.status == "pending"
            and self.due_date < timezone.now().date()
        )

    def __str__(self):
        return f"{self.user} | {self.review_type} | due:{self.due_date} [{self.status}]"

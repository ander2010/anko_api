"""
Ankard Enterprise v1.0 — Phase 4 Compliance Engine Models

ComplianceProgram     → defines a compliance obligation (e.g. FAA Safety Annual)
ComplianceRequirement → learning paths required to complete a program
ComplianceAssignment  → assigns a program to a user OR team
ComplianceReview      → individual review/audit record (never overwrite)
"""

from __future__ import annotations

from typing import Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from api.enterprise_models import BusinessUnit, Company, Team, TenantMixin


# ==========================================================================
# ComplianceProgram
# ==========================================================================

class ComplianceProgram(TenantMixin):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("active", "Active"),
        ("archived", "Archived"),
    ]

    COMPLIANCE_TYPE_CHOICES = [
        ("regulatory", "Regulatory"),
        ("internal", "Internal Policy"),
        ("certification", "Certification"),
        ("safety", "Safety"),
        ("other", "Other"),
    ]

    FREQUENCY_CHOICES = [
        ("one_time", "One Time"),
        ("monthly", "Monthly"),
        ("quarterly", "Quarterly"),
        ("biannual", "Bi-Annual"),
        ("annual", "Annual"),
        ("custom", "Custom"),
    ]

    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="compliance_programs",
    )

    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, help_text="Unique code within the company")
    description = models.TextField(blank=True)
    compliance_type = models.CharField(
        max_length=30, choices=COMPLIANCE_TYPE_CHOICES, default="regulatory"
    )
    frequency = models.CharField(
        max_length=20, choices=FREQUENCY_CHOICES, default="annual"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")

    # How many days a completed compliance is valid for
    validity_days = models.PositiveIntegerField(
        default=365,
        help_text="Days the compliance remains valid after completion",
    )

    # Scoring
    requires_score = models.BooleanField(default=False)
    passing_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True,
        help_text="Minimum score to be considered compliant (0-100)",
    )

    is_mandatory = models.BooleanField(default=True)

    effective_date = models.DateField(null=True, blank=True)
    expiry_date = models.DateField(null=True, blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="created_compliance_programs",
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_compliance_programs"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "code"],
                name="uniq_compliance_program_company_code",
            )
        ]
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "compliance_type"]),
            models.Index(fields=["company", "is_mandatory"]),
        ]

    def __str__(self):
        return f"{self.code} — {self.name} ({self.company})"


# ==========================================================================
# ComplianceRequirement
# ==========================================================================

class ComplianceRequirement(models.Model):
    """
    A specific learning path required to fulfill a ComplianceProgram.
    Programs can have multiple requirements (ordered).
    """

    program = models.ForeignKey(
        ComplianceProgram,
        on_delete=models.CASCADE,
        related_name="requirements",
    )
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="compliance_requirements",
    )

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_mandatory = models.BooleanField(default=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_compliance_requirements"
        ordering = ["order"]
        indexes = [
            models.Index(fields=["program", "order"]),
        ]

    def __str__(self):
        return f"{self.program.code} → req:{self.order} {self.name}"


# ==========================================================================
# ComplianceAssignment
# ==========================================================================

class ComplianceAssignment(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
        ("expired", "Expired"),
        ("non_compliant", "Non-Compliant"),
        ("waived", "Waived"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="compliance_assignments",
    )
    program = models.ForeignKey(
        ComplianceProgram,
        on_delete=models.CASCADE,
        related_name="assignments",
    )

    # Exactly one of user/team must be set
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.CASCADE,
        related_name="compliance_assignments",
    )
    team = models.ForeignKey(
        Team,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="compliance_assignments",
    )

    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_compliance",
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    due_date = models.DateField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # When this compliance certification expires (due_date + validity_days)
    expires_at = models.DateField(null=True, blank=True)

    last_reviewed_at = models.DateTimeField(null=True, blank=True)
    score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    is_compliant = models.BooleanField(default=False)

    # How many times this assignment has been renewed
    renewal_count = models.PositiveIntegerField(default=0)
    # Link to the previous assignment this was renewed from
    renewed_from = models.ForeignKey(
        "self",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="renewals",
    )

    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_compliance_assignments"
        indexes = [
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "program"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["team", "status"]),
            models.Index(fields=["company", "user", "status"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["due_date"]),
        ]
        ordering = ["-created_at"]

    def clean(self):
        if bool(self.user_id) == bool(self.team_id):
            raise ValidationError(
                "Exactly one of user or team must be set — not both, not neither."
            )

    def days_until_expiry(self) -> Optional[int]:
        if not self.expires_at:
            return None
        return (self.expires_at - timezone.now().date()).days

    def is_expiring_soon(self, days: int = 30) -> bool:
        d = self.days_until_expiry()
        return d is not None and 0 <= d <= days

    def is_expired(self) -> bool:
        return (
            self.expires_at is not None
            and self.expires_at < timezone.now().date()
            and self.status != "waived"
        )

    def __str__(self):
        target = f"user:{self.user_id}" if self.user_id else f"team:{self.team_id}"
        return f"{self.program.code} → {target} [{self.status}]"


# ==========================================================================
# ComplianceReview
# ==========================================================================

class ComplianceReview(models.Model):
    """
    Individual review/audit record for a user against a compliance program.
    NEVER overwrite — always insert a new row.
    """

    REVIEW_TYPE_CHOICES = [
        ("initial", "Initial Compliance"),
        ("renewal", "Renewal"),
        ("audit", "Audit"),
        ("override", "Manual Override"),
    ]

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("passed", "Passed"),
        ("failed", "Failed"),
        ("waived", "Waived"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="compliance_reviews",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="compliance_reviews",
    )
    program = models.ForeignKey(
        ComplianceProgram,
        on_delete=models.CASCADE,
        related_name="reviews",
    )
    assignment = models.ForeignKey(
        ComplianceAssignment,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="reviews",
    )

    review_type = models.CharField(
        max_length=20, choices=REVIEW_TYPE_CHOICES, default="initial"
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending"
    )

    score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)

    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="conducted_compliance_reviews",
    )

    notes = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateField(null=True, blank=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_compliance_reviews"
        indexes = [
            models.Index(fields=["company", "user"]),
            models.Index(fields=["company", "program"]),
            models.Index(fields=["user", "program"]),
            models.Index(fields=["company", "status"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} | {self.program.code} | {self.review_type} | {self.status}"

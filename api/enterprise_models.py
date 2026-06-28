"""
Ankard Enterprise v1.0 — Phase 1 Foundation Models

Additive layer. Nothing in api/models.py is modified.
These models live inside the `api` app so they share the same migration history.
"""

import datetime
from django.conf import settings
from django.db import models


# ==========================================================================
# Company (defined first — TenantMixin depends on it)
# ==========================================================================

class Company(models.Model):
    INDUSTRY_CHOICES = [
        ("aviation", "Aviation"),
        ("healthcare", "Healthcare"),
        ("manufacturing", "Manufacturing"),
        ("logistics", "Logistics"),
        ("technology", "Technology"),
        ("finance", "Finance"),
        ("education", "Education"),
        ("other", "Other"),
    ]
    SIZE_CHOICES = [
        ("1_10", "1-10"),
        ("11_50", "11-50"),
        ("51_200", "51-200"),
        ("201_500", "201-500"),
        ("501_1000", "501-1,000"),
        ("1000_plus", "1,000+"),
    ]

    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=100, unique=True)
    logo = models.ImageField(upload_to="company_logos/", null=True, blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="owned_companies",
    )
    website = models.URLField(blank=True)
    industry = models.CharField(max_length=50, choices=INDUSTRY_CHOICES, blank=True)
    company_size = models.CharField(max_length=20, choices=SIZE_CHOICES, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Companies"
        db_table = "enterprise_companies"
        indexes = [
            models.Index(fields=["slug"]),
            models.Index(fields=["owner"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return self.name


# ==========================================================================
# TenantMixin — base for all enterprise models scoped to a Company
# ==========================================================================

class TenantMixin(models.Model):
    """Abstract mixin that binds a model to a Company."""

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="+",
    )

    class Meta:
        abstract = True


# ==========================================================================
# BusinessUnit
# ==========================================================================

class BusinessUnit(TenantMixin):
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=20)
    description = models.TextField(blank=True)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="managed_business_units",
    )
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_business_units"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "code"], name="uniq_bu_company_code"
            ),
            models.UniqueConstraint(
                fields=["company", "name"], name="uniq_bu_company_name"
            ),
        ]

    def __str__(self):
        return f"{self.company.name} — {self.name} ({self.code})"


# ==========================================================================
# CompanyMembership
# ==========================================================================

class CompanyMembership(models.Model):
    ROLE_CHOICES = [
        ("owner", "Owner"),
        ("admin", "Admin"),
        ("manager", "Manager"),
        ("trainer", "Trainer"),
        ("employee", "Employee"),
        ("auditor", "Auditor"),
    ]
    STAGE_CHOICES = [
        ("candidate", "Candidate"),
        ("onboarding", "Onboarding"),
        ("trainee", "Trainee"),
        ("active_employee", "Active Employee"),
        ("contractor", "Contractor"),
        ("former_employee", "Former Employee"),
    ]
    STATUS_CHOICES = [
        ("invited", "Invited"),
        ("active", "Active"),
        ("suspended", "Suspended"),
        ("removed", "Removed"),
    ]

    company = models.ForeignKey(
        Company, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="company_memberships",
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="employee")
    employee_stage = models.CharField(
        max_length=30, choices=STAGE_CHOICES, default="onboarding"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="invited")

    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sent_company_invites",
    )
    joined_at = models.DateTimeField(null=True, blank=True)
    stage_changed_at = models.DateTimeField(null=True, blank=True)
    stage_changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="membership_stage_changes",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_company_memberships"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "user"], name="uniq_membership_company_user"
            ),
        ]
        indexes = [
            models.Index(fields=["company"]),
            models.Index(fields=["user"]),
            models.Index(fields=["role"]),
            models.Index(fields=["employee_stage"]),
            models.Index(fields=["status"]),
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "role"]),
        ]

    def __str__(self):
        return f"{self.user} @ {self.company} ({self.role}/{self.employee_stage})"

    def is_active_member(self) -> bool:
        return self.status == "active"


# ==========================================================================
# Team
# ==========================================================================

class Team(TenantMixin):
    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="teams",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="managed_teams",
    )
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_teams"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "name"], name="uniq_team_company_name"
            ),
        ]
        indexes = [
            models.Index(fields=["company"]),
            models.Index(fields=["business_unit"]),
            models.Index(fields=["manager"]),
        ]

    def __str__(self):
        return f"{self.company.name} — {self.name}"


# ==========================================================================
# TeamMembership
# ==========================================================================

class TeamMembership(models.Model):
    ROLE_CHOICES = [
        ("manager", "Manager"),
        ("member", "Member"),
    ]

    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="team_memberships",
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="member")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_team_memberships"
        constraints = [
            models.UniqueConstraint(
                fields=["team", "user"], name="uniq_team_membership_team_user"
            ),
        ]

    def __str__(self):
        return f"{self.user} in {self.team} ({self.role})"


# ==========================================================================
# EnterpriseProfile
# ==========================================================================

class EnterpriseProfile(models.Model):
    EMPLOYMENT_STATUS_CHOICES = [
        ("active", "Active"),
        ("on_leave", "On Leave"),
        ("terminated", "Terminated"),
        ("suspended", "Suspended"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="enterprise_profile",
    )
    default_company = models.ForeignKey(
        Company,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="default_profile_users",
    )
    job_title = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=200, blank=True)
    employee_code = models.CharField(max_length=100, blank=True)
    hire_date = models.DateField(null=True, blank=True)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="direct_reports",
    )
    employment_status = models.CharField(
        max_length=30, choices=EMPLOYMENT_STATUS_CHOICES, blank=True
    )
    onboarding_completed_at = models.DateTimeField(null=True, blank=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_profiles"

    def __str__(self):
        return f"EnterpriseProfile: {self.user}"


# ==========================================================================
# LearningEvent  (high-volume — optimized indexes)
# ==========================================================================

class LearningEvent(models.Model):
    EVENT_TYPES = [
        ("flashcard_review", "Flashcard Review"),
        ("battery_completed", "Battery Completed"),
        ("battery_attempted", "Battery Attempted"),
        ("module_completed", "Module Completed"),
        ("module_started", "Module Started"),
        ("learning_path_completed", "Learning Path Completed"),
        ("learning_path_assigned", "Learning Path Assigned"),
        ("review_completed", "Review Completed"),
        ("compliance_completed", "Compliance Completed"),
        ("compliance_assigned", "Compliance Assigned"),
        ("compliance_expired", "Compliance Expired"),
        ("certificate_issued", "Certificate Issued"),
        ("certificate_expired", "Certificate Expired"),
        ("certificate_revoked", "Certificate Revoked"),
        ("employee_activated", "Employee Activated"),
        ("knowledge_gap_detected", "Knowledge Gap Detected"),
        ("document_uploaded", "Document Uploaded"),
        ("document_processed", "Document Processed"),
        ("training_generated", "Training Generated"),
        ("training_regenerated", "Training Regenerated"),
        ("retention_recalculated", "Retention Recalculated"),
    ]

    company = models.ForeignKey(
        Company, on_delete=models.CASCADE, related_name="learning_events"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="learning_events",
    )
    event_type = models.CharField(max_length=60, choices=EVENT_TYPES, db_index=True)

    # References to existing api models (nullable — populated as they exist)
    topic = models.ForeignKey(
        "api.Topic",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="learning_events",
    )
    battery = models.ForeignKey(
        "api.Battery",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="learning_events",
    )
    flashcard = models.ForeignKey(
        "api.Flashcard",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="learning_events",
    )
    # Phase 2 — Learning Engine (nullable until Phase 2 migration is applied)
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="events",
    )
    learning_module = models.ForeignKey(
        "api.LearningModule",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="events",
    )

    score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "enterprise_learning_events"
        indexes = [
            models.Index(fields=["company"]),
            models.Index(fields=["user"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["company", "user"]),
            models.Index(fields=["company", "event_type"]),
            models.Index(fields=["company", "created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} | {self.user} | {self.company} | {self.created_at:%Y-%m-%d}"


# ==========================================================================
# KnowledgeHealthSnapshot
# ==========================================================================

class KnowledgeHealthSnapshot(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="health_snapshots",
    )
    snapshot_date = models.DateField(db_index=True)

    global_retention_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    global_risk_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    compliance_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    onboarding_completion_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )

    employees_at_risk = models.PositiveIntegerField(default=0)
    employees_in_onboarding = models.PositiveIntegerField(default=0)
    active_employees = models.PositiveIntegerField(default=0)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_knowledge_health_snapshots"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "snapshot_date"],
                name="uniq_health_snapshot_company_date",
            ),
        ]
        indexes = [
            models.Index(fields=["company", "snapshot_date"]),
        ]

    def __str__(self):
        return f"{self.company} — snapshot {self.snapshot_date}"

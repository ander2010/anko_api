"""
Ankard Enterprise v1.0 — Phase 5 Certifications

CertificateTemplate   → defines a certificate type and its requirements
CertificationRequirement → what a user must complete to earn a certificate
Certification         → actual certificate issued to a user (never overwrite)
"""

from __future__ import annotations

import uuid
from typing import Optional

from django.conf import settings
from django.db import models
from django.utils import timezone

from api.enterprise_models import Company, TenantMixin


# ==========================================================================
# CertificateTemplate
# ==========================================================================

class CertificateTemplate(TenantMixin):
    """
    Defines a certificate type: layout, validity, and what triggers issuance.
    """

    TEMPLATE_TYPE_CHOICES = [
        ("course_completion", "Course Completion"),
        ("compliance", "Compliance"),
        ("skill_mastery", "Skill Mastery"),
        ("certification", "Professional Certification"),
        ("custom", "Custom"),
    ]

    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, help_text="Unique code within the company")
    description = models.TextField(blank=True)
    template_type = models.CharField(
        max_length=30, choices=TEMPLATE_TYPE_CHOICES, default="course_completion"
    )

    # Template content (rendered server-side to produce the certificate)
    header_text = models.TextField(blank=True)
    body_text = models.TextField(blank=True)
    footer_text = models.TextField(blank=True)

    # Scoring
    requires_score = models.BooleanField(default=False)
    minimum_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )

    # 0 = never expires
    validity_days = models.PositiveIntegerField(
        default=0,
        help_text="Days the certificate is valid (0 = no expiry)",
    )

    is_active = models.BooleanField(default=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="created_certificate_templates",
    )

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_certificate_templates"
        constraints = [
            models.UniqueConstraint(
                fields=["company", "code"],
                name="uniq_certificate_template_company_code",
            )
        ]
        indexes = [
            models.Index(fields=["company", "template_type"]),
            models.Index(fields=["company", "is_active"]),
        ]

    def __str__(self) -> str:
        return f"{self.code} — {self.name} ({self.company})"


# ==========================================================================
# CertificationRequirement
# ==========================================================================

class CertificationRequirement(models.Model):
    """
    A condition a user must fulfill to automatically earn a certificate.
    A template can have multiple requirements (all must be met).
    """

    template = models.ForeignKey(
        CertificateTemplate,
        on_delete=models.CASCADE,
        related_name="requirements",
    )
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="certification_requirements",
    )
    compliance_program = models.ForeignKey(
        "api.ComplianceProgram",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="certification_requirements",
    )

    description = models.TextField(blank=True)
    minimum_score = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    order = models.PositiveIntegerField(default=0)
    is_mandatory = models.BooleanField(default=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "enterprise_certification_requirements"
        ordering = ["order"]
        indexes = [
            models.Index(fields=["template", "order"]),
        ]

    def __str__(self) -> str:
        return f"{self.template.code} req:{self.order}"


# ==========================================================================
# Certification
# ==========================================================================

class Certification(models.Model):
    """
    An actual certificate issued to a user.
    NEVER overwrite — revoke and re-issue instead.
    """

    STATUS_CHOICES = [
        ("active", "Active"),
        ("expired", "Expired"),
        ("revoked", "Revoked"),
    ]

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="certifications",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="certifications",
    )
    template = models.ForeignKey(
        CertificateTemplate,
        on_delete=models.PROTECT,
        related_name="issued_certifications",
    )

    # Unique identifiers
    certificate_number = models.UUIDField(
        default=uuid.uuid4, unique=True, editable=False
    )
    verification_code = models.CharField(
        max_length=16, unique=True, editable=False, db_index=True
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")

    # What triggered issuance (optional links)
    learning_path = models.ForeignKey(
        "api.LearningPath",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="certifications",
    )
    compliance_program = models.ForeignKey(
        "api.ComplianceProgram",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="certifications",
    )

    score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)

    issued_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)

    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="issued_certifications",
    )

    # Revocation
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="revoked_certifications",
    )
    revocation_reason = models.TextField(blank=True)

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_certifications"
        indexes = [
            models.Index(fields=["company", "user"]),
            models.Index(fields=["company", "status"]),
            models.Index(fields=["company", "template"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["issued_at"]),
        ]
        ordering = ["-issued_at"]

    def save(self, *args, **kwargs):
        if not self.verification_code:
            self.verification_code = self._generate_verification_code()
        super().save(*args, **kwargs)

    @staticmethod
    def _generate_verification_code() -> str:
        import random
        import string
        alphabet = string.ascii_uppercase + string.digits
        while True:
            code = "".join(random.choices(alphabet, k=12))
            if not Certification.objects.filter(verification_code=code).exists():
                return code

    def is_valid(self) -> bool:
        if self.status != "active":
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < timezone.now()

    def days_until_expiry(self) -> Optional[int]:
        if not self.expires_at:
            return None
        delta = self.expires_at.date() - timezone.now().date()
        return delta.days

    def __str__(self) -> str:
        return f"CERT-{str(self.certificate_number)[:8].upper()} {self.user} [{self.status}]"

"""Phase 5 Certification Serializers."""

from __future__ import annotations

from rest_framework import serializers

from api.enterprise_certification_models import (
    CertificateTemplate,
    Certification,
    CertificationRequirement,
)


class CertificationRequirementSerializer(serializers.ModelSerializer):
    learning_path_name = serializers.CharField(
        source="learning_path.name", read_only=True
    )
    compliance_program_name = serializers.CharField(
        source="compliance_program.name", read_only=True
    )

    class Meta:
        model = CertificationRequirement
        fields = [
            "id", "template",
            "learning_path", "learning_path_name",
            "compliance_program", "compliance_program_name",
            "description", "minimum_score", "order", "is_mandatory",
            "metadata", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "learning_path_name", "compliance_program_name",
            "created_at", "updated_at",
        ]


class CertificateTemplateSerializer(serializers.ModelSerializer):
    requirements = CertificationRequirementSerializer(many=True, read_only=True)
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )
    issued_count = serializers.SerializerMethodField()

    class Meta:
        model = CertificateTemplate
        fields = [
            "id", "company", "name", "code", "description",
            "template_type", "header_text", "body_text", "footer_text",
            "requires_score", "minimum_score", "validity_days",
            "is_active", "created_by", "created_by_username",
            "issued_count", "requirements",
            "metadata", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "company", "created_by", "created_by_username",
            "issued_count", "created_at", "updated_at",
        ]

    def get_issued_count(self, obj):
        return obj.issued_certifications.count()


class CertificateTemplateListSerializer(serializers.ModelSerializer):
    """Light version — no nested requirements."""
    issued_count = serializers.SerializerMethodField()
    active_count = serializers.SerializerMethodField()
    requirement_count = serializers.SerializerMethodField()

    class Meta:
        model = CertificateTemplate
        fields = [
            "id", "company", "name", "code", "template_type",
            "requires_score", "minimum_score", "validity_days",
            "is_active", "issued_count", "active_count", "requirement_count",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "company", "created_at", "updated_at"]

    def get_issued_count(self, obj):
        return obj.issued_certifications.count()

    def get_active_count(self, obj):
        return obj.issued_certifications.filter(status="active").count()

    def get_requirement_count(self, obj):
        return obj.requirements.count()


class CertificationSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    user_full_name = serializers.SerializerMethodField()
    template_name = serializers.CharField(source="template.name", read_only=True)
    template_code = serializers.CharField(source="template.code", read_only=True)
    learning_path_name = serializers.CharField(
        source="learning_path.name", read_only=True
    )
    compliance_program_name = serializers.CharField(
        source="compliance_program.name", read_only=True
    )
    issued_by_username = serializers.CharField(
        source="issued_by.username", read_only=True
    )
    revoked_by_username = serializers.CharField(
        source="revoked_by.username", read_only=True
    )
    is_valid = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    days_until_expiry = serializers.SerializerMethodField()
    verification_url = serializers.SerializerMethodField()

    class Meta:
        model = Certification
        fields = [
            "id", "company",
            "user", "user_username", "user_full_name",
            "template", "template_name", "template_code",
            "certificate_number", "verification_code", "verification_url",
            "status",
            "learning_path", "learning_path_name",
            "compliance_program", "compliance_program_name",
            "score",
            "issued_at", "expires_at",
            "issued_by", "issued_by_username",
            "revoked_at", "revoked_by", "revoked_by_username",
            "revocation_reason",
            "is_valid", "is_expired", "days_until_expiry",
            "metadata", "created_at",
        ]
        read_only_fields = [
            "id", "company",
            "user_username", "user_full_name",
            "template_name", "template_code",
            "learning_path_name", "compliance_program_name",
            "certificate_number", "verification_code", "verification_url",
            "issued_by_username", "revoked_by_username",
            "status", "issued_at", "expires_at",
            "revoked_at", "revoked_by",
            "is_valid", "is_expired", "days_until_expiry",
            "created_at",
        ]

    def get_user_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username

    def get_is_valid(self, obj):
        return obj.is_valid()

    def get_is_expired(self, obj):
        return obj.is_expired()

    def get_days_until_expiry(self, obj):
        return obj.days_until_expiry()

    def get_verification_url(self, obj):
        from api.enterprise.services.certification_service import CertificationService
        return CertificationService.generate_verification_url(obj)


class CertificationVerifySerializer(serializers.Serializer):
    """Response for the public /verify/ endpoint."""
    valid = serializers.BooleanField()
    status = serializers.CharField(required=False)
    error = serializers.CharField(required=False)
    certificate_number = serializers.CharField(required=False)
    verification_code = serializers.CharField(required=False)
    holder_name = serializers.CharField(required=False)
    template_name = serializers.CharField(required=False)
    template_code = serializers.CharField(required=False)
    issued_at = serializers.CharField(required=False)
    expires_at = serializers.CharField(required=False, allow_null=True)
    company_name = serializers.CharField(required=False)
    score = serializers.CharField(required=False, allow_null=True)


class CertificationEligibilitySerializer(serializers.Serializer):
    """Response for the eligibility-check action."""
    eligible = serializers.BooleanField()
    reasons = serializers.ListField(child=serializers.CharField())
    met_requirements = serializers.IntegerField()
    total_requirements = serializers.IntegerField()


class CertificationStatsSerializer(serializers.Serializer):
    """Company-level certification statistics."""
    company_id = serializers.IntegerField()
    company_name = serializers.CharField()
    total_issued = serializers.IntegerField()
    active = serializers.IntegerField()
    expired = serializers.IntegerField()
    revoked = serializers.IntegerField()
    expiring_soon = serializers.IntegerField()
    unique_holders = serializers.IntegerField()


class UserCertificationStatsSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    total = serializers.IntegerField()
    active = serializers.IntegerField()
    expired = serializers.IntegerField()
    revoked = serializers.IntegerField()


class CertificateDataSerializer(serializers.Serializer):
    """Full data for rendering a certificate PDF/HTML."""
    certificate_number = serializers.CharField()
    verification_code = serializers.CharField()
    verification_url = serializers.CharField()
    holder_name = serializers.CharField()
    template_name = serializers.CharField()
    template_type = serializers.CharField()
    header_text = serializers.CharField()
    body_text = serializers.CharField()
    footer_text = serializers.CharField()
    company_name = serializers.CharField()
    issued_at = serializers.CharField()
    expires_at = serializers.CharField(allow_null=True)
    score = serializers.CharField(allow_null=True)
    status = serializers.CharField()

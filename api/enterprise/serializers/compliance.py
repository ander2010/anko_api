"""Phase 4 Compliance Engine Serializers."""

from __future__ import annotations

from rest_framework import serializers

from api.enterprise_compliance_models import (
    ComplianceAssignment,
    ComplianceProgram,
    ComplianceRequirement,
    ComplianceReview,
)


class ComplianceRequirementSerializer(serializers.ModelSerializer):
    learning_path_name = serializers.CharField(source="learning_path.name", read_only=True)

    class Meta:
        model = ComplianceRequirement
        fields = [
            "id", "program", "learning_path", "learning_path_name",
            "name", "description", "order", "is_mandatory",
            "metadata", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "learning_path_name", "created_at", "updated_at"]


class ComplianceProgramSerializer(serializers.ModelSerializer):
    requirements = ComplianceRequirementSerializer(many=True, read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)
    requirement_count = serializers.SerializerMethodField()

    class Meta:
        model = ComplianceProgram
        fields = [
            "id", "company", "business_unit",
            "name", "code", "description",
            "compliance_type", "frequency", "status",
            "validity_days", "requires_score", "passing_score",
            "is_mandatory", "effective_date", "expiry_date",
            "created_by", "created_by_username",
            "metadata", "requirement_count", "requirements",
            "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "company", "created_by", "created_by_username",
            "requirement_count", "created_at", "updated_at",
        ]

    def get_requirement_count(self, obj):
        return obj.requirements.count()


class ComplianceProgramListSerializer(serializers.ModelSerializer):
    """Light serializer — no nested requirements."""
    requirement_count = serializers.SerializerMethodField()
    assignment_count = serializers.SerializerMethodField()

    class Meta:
        model = ComplianceProgram
        fields = [
            "id", "company", "business_unit",
            "name", "code", "compliance_type", "frequency", "status",
            "is_mandatory", "validity_days",
            "effective_date", "expiry_date",
            "requirement_count", "assignment_count",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "company", "created_at", "updated_at"]

    def get_requirement_count(self, obj):
        return obj.requirements.count()

    def get_assignment_count(self, obj):
        return obj.assignments.count()


class ComplianceAssignmentSerializer(serializers.ModelSerializer):
    program_name = serializers.CharField(source="program.name", read_only=True)
    program_code = serializers.CharField(source="program.code", read_only=True)
    user_username = serializers.CharField(source="user.username", read_only=True)
    team_name = serializers.CharField(source="team.name", read_only=True)
    assigned_by_username = serializers.CharField(source="assigned_by.username", read_only=True)
    days_until_expiry = serializers.SerializerMethodField()
    is_expiring_soon = serializers.SerializerMethodField()
    is_expired_field = serializers.SerializerMethodField(method_name="get_is_expired")

    class Meta:
        model = ComplianceAssignment
        fields = [
            "id", "company", "program", "program_name", "program_code",
            "user", "user_username", "team", "team_name",
            "assigned_by", "assigned_by_username",
            "status", "is_compliant",
            "due_date", "completed_at", "expires_at", "last_reviewed_at",
            "score", "renewal_count", "renewed_from",
            "days_until_expiry", "is_expiring_soon", "is_expired_field",
            "notes", "metadata", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "company", "assigned_by", "assigned_by_username",
            "status", "is_compliant", "completed_at", "expires_at",
            "last_reviewed_at", "renewal_count", "renewed_from",
            "days_until_expiry", "is_expiring_soon", "is_expired_field",
            "program_name", "program_code", "user_username", "team_name",
            "created_at", "updated_at",
        ]

    def get_days_until_expiry(self, obj):
        return obj.days_until_expiry()

    def get_is_expiring_soon(self, obj):
        return obj.is_expiring_soon()

    def get_is_expired(self, obj):
        return obj.is_expired()

    def validate(self, attrs):
        user = attrs.get("user")
        team = attrs.get("team")
        if bool(user) == bool(team):
            raise serializers.ValidationError(
                "Exactly one of user or team must be provided."
            )
        return attrs


class ComplianceReviewSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    program_code = serializers.CharField(source="program.code", read_only=True)
    reviewer_username = serializers.CharField(source="reviewer.username", read_only=True)

    class Meta:
        model = ComplianceReview
        fields = [
            "id", "company", "user", "user_username",
            "program", "program_code", "assignment",
            "review_type", "status", "score",
            "reviewer", "reviewer_username",
            "notes", "reviewed_at", "valid_until",
            "metadata", "created_at",
        ]
        read_only_fields = ["id", "user_username", "program_code", "reviewer_username", "created_at"]


class ComplianceStatusSerializer(serializers.Serializer):
    """Used by evaluate_compliance and compliance status endpoints."""
    user_id = serializers.IntegerField(required=False)
    total_programs = serializers.IntegerField()
    compliant = serializers.IntegerField()
    non_compliant = serializers.IntegerField()
    pending = serializers.IntegerField()
    expired = serializers.IntegerField()
    compliance_rate = serializers.DecimalField(max_digits=6, decimal_places=2)


class ComplianceAuditReportSerializer(serializers.Serializer):
    program_code = serializers.CharField()
    program_name = serializers.CharField()
    compliance_type = serializers.CharField()
    total_assignments = serializers.IntegerField()
    compliant = serializers.IntegerField()
    non_compliant = serializers.IntegerField()
    pending = serializers.IntegerField()
    expired = serializers.IntegerField()
    compliance_rate = serializers.DecimalField(max_digits=6, decimal_places=2)
    total_reviews = serializers.IntegerField()
    passed_reviews = serializers.IntegerField()
    failed_reviews = serializers.IntegerField()

from __future__ import annotations

from rest_framework import serializers

from api.enterprise_models import CompanyInvitation, CompanyMembership


class SendInvitationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=CompanyMembership.ROLE_CHOICES, default="employee")
    employee_stage = serializers.ChoiceField(
        choices=CompanyMembership.STAGE_CHOICES, default="onboarding"
    )


class InvitationSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source="company.name", read_only=True)
    invited_by_email = serializers.EmailField(source="invited_by.email", read_only=True, default=None)
    is_usable = serializers.SerializerMethodField()

    class Meta:
        model = CompanyInvitation
        fields = [
            "id",
            "company",
            "company_name",
            "email",
            "role",
            "employee_stage",
            "token",
            "status",
            "is_usable",
            "invited_by",
            "invited_by_email",
            "accepted_by",
            "accepted_at",
            "expires_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_is_usable(self, obj):
        return obj.is_usable()


class InvitationPreviewSerializer(serializers.ModelSerializer):
    """
    Safe public serializer — returned to the frontend when it validates a token.
    Does NOT expose token or internal IDs.
    """
    company_name = serializers.CharField(source="company.name", read_only=True)
    company_logo = serializers.SerializerMethodField()
    invited_by_name = serializers.SerializerMethodField()

    class Meta:
        model = CompanyInvitation
        fields = [
            "email",
            "role",
            "employee_stage",
            "company_name",
            "company_logo",
            "invited_by_name",
            "expires_at",
        ]
        read_only_fields = fields

    def get_company_logo(self, obj):
        logo = getattr(obj.company, "logo", None)
        if logo:
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(logo.url)
        return None

    def get_invited_by_name(self, obj):
        if obj.invited_by:
            return obj.invited_by.get_full_name() or obj.invited_by.username
        return None


class AcceptInvitationSerializer(serializers.Serializer):
    token = serializers.UUIDField()

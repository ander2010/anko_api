"""
Phase 8 — Company Management Serializers
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers

from api.enterprise_models import (
    BusinessUnit,
    Company,
    CompanyMembership,
    Team,
    TeamMembership,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Company
# ---------------------------------------------------------------------------

class CompanySerializer(serializers.ModelSerializer):
    owner_username = serializers.CharField(source="owner.username", read_only=True)
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Company
        fields = [
            "id",
            "name",
            "slug",
            "logo",
            "owner",
            "owner_username",
            "website",
            "industry",
            "company_size",
            "description",
            "is_active",
            "settings",
            "member_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "owner",
            "owner_username",
            "is_active",
            "member_count",
            "created_at",
            "updated_at",
        ]

    def get_member_count(self, obj):
        return obj.memberships.filter(status="active").count()


class CompanyCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = [
            "name",
            "slug",
            "website",
            "industry",
            "company_size",
            "description",
        ]


class CompanyListSerializer(serializers.ModelSerializer):
    """Light serializer — used in list views."""

    owner_username = serializers.CharField(source="owner.username", read_only=True)
    member_count = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()

    class Meta:
        model = Company
        fields = [
            "id",
            "name",
            "slug",
            "logo",
            "owner_username",
            "industry",
            "company_size",
            "is_active",
            "member_count",
            "user_role",
            "created_at",
        ]
        read_only_fields = fields

    def get_member_count(self, obj):
        return obj.memberships.filter(status="active").count()

    def get_user_role(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
        membership = obj.memberships.filter(user=request.user, status="active").first()
        return membership.role if membership else None


# ---------------------------------------------------------------------------
# CompanyMembership
# ---------------------------------------------------------------------------

class MembershipSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = CompanyMembership
        fields = [
            "id",
            "user",
            "username",
            "email",
            "full_name",
            "role",
            "employee_stage",
            "status",
            "joined_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "username",
            "email",
            "full_name",
            "joined_at",
            "created_at",
            "updated_at",
        ]

    def get_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username


class InviteUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(
        choices=CompanyMembership.ROLE_CHOICES,
        default="employee",
    )
    employee_stage = serializers.ChoiceField(
        choices=CompanyMembership.STAGE_CHOICES,
        default="onboarding",
    )


class ChangeMemberRoleSerializer(serializers.Serializer):
    membership_id = serializers.IntegerField()
    role = serializers.ChoiceField(choices=CompanyMembership.ROLE_CHOICES)


class RemoveMemberSerializer(serializers.Serializer):
    membership_id = serializers.IntegerField()


# ---------------------------------------------------------------------------
# BusinessUnit
# ---------------------------------------------------------------------------

class BusinessUnitSerializer(serializers.ModelSerializer):
    manager_username = serializers.CharField(
        source="manager.username", read_only=True
    )
    team_count = serializers.SerializerMethodField()

    class Meta:
        model = BusinessUnit
        fields = [
            "id",
            "company",
            "name",
            "code",
            "description",
            "manager",
            "manager_username",
            "is_active",
            "metadata",
            "team_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "manager_username",
            "team_count",
            "created_at",
            "updated_at",
        ]

    def get_team_count(self, obj):
        return obj.teams.filter(is_active=True).count()


# ---------------------------------------------------------------------------
# Team
# ---------------------------------------------------------------------------

class TeamMembershipSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = TeamMembership
        fields = [
            "id",
            "team",
            "user",
            "username",
            "email",
            "full_name",
            "role",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "team",
            "username",
            "email",
            "full_name",
            "created_at",
        ]

    def get_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username


class TeamSerializer(serializers.ModelSerializer):
    manager_username = serializers.CharField(
        source="manager.username", read_only=True
    )
    member_count = serializers.SerializerMethodField()
    members = TeamMembershipSerializer(
        source="memberships", many=True, read_only=True
    )
    business_unit_name = serializers.CharField(
        source="business_unit.name", read_only=True
    )

    class Meta:
        model = Team
        fields = [
            "id",
            "company",
            "business_unit",
            "business_unit_name",
            "name",
            "description",
            "manager",
            "manager_username",
            "is_active",
            "metadata",
            "member_count",
            "members",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "manager_username",
            "business_unit_name",
            "member_count",
            "created_at",
            "updated_at",
        ]

    def get_member_count(self, obj):
        return obj.memberships.count()


class TeamListSerializer(serializers.ModelSerializer):
    manager_username = serializers.CharField(
        source="manager.username", read_only=True
    )
    member_count = serializers.SerializerMethodField()
    business_unit_name = serializers.CharField(
        source="business_unit.name", read_only=True
    )

    class Meta:
        model = Team
        fields = [
            "id",
            "company",
            "business_unit",
            "business_unit_name",
            "name",
            "description",
            "manager",
            "manager_username",
            "is_active",
            "member_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_member_count(self, obj):
        return obj.memberships.count()


class AddTeamMemberSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    role = serializers.ChoiceField(
        choices=TeamMembership.ROLE_CHOICES, default="member"
    )

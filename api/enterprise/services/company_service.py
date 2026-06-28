"""
Phase 8 — Company Management Service

Business logic for company, business unit, and team management.
"""

from __future__ import annotations

from typing import Optional

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from api.enterprise_models import (
    BusinessUnit,
    Company,
    CompanyMembership,
    Team,
    TeamMembership,
)

User = get_user_model()


class CompanyService:

    @staticmethod
    @transaction.atomic
    def create_company(user, validated_data: dict) -> Company:
        company = Company.objects.create(owner=user, **validated_data)
        CompanyMembership.objects.create(
            company=company,
            user=user,
            role="owner",
            employee_stage="active_employee",
            status="active",
            joined_at=timezone.now(),
        )
        return company

    @staticmethod
    @transaction.atomic
    def add_user(
        company: Company,
        email: str,
        role: str,
        employee_stage: str,
        added_by,
    ) -> CompanyMembership:
        try:
            target_user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Auto-create user — they can reset their password via email
            username = email.split("@")[0]
            base = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base}{counter}"
                counter += 1
            target_user = User.objects.create_user(
                username=username,
                email=email,
                password=None,
            )
            target_user.set_unusable_password()
            target_user.save()

        existing = CompanyMembership.objects.filter(
            company=company, user=target_user
        ).first()
        if existing:
            if existing.status == "removed":
                # Re-activate a previously removed member
                existing.status = "active"
                existing.role = role
                existing.employee_stage = employee_stage
                existing.invited_by = added_by
                existing.joined_at = existing.joined_at or timezone.now()
                existing.save(
                    update_fields=[
                        "status",
                        "role",
                        "employee_stage",
                        "invited_by",
                        "joined_at",
                        "updated_at",
                    ]
                )
                return existing
            raise ValidationError(
                {
                    "email": (
                        f"User with email '{email}' is already a member "
                        f"of this company (status: {existing.status})."
                    )
                }
            )

        membership = CompanyMembership.objects.create(
            company=company,
            user=target_user,
            role=role,
            employee_stage=employee_stage,
            status="active",          # immediate access — no invite step
            joined_at=timezone.now(),
            invited_by=added_by,
        )
        return membership

    @staticmethod
    def change_member_role(
        company: Company,
        membership_id: int,
        new_role: str,
        changed_by,
    ) -> CompanyMembership:
        try:
            membership = CompanyMembership.objects.get(
                id=membership_id, company=company
            )
        except CompanyMembership.DoesNotExist:
            raise ValidationError({"membership_id": "Membership not found in this company."})

        if membership.role == "owner":
            raise ValidationError({"role": "Cannot change the owner's role."})

        if new_role == "owner":
            raise ValidationError(
                {"role": "Use the transfer-ownership endpoint to assign the owner role."}
            )

        membership.role = new_role
        membership.save(update_fields=["role", "updated_at"])
        return membership

    @staticmethod
    def remove_member(
        company: Company,
        membership_id: int,
        removed_by,
    ) -> CompanyMembership:
        try:
            membership = CompanyMembership.objects.get(
                id=membership_id, company=company
            )
        except CompanyMembership.DoesNotExist:
            raise ValidationError({"membership_id": "Membership not found in this company."})

        if membership.role == "owner":
            raise ValidationError({"membership_id": "Cannot remove the company owner."})

        membership.status = "removed"
        membership.save(update_fields=["status", "updated_at"])
        return membership

    @staticmethod
    def activate_member(company: Company, membership_id: int) -> CompanyMembership:
        try:
            membership = CompanyMembership.objects.get(
                id=membership_id, company=company
            )
        except CompanyMembership.DoesNotExist:
            raise ValidationError({"membership_id": "Membership not found in this company."})

        membership.status = "active"
        membership.joined_at = membership.joined_at or timezone.now()
        membership.save(update_fields=["status", "joined_at", "updated_at"])
        return membership


class BusinessUnitService:

    @staticmethod
    def create_business_unit(company: Company, validated_data: dict) -> BusinessUnit:
        return BusinessUnit.objects.create(company=company, **validated_data)


class TeamService:

    @staticmethod
    @transaction.atomic
    def create_team(company: Company, validated_data: dict) -> Team:
        return Team.objects.create(company=company, **validated_data)

    @staticmethod
    def add_member(
        team: Team,
        user_id: int,
        role: str,
    ) -> TeamMembership:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})

        # Verify the user is a member of the same company
        is_company_member = CompanyMembership.objects.filter(
            company=team.company,
            user=user,
            status__in=["active", "invited"],
        ).exists()
        if not is_company_member:
            raise ValidationError(
                {"user_id": "User is not a member of this company."}
            )

        membership, created = TeamMembership.objects.get_or_create(
            team=team,
            user=user,
            defaults={"role": role},
        )
        if not created:
            raise ValidationError(
                {"user_id": "User is already a member of this team."}
            )
        return membership

    @staticmethod
    def remove_member(team: Team, user_id: int) -> None:
        deleted, _ = TeamMembership.objects.filter(
            team=team, user_id=user_id
        ).delete()
        if not deleted:
            raise ValidationError(
                {"user_id": "User is not a member of this team."}
            )

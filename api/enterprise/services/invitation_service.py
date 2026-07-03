"""
Enterprise — Invitation Service

Handles the full lifecycle of company invitations:
  create  → generates token, sends email
  validate → checks token is usable
  accept  → activates membership for an authenticated user
  silent_join → called at register/login to auto-accept pending invitations by email
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from api.enterprise_models import Company, CompanyInvitation, CompanyMembership

User = get_user_model()

TOKEN_TTL_HOURS = 72


class InvitationService:

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_invitation(
        *,
        company: Company,
        email: str,
        role: str,
        employee_stage: str,
        invited_by,
    ) -> CompanyInvitation:
        email = email.strip().lower()

        # Cancel any previous pending invitation for this email+company
        CompanyInvitation.objects.filter(
            company=company,
            email=email,
            status=CompanyInvitation.STATUS_PENDING,
        ).update(status=CompanyInvitation.STATUS_CANCELLED)

        # Guard: if the user already has an active/suspended membership, reject
        existing_user = User.objects.filter(email=email).first()
        if existing_user:
            existing_membership = CompanyMembership.objects.filter(
                company=company,
                user=existing_user,
                status__in=["active", "suspended"],
            ).first()
            if existing_membership:
                raise ValidationError(
                    {
                        "email": (
                            f"'{email}' is already a {existing_membership.status} "
                            f"member of this company."
                        )
                    }
                )

        invitation = CompanyInvitation.objects.create(
            company=company,
            email=email,
            role=role,
            employee_stage=employee_stage,
            token=uuid.uuid4(),
            expires_at=timezone.now() + timedelta(hours=TOKEN_TTL_HOURS),
            status=CompanyInvitation.STATUS_PENDING,
            invited_by=invited_by,
        )
        return invitation

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    @staticmethod
    def validate_token(token: str) -> CompanyInvitation:
        try:
            invitation = CompanyInvitation.objects.select_related(
                "company", "invited_by"
            ).get(token=token)
        except (CompanyInvitation.DoesNotExist, ValueError):
            raise ValidationError({"token": "Invitation not found."})

        if invitation.status == CompanyInvitation.STATUS_ACCEPTED:
            raise ValidationError({"token": "This invitation has already been accepted."})

        if invitation.status == CompanyInvitation.STATUS_CANCELLED:
            raise ValidationError({"token": "This invitation has been cancelled."})

        if invitation.status == CompanyInvitation.STATUS_EXPIRED:
            raise ValidationError({"token": "This invitation has expired."})

        if not invitation.is_usable():
            # Mark as expired now
            invitation.status = CompanyInvitation.STATUS_EXPIRED
            invitation.save(update_fields=["status", "updated_at"])
            raise ValidationError(
                {"token": f"This invitation expired. Ask an admin to resend it."}
            )

        return invitation

    # ------------------------------------------------------------------
    # Accept
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def accept_invitation(*, token: str, user) -> CompanyMembership:
        invitation = InvitationService.validate_token(token)

        # The accepting user must match the invited email
        if user.email.lower() != invitation.email.lower():
            raise ValidationError(
                {
                    "token": (
                        f"This invitation was sent to {invitation.email}. "
                        f"You are logged in as {user.email}."
                    )
                }
            )

        membership = InvitationService._activate_membership(invitation, user)

        invitation.status = CompanyInvitation.STATUS_ACCEPTED
        invitation.accepted_by = user
        invitation.accepted_at = timezone.now()
        invitation.save(update_fields=["status", "accepted_by", "accepted_at", "updated_at"])

        return membership

    # ------------------------------------------------------------------
    # Silent join (called at register / login)
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def silent_join(*, user) -> list[CompanyMembership]:
        """
        Auto-accept all pending invitations for the user's email.
        Returns the list of newly activated memberships.
        Called after register or login — never raises, only logs.
        """
        import logging
        logger = logging.getLogger(__name__)

        email = user.email.strip().lower()
        pending = CompanyInvitation.objects.select_related("company").filter(
            email=email,
            status=CompanyInvitation.STATUS_PENDING,
        )

        activated = []
        for invitation in pending:
            if not invitation.is_usable():
                invitation.status = CompanyInvitation.STATUS_EXPIRED
                invitation.save(update_fields=["status", "updated_at"])
                continue
            try:
                membership = InvitationService._activate_membership(invitation, user)
                invitation.status = CompanyInvitation.STATUS_ACCEPTED
                invitation.accepted_by = user
                invitation.accepted_at = timezone.now()
                invitation.save(
                    update_fields=["status", "accepted_by", "accepted_at", "updated_at"]
                )
                activated.append(membership)
                logger.info(
                    "silent_join: user_id=%s joined company_id=%s role=%s",
                    user.id,
                    invitation.company_id,
                    invitation.role,
                )
            except Exception as exc:
                logger.warning(
                    "silent_join failed for invitation_id=%s user_id=%s: %s",
                    invitation.id,
                    user.id,
                    exc,
                )

        return activated

    # ------------------------------------------------------------------
    # Resend
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def resend_invitation(*, invitation: CompanyInvitation, resent_by) -> CompanyInvitation:
        if invitation.status == CompanyInvitation.STATUS_ACCEPTED:
            raise ValidationError({"detail": "Invitation already accepted."})

        invitation.token = uuid.uuid4()
        invitation.expires_at = timezone.now() + timedelta(hours=TOKEN_TTL_HOURS)
        invitation.status = CompanyInvitation.STATUS_PENDING
        invitation.save(update_fields=["token", "expires_at", "status", "updated_at"])
        return invitation

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _activate_membership(
        invitation: CompanyInvitation, user
    ) -> CompanyMembership:
        existing = CompanyMembership.objects.filter(
            company=invitation.company, user=user
        ).first()

        if existing:
            if existing.status in ("active", "suspended"):
                return existing
            # Re-activate a removed/invited membership
            existing.status = "active"
            existing.role = invitation.role
            existing.employee_stage = invitation.employee_stage
            existing.invited_by = invitation.invited_by
            existing.joined_at = existing.joined_at or timezone.now()
            existing.save(
                update_fields=[
                    "status", "role", "employee_stage",
                    "invited_by", "joined_at", "updated_at",
                ]
            )
            return existing

        return CompanyMembership.objects.create(
            company=invitation.company,
            user=user,
            role=invitation.role,
            employee_stage=invitation.employee_stage,
            status="active",
            invited_by=invitation.invited_by,
            joined_at=timezone.now(),
        )

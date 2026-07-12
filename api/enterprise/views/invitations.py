"""
Enterprise — Invitation Views

Endpoints:
    POST   /api/enterprise/companies/{company_id}/invitations/         → send invitation
    GET    /api/enterprise/companies/{company_id}/invitations/         → list invitations
    POST   /api/enterprise/companies/{company_id}/invitations/{id}/resend/ → resend
    DELETE /api/enterprise/companies/{company_id}/invitations/{id}/    → cancel

    GET    /api/enterprise/invitations/validate/?token=XYZ             → public preview (no auth)
    POST   /api/enterprise/invitations/accept/                         → accept (authenticated)
"""
from __future__ import annotations

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from api.enterprise.serializers.invitations import (
    AcceptInvitationSerializer,
    InvitationPreviewSerializer,
    InvitationSerializer,
    SendInvitationSerializer,
)
from api.enterprise.services.email_service import send_invitation_email
from api.enterprise.services.invitation_service import InvitationService
from api.enterprise.services.rbac_service import has_permission
from api.enterprise_models import Company, CompanyInvitation, CompanyMembership


def _get_company_or_404(company_id):
    try:
        return Company.objects.get(pk=company_id, is_active=True)
    except Company.DoesNotExist:
        raise NotFound("Company not found.")


def _require_admin(user, company):
    if user.is_staff:
        return None
    membership = CompanyMembership.objects.filter(
        company=company, user=user, status="active"
    ).first()
    if not membership or not has_permission(membership.role, "enterprise.ent-invitations", "manage"):
        raise PermissionDenied("Owner or Admin role required.")
    return membership


# ---------------------------------------------------------------------------
# CompanyInvitationViewSet — scoped under /enterprise/companies/{company_id}/
# ---------------------------------------------------------------------------

class CompanyInvitationViewSet(viewsets.ViewSet):
    """
    Manages invitations within a specific company.
    All actions require owner or admin role (or is_staff).
    """

    permission_classes = [IsAuthenticated]

    def _company(self):
        return _get_company_or_404(self.kwargs["company_pk"])

    # GET /enterprise/companies/{company_id}/invitations/
    def list(self, request, company_pk=None):
        company = self._company()
        _require_admin(request.user, company)

        status_filter = request.query_params.get("status")
        qs = (
            CompanyInvitation.objects.filter(company=company)
            .select_related("invited_by", "accepted_by")
            .order_by("-created_at")
        )
        if status_filter:
            qs = qs.filter(status=status_filter)

        return Response(InvitationSerializer(qs, many=True).data)

    # POST /enterprise/companies/{company_id}/invitations/
    def create(self, request, company_pk=None):
        company = self._company()
        _require_admin(request.user, company)

        serializer = SendInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data

        invitation = InvitationService.create_invitation(
            company=company,
            email=d["email"],
            role=d["role"],
            employee_stage=d["employee_stage"],
            invited_by=request.user,
        )
        send_invitation_email(invitation)

        return Response(
            InvitationSerializer(invitation).data,
            status=status.HTTP_201_CREATED,
        )

    # DELETE /enterprise/companies/{company_id}/invitations/{id}/
    def destroy(self, request, company_pk=None, pk=None):
        company = self._company()
        _require_admin(request.user, company)

        invitation = self._get_invitation(company, pk)
        if invitation.status != CompanyInvitation.STATUS_PENDING:
            raise ValidationError(
                {"detail": "Only pending invitations can be cancelled."}
            )
        invitation.status = CompanyInvitation.STATUS_CANCELLED
        invitation.save(update_fields=["status", "updated_at"])
        return Response(status=status.HTTP_204_NO_CONTENT)

    # POST /enterprise/companies/{company_id}/invitations/{id}/resend/
    @action(detail=True, methods=["post"], url_path="resend")
    def resend(self, request, company_pk=None, pk=None):
        company = self._company()
        _require_admin(request.user, company)

        invitation = self._get_invitation(company, pk)
        invitation = InvitationService.resend_invitation(
            invitation=invitation, resent_by=request.user
        )
        send_invitation_email(invitation)
        return Response(InvitationSerializer(invitation).data)

    def _get_invitation(self, company, pk):
        try:
            return CompanyInvitation.objects.get(pk=pk, company=company)
        except CompanyInvitation.DoesNotExist:
            raise NotFound("Invitation not found.")


# ---------------------------------------------------------------------------
# InvitationActionViewSet — public validate + authenticated accept
# ---------------------------------------------------------------------------

class InvitationActionViewSet(viewsets.ViewSet):
    """
    Token-based actions — not scoped to a company_id in the URL.
    """

    def get_permissions(self):
        if self.action == "validate":
            return [AllowAny()]
        return [IsAuthenticated()]

    # GET /enterprise/invitations/global/ — staff only, all companies
    @action(detail=False, methods=["get"], url_path="global")
    def global_list(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("Staff access required.")

        company_id = request.query_params.get("company")
        status_filter = request.query_params.get("status")
        recent = request.query_params.get("recent")

        qs = (
            CompanyInvitation.objects.all()
            .select_related("company", "invited_by", "accepted_by")
            .order_by("-created_at")
        )
        if company_id:
            qs = qs.filter(company_id=company_id)
        if status_filter:
            qs = qs.filter(status=status_filter)
        if recent:
            from django.utils import timezone
            from datetime import timedelta
            qs = qs.filter(created_at__gte=timezone.now() - timedelta(days=7))

        return Response(InvitationSerializer(qs, many=True).data)

    # GET /enterprise/invitations/validate/?token=XYZ
    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def validate(self, request):
        token = request.query_params.get("token")
        if not token:
            raise ValidationError({"token": "This field is required."})

        invitation = InvitationService.validate_token(token)
        serializer = InvitationPreviewSerializer(
            invitation, context={"request": request}
        )
        return Response(serializer.data)

    # POST /enterprise/invitations/accept/
    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def accept(self, request):
        serializer = AcceptInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        membership = InvitationService.accept_invitation(
            token=str(serializer.validated_data["token"]),
            user=request.user,
        )

        from api.enterprise.serializers.company import MembershipSerializer
        return Response(
            {
                "detail": "Invitation accepted.",
                "membership": MembershipSerializer(membership).data,
            }
        )

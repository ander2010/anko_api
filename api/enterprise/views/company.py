"""
Phase 8 — Company Management Views

CompanyViewSet, BusinessUnitViewSet, TeamViewSet
"""

from __future__ import annotations

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.company_service import (
    BusinessUnitService,
    CompanyService,
    TeamService,
)
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.services.rbac_service import require_permission
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise.serializers.company import (
    AddTeamMemberSerializer,
    BusinessUnitSerializer,
    ChangeMemberRoleSerializer,
    CompanyCreateSerializer,
    CompanyListSerializer,
    CompanySerializer,
    InviteUserSerializer,
    MembershipSerializer,
    RemoveMemberSerializer,
    TeamListSerializer,
    TeamMembershipSerializer,
    TeamSerializer,
)
from api.enterprise_models import (
    BusinessUnit,
    Company,
    CompanyMembership,
    Team,
    TeamMembership,
)


ADMIN_ROLES = ("owner", "admin")
READ_ROLES = ("owner", "admin", "manager", "trainer", "employee", "auditor")


# ---------------------------------------------------------------------------
# CompanyViewSet
# ---------------------------------------------------------------------------

class CompanyViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    CRUD for Companies.

    list   → companies where the user has an active membership
    create → creates company + owner membership
    retrieve, update, destroy → owner/admin only
    """

    permission_classes = [IsAuthenticated]

    def list(self, request):
        company_ids = self._user_company_ids()
        companies = (
            Company.objects.filter(id__in=company_ids, is_active=True)
            .select_related("owner")
            .prefetch_related("memberships")
            .order_by("name")
        )
        serializer = CompanyListSerializer(
            companies, many=True, context={"request": request}
        )
        return Response(serializer.data)

    def create(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("Only platform administrators can create companies.")
        serializer = CompanyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = CompanyService.create_company(request.user, serializer.validated_data)
        return Response(
            CompanySerializer(company, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )

    def retrieve(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_read_access(company)
        return Response(CompanySerializer(company, context={"request": request}).data)

    def partial_update(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_admin_access(company)
        serializer = CompanySerializer(
            company, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            raise PermissionDenied("Only platform administrators can delete companies.")
        company = self._get_company_obj(pk)
        company.is_active = False
        company.save(update_fields=["is_active", "updated_at"])
        return Response(status=status.HTTP_204_NO_CONTENT)

    # --- members / users ---

    @action(detail=True, methods=["post"], url_path="add-user")
    def add_user(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_admin_access(company)
        serializer = InviteUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data
        membership = CompanyService.add_user(
            company=company,
            email=d["email"],
            role=d["role"],
            employee_stage=d["employee_stage"],
            added_by=request.user,
        )
        from api.enterprise.services.email_service import send_added_to_company
        send_added_to_company(membership)
        return Response(
            MembershipSerializer(membership).data, status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=["post"], url_path="change-member-role")
    def change_member_role(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_admin_access(company)
        serializer = ChangeMemberRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data
        membership = CompanyService.change_member_role(
            company=company,
            membership_id=d["membership_id"],
            new_role=d["role"],
            changed_by=request.user,
        )
        return Response(MembershipSerializer(membership).data)

    @action(detail=True, methods=["post"], url_path="remove-member")
    def remove_member(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_admin_access(company)
        serializer = RemoveMemberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        CompanyService.remove_member(
            company=company,
            membership_id=serializer.validated_data["membership_id"],
            removed_by=request.user,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"], url_path="resend-welcome")
    def resend_welcome(self, request, pk=None):
        """Re-sends the 'added to company' welcome email to an existing member.

        Reuses send_added_to_company as-is (same email add_user already sends
        on first creation) — this just lets an admin trigger it again for a
        member who already exists (add_user itself rejects already-active
        members, so it can't be reused for a resend).
        """
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            self._check_admin_access(company)
        membership_id = request.data.get("membership_id")
        if not membership_id:
            raise ValidationError({"membership_id": "This field is required."})
        try:
            membership = CompanyMembership.objects.get(id=membership_id, company=company)
        except CompanyMembership.DoesNotExist:
            raise ValidationError({"membership_id": "Membership not found."})
        from api.enterprise.services.email_service import send_added_to_company
        send_added_to_company(membership)
        return Response({"sent": True})

    @action(detail=True, methods=["get"])
    def members(self, request, pk=None):
        company = self._get_company_obj(pk)
        if not request.user.is_staff:
            require_permission(self.request.user, company.id, "enterprise.ent-members", "manage")
        status_filter = request.query_params.get("status", "active")
        qs = (
            CompanyMembership.objects.filter(company=company)
            .select_related("user")
            .order_by("user__username")
        )
        if status_filter != "all":
            qs = qs.filter(status=status_filter)
        return Response(MembershipSerializer(qs, many=True).data)

    # --- helpers ---

    def _get_company_obj(self, pk):
        try:
            return Company.objects.get(pk=pk)
        except Company.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("Company not found.")

    def _check_read_access(self, company):
        is_member = CompanyMembership.objects.filter(
            company=company,
            user=self.request.user,
            status__in=["active", "invited"],
        ).exists()
        if not is_member:
            raise PermissionDenied("You are not a member of this company.")

    def _check_admin_access(self, company):
        membership = CompanyMembership.objects.filter(
            company=company,
            user=self.request.user,
            status="active",
            role__in=ADMIN_ROLES,
        ).first()
        if not membership:
            raise PermissionDenied("Owner or Admin role required.")


# ---------------------------------------------------------------------------
# BusinessUnitViewSet
# ---------------------------------------------------------------------------

class BusinessUnitViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    """
    CRUD for Business Units inside a company.
    Requires ?company_id=X on create/list; detail actions use the instance's company.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = BusinessUnitSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return BusinessUnit.objects.none()
            return (
                BusinessUnit.objects.filter(company_id=company_id)
                .select_related("company", "manager")
                .prefetch_related("teams")
                .order_by("name")
            )
        return (
            BusinessUnit.objects.filter(company_id__in=self._user_company_ids())
            .select_related("company", "manager")
            .order_by("name")
        )

    def perform_create(self, serializer):
        company = self._get_company(*ADMIN_ROLES)
        serializer.save(company=company)

    def perform_update(self, serializer):
        self._check_instance_access(serializer.instance.company_id, *ADMIN_ROLES)
        serializer.save()

    def perform_destroy(self, instance):
        self._check_instance_access(instance.company_id, *ADMIN_ROLES)
        instance.delete()

    def _check_instance_access(self, company_id, *allowed_roles):
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        if allowed_roles and membership.role not in allowed_roles:
            raise PermissionDenied(
                f"This action requires one of: {', '.join(allowed_roles)}."
            )


# ---------------------------------------------------------------------------
# TeamViewSet
# ---------------------------------------------------------------------------

class TeamViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    """
    CRUD for Teams inside a company.
    Requires ?company_id=X.
    """

    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "list":
            return TeamListSerializer
        return TeamSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return Team.objects.none()
            qs = (
                Team.objects.filter(company_id=company_id)
                .select_related("company", "business_unit", "manager")
                .prefetch_related("memberships__user")
                .order_by("name")
            )
            bu_id = self.request.query_params.get("business_unit_id")
            if bu_id:
                qs = qs.filter(business_unit_id=bu_id)
            return qs
        return (
            Team.objects.filter(company_id__in=self._user_company_ids())
            .select_related("company", "business_unit", "manager")
            .order_by("name")
        )

    def perform_create(self, serializer):
        membership = require_permission(self.request.user, self._get_company_id(), "enterprise.ent-teams", "manage")
        company = Company.objects.get(id=membership.company_id)
        serializer.save(company=company)

    def perform_update(self, serializer):
        require_permission(self.request.user, serializer.instance.company_id, "enterprise.ent-teams", "manage")
        serializer.save()

    def perform_destroy(self, instance):
        self._check_team_access(instance.company_id, *ADMIN_ROLES)
        instance.delete()

    @action(detail=True, methods=["post"], url_path="add-member")
    def add_member(self, request, pk=None):
        team = self.get_object()
        require_permission(self.request.user, team.company_id, "enterprise.ent-teams", "manage")
        serializer = AddTeamMemberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        d = serializer.validated_data
        membership = TeamService.add_member(
            team=team,
            user_id=d["user_id"],
            role=d["role"],
        )
        from api.enterprise.services.email_service import send_added_to_team, send_assignment_notification
        from api.enterprise.services.learning_service import EnterpriseLearningService
        send_added_to_team(membership)
        backfilled = EnterpriseLearningService.backfill_team_assignments(
            team=team, user=membership.user, assigned_by=request.user
        )
        for assignment in backfilled:
            send_assignment_notification(assignment)
        return Response(
            TeamMembershipSerializer(membership).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="remove-member")
    def remove_member(self, request, pk=None):
        team = self.get_object()
        require_permission(self.request.user, team.company_id, "enterprise.ent-teams", "manage")
        user_id = request.data.get("user_id")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})
        TeamService.remove_member(team=team, user_id=user_id)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["get"])
    def members(self, request, pk=None):
        team = self.get_object()
        qs = TeamMembership.objects.filter(team=team).select_related("user")
        return Response(TeamMembershipSerializer(qs, many=True).data)

    def _check_team_access(self, company_id, *allowed_roles):
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        if allowed_roles and membership.role not in allowed_roles:
            raise PermissionDenied(
                f"This action requires one of: {', '.join(allowed_roles)}."
            )

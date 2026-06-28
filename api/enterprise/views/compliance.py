"""Phase 4 Compliance Engine ViewSets."""

from __future__ import annotations

import datetime
from decimal import Decimal, InvalidOperation

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.compliance_service import ComplianceService
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise_compliance_models import (
    ComplianceAssignment,
    ComplianceProgram,
    ComplianceRequirement,
    ComplianceReview,
)
from api.enterprise.serializers.compliance import (
    ComplianceAssignmentSerializer,
    ComplianceAuditReportSerializer,
    ComplianceProgramListSerializer,
    ComplianceProgramSerializer,
    ComplianceRequirementSerializer,
    ComplianceReviewSerializer,
    ComplianceStatusSerializer,
)

MANAGE_ROLES = ("owner", "admin", "manager")
CONTENT_ROLES = ("owner", "admin", "trainer", "manager")
READ_ROLES = ("owner", "admin", "manager", "trainer", "auditor", "employee")


# ---------------------------------------------------------------------------
# ComplianceProgramViewSet
# ---------------------------------------------------------------------------

class ComplianceProgramViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "list":
            return ComplianceProgramListSerializer
        return ComplianceProgramSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return ComplianceProgram.objects.none()
            return (
                ComplianceProgram.objects.filter(company_id=company_id)
                .select_related("company", "business_unit", "created_by")
                .prefetch_related("requirements")
            )
        return (
            ComplianceProgram.objects.filter(company_id__in=self._user_company_ids())
            .select_related("company", "business_unit", "created_by")
            .prefetch_related("requirements")
        )

    def perform_create(self, serializer):
        company = self._get_company(*CONTENT_ROLES)
        serializer.save(company=company, created_by=self.request.user)

    def perform_update(self, serializer):
        self._require_membership(*CONTENT_ROLES)
        serializer.save()

    def perform_destroy(self, instance):
        self._require_membership("owner", "admin")
        instance.delete()

    @action(detail=True, methods=["post"], url_path="assign-to-user")
    def assign_to_user(self, request, pk=None):
        program = self.get_object()
        self._require_membership(*MANAGE_ROLES)

        user_id = request.data.get("user_id")
        due_date_str = request.data.get("due_date")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})

        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})

        due_date = None
        if due_date_str:
            try:
                due_date = datetime.date.fromisoformat(due_date_str)
            except ValueError:
                raise ValidationError({"due_date": "Invalid date format. Use YYYY-MM-DD."})

        assignment = ComplianceService.assign_to_user(
            program, target, request.user, program.company, due_date
        )
        return Response(
            ComplianceAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="assign-to-team")
    def assign_to_team(self, request, pk=None):
        program = self.get_object()
        self._require_membership(*MANAGE_ROLES)

        team_id = request.data.get("team_id")
        due_date_str = request.data.get("due_date")
        if not team_id:
            raise ValidationError({"team_id": "This field is required."})

        from api.enterprise_models import Team
        try:
            team = Team.objects.get(id=team_id, company=program.company)
        except Team.DoesNotExist:
            raise ValidationError({"team_id": "Team not found in this company."})

        due_date = None
        if due_date_str:
            try:
                due_date = datetime.date.fromisoformat(due_date_str)
            except ValueError:
                raise ValidationError({"due_date": "Invalid date format. Use YYYY-MM-DD."})

        assignment = ComplianceService.assign_to_team(
            program, team, request.user, program.company, due_date
        )
        return Response(
            ComplianceAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="audit-report")
    def audit_report(self, request, pk=None):
        program = self.get_object()
        self._require_membership("owner", "admin", "auditor")
        report = ComplianceService.generate_audit_report(program.company, program)
        return Response(ComplianceAuditReportSerializer(report).data)

    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        program = self.get_object()
        self._require_membership(*CONTENT_ROLES)
        program.status = "active"
        program.save(update_fields=["status", "updated_at"])
        return Response(ComplianceProgramSerializer(program).data)

    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        program = self.get_object()
        self._require_membership("owner", "admin")
        program.status = "archived"
        program.save(update_fields=["status", "updated_at"])
        return Response({"status": "archived"})


# ---------------------------------------------------------------------------
# ComplianceRequirementViewSet
# ---------------------------------------------------------------------------

class ComplianceRequirementViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ComplianceRequirementSerializer

    def get_queryset(self):
        program_id = self.request.query_params.get("program_id")
        qs = ComplianceRequirement.objects.filter(
            program__company_id__in=self._user_company_ids()
        ).select_related("program", "learning_path")
        if program_id:
            qs = qs.filter(program_id=program_id)
        return qs

    def perform_create(self, serializer):
        program = serializer.validated_data.get("program")
        try:
            validate_company_access(self.request.user, program.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        serializer.save()

    def perform_update(self, serializer):
        program = serializer.instance.program
        try:
            validate_company_access(self.request.user, program.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        serializer.save()

    def perform_destroy(self, instance):
        try:
            validate_company_access(self.request.user, instance.program.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        instance.delete()


# ---------------------------------------------------------------------------
# ComplianceAssignmentViewSet
# ---------------------------------------------------------------------------

class ComplianceAssignmentViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ComplianceAssignmentSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                membership = validate_company_access(self.request.user, company_id)
            except PermissionError:
                return ComplianceAssignment.objects.none()
            qs = ComplianceAssignment.objects.filter(company_id=company_id)
            if membership.role == "employee":
                qs = qs.filter(user=self.request.user)
            return qs.select_related("program", "user", "team", "assigned_by")
        return ComplianceAssignment.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("program", "user", "team")

    def perform_create(self, serializer):
        company = self._get_company(*MANAGE_ROLES)
        serializer.save(company=company, assigned_by=self.request.user)

    @action(detail=True, methods=["get"])
    def status_detail(self, request, pk=None):
        assignment = self.get_object()
        data = ComplianceService.evaluate_compliance(assignment.user, assignment.company)
        return Response(data)

    @action(detail=True, methods=["post"])
    def complete(self, request, pk=None):
        assignment = self.get_object()
        self._require_membership(*MANAGE_ROLES + ("employee",))

        score_raw = request.data.get("score")
        score = None
        if score_raw is not None:
            try:
                score = Decimal(str(score_raw))
            except InvalidOperation:
                raise ValidationError({"score": "Invalid decimal value."})

        notes = request.data.get("notes", "")
        updated = ComplianceService.complete_assignment(
            assignment,
            user=assignment.user or request.user,
            score=score,
            reviewer=request.user,
            notes=notes,
        )
        return Response(ComplianceAssignmentSerializer(updated).data)

    @action(detail=True, methods=["post"])
    def renew(self, request, pk=None):
        assignment = self.get_object()
        self._require_membership(*MANAGE_ROLES)

        due_date_str = request.data.get("due_date")
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.date.fromisoformat(due_date_str)
            except ValueError:
                raise ValidationError({"due_date": "Invalid date format. Use YYYY-MM-DD."})

        renewal = ComplianceService.create_renewal(assignment, request.user, due_date)
        return Response(
            ComplianceAssignmentSerializer(renewal).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=["get"], url_path="my-compliance")
    def my_compliance(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        data = ComplianceService.evaluate_compliance(request.user, company)
        return Response(data)

    @action(detail=False, methods=["get"], url_path="expiring")
    def expiring(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_membership(*MANAGE_ROLES)
        days = int(request.query_params.get("days", 30))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        assignments = ComplianceService.check_expiring_assignments(company, days)
        return Response(ComplianceAssignmentSerializer(assignments, many=True).data)

    @action(detail=False, methods=["get"], url_path="company-compliance")
    def company_compliance(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_membership("owner", "admin", "auditor")
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        data = ComplianceService.get_company_compliance(company)
        return Response(data)

    @action(detail=False, methods=["get"], url_path="team-compliance")
    def team_compliance(self, request):
        company_id = self._get_company_id()
        team_id = request.query_params.get("team_id")
        if not company_id or not team_id:
            raise ValidationError({"company_id": "Required.", "team_id": "Required."})
        self._require_membership(*MANAGE_ROLES)
        from api.enterprise_models import Company, Team
        company = Company.objects.get(id=company_id)
        try:
            team = Team.objects.get(id=team_id, company=company)
        except Team.DoesNotExist:
            raise ValidationError({"team_id": "Team not found."})
        data = ComplianceService.get_team_compliance(team, company)
        return Response(data)


# ---------------------------------------------------------------------------
# ComplianceReviewViewSet
# ---------------------------------------------------------------------------

class ComplianceReviewViewSet(EnterpriseViewSetMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ComplianceReviewSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                membership = validate_company_access(self.request.user, company_id)
            except PermissionError:
                return ComplianceReview.objects.none()
            qs = ComplianceReview.objects.filter(company_id=company_id)
            if membership.role == "employee":
                qs = qs.filter(user=self.request.user)
            return qs.select_related("user", "program", "assignment", "reviewer")
        return ComplianceReview.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("program", "assignment")

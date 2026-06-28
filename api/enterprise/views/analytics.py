"""Phase 6 Analytics & Dashboard ViewSets."""

from __future__ import annotations

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.analytics_service import AnalyticsService
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise.serializers.analytics import (
    AuditorDashboardSerializer,
    CompanyHealthSerializer,
    ComplianceTrendSerializer,
    EmployeeDashboardSerializer,
    ExecutiveDashboardSerializer,
    LearningTrendSerializer,
    ManagerDashboardSerializer,
    RetentionTrendSerializer,
    TrainerDashboardSerializer,
)


class AnalyticsDashboardViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Non-model ViewSet — all endpoints return aggregated analytics data.

    Endpoints:
      GET /enterprise/analytics/employee-dashboard/
      GET /enterprise/analytics/manager-dashboard/
      GET /enterprise/analytics/trainer-dashboard/
      GET /enterprise/analytics/auditor-dashboard/
      GET /enterprise/analytics/executive-dashboard/
      GET /enterprise/analytics/company-health/
      GET /enterprise/analytics/retention-trends/
      GET /enterprise/analytics/compliance-trends/
      GET /enterprise/analytics/learning-trends/
    """

    permission_classes = [IsAuthenticated]

    def _resolve_company(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        return company, membership

    # ------------------------------------------------------------------
    # Employee Dashboard — any authenticated member
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="employee-dashboard")
    def employee_dashboard(self, request):
        company, membership = self._resolve_company(request)
        data = AnalyticsService.get_employee_dashboard(request.user, company)
        return Response(EmployeeDashboardSerializer(data).data)

    # ------------------------------------------------------------------
    # Manager Dashboard — manager+ only
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="manager-dashboard")
    def manager_dashboard(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "manager"):
            raise PermissionDenied("Manager role or higher required.")

        team_id = request.query_params.get("team_id")
        team = None
        if team_id:
            from api.enterprise_models import Team
            try:
                team = Team.objects.get(id=team_id, company=company)
            except Team.DoesNotExist:
                raise ValidationError({"team_id": "Team not found."})

        data = AnalyticsService.get_manager_dashboard(request.user, company, team)
        return Response(ManagerDashboardSerializer(data).data)

    # ------------------------------------------------------------------
    # Trainer Dashboard — trainer+ only
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="trainer-dashboard")
    def trainer_dashboard(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

        data = AnalyticsService.get_trainer_dashboard(request.user, company)
        return Response(TrainerDashboardSerializer(data).data)

    # ------------------------------------------------------------------
    # Auditor Dashboard — auditor+ only
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="auditor-dashboard")
    def auditor_dashboard(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "auditor"):
            raise PermissionDenied("Auditor role or higher required.")

        data = AnalyticsService.get_auditor_dashboard(request.user, company)
        return Response(AuditorDashboardSerializer(data).data)

    # ------------------------------------------------------------------
    # Executive Dashboard — owner/admin only
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="executive-dashboard")
    def executive_dashboard(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin"):
            raise PermissionDenied("Owner or admin role required.")

        data = AnalyticsService.get_executive_dashboard(company)
        return Response(ExecutiveDashboardSerializer(data).data)

    # ------------------------------------------------------------------
    # Company Health Score
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="company-health")
    def company_health(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "auditor"):
            raise PermissionDenied("Auditor role or higher required.")

        health_score = AnalyticsService.get_company_health_score(company)
        return Response(CompanyHealthSerializer({
            "company_id": company.id,
            "company_name": company.name,
            "health_score": health_score,
        }).data)

    # ------------------------------------------------------------------
    # Trend endpoints
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="retention-trends")
    def retention_trends(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "manager", "auditor"):
            raise PermissionDenied("Manager role or higher required.")

        days = int(request.query_params.get("days", 90))
        data = AnalyticsService.get_retention_trends(company, days)
        return Response(RetentionTrendSerializer(data, many=True).data)

    @action(detail=False, methods=["get"], url_path="compliance-trends")
    def compliance_trends(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "auditor"):
            raise PermissionDenied("Auditor role or higher required.")

        days = int(request.query_params.get("days", 90))
        data = AnalyticsService.get_compliance_trends(company, days)
        return Response(ComplianceTrendSerializer(data, many=True).data)

    @action(detail=False, methods=["get"], url_path="learning-trends")
    def learning_trends(self, request):
        company, membership = self._resolve_company(request)
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

        days = int(request.query_params.get("days", 90))
        data = AnalyticsService.get_learning_trends(company, days)
        return Response(LearningTrendSerializer(data, many=True).data)

"""Phase 5 Certification ViewSets."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.certification_service import CertificationService
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise_certification_models import (
    CertificateTemplate,
    Certification,
    CertificationRequirement,
)
from api.enterprise.serializers.certification import (
    CertificateDataSerializer,
    CertificateTemplateListSerializer,
    CertificateTemplateSerializer,
    CertificationEligibilitySerializer,
    CertificationRequirementSerializer,
    CertificationSerializer,
    CertificationStatsSerializer,
    CertificationVerifySerializer,
    UserCertificationStatsSerializer,
)

MANAGE_ROLES = ("owner", "admin", "manager")
CONTENT_ROLES = ("owner", "admin", "trainer", "manager")


# ---------------------------------------------------------------------------
# CertificateTemplateViewSet
# ---------------------------------------------------------------------------

class CertificateTemplateViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "list":
            return CertificateTemplateListSerializer
        return CertificateTemplateSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return CertificateTemplate.objects.none()
            return (
                CertificateTemplate.objects.filter(company_id=company_id)
                .select_related("company", "created_by")
                .prefetch_related("requirements")
            )
        return (
            CertificateTemplate.objects.filter(
                company_id__in=self._user_company_ids()
            )
            .select_related("company", "created_by")
            .prefetch_related("requirements")
        )

    def perform_create(self, serializer):
        membership = self._require_permission("enterprise.ent-certs-templates", "manage")
        from api.enterprise_models import Company
        company = Company.objects.get(id=membership.company_id)
        serializer.save(company=company, created_by=self.request.user)

    def perform_update(self, serializer):
        self._require_permission("enterprise.ent-certs-templates", "manage")
        serializer.save()

    def perform_destroy(self, instance):
        self._require_membership("owner", "admin")
        instance.delete()

    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        template = self.get_object()
        self._require_permission("enterprise.ent-certs-templates", "manage")
        template.is_active = True
        template.save(update_fields=["is_active", "updated_at"])
        return Response(CertificateTemplateSerializer(template).data)

    @action(detail=True, methods=["post"])
    def deactivate(self, request, pk=None):
        template = self.get_object()
        self._require_membership("owner", "admin")
        template.is_active = False
        template.save(update_fields=["is_active", "updated_at"])
        return Response({"is_active": False})

    @action(detail=True, methods=["get"], url_path="check-eligibility")
    def check_eligibility(self, request, pk=None):
        template = self.get_object()
        self._require_permission("enterprise.ent-certs-templates", "manage")

        user_id = request.query_params.get("user_id")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})

        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})

        result = CertificationService.check_eligibility(
            target, template.company, template
        )
        return Response(CertificationEligibilitySerializer(result).data)

    @action(detail=True, methods=["post"], url_path="issue")
    def issue(self, request, pk=None):
        template = self.get_object()
        self._require_permission("enterprise.ent-certs-templates", "manage")

        user_id = request.data.get("user_id")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})

        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})

        score_raw = request.data.get("score")
        score = None
        if score_raw is not None:
            try:
                score = Decimal(str(score_raw))
            except InvalidOperation:
                raise ValidationError({"score": "Invalid decimal value."})

        lp_id = request.data.get("learning_path_id")
        cp_id = request.data.get("compliance_program_id")
        learning_path = None
        compliance_program = None

        if lp_id:
            from api.enterprise_learning_models import LearningPath
            try:
                learning_path = LearningPath.objects.get(
                    id=lp_id, company=template.company
                )
            except LearningPath.DoesNotExist:
                raise ValidationError({"learning_path_id": "Not found."})

        if cp_id:
            from api.enterprise_compliance_models import ComplianceProgram
            try:
                compliance_program = ComplianceProgram.objects.get(
                    id=cp_id, company=template.company
                )
            except ComplianceProgram.DoesNotExist:
                raise ValidationError({"compliance_program_id": "Not found."})

        try:
            cert = CertificationService.issue_certificate(
                target, template.company, template,
                issued_by=request.user,
                score=score,
                learning_path=learning_path,
                compliance_program=compliance_program,
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})

        return Response(
            CertificationSerializer(cert).data,
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# CertificationRequirementViewSet
# ---------------------------------------------------------------------------

class CertificationRequirementViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CertificationRequirementSerializer

    def get_queryset(self):
        template_id = self.request.query_params.get("template_id")
        qs = CertificationRequirement.objects.filter(
            template__company_id__in=self._user_company_ids()
        ).select_related("template", "learning_path", "compliance_program")
        if template_id:
            qs = qs.filter(template_id=template_id)
        return qs

    def _backfill(self, requirement):
        # Best-effort — a failure here must not roll back the requirement
        # create/update itself (same pattern as the other auto-issue triggers).
        try:
            CertificationService.backfill_for_requirement(requirement)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Certificate backfill failed for requirement %s", requirement.id
            )

    def perform_create(self, serializer):
        template = serializer.validated_data.get("template")
        try:
            validate_company_access(self.request.user, template.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        requirement = serializer.save()
        self._backfill(requirement)

    def perform_update(self, serializer):
        template = serializer.instance.template
        try:
            validate_company_access(self.request.user, template.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        requirement = serializer.save()
        self._backfill(requirement)

    def perform_destroy(self, instance):
        try:
            validate_company_access(self.request.user, instance.template.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        instance.delete()


# ---------------------------------------------------------------------------
# CertificationViewSet
# ---------------------------------------------------------------------------

class CertificationViewSet(EnterpriseViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """
    Certifications are read-only via API.
    Issuance is done through CertificateTemplateViewSet.issue action.
    Revocation via the /revoke/ action here.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = CertificationSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                membership = validate_company_access(self.request.user, company_id)
            except PermissionError:
                return Certification.objects.none()
            qs = Certification.objects.filter(company_id=company_id)
            if membership.role == "employee":
                qs = qs.filter(user=self.request.user)
            return qs.select_related(
                "user", "template", "company",
                "learning_path", "compliance_program",
                "issued_by", "revoked_by",
            )
        return Certification.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("user", "template", "company")

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        cert = self.get_object()
        self._require_membership("owner", "admin")
        reason = request.data.get("reason", "")
        try:
            updated = CertificationService.revoke_certificate(
                cert, request.user, reason
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})
        return Response(CertificationSerializer(updated).data)

    @action(detail=True, methods=["get"], url_path="certificate-data")
    def certificate_data(self, request, pk=None):
        cert = self.get_object()
        data = CertificationService.get_certificate_data(cert)
        return Response(CertificateDataSerializer(data).data)

    @action(detail=False, methods=["get"], url_path="my-certifications")
    def my_certifications(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        certs = Certification.objects.filter(
            company=company, user=request.user
        ).select_related("template")
        return Response(CertificationSerializer(certs, many=True).data)

    @action(detail=False, methods=["get"], url_path="my-stats")
    def my_stats(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        data = CertificationService.get_user_certifications(request.user, company)
        return Response(UserCertificationStatsSerializer(data).data)

    @action(detail=False, methods=["get"], url_path="company-stats")
    def company_stats(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_permission("enterprise.ent-certs-company", "view")
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        data = CertificationService.get_company_certification_stats(company)
        return Response(CertificationStatsSerializer(data).data)

    @action(detail=False, methods=["get"], url_path="expiring")
    def expiring(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_membership(*MANAGE_ROLES)
        days = int(request.query_params.get("days", 30))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        certs = CertificationService.get_expiring_certifications(company, days)
        return Response(CertificationSerializer(certs, many=True).data)


# ---------------------------------------------------------------------------
# Public verification endpoint (no auth required)
# ---------------------------------------------------------------------------

class CertificationVerifyViewSet(viewsets.ViewSet):
    """
    Public endpoint: verify a certificate without authentication.
    GET /api/enterprise/verify/<identifier>/
    """
    permission_classes = [AllowAny]

    def retrieve(self, request, pk=None):
        result = CertificationService.verify_certificate(pk)
        return Response(CertificationVerifySerializer(result).data)

"""
Phase 2 Learning Engine ViewSets

Each ViewSet delegates business logic to EnterpriseLearningService.
Company filtering is enforced via get_queryset() — no data leaks across tenants.
"""

from __future__ import annotations

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.learning_service import EnterpriseLearningService
from api.enterprise.services.security_service import validate_company_access
from api.enterprise_learning_models import (
    LearningModule,
    LearningModuleItem,
    LearningPath,
    LearningPathAssignment,
    TrainingProgram,
)
from api.enterprise_models import Company, CompanyMembership, Team
from api.enterprise.serializers.learning import (
    LearningModuleProgressSerializer,
    LearningModuleSerializer,
    LearningModuleItemSerializer,
    LearningPathAssignmentSerializer,
    LearningPathListSerializer,
    LearningPathSerializer,
    TrainingProgramListSerializer,
    TrainingProgramSerializer,
    TrainingProgramVersionSerializer,
)


# ---------------------------------------------------------------------------
# Mixin
# ---------------------------------------------------------------------------

CONTENT_ROLES = ("owner", "admin", "trainer", "manager")
ASSIGN_ROLES = ("owner", "admin", "manager")
READ_ROLES = ("owner", "admin", "manager", "trainer", "employee", "auditor")


class EnterpriseViewSetMixin:
    """
    Shared helpers for enterprise ViewSets.

    Company resolution order (first wins):
      1. URL kwarg  company_pk / company_id
      2. Query param ?company_id=
      3. Request body company_id
    """

    def _get_company_id(self):
        for key in ("company_pk", "company_id"):
            v = self.kwargs.get(key)
            if v:
                return v
        v = self.request.query_params.get("company_id")
        if v:
            return v
        return self.request.data.get("company_id")

    def _require_membership(self, *allowed_roles):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        if allowed_roles and membership.role not in allowed_roles:
            raise PermissionDenied(
                f"This action requires one of: {', '.join(allowed_roles)}."
            )
        return membership

    def _get_company(self, *allowed_roles):
        membership = self._require_membership(*allowed_roles)
        return Company.objects.get(id=membership.company_id)

    def _user_company_ids(self):
        return CompanyMembership.objects.filter(
            user=self.request.user, status="active"
        ).values_list("company_id", flat=True)


# ---------------------------------------------------------------------------
# LearningPathViewSet
# ---------------------------------------------------------------------------

class LearningPathViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    """
    CRUD for Learning Paths, filtered by company.

    list/create: ?company_id required
    retrieve/update/delete: filtered by user's active memberships
    """

    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "list":
            return LearningPathListSerializer
        return LearningPathSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return LearningPath.objects.none()
            return (
                LearningPath.objects.filter(company_id=company_id)
                .select_related("company", "business_unit", "created_by")
                .prefetch_related("modules")
            )
        # detail actions — allow access to any company the user belongs to
        return (
            LearningPath.objects.filter(company_id__in=self._user_company_ids())
            .select_related("company", "business_unit", "created_by")
            .prefetch_related("modules")
        )

    def perform_create(self, serializer):
        company = self._get_company(*CONTENT_ROLES)
        module_ids = serializer.validated_data.pop("module_ids", [])
        path = serializer.save(company=company, created_by=self.request.user)
        if module_ids:
            self._link_modules(path, module_ids, company)

    def perform_update(self, serializer):
        self._require_membership(*CONTENT_ROLES)
        module_ids = serializer.validated_data.pop("module_ids", [])
        path = serializer.save()
        if module_ids:
            self._link_modules(path, module_ids, path.company)

    def perform_destroy(self, instance):
        self._require_membership("owner", "admin")
        # Modules become standalone — don't delete them
        instance.modules.all().update(learning_path=None)
        instance.delete()

    def _link_modules(self, path, module_ids, company):
        """Associate existing procesos to this learning path."""
        modules = LearningModule.objects.filter(
            id__in=module_ids, company=company
        )
        for order, module in enumerate(modules.order_by("order"), start=0):
            module.learning_path = path
            module.order = order
            module.save(update_fields=["learning_path", "order", "updated_at"])

    # --- custom actions ---

    @action(detail=True, methods=["post"], url_path="add-module")
    def add_module(self, request, pk=None):
        """Link an existing proceso to this learning path."""
        path = self.get_object()
        self._require_membership(*CONTENT_ROLES)
        module_id = request.data.get("module_id")
        order = request.data.get("order")
        if not module_id:
            raise ValidationError({"module_id": "This field is required."})
        try:
            module = LearningModule.objects.get(id=module_id, company=path.company)
        except LearningModule.DoesNotExist:
            raise ValidationError({"module_id": "Proceso not found in this company."})
        module.learning_path = path
        if order is not None:
            module.order = order
        module.save(update_fields=["learning_path", "order", "updated_at"])
        from api.enterprise.serializers.learning import LearningModuleSerializer as LMS
        return Response(LMS(module).data)

    @action(detail=True, methods=["post"], url_path="remove-module")
    def remove_module(self, request, pk=None):
        """Unlink a proceso from this learning path (becomes standalone)."""
        path = self.get_object()
        self._require_membership(*CONTENT_ROLES)
        module_id = request.data.get("module_id")
        if not module_id:
            raise ValidationError({"module_id": "This field is required."})
        updated = LearningModule.objects.filter(
            id=module_id, learning_path=path
        ).update(learning_path=None)
        if not updated:
            raise ValidationError({"module_id": "Proceso not found in this learning path."})
        return Response(status=204)

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        path = self.get_object()
        self._require_membership(*CONTENT_ROLES)
        updated = EnterpriseLearningService.publish_learning_path(path, request.user)
        return Response(LearningPathSerializer(updated).data)

    @action(detail=True, methods=["post"], url_path="assign-to-user")
    def assign_to_user(self, request, pk=None):
        path = self.get_object()
        self._require_membership(*ASSIGN_ROLES)

        user_id = request.data.get("user_id")
        due_date = request.data.get("due_date")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})

        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})

        assignment = EnterpriseLearningService.assign_to_user(
            learning_path=path,
            user=target_user,
            assigned_by=request.user,
            company=path.company,
            due_date=due_date,
        )
        from api.enterprise.services.email_service import send_assignment_notification
        send_assignment_notification(assignment)
        return Response(
            LearningPathAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="assign-to-team")
    def assign_to_team(self, request, pk=None):
        path = self.get_object()
        self._require_membership(*ASSIGN_ROLES)

        team_id = request.data.get("team_id")
        due_date = request.data.get("due_date")
        if not team_id:
            raise ValidationError({"team_id": "This field is required."})

        try:
            team = Team.objects.get(id=team_id, company=path.company)
        except Team.DoesNotExist:
            raise ValidationError({"team_id": "Team not found in this company."})

        assignment = EnterpriseLearningService.assign_to_team(
            learning_path=path,
            team=team,
            assigned_by=request.user,
            company=path.company,
            due_date=due_date,
        )
        from api.enterprise.services.email_service import send_assignment_notification
        send_assignment_notification(assignment)
        return Response(
            LearningPathAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"])
    def analytics(self, request, pk=None):
        path = self.get_object()
        self._require_membership(*ASSIGN_ROLES)

        total_assignments = path.assignments.count()
        completed = path.assignments.filter(status="completed").count()
        in_progress = path.assignments.filter(status="in_progress").count()
        pending = path.assignments.filter(status="pending").count()

        return Response({
            "learning_path_id": path.id,
            "name": path.name,
            "total_assignments": total_assignments,
            "completed": completed,
            "in_progress": in_progress,
            "pending": pending,
            "completion_rate": (
                round(completed / total_assignments * 100, 2)
                if total_assignments else 0
            ),
        })


# ---------------------------------------------------------------------------
# LearningModuleViewSet
# ---------------------------------------------------------------------------

class LearningModuleViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    """
    CRUD for modules inside a LearningPath.
    Requires ?company_id or inferrable from the parent LearningPath.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = LearningModuleSerializer

    def get_queryset(self):
        company_ids = self._user_company_ids()
        qs = LearningModule.objects.filter(
            company_id__in=company_ids
        ).prefetch_related("items").select_related("learning_path", "company")

        path_id = self.request.query_params.get("learning_path_id")
        if path_id:
            qs = qs.filter(learning_path_id=path_id)

        # standalone=true → procesos sin learning path
        if self.request.query_params.get("standalone") == "true":
            qs = qs.filter(learning_path__isnull=True)

        company_id = self.request.query_params.get("company_id")
        if company_id:
            qs = qs.filter(company_id=company_id)

        return qs

    def _resolve_company_id(self, validated_data):
        """Return the company_id from learning_path or company field."""
        path = validated_data.get("learning_path")
        if path:
            return path.company_id
        company = validated_data.get("company")
        if company:
            return company.id
        return None

    def perform_create(self, serializer):
        company_id = self._resolve_company_id(serializer.validated_data)
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        # If only learning_path provided, populate company automatically
        if not serializer.validated_data.get("company") and serializer.validated_data.get("learning_path"):
            serializer.save(company=serializer.validated_data["learning_path"].company)
        else:
            serializer.save()

    def perform_update(self, serializer):
        company_id = (
            serializer.instance.company_id
            or (serializer.instance.learning_path.company_id if serializer.instance.learning_path_id else None)
        )
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        serializer.save()

    def perform_destroy(self, instance):
        company_id = instance.company_id or (
            instance.learning_path.company_id if instance.learning_path_id else None
        )
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        instance.delete()

    @action(detail=True, methods=["post"], url_path="assign-to-user")
    def assign_to_user(self, request, pk=None):
        module = self.get_object()
        self._require_membership(*ASSIGN_ROLES)
        user_id = request.data.get("user_id")
        due_date = request.data.get("due_date")
        if not user_id:
            raise ValidationError({"user_id": "This field is required."})
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"user_id": "User not found."})
        assignment = EnterpriseLearningService.assign_to_user(
            learning_path=None,
            learning_module=module,
            user=target_user,
            assigned_by=request.user,
            company=module.company,
            due_date=due_date,
        )
        from api.enterprise.services.email_service import send_assignment_notification
        send_assignment_notification(assignment)
        return Response(
            LearningPathAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="assign-to-team")
    def assign_to_team(self, request, pk=None):
        module = self.get_object()
        self._require_membership(*ASSIGN_ROLES)
        team_id = request.data.get("team_id")
        due_date = request.data.get("due_date")
        if not team_id:
            raise ValidationError({"team_id": "This field is required."})
        try:
            team = Team.objects.get(id=team_id, company=module.company)
        except Team.DoesNotExist:
            raise ValidationError({"team_id": "Team not found in this company."})
        assignment = EnterpriseLearningService.assign_to_team(
            learning_path=None,
            learning_module=module,
            team=team,
            assigned_by=request.user,
            company=module.company,
            due_date=due_date,
        )
        from api.enterprise.services.email_service import send_assignment_notification
        send_assignment_notification(assignment)
        return Response(
            LearningPathAssignmentSerializer(assignment).data,
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# TrainingProgramViewSet
# ---------------------------------------------------------------------------

class TrainingProgramViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "list":
            return TrainingProgramListSerializer
        return TrainingProgramSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return TrainingProgram.objects.none()
            return (
                TrainingProgram.objects.filter(company_id=company_id)
                .select_related("company", "business_unit", "created_by")
                .prefetch_related("versions")
            )
        return (
            TrainingProgram.objects.filter(company_id__in=self._user_company_ids())
            .select_related("company", "business_unit", "created_by")
            .prefetch_related("versions")
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

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        program = self.get_object()
        self._require_membership(*CONTENT_ROLES)

        learning_path_id = request.data.get("learning_path_id")
        notes = request.data.get("notes", "")

        if not learning_path_id:
            raise ValidationError({"learning_path_id": "This field is required."})

        try:
            path = LearningPath.objects.get(id=learning_path_id, company=program.company)
        except LearningPath.DoesNotExist:
            raise ValidationError({"learning_path_id": "Learning path not found in this company."})

        version = EnterpriseLearningService.publish_training_program(
            program=program,
            learning_path=path,
            created_by=request.user,
            notes=notes,
        )
        return Response(
            TrainingProgramVersionSerializer(version).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        program = self.get_object()
        self._require_membership("owner", "admin")
        program.status = "archived"
        program.save(update_fields=["status", "updated_at"])
        return Response({"status": "archived"})

    @action(detail=True, methods=["get"])
    def versions(self, request, pk=None):
        program = self.get_object()
        self._require_membership(*READ_ROLES)
        versions = program.versions.all()
        return Response(TrainingProgramVersionSerializer(versions, many=True).data)


# ---------------------------------------------------------------------------
# LearningPathAssignmentViewSet
# ---------------------------------------------------------------------------

class LearningPathAssignmentViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = LearningPathAssignmentSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return LearningPathAssignment.objects.none()
            return (
                LearningPathAssignment.objects.filter(company_id=company_id)
                .select_related("company", "learning_path", "user", "team", "assigned_by")
            )
        # Default: own assignments across all companies
        return (
            LearningPathAssignment.objects.filter(
                company_id__in=self._user_company_ids(),
                user=self.request.user,
            )
            .select_related("company", "learning_path", "user", "team", "assigned_by")
        )

    def perform_create(self, serializer):
        company = self._get_company(*ASSIGN_ROLES)
        serializer.save(company=company, assigned_by=self.request.user)

    # --- custom actions ---

    @action(detail=False, methods=["get"], url_path="my-assignments")
    def my_assignments(self, request):
        company_id = self._get_company_id()
        qs = LearningPathAssignment.objects.filter(user=request.user)
        if company_id:
            qs = qs.filter(company_id=company_id)
        qs = qs.select_related("learning_path", "company").order_by("-created_at")
        return Response(LearningPathAssignmentSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"])
    def overdue(self, request):
        from django.utils import timezone
        company_id = self._get_company_id()
        self._require_membership(*ASSIGN_ROLES)
        qs = LearningPathAssignment.objects.filter(
            company_id=company_id,
            due_date__lt=timezone.now(),
        ).exclude(status="completed")
        return Response(LearningPathAssignmentSerializer(qs, many=True).data)

    @action(detail=True, methods=["post"])
    def start(self, request, pk=None):
        assignment = self.get_object()
        updated = EnterpriseLearningService.start_assignment(assignment, request.user)
        return Response(LearningPathAssignmentSerializer(updated).data)

    @action(detail=True, methods=["post"], url_path="complete-module")
    def complete_module(self, request, pk=None):
        assignment = self.get_object()
        module_id = request.data.get("module_id")
        score = request.data.get("score")

        if not module_id:
            raise ValidationError({"module_id": "This field is required."})

        try:
            module = assignment.learning_path.modules.get(id=module_id)
        except LearningModule.DoesNotExist:
            raise ValidationError({"module_id": "Module not found in this learning path."})

        from decimal import Decimal as D, InvalidOperation
        score_val = None
        if score is not None:
            try:
                score_val = D(str(score))
            except InvalidOperation:
                raise ValidationError({"score": "Invalid decimal value."})

        progress = EnterpriseLearningService.complete_module(
            assignment=assignment,
            module=module,
            user=request.user,
            score=score_val,
        )
        return Response(LearningModuleProgressSerializer(progress).data)

    @action(detail=True, methods=["post"], url_path="complete-learning-path")
    def complete_learning_path(self, request, pk=None):
        assignment = self.get_object()
        assignment.status = "completed"
        from django.utils import timezone
        assignment.completed_at = timezone.now()
        assignment.save(update_fields=["status", "completed_at", "updated_at"])
        return Response(LearningPathAssignmentSerializer(assignment).data)

    @action(detail=True, methods=["get"])
    def progress(self, request, pk=None):
        assignment = self.get_object()
        data = EnterpriseLearningService.calculate_progress(assignment, request.user)
        return Response(data)


# ---------------------------------------------------------------------------
# LearningModuleItemViewSet
# ---------------------------------------------------------------------------

class LearningModuleItemViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    """
    CRUD for items (topic, battery, deck, document) inside a LearningModule.
    Filter by ?module_id=X or ?learning_path_id=X.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = LearningModuleItemSerializer

    def get_queryset(self):
        user_company_ids = self._user_company_ids()
        qs = LearningModuleItem.objects.filter(
            module__learning_path__company_id__in=user_company_ids
        ).select_related("module", "topic", "battery", "deck", "document")

        module_id = self.request.query_params.get("module_id")
        if module_id:
            qs = qs.filter(module_id=module_id)

        path_id = self.request.query_params.get("learning_path_id")
        if path_id:
            qs = qs.filter(module__learning_path_id=path_id)

        item_type = self.request.query_params.get("item_type")
        if item_type:
            qs = qs.filter(item_type=item_type)

        return qs.order_by("module__order", "order")

    def perform_create(self, serializer):
        module = serializer.validated_data.get("module")
        try:
            validate_company_access(self.request.user, module.learning_path.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        serializer.save()

    def perform_update(self, serializer):
        module = serializer.instance.module
        try:
            validate_company_access(self.request.user, module.learning_path.company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        serializer.save()

    def perform_destroy(self, instance):
        try:
            validate_company_access(
                self.request.user, instance.module.learning_path.company_id
            )
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        instance.delete()

"""Phase 3 Retention Engine ViewSets."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.retention_service import RetentionService
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise_retention_models import (
    KnowledgeAssessment,
    KnowledgeGap,
    RetentionSnapshot,
    ReviewSchedule,
)
from api.enterprise.serializers.retention import (
    KnowledgeAssessmentSerializer,
    KnowledgeGapSerializer,
    RetentionSnapshotSerializer,
    RetentionSummarySerializer,
    ReviewScheduleSerializer,
)


# ---------------------------------------------------------------------------
# KnowledgeAssessmentViewSet
# ---------------------------------------------------------------------------

class KnowledgeAssessmentViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = KnowledgeAssessmentSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return KnowledgeAssessment.objects.none()
            return KnowledgeAssessment.objects.filter(
                company_id=company_id
            ).select_related("user", "topic", "battery", "learning_path")
        # Own assessments
        return KnowledgeAssessment.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("topic", "battery", "learning_path")

    def perform_create(self, serializer):
        company = self._get_company()
        score = serializer.validated_data.get("score", Decimal("0"))
        items_total = serializer.validated_data.get("items_total", 0)
        items_correct = serializer.validated_data.get("items_correct", 0)
        topic = serializer.validated_data.get("topic")
        battery = serializer.validated_data.get("battery")
        learning_path = serializer.validated_data.get("learning_path")
        learning_module = serializer.validated_data.get("learning_module")
        assessment_type = serializer.validated_data.get("assessment_type", "battery")
        metadata = serializer.validated_data.get("metadata", {})

        RetentionService.create_assessment(
            user=self.request.user,
            company=company,
            score=score,
            assessment_type=assessment_type,
            items_total=items_total,
            items_correct=items_correct,
            topic=topic,
            battery=battery,
            learning_path=learning_path,
            learning_module=learning_module,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# RetentionViewSet  — /api/retention/
# ---------------------------------------------------------------------------

class RetentionViewSet(EnterpriseViewSetMixin, viewsets.GenericViewSet):
    """
    Non-model ViewSet for retention aggregation endpoints.
    No list/create/update/delete — only custom actions.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = RetentionSummarySerializer

    @action(detail=False, methods=["get"], url_path="my-retention")
    def my_retention(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))

        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)

        retention = RetentionService.calculate_user_retention(request.user, company)
        risk = RetentionService.calculate_risk_score(request.user, company)
        confidence = RetentionService.calculate_confidence_score(request.user, company)

        open_gaps = KnowledgeGap.objects.filter(
            company=company, user=request.user, status="open"
        ).count()

        return Response({
            "user_id": request.user.id,
            "user_username": request.user.username,
            "retention_score": retention,
            "risk_score": risk,
            "confidence_score": confidence,
            "open_gaps": open_gaps,
        })

    @action(detail=False, methods=["get"], url_path="team-retention")
    def team_retention(self, request):
        company_id = self._get_company_id()
        team_id = request.query_params.get("team_id")
        if not company_id or not team_id:
            raise ValidationError({
                "company_id": "Required.",
                "team_id": "Required.",
            })
        self._require_permission("enterprise.ent-retention-team", "view")

        from api.enterprise_models import Company, Team
        company = Company.objects.get(id=company_id)
        try:
            team = Team.objects.get(id=team_id, company=company)
        except Team.DoesNotExist:
            raise ValidationError({"team_id": "Team not found in this company."})

        data = RetentionService.get_team_retention(team, company)
        return Response(data)

    @action(detail=False, methods=["get"], url_path="company-retention")
    def company_retention(self, request):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_permission("enterprise.ent-retention-company", "view")

        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        data = RetentionService.get_company_retention(company)
        return Response(data)

    @action(detail=False, methods=["post"])
    def recalculate(self, request):
        """
        Trigger a retention snapshot for the requesting user.
        Managers/admins can pass user_id to snapshot another user.
        """
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})

        membership = self._require_membership("owner", "admin", "manager", "trainer", "employee")

        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)

        user_id = request.data.get("user_id")
        if user_id and membership.role in ("owner", "admin", "manager"):
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                target = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise ValidationError({"user_id": "User not found."})
        else:
            target = request.user

        snap = RetentionService.create_retention_snapshot(target, company)
        return Response(
            RetentionSnapshotSerializer(snap).data,
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# RetentionSnapshotViewSet
# ---------------------------------------------------------------------------

class RetentionSnapshotViewSet(EnterpriseViewSetMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = RetentionSnapshotSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        user_id = self.request.query_params.get("user_id")

        if company_id:
            try:
                membership = validate_company_access(self.request.user, company_id)
            except PermissionError:
                return RetentionSnapshot.objects.none()
            qs = RetentionSnapshot.objects.filter(company_id=company_id)
            # Employees only see their own snapshots
            if membership.role == "employee":
                qs = qs.filter(user=self.request.user)
            elif user_id:
                qs = qs.filter(user_id=user_id)
            return qs.select_related("user", "topic", "learning_path")

        return RetentionSnapshot.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("topic", "learning_path")


# ---------------------------------------------------------------------------
# KnowledgeGapViewSet
# ---------------------------------------------------------------------------

class KnowledgeGapViewSet(EnterpriseViewSetMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = KnowledgeGapSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                membership = validate_company_access(self.request.user, company_id)
            except PermissionError:
                return KnowledgeGap.objects.none()
            qs = KnowledgeGap.objects.filter(company_id=company_id)
            if membership.role == "employee":
                qs = qs.filter(user=self.request.user)
            return qs.select_related("user", "team", "topic", "learning_path")
        return KnowledgeGap.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        )

    @action(detail=False, methods=["get"])
    def open(self, request):
        company_id = self._get_company_id()
        self._require_permission("enterprise.ent-gaps", "view")
        qs = self.get_queryset().filter(status="open")
        return Response(KnowledgeGapSerializer(qs, many=True).data)

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        gap = self.get_object()
        self._require_permission("enterprise.ent-gaps", "manage")
        if gap.status != "open":
            raise ValidationError({"detail": "Only open gaps can be acknowledged."})
        from django.utils import timezone as tz
        gap.status = "acknowledged"
        gap.acknowledged_at = tz.now()
        gap.acknowledged_by = request.user
        gap.save(update_fields=["status", "acknowledged_at", "acknowledged_by", "updated_at"])
        return Response(KnowledgeGapSerializer(gap).data)

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        gap = self.get_object()
        self._require_permission("enterprise.ent-gaps", "manage")
        if gap.status == "resolved":
            raise ValidationError({"detail": "Gap is already resolved."})
        from django.utils import timezone as tz
        gap.status = "resolved"
        gap.resolved_at = tz.now()
        gap.resolved_by = request.user
        gap.notes = request.data.get("notes", gap.notes)
        gap.save(update_fields=["status", "resolved_at", "resolved_by", "notes", "updated_at"])
        return Response(KnowledgeGapSerializer(gap).data)

    @action(detail=False, methods=["post"], url_path="detect")
    def detect(self, request):
        """Trigger gap detection for the company. Manager/admin only."""
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        self._require_permission("enterprise.ent-gaps", "manage")

        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        gaps = RetentionService.detect_knowledge_gaps(company)
        return Response({
            "gaps_detected": len(gaps),
            "gaps": KnowledgeGapSerializer(gaps, many=True).data,
        })


# ---------------------------------------------------------------------------
# ReviewScheduleViewSet
# ---------------------------------------------------------------------------

class ReviewScheduleViewSet(EnterpriseViewSetMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ReviewScheduleSerializer

    def get_queryset(self):
        company_id = self._get_company_id()
        if company_id:
            try:
                validate_company_access(self.request.user, company_id)
            except PermissionError:
                return ReviewSchedule.objects.none()
            return ReviewSchedule.objects.filter(
                company_id=company_id,
                user=self.request.user,
            ).select_related("topic", "battery", "learning_path", "learning_module")
        return ReviewSchedule.objects.filter(
            company_id__in=self._user_company_ids(),
            user=self.request.user,
        ).select_related("topic", "battery", "learning_path", "learning_module")

    def perform_create(self, serializer):
        company = self._get_company()
        serializer.save(company=company, user=self.request.user)

    @action(detail=False, methods=["get"], url_path="my-due-reviews")
    def my_due_reviews(self, request):
        from django.utils import timezone as tz
        company_id = self._get_company_id()
        qs = ReviewSchedule.objects.filter(
            user=request.user,
            status="pending",
            due_date__lte=tz.now().date(),
        )
        if company_id:
            qs = qs.filter(company_id=company_id)
        qs = qs.select_related("topic", "battery", "learning_path").order_by("due_date")
        return Response(ReviewScheduleSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"])
    def overdue(self, request):
        from django.utils import timezone as tz
        company_id = self._get_company_id()
        qs = ReviewSchedule.objects.filter(
            user=request.user,
            status="pending",
            due_date__lt=tz.now().date(),
        )
        if company_id:
            qs = qs.filter(company_id=company_id)
        return Response(ReviewScheduleSerializer(qs, many=True).data)

    @action(detail=True, methods=["post"])
    def complete(self, request, pk=None):
        review = self.get_object()
        if review.user != request.user:
            raise PermissionDenied("You can only complete your own reviews.")
        if review.status == "completed":
            raise ValidationError({"detail": "This review is already completed."})

        score_raw = request.data.get("score")
        if score_raw is None:
            raise ValidationError({"score": "This field is required."})
        try:
            score = Decimal(str(score_raw))
        except InvalidOperation:
            raise ValidationError({"score": "Invalid decimal value."})

        next_review = RetentionService.complete_review(review, request.user, score)
        return Response({
            "completed_review": ReviewScheduleSerializer(review).data,
            "next_review": ReviewScheduleSerializer(next_review).data,
        })

    @action(detail=False, methods=["post"], url_path="generate-due-reviews")
    def generate_due_reviews(self, request):
        """
        Generate ReviewSchedule rows for topics where the user has recent
        assessments but no pending review scheduled.
        Manager/admin can pass user_id to generate for another user.
        """
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        membership = self._require_membership("owner", "admin", "manager", "employee")

        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)

        user_id = request.data.get("user_id")
        if user_id and membership.role in ("owner", "admin", "manager"):
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                target = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise ValidationError({"user_id": "User not found."})
        else:
            target = request.user

        # Find assessments with no pending review for same content
        from django.db.models import OuterRef, Exists
        pending_for_topic = ReviewSchedule.objects.filter(
            company=company,
            user=target,
            status="pending",
            topic=OuterRef("topic"),
        )
        assessments_needing_review = KnowledgeAssessment.objects.filter(
            company=company,
            user=target,
            topic__isnull=False,
        ).exclude(
            Exists(pending_for_topic)
        ).values("topic").distinct()

        created = []
        for row in assessments_needing_review:
            if not row["topic"]:
                continue
            from api.models import Topic
            try:
                topic = Topic.objects.get(id=row["topic"])
            except Topic.DoesNotExist:
                continue
            review = RetentionService.schedule_review(
                user=target,
                company=company,
                review_type="battery",
                topic=topic,
                priority="medium",
            )
            created.append(review)

        return Response({
            "reviews_created": len(created),
            "reviews": ReviewScheduleSerializer(created, many=True).data,
        }, status=status.HTTP_201_CREATED)

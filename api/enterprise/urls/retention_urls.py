from rest_framework.routers import DefaultRouter

from api.enterprise.views.retention import (
    KnowledgeAssessmentViewSet,
    KnowledgeGapViewSet,
    RetentionSnapshotViewSet,
    RetentionViewSet,
    ReviewScheduleViewSet,
)

router = DefaultRouter()
router.register(r"enterprise/assessments", KnowledgeAssessmentViewSet, basename="enterprise-assessments")
router.register(r"enterprise/retention", RetentionViewSet, basename="enterprise-retention")
router.register(r"enterprise/retention-snapshots", RetentionSnapshotViewSet, basename="enterprise-retention-snapshots")
router.register(r"enterprise/knowledge-gaps", KnowledgeGapViewSet, basename="enterprise-knowledge-gaps")
router.register(r"enterprise/review-schedules", ReviewScheduleViewSet, basename="enterprise-review-schedules")

urlpatterns = router.urls

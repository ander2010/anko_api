from rest_framework.routers import DefaultRouter

from api.enterprise.views.compliance import (
    ComplianceAssignmentViewSet,
    ComplianceProgramViewSet,
    ComplianceRequirementViewSet,
    ComplianceReviewViewSet,
)

router = DefaultRouter()
router.register(r"enterprise/compliance-programs", ComplianceProgramViewSet, basename="enterprise-compliance-programs")
router.register(r"enterprise/compliance-requirements", ComplianceRequirementViewSet, basename="enterprise-compliance-requirements")
router.register(r"enterprise/compliance-assignments", ComplianceAssignmentViewSet, basename="enterprise-compliance-assignments")
router.register(r"enterprise/compliance-reviews", ComplianceReviewViewSet, basename="enterprise-compliance-reviews")

urlpatterns = router.urls

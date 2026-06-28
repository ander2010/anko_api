from rest_framework.routers import DefaultRouter

from api.enterprise.views.learning import (
    LearningModuleItemViewSet,
    LearningModuleViewSet,
    LearningPathAssignmentViewSet,
    LearningPathViewSet,
    TrainingProgramViewSet,
)

router = DefaultRouter()
router.register(r"enterprise/learning-paths", LearningPathViewSet, basename="enterprise-learning-paths")
router.register(r"enterprise/learning-modules", LearningModuleViewSet, basename="enterprise-learning-modules")
router.register(r"enterprise/learning-module-items", LearningModuleItemViewSet, basename="enterprise-learning-module-items")
router.register(r"enterprise/training-programs", TrainingProgramViewSet, basename="enterprise-training-programs")
router.register(r"enterprise/learning-assignments", LearningPathAssignmentViewSet, basename="enterprise-learning-assignments")

urlpatterns = router.urls

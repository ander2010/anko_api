from rest_framework.routers import DefaultRouter

from api.enterprise.views.document_intelligence import (
    ChangeImpactAnalysisViewSet,
    KnowledgeGraphViewSet,
    KnowledgeSourceViewSet,
    ProcedureViewSet,
)

router = DefaultRouter()
router.register(
    r"enterprise/knowledge-sources",
    KnowledgeSourceViewSet,
    basename="enterprise-knowledge-sources",
)
router.register(
    r"enterprise/procedures",
    ProcedureViewSet,
    basename="enterprise-procedures",
)
router.register(
    r"enterprise/change-impact",
    ChangeImpactAnalysisViewSet,
    basename="enterprise-change-impact",
)
router.register(
    r"enterprise/knowledge-graph",
    KnowledgeGraphViewSet,
    basename="enterprise-knowledge-graph",
)

urlpatterns = router.urls

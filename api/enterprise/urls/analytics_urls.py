from rest_framework.routers import DefaultRouter

from api.enterprise.views.analytics import AnalyticsDashboardViewSet

router = DefaultRouter()
router.register(
    r"enterprise/analytics",
    AnalyticsDashboardViewSet,
    basename="enterprise-analytics",
)

urlpatterns = router.urls

from rest_framework.routers import DefaultRouter

from api.enterprise.views.company import (
    BusinessUnitViewSet,
    CompanyViewSet,
    TeamViewSet,
)
from api.enterprise.views.email_logs import EmailLogViewSet

router = DefaultRouter()
router.register(r"enterprise/companies", CompanyViewSet, basename="enterprise-companies")
router.register(r"enterprise/business-units", BusinessUnitViewSet, basename="enterprise-business-units")
router.register(r"enterprise/teams", TeamViewSet, basename="enterprise-teams")
router.register(r"enterprise/email-logs", EmailLogViewSet, basename="enterprise-email-logs")

urlpatterns = router.urls

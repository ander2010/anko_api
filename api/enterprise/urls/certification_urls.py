from rest_framework.routers import DefaultRouter

from api.enterprise.views.certification import (
    CertificateTemplateViewSet,
    CertificationRequirementViewSet,
    CertificationVerifyViewSet,
    CertificationViewSet,
)

router = DefaultRouter()
router.register(
    r"enterprise/certificate-templates",
    CertificateTemplateViewSet,
    basename="enterprise-certificate-templates",
)
router.register(
    r"enterprise/certification-requirements",
    CertificationRequirementViewSet,
    basename="enterprise-certification-requirements",
)
router.register(
    r"enterprise/certifications",
    CertificationViewSet,
    basename="enterprise-certifications",
)
router.register(
    r"enterprise/verify",
    CertificationVerifyViewSet,
    basename="enterprise-verify",
)

urlpatterns = router.urls

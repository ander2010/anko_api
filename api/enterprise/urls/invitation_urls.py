from django.urls import path
from rest_framework.routers import DefaultRouter

from api.enterprise.views.invitations import (
    CompanyInvitationViewSet,
    InvitationActionViewSet,
)

# Token-based actions — flat, no company in URL
#   GET  /api/enterprise/invitations/validate/?token=XYZ
#   POST /api/enterprise/invitations/accept/
action_router = DefaultRouter()
action_router.register(
    r"enterprise/invitations",
    InvitationActionViewSet,
    basename="enterprise-invitations",
)

# Company-scoped invitation CRUD — manual paths (no nested-routers dependency)
#   GET  /api/enterprise/companies/{company_id}/invitations/
#   POST /api/enterprise/companies/{company_id}/invitations/
#   DELETE /api/enterprise/companies/{company_id}/invitations/{pk}/
#   POST /api/enterprise/companies/{company_id}/invitations/{pk}/resend/
_view = CompanyInvitationViewSet.as_view

company_invitation_patterns = [
    path(
        "enterprise/companies/<int:company_pk>/invitations/",
        CompanyInvitationViewSet.as_view({"get": "list", "post": "create"}),
        name="enterprise-company-invitations-list",
    ),
    path(
        "enterprise/companies/<int:company_pk>/invitations/<int:pk>/",
        CompanyInvitationViewSet.as_view({"delete": "destroy"}),
        name="enterprise-company-invitations-detail",
    ),
    path(
        "enterprise/companies/<int:company_pk>/invitations/<int:pk>/resend/",
        CompanyInvitationViewSet.as_view({"post": "resend"}),
        name="enterprise-company-invitations-resend",
    ),
]

urlpatterns = action_router.urls + company_invitation_patterns

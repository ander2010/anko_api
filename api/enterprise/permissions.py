"""
Enterprise RBAC Permissions

All permissions resolve the company from the request context and verify
the caller has an *active* CompanyMembership with the required role.

Usage in a ViewSet:
    permission_classes = [IsAuthenticated, IsCompanyManager]

    def get_company_id(self):
        # Override if the company comes from the request body instead of the URL
        return self.kwargs.get("company_pk") or self.request.query_params.get("company_id")
"""

from rest_framework.permissions import BasePermission
from api.enterprise_models import CompanyMembership


def _resolve_company_id(request, view):
    """Try common locations for a company identifier."""
    # URL kwargs: /companies/{company_pk}/...  or  /companies/{pk}/...
    for key in ("company_pk", "company_id", "pk"):
        value = view.kwargs.get(key)
        if value:
            return value
    # Query params: ?company_id=1
    return request.query_params.get("company_id") or request.data.get("company_id")


def _active_membership(user, company_id):
    """Return an active CompanyMembership or None."""
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if not company_id:
        return None
    try:
        return CompanyMembership.objects.select_related("company").get(
            company_id=company_id,
            user=user,
            status="active",
        )
    except (CompanyMembership.DoesNotExist, ValueError, TypeError):
        return None


class HasCompanyAccess(BasePermission):
    """User must have any active membership in the target company."""

    message = "You do not have access to this company."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        return _active_membership(request.user, company_id) is not None


class IsCompanyOwner(BasePermission):
    message = "Only the company owner can perform this action."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        m = _active_membership(request.user, company_id)
        return m is not None and m.role == "owner"


class IsCompanyAdmin(BasePermission):
    """Owner or Admin."""

    message = "Admin-level access required."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        m = _active_membership(request.user, company_id)
        return m is not None and m.role in ("owner", "admin")


class IsCompanyManager(BasePermission):
    """Owner, Admin, or Manager."""

    message = "Manager-level access required."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        m = _active_membership(request.user, company_id)
        return m is not None and m.role in ("owner", "admin", "manager")


class IsCompanyTrainer(BasePermission):
    """Owner, Admin, or Trainer."""

    message = "Trainer-level access required."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        m = _active_membership(request.user, company_id)
        return m is not None and m.role in ("owner", "admin", "trainer")


class IsCompanyEmployee(BasePermission):
    """Any active member of the company."""

    message = "Active company membership required."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        return _active_membership(request.user, company_id) is not None


class IsCompanyAuditor(BasePermission):
    """Owner, Admin, or Auditor."""

    message = "Auditor-level access required."

    def has_permission(self, request, view):
        company_id = _resolve_company_id(request, view)
        m = _active_membership(request.user, company_id)
        return m is not None and m.role in ("owner", "admin", "auditor")

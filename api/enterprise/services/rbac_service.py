"""
Enterprise RBAC resolution.

Resolves permissions via CompanyMembership.role (a plain string:
owner/admin/manager/trainer/employee/auditor) -> Role named
f"enterprise.{role}" -> its Permissions. This is the single source of
truth for enterprise authorization — both API-level enforcement
(require_permission, called from views) and sidebar visibility
(RBACViewSet.me_allowed_routes) read from the same Role/Permission rows,
which are editable from the Admin Area (Roles / Permissions / Global
Resources pages).

Deliberately does not touch User.roles/UserRole — that join is global
(not company-scoped) and is only ever populated with the bare "admin"/
"client" Role elsewhere in the codebase.
"""

from __future__ import annotations

from rest_framework.exceptions import PermissionDenied, ValidationError

from api.models import Role
from api.enterprise.services.security_service import validate_company_access


def has_permission(membership_role: str, resource_key: str, action: str) -> bool:
    return Role.objects.filter(
        name=f"enterprise.{membership_role}",
        permissions__resource__key=resource_key,
        permissions__action=action,
    ).exists()


def require_permission(user, company_id, resource_key: str, action: str = "manage"):
    """Raises PermissionDenied/ValidationError, or returns the active CompanyMembership."""
    if not company_id:
        raise ValidationError({"company_id": "This field is required."})
    try:
        membership = validate_company_access(user, company_id)
    except PermissionError as exc:
        raise PermissionDenied(str(exc))
    if not has_permission(membership.role, resource_key, action):
        raise PermissionDenied(
            f"This action requires the '{resource_key}:{action}' permission."
        )
    return membership

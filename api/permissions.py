"""Platform-level (not company-scoped) DRF permission classes."""

from rest_framework.permissions import BasePermission


class IsPlatformAdmin(BasePermission):
    """Allows access only to platform admins (is_staff/is_superuser/global "admin" Role).

    Mirrors _is_rbac_admin_user (api/views.py) — duplicated rather than imported
    to avoid a circular import (views.py imports from this module too).
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
            return True
        try:
            return user.roles.filter(name="admin").exists()
        except Exception:
            return False

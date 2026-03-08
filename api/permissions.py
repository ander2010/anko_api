from rest_framework.permissions import BasePermission


def is_admin_like(user) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
        return True
    try:
        return user.roles.filter(name="admin").exists()
    except Exception:
        return False


class IsRbacAdmin(BasePermission):
    message = "Admin access required."

    def has_permission(self, request, view):
        return is_admin_like(getattr(request, "user", None))

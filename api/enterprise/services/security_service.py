"""
Enterprise Security Service

All authorization helpers for the enterprise layer live here.
ViewSets call these functions instead of duplicating logic.

Critical rule: every function that accesses company-scoped data
MUST verify an active CompanyMembership first.
"""

from __future__ import annotations

from typing import List, Optional
from django.utils import timezone
from api.enterprise_models import Company, BusinessUnit, CompanyMembership, Team


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_active_membership(user, company_id) -> "CompanyMembership | None":
    """Return the active membership or None — never raise."""
    if not user or not getattr(user, "is_authenticated", False):
        return None
    try:
        return CompanyMembership.objects.select_related("company", "user").get(
            company_id=company_id,
            user=user,
            status="active",
        )
    except (CompanyMembership.DoesNotExist, ValueError, TypeError):
        if getattr(user, "is_staff", False):
            return _staff_virtual_membership(user, company_id)
        return None


def _staff_virtual_membership(user, company_id) -> "CompanyMembership | None":
    """Platform admins (is_staff) can operate as any active company without a
    real CompanyMembership row — returns an unsaved, owner-level membership
    so the existing role-based checks throughout the enterprise app treat
    them like the company's owner. Never persisted to the database."""
    try:
        company = Company.objects.get(id=company_id, is_active=True)
    except (Company.DoesNotExist, ValueError, TypeError):
        return None
    return CompanyMembership(company=company, user=user, role="owner", status="active")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_company_access(user, company_id) -> "CompanyMembership":
    """
    Verify that the user has an active membership in the company.

    Returns the membership on success.
    Raises PermissionError on failure.
    """
    membership = _get_active_membership(user, company_id)
    if not membership:
        raise PermissionError(
            f"User '{getattr(user, 'username', user)}' has no active membership "
            f"in company {company_id}."
        )
    return membership


def validate_team_access(user, team_id) -> tuple["Team", "CompanyMembership"]:
    """
    Verify the user may access the given team.

    - owner / admin  →  always allowed.
    - manager        →  only if they are a manager of that specific team.
    - others         →  only if they are a team member.

    Returns (team, membership).
    Raises PermissionError or Team.DoesNotExist.
    """
    try:
        team = Team.objects.select_related("company").get(id=team_id, is_active=True)
    except Team.DoesNotExist:
        raise Team.DoesNotExist(f"Team {team_id} not found or inactive.")

    membership = validate_company_access(user, team.company_id)

    if membership.role in ("owner", "admin"):
        return team, membership

    if membership.role == "manager":
        is_team_manager = team.memberships.filter(user=user, role="manager").exists()
        if not is_team_manager:
            raise PermissionError(
                "Managers can only access teams they are assigned to manage."
            )

    elif membership.role not in ("trainer", "employee", "auditor"):
        # Generic check: user must be a team member
        if not team.memberships.filter(user=user).exists():
            raise PermissionError("You are not a member of this team.")

    return team, membership


def validate_business_unit_access(
    user, business_unit_id
) -> tuple["BusinessUnit", "CompanyMembership"]:
    """
    Verify the user may access the given business unit.

    Returns (business_unit, membership).
    """
    try:
        bu = BusinessUnit.objects.select_related("company").get(
            id=business_unit_id, is_active=True
        )
    except BusinessUnit.DoesNotExist:
        raise BusinessUnit.DoesNotExist(
            f"BusinessUnit {business_unit_id} not found or inactive."
        )

    membership = validate_company_access(user, bu.company_id)
    return bu, membership


def validate_dashboard_access(user, company_id, dashboard_type: str) -> "CompanyMembership":
    """
    Verify the user may access a specific dashboard type.

    dashboard_type: 'employee' | 'manager' | 'trainer' | 'auditor' | 'executive'
    """
    membership = validate_company_access(user, company_id)

    allowed_roles: dict[str, list[str]] = {
        "employee": ["owner", "admin", "manager", "trainer", "employee", "auditor"],
        "manager": ["owner", "admin", "manager"],
        "trainer": ["owner", "admin", "trainer"],
        "auditor": ["owner", "admin", "auditor"],
        "executive": ["owner", "admin"],
    }

    permitted = allowed_roles.get(dashboard_type, [])
    if membership.role not in permitted:
        raise PermissionError(
            f"Role '{membership.role}' cannot access the '{dashboard_type}' dashboard."
        )

    return membership


def validate_learning_access(user, company_id) -> "CompanyMembership":
    """Any active member may access learning resources."""
    return validate_company_access(user, company_id)


def validate_compliance_access(
    user, company_id, *, require_roles: Optional[List[str]] = None
) -> "CompanyMembership":
    """
    Verify compliance access.

    require_roles: if provided, the membership role must be one of them.
    """
    membership = validate_company_access(user, company_id)
    if require_roles and membership.role not in require_roles:
        raise PermissionError(
            f"Role '{membership.role}' cannot access compliance data for this company."
        )
    return membership


def get_company_or_403(user, company_id) -> "Company":
    """
    Return the Company object if the user is an active member.
    Raises PermissionError if not.
    """
    validate_company_access(user, company_id)
    try:
        return Company.objects.get(id=company_id, is_active=True)
    except Company.DoesNotExist:
        raise PermissionError(f"Company {company_id} not found or inactive.")

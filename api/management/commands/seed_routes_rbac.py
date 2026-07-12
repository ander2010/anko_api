from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import connection, transaction

from api.models import Permission, Resource, Role

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM ROUTES  (dashboard / auth)
# Keys match the `name` field in routes.jsx  →  layout "dashboard"
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_KEYS = [
    "dashboard.home",
    "dashboard.projects",
    "dashboard.topics",
    "dashboard.rules",
    "dashboard.batteries",
    "dashboard.sections",
    "dashboard.my-decks",
    "dashboard.my-batteries",
    "dashboard.public-decks",
    "dashboard.public-batteries",

    # Platform Admin Area (is_staff / owner only)
    "dashboard.admin.users",
    "dashboard.admin.resources",
    "dashboard.admin.permissions",
    "dashboard.admin.roles",
    "dashboard.admin.plans",
    "dashboard.admin.plan-limits",
    "dashboard.admin.subscriptions",
    "dashboard.admin.battery-shares",
    "dashboard.admin.saved-batteries",
    "dashboard.admin.invites",
    "dashboard.admin.batteries",
    "dashboard.admin.decks",
    "dashboard.admin.flashcards",
    "dashboard.admin.deck-shares",
    "dashboard.admin.saved-decks",

    "dashboard.billing",
    "dashboard.faqs",
    "dashboard.about-us",
    "dashboard.contact-us",
]

AUTH_KEYS = [
    "auth.sign-in",
    "auth.sign-up",
]

# ─────────────────────────────────────────────────────────────────────────────
# ENTERPRISE ROUTES
# Keys match the `name` field in routes.jsx  →  enterprise group children
# Format: enterprise.<name-from-routes.jsx>
#
# Routes marked (*NEW*) don't exist yet in routes.jsx but are defined here
# so the frontend can add them and the RBAC already estará listo.
# ─────────────────────────────────────────────────────────────────────────────

ENTERPRISE_KEYS = [
    # ── Core ──────────────────────────────────────────────────────────────────
    "enterprise.ent-dashboard",           # /enterprise/dashboard
    "enterprise.ent-knowledge",           # /enterprise/knowledge  (Knowledge Sources + auto-generate)
    "enterprise.ent-knowledge-graph",     # /enterprise/knowledge/graph

    # ── Learning ──────────────────────────────────────────────────────────────
    "enterprise.ent-paths",               # /enterprise/learning/paths
    "enterprise.ent-manage-assignments",  # /enterprise/learning/manage-assignments
    "enterprise.ent-assignments",         # /enterprise/learning/assignments  (own)
    "enterprise.ent-reviews",             # /enterprise/learning/reviews
    "enterprise.ent-gaps",                # /enterprise/learning/gaps
    "enterprise.ent-programs",            # /enterprise/learning/programs

    # ── Retention ─────────────────────────────────────────────────────────────
    "enterprise.ent-retention-me",        # /enterprise/retention/me
    "enterprise.ent-retention-team",      # /enterprise/retention/team
    "enterprise.ent-retention-company",   # /enterprise/retention/company

    # ── Compliance ────────────────────────────────────────────────────────────
    "enterprise.ent-compliance-me",       # /enterprise/compliance/me
    "enterprise.ent-compliance-programs", # /enterprise/compliance/programs
    "enterprise.ent-compliance-team",     # /enterprise/compliance/team
    "enterprise.ent-compliance-company",  # /enterprise/compliance/company

    # ── Certifications ────────────────────────────────────────────────────────
    "enterprise.ent-certs-me",            # /enterprise/certifications
    "enterprise.ent-certs-templates",     # /enterprise/certifications/templates
    "enterprise.ent-certs-company",       # /enterprise/certifications/company

    # ── Analytics (owner / auditor only) ─────────────────────────────────────
    "enterprise.ent-analytics-retention", # /enterprise/analytics/retention
    "enterprise.ent-analytics-compliance",# /enterprise/analytics/compliance
    "enterprise.ent-analytics-learning",  # /enterprise/analytics/learning
    "enterprise.ent-analytics-health",    # /enterprise/analytics/health

    # ── Management (owner / manager only) ────────────────────────────────────
    "enterprise.ent-members",             # /enterprise/settings/members
    "enterprise.ent-settings",            # /enterprise/settings

    # ── *NEW* — add these routes in routes.jsx ────────────────────────────────
    "enterprise.ent-users",               # /enterprise/users      (owner only)
    "enterprise.ent-invitations",         # /enterprise/invitations (owner only)
    "enterprise.ent-teams",              # /enterprise/teams       (owner / manager)
]

ALL_KEYS = DASHBOARD_KEYS + AUTH_KEYS + ENTERPRISE_KEYS

# ─────────────────────────────────────────────────────────────────────────────
# CLIENT ROLE  (regular platform user — no enterprise)
# ─────────────────────────────────────────────────────────────────────────────

CLIENT_ALLOWED = [
    "dashboard.home",
    "dashboard.projects",
    "dashboard.my-decks",
    "dashboard.my-batteries",
    "dashboard.public-decks",
    "dashboard.public-batteries",
    "dashboard.billing",
    "dashboard.faqs",
    "dashboard.about-us",
    "dashboard.contact-us",
]

# ─────────────────────────────────────────────────────────────────────────────
# ENTERPRISE ROLE PERMISSIONS
#
# owner   → is_staff / platform admin.  Sees EVERYTHING (admin area + enterprise).
# manager → manages teams and assignments. No content creation. No platform admin.
# trainer → creates content (knowledge sources, auto-generate, learning paths).
# employee→ consumes content (assignments, reviews, gaps, certs).
# auditor → read-only on compliance and analytics. No content interaction.
# ─────────────────────────────────────────────────────────────────────────────

OWNER_ALLOWED = ALL_KEYS  # owner sees everything

# View lists below are the source of truth for sidebar visibility, agreed with
# the user role-by-role after auditing what each backend endpoint already
# enforces (see MANAGE_GATED_KEYS below for the write-side mirror). This also
# fixes drift from the previous version of this file, which had diverged from
# real backend behavior in a few spots: trainer used to see "ent-gaps" even
# though retention.py's knowledge-gap endpoints exclude trainer entirely;
# auditor used to see "ent-retention-team"/"ent-compliance-team" even though
# those require manager, not auditor; manager was missing "ent-knowledge",
# "ent-retention-company", "ent-compliance-company", "ent-analytics-retention",
# "ent-analytics-learning", "ent-settings" despite being allowed to manage/view
# them; manager used to see "ent-certs-company" which is owner/admin/auditor-only.

MANAGER_ALLOWED = [
    "enterprise.ent-dashboard",
    "enterprise.ent-knowledge",
    "enterprise.ent-paths",
    "enterprise.ent-manage-assignments",
    "enterprise.ent-knowledge-graph",
    "enterprise.ent-assignments",
    "enterprise.ent-reviews",
    "enterprise.ent-gaps",
    "enterprise.ent-programs",
    "enterprise.ent-retention-me",
    "enterprise.ent-retention-team",
    "enterprise.ent-retention-company",
    "enterprise.ent-compliance-me",
    "enterprise.ent-compliance-programs",
    "enterprise.ent-compliance-team",
    # NOT "ent-compliance-company" — ComplianceAssignmentViewSet.company_compliance
    # (compliance.py) explicitly restricts that to owner/admin/auditor, manager excluded.
    "enterprise.ent-certs-me",
    "enterprise.ent-certs-templates",
    "enterprise.ent-analytics-retention",
    "enterprise.ent-analytics-learning",
    "enterprise.ent-settings",
    "enterprise.ent-members",
    "enterprise.ent-teams",
]

TRAINER_ALLOWED = [
    "enterprise.ent-dashboard",
    "enterprise.ent-knowledge",
    "enterprise.ent-knowledge-graph",
    "enterprise.ent-paths",
    "enterprise.ent-assignments",
    "enterprise.ent-reviews",
    "enterprise.ent-programs",
    "enterprise.ent-retention-me",
    "enterprise.ent-compliance-me",
    "enterprise.ent-compliance-programs",
    "enterprise.ent-certs-me",
    "enterprise.ent-certs-templates",
    "enterprise.ent-analytics-learning",
]

EMPLOYEE_ALLOWED = [
    "enterprise.ent-dashboard",
    "enterprise.ent-assignments",
    "enterprise.ent-reviews",
    "enterprise.ent-gaps",
    "enterprise.ent-retention-me",
    "enterprise.ent-compliance-me",
    "enterprise.ent-certs-me",
]

AUDITOR_ALLOWED = [
    "enterprise.ent-dashboard",
    "enterprise.ent-assignments",
    "enterprise.ent-reviews",
    "enterprise.ent-gaps",
    "enterprise.ent-retention-me",
    "enterprise.ent-retention-company",
    "enterprise.ent-compliance-me",
    "enterprise.ent-compliance-company",
    "enterprise.ent-certs-me",
    "enterprise.ent-certs-company",
    "enterprise.ent-analytics-retention",
    "enterprise.ent-analytics-compliance",
    "enterprise.ent-analytics-health",
]

# Company-membership role string (CompanyMembership.role) each enterprise Role
# represents — used only to resolve MANAGE_GATED_KEYS below. "owner"/"admin"
# aren't listed since they use OWNER_ALLOWED (get every view+manage permission).
ROLE_COMPANY_NAME = {
    "enterprise.manager": "manager",
    "enterprise.trainer": "trainer",
    "enterprise.employee": "employee",
    "enterprise.auditor": "auditor",
}

# Resources with a real, narrower "who can create/edit/delete" action distinct
# from "who can view" — mirrors the hardcoded role-tuples already enforced in
# the matching Django view (learning.py CONTENT_ROLES/ASSIGN_ROLES,
# compliance.py/certification.py CONTENT_ROLES, retention.py's team-retention
# and knowledge-gap acknowledge/resolve checks, invitations.py ADMIN_ROLES,
# company.py MANAGE_ROLES). Keys not listed here have no differentiated write
# action today, so their "manage" permission simply mirrors "view".
MANAGE_GATED_KEYS = {
    "enterprise.ent-knowledge":            ("owner", "admin", "trainer", "manager"),
    "enterprise.ent-paths":                ("owner", "admin", "trainer", "manager"),
    "enterprise.ent-programs":             ("owner", "admin", "trainer", "manager"),
    "enterprise.ent-compliance-programs":  ("owner", "admin", "trainer", "manager"),
    "enterprise.ent-certs-templates":      ("owner", "admin", "trainer", "manager"),
    "enterprise.ent-manage-assignments":   ("owner", "admin", "manager"),
    "enterprise.ent-retention-team":       ("owner", "admin", "manager"),
    "enterprise.ent-compliance-team":      ("owner", "admin", "manager"),
    "enterprise.ent-gaps":                 ("owner", "admin", "manager"),
    "enterprise.ent-settings":             ("owner", "admin", "manager"),
    "enterprise.ent-members":              ("owner", "admin", "manager"),
    "enterprise.ent-teams":                ("owner", "admin", "manager"),
    "enterprise.ent-invitations":          ("owner", "admin"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Admin route → model validation (ensures model exists before seeding)
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_ROUTE_MODEL_BINDINGS = {
    "dashboard.admin.users": "User",
    "dashboard.admin.resources": "Resource",
    "dashboard.admin.permissions": "Permission",
    "dashboard.admin.roles": "Role",
    "dashboard.admin.plans": "Plan",
    "dashboard.admin.plan-limits": "PlanLimit",
    "dashboard.admin.subscriptions": "Subscription",
    "dashboard.admin.battery-shares": "BatteryShare",
    "dashboard.admin.saved-batteries": "SavedBattery",
    "dashboard.admin.invites": "Invite",
    "dashboard.admin.batteries": "Battery",
    "dashboard.admin.decks": "Deck",
    "dashboard.admin.flashcards": "Flashcard",
    "dashboard.admin.deck-shares": "DeckShare",
    "dashboard.admin.saved-decks": "SavedDeck",
}

# ─────────────────────────────────────────────────────────────────────────────
# Roles to seed
# ─────────────────────────────────────────────────────────────────────────────

ROLES = [
    {
        "name": "admin",
        "description": "Platform admin (is_staff). Sees everything — admin area + all enterprise.",
        "allowed_keys": OWNER_ALLOWED,
    },
    {
        "name": "client",
        "description": "Regular platform user (no enterprise). Limited to personal routes.",
        "allowed_keys": CLIENT_ALLOWED,
    },
    {
        "name": "enterprise.owner",
        "description": "Enterprise owner. Full access to all enterprise routes + platform admin area.",
        "allowed_keys": OWNER_ALLOWED,
    },
    {
        "name": "enterprise.admin",
        "description": "Enterprise admin (CompanyMembership role='admin'). Equivalent to owner within their company.",
        "allowed_keys": OWNER_ALLOWED,
    },
    {
        "name": "enterprise.manager",
        "description": "Enterprise manager. Manages teams, assignments, and reviews their members' progress.",
        "allowed_keys": MANAGER_ALLOWED,
    },
    {
        "name": "enterprise.trainer",
        "description": "Enterprise trainer. Creates content: knowledge sources, auto-generate, learning paths.",
        "allowed_keys": TRAINER_ALLOWED,
    },
    {
        "name": "enterprise.employee",
        "description": "Enterprise employee. Consumes content: assignments, reviews, certifications.",
        "allowed_keys": EMPLOYEE_ALLOWED,
    },
    {
        "name": "enterprise.auditor",
        "description": "Enterprise auditor. Read-only access to compliance and analytics reports.",
        "allowed_keys": AUDITOR_ALLOWED,
    },
]


class Command(BaseCommand):
    help = "Seed RBAC Resources/Permissions for all frontend routes (platform + enterprise) and assign roles."

    @transaction.atomic
    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.WARNING("=" * 60))
        self.stdout.write(self.style.WARNING("RUNNING seed_routes_rbac"))
        self.stdout.write(self.style.WARNING(f"DB: {connection.settings_dict.get('NAME')}"))
        self.stdout.write(self.style.WARNING("=" * 60))

        self._validate_admin_bindings()

        before_r = Resource.objects.count()
        before_p = Permission.objects.count()
        before_roles = Role.objects.count()
        self.stdout.write(f"BEFORE → resources={before_r} perms={before_p} roles={before_roles}")

        # ── 1) Create one Resource + a "view" and a "manage" Permission per key ─
        # "view" gates sidebar visibility; "manage" gates create/update/delete
        # actions. Every resource gets both, even ones with no differentiated
        # write action today (personal pages, read-only reports) — those just
        # end up with identical view/manage audiences (see step 2).
        perm_by_key = {}
        manage_perm_by_key = {}
        for key in ALL_KEYS:
            res, _ = Resource.objects.get_or_create(
                key=key,
                defaults={
                    "name": key,
                    "description": f"Frontend route: {key}",
                },
            )
            perm, _ = Permission.objects.get_or_create(
                resource=res,
                action="view",
                code="",
                defaults={},
            )
            perm_by_key[key] = perm
            manage_perm, _ = Permission.objects.get_or_create(
                resource=res,
                action="manage",
                code="",
                defaults={},
            )
            manage_perm_by_key[key] = manage_perm

        # ── 2) Create roles and assign permissions ────────────────────────────
        for role_def in ROLES:
            role, created = Role.objects.get_or_create(
                name=role_def["name"],
                defaults={"description": role_def["description"]},
            )
            if not created:
                # Update description in case it changed
                role.description = role_def["description"]
                role.save(update_fields=["description"])

            allowed = role_def["allowed_keys"]
            if allowed is OWNER_ALLOWED:
                # owner/admin gets every view + manage permission
                perms = list(Permission.objects.filter(action__in=["view", "manage"], resource__key__in=ALL_KEYS))
            else:
                missing = [k for k in allowed if k not in perm_by_key]
                if missing:
                    raise RuntimeError(
                        f"Role '{role_def['name']}' references unknown keys: {missing}"
                    )
                perms = [perm_by_key[k] for k in allowed]

                company_role = ROLE_COMPANY_NAME.get(role_def["name"])
                for key in allowed:
                    gated_roles = MANAGE_GATED_KEYS.get(key)
                    if gated_roles is None:
                        # No differentiated write action for this resource — manage
                        # mirrors view (e.g. personal pages, read-only reports).
                        perms.append(manage_perm_by_key[key])
                    elif company_role and company_role in gated_roles:
                        perms.append(manage_perm_by_key[key])

            role.permissions.set(perms)
            count = role.permissions.count()
            status = "created" if created else "updated"
            self.stdout.write(
                self.style.SUCCESS(f"  [{status}] {role.name} → {count} permissions")
            )

        after_r = Resource.objects.count()
        after_p = Permission.objects.count()
        after_roles = Role.objects.count()

        self.stdout.write(self.style.WARNING("=" * 60))
        self.stdout.write(self.style.SUCCESS("RBAC seeded successfully"))
        self.stdout.write(f"AFTER  → resources={after_r} perms={after_p} roles={after_roles}")
        self.stdout.write(self.style.WARNING("=" * 60))

    def _validate_admin_bindings(self):
        missing_models = []
        for route_key, model_name in ADMIN_ROUTE_MODEL_BINDINGS.items():
            if route_key not in ALL_KEYS:
                raise RuntimeError(f"Admin route key missing in ALL_KEYS: {route_key}")
            try:
                apps.get_model("api", model_name)
            except LookupError:
                missing_models.append((route_key, model_name))
        if missing_models:
            details = ", ".join([f"{k}→{m}" for k, m in missing_models])
            raise RuntimeError(f"RBAC admin bindings reference missing models: {details}")

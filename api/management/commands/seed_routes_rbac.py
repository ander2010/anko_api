from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import connection, transaction

from api.models import Permission, Resource, Role

# Keys based on frontend routes.js
DASHBOARD_KEYS = [
    "dashboard.home",          # /dashboard/home (path "/home")
    "dashboard.projects",      # "/projects"
    "dashboard.topics",        # "/topics"
    "dashboard.rules",         # "/rules"
    "dashboard.batteries",     # "/batteries"
    "dashboard.sections",      # "/sections"
    "dashboard.my-decks",      # "/my-decks"
    "dashboard.my-batteries",  # "/my-batteries"
    "dashboard.public-decks",  # "/public-decks"
    "dashboard.public-batteries",  # "/public-batteries"

    # Admin group (nested)
    "dashboard.admin.users",            # "/users"
    "dashboard.admin.resources",        # "/resources"
    "dashboard.admin.permissions",      # "/permissions"
    "dashboard.admin.roles",            # "/roles"
    "dashboard.admin.plans",            # "/plans"
    "dashboard.admin.plan-limits",      # "/plan-limits"
    "dashboard.admin.subscriptions",    # "/subscriptions"
    "dashboard.admin.battery-shares",   # "/battery-shares"
    "dashboard.admin.saved-batteries",  # "/saved-batteries"
    "dashboard.admin.invites",          # "/invites"
    "dashboard.admin.batteries",        # "/batteries"
    "dashboard.admin.decks",            # "/decks"
    "dashboard.admin.flashcards",       # "/flashcards"
    "dashboard.admin.deck-shares",      # "/deck-shares"
    "dashboard.admin.saved-decks",      # "/saved-decks"

    "dashboard.billing",       # "/billing"

    # hidden=true but still routes
    "dashboard.faqs",          # "/faqs"
    "dashboard.about-us",      # "/about-us"
    "dashboard.contact-us",    # "/contact-us"
]

AUTH_KEYS = [
    "auth.sign-in",            # "/sign-in"
    "auth.sign-up",            # "/sign-up"
]

ALL_KEYS = DASHBOARD_KEYS + AUTH_KEYS

# Routes visible to client role
CLIENT_ALLOWED = [
    "dashboard.home",
    "dashboard.projects",
]

# RBAC admin route keys must be backed by real API models/panels.
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


class Command(BaseCommand):
    help = "Seed RBAC Resources/Permissions for frontend routes and assign admin/client roles."

    @transaction.atomic
    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.WARNING("RUNNING seed_routes_rbac"))
        self.stdout.write(self.style.WARNING(f"DB NAME: {connection.settings_dict.get('NAME')}"))
        self._validate_admin_bindings()

        before_r = Resource.objects.count()
        before_p = Permission.objects.count()
        before_roles = Role.objects.count()

        self.stdout.write(
            self.style.WARNING(
                f"BEFORE: resources={before_r} perms={before_p} roles={before_roles}"
            )
        )

        # 1) Create resources + view permission for each route key
        perm_by_key = {}

        for key in ALL_KEYS:
            res, _ = Resource.objects.get_or_create(
                key=key,
                defaults={
                    "name": key,
                    "description": f"Frontend route access: {key}",
                },
            )

            # unique_together includes (resource, action, code)
            perm, _ = Permission.objects.get_or_create(
                resource=res,
                action="view",
                code="",
                defaults={},
            )

            perm_by_key[key] = perm

        # 2) Create roles admin/client
        admin_role, _ = Role.objects.get_or_create(
            name="admin",
            defaults={"description": "Admin: can view all routes"},
        )
        client_role, _ = Role.objects.get_or_create(
            name="client",
            defaults={"description": "Client: limited routes"},
        )

        # 3) Assign permissions
        admin_perms = Permission.objects.filter(action="view", resource__key__in=ALL_KEYS)
        admin_role.permissions.set(admin_perms)

        missing = [k for k in CLIENT_ALLOWED if k not in perm_by_key]
        if missing:
            raise RuntimeError(f"CLIENT_ALLOWED keys not found in perm_by_key: {missing}")

        client_role.permissions.set([perm_by_key[k] for k in CLIENT_ALLOWED])

        after_r = Resource.objects.count()
        after_p = Permission.objects.count()
        after_roles = Role.objects.count()

        self.stdout.write(self.style.SUCCESS("RBAC routes seeded successfully"))
        self.stdout.write(
            self.style.SUCCESS(
                f"AFTER: resources={after_r} perms={after_p} roles={after_roles}"
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Admin permissions assigned: {admin_role.permissions.count()}"
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Client permissions assigned: {client_role.permissions.count()}"
            )
        )

    def _validate_admin_bindings(self):
        missing_models = []
        for route_key, model_name in ADMIN_ROUTE_MODEL_BINDINGS.items():
            if route_key not in DASHBOARD_KEYS:
                raise RuntimeError(f"Admin route key is missing in DASHBOARD_KEYS: {route_key}")
            try:
                apps.get_model("api", model_name)
            except LookupError:
                missing_models.append((route_key, model_name))

        if missing_models:
            details = ", ".join([f"{k}->{m}" for k, m in missing_models])
            raise RuntimeError(f"RBAC admin bindings reference missing models: {details}")

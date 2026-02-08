# api/management/commands/seed_routes_rbac.py
from django.core.management.base import BaseCommand
from django.db import transaction, connection

from api.models import Resource, Permission, Role


# ====== Keys basadas en tu routes.js ======
DASHBOARD_KEYS = [
    "dashboard.home",          # /dashboard/home (path "/home")
    "dashboard.projects",      # "/projects"
    "dashboard.topics",        # "/topics"
    "dashboard.rules",         # "/rules"
    "dashboard.batteries",     # "/batteries"
    "dashboard.sections",      # "/sections"
    "dashboard.my-decks",      # "/my-decks"
    "dashboard.my-batteries",  # "/my-batteries"

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
    "dashboard.admin.decks",            # "/decks"
    "dashboard.admin.flashcards",       # "/flashcards"
    "dashboard.admin.deck-shares",      # "/deck-shares"
    "dashboard.admin.saved-decks",      # "/saved-decks"

    "dashboard.billing",       # "/billing"

    # hidden=true pero igual son rutas
    "dashboard.faqs",          # "/faqs"
    "dashboard.about-us",      # "/about-us"
    "dashboard.contact-us",    # "/contact-us"
]

AUTH_KEYS = [
    "auth.sign-in",            # "/sign-in"
    "auth.sign-up",            # "/sign-up"
]

ALL_KEYS = DASHBOARD_KEYS + AUTH_KEYS

# ====== Lo que el client puede ver ======
CLIENT_ALLOWED = [
    "dashboard.home",
    "dashboard.projects",
]


class Command(BaseCommand):
    help = "Seed RBAC Resources/Permissions for frontend routes and assign admin/client roles."

    @transaction.atomic
    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.WARNING("RUNNING seed_routes_rbac ✅"))
        self.stdout.write(self.style.WARNING(f"DB NAME: {connection.settings_dict.get('NAME')}"))

        before_r = Resource.objects.count()
        before_p = Permission.objects.count()
        before_roles = Role.objects.count()

        self.stdout.write(self.style.WARNING(
            f"BEFORE: resources={before_r} perms={before_p} roles={before_roles}"
        ))

        # 1) Crear resources + permission(view) por cada key
        perm_by_key = {}

        for key in ALL_KEYS:
            res, res_created = Resource.objects.get_or_create(
                key=key,
                defaults={
                    "name": key,
                    "description": f"Frontend route access: {key}",
                },
            )

            # IMPORTANTE: tu unique_together incluye ("resource","action","code")
            # para view lo dejamos con code="" (string vacio)
            perm, perm_created = Permission.objects.get_or_create(
                resource=res,
                action="view",
                code="",
                defaults={},  # por si luego agregas campos
            )

            perm_by_key[key] = perm

        # 2) Crear roles admin / client
        admin_role, _ = Role.objects.get_or_create(
            name="admin",
            defaults={"description": "Admin: can view all routes"},
        )
        client_role, _ = Role.objects.get_or_create(
            name="client",
            defaults={"description": "Client: limited routes"},
        )

        # 3) Asignar permisos
        # admin: todas las permissions de "view" (solo las de rutas)
        admin_perms = Permission.objects.filter(action="view", resource__key__in=ALL_KEYS)
        admin_role.permissions.set(admin_perms)

        # client: solo las permitidas
        missing = [k for k in CLIENT_ALLOWED if k not in perm_by_key]
        if missing:
            raise RuntimeError(f"CLIENT_ALLOWED keys not found in perm_by_key: {missing}")

        client_role.permissions.set([perm_by_key[k] for k in CLIENT_ALLOWED])

        after_r = Resource.objects.count()
        after_p = Permission.objects.count()
        after_roles = Role.objects.count()

        self.stdout.write(self.style.SUCCESS("✅ RBAC routes seeded successfully"))
        self.stdout.write(self.style.SUCCESS(
            f"AFTER: resources={after_r} perms={after_p} roles={after_roles}"
        ))
        self.stdout.write(self.style.SUCCESS(
            f"Admin permissions assigned: {admin_role.permissions.count()}"
        ))
        self.stdout.write(self.style.SUCCESS(
            f"Client permissions assigned: {client_role.permissions.count()}"
        ))

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from api.enterprise_models import Company, CompanyMembership

# Snapshot of this dev environment's real "optisoft360" company and its
# members, captured on 2026-07-12. Password hashes are copied verbatim
# (not re-hashed) so each account logs in with the *same* plaintext
# password here as it does locally — Django's pbkdf2_sha256 hasher does
# not depend on SECRET_KEY, so a copied hash verifies identically in any
# environment.
#
# Re-running this command is safe: everything is matched by username/slug
# and updated in place rather than duplicated.

COMPANY_DATA = {
    "name": "optisoft360",
    "slug": "optisoft360",
    "website": "",
    "industry": "healthcare",
    "company_size": "11_50",
    "description": "",
    "is_active": True,
    "settings": {},
    "owner_username": "andersanchez1987",
}

USERS_DATA = [
    {
        "username": "andersanchez1987",
        "email": "andersanchez1987@gmail.com",
        "password": "pbkdf2_sha256$600000$EA9S0hl6il5Ga5aPXRy8Wz$fzGFFxiU+swMkIZFEPpGektnJCJdIfQ7BsadQUwzVlw=",
        "first_name": "",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "owner",
        "status": "active",
        "employee_stage": "active_employee",
    },
    {
        "username": "letalcarlos7",
        "email": "letalcarlos7@gmail.com",
        "password": "pbkdf2_sha256$600000$jAvq4Unu8PY4EQk62rgrx7$xCAC0Bv79lVmLrhOHb0gadkIRcD9MhNIWTmprZIXhno=",
        "first_name": "Letal",
        "last_name": "Sanchez",
        "is_active": True,
        "is_staff": True,
        "is_superuser": False,
        "email_verified": True,
        "role": "admin",
        "status": "active",
        "employee_stage": "contractor",
    },
    {
        "username": "ernestocarlos",
        "email": "ernestocarlos2010@gmail.com",
        "password": "pbkdf2_sha256$600000$FEqx7pqnBj1F2NSrdQVtrF$0RaPtwoBQTSB8wmWy3e8s6labDa8wmbAfg8FNBpO+sQ=",
        "first_name": "",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "employee",
        "status": "active",
        "employee_stage": "onboarding",
    },
    {
        "username": "test_admin",
        "email": "andersanchez1987+admin@gmail.com",
        "password": "pbkdf2_sha256$600000$4d5heBLO71r3NG9PJSZQmz$Neepve2kGJ8kTYIQmrFqJ4L2PMsbge6s0blter4j6eQ=",
        "first_name": "Admin",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "admin",
        "status": "active",
        "employee_stage": "active_employee",
    },
    {
        "username": "test_manager",
        "email": "andersanchez1987+manager@gmail.com",
        "password": "pbkdf2_sha256$600000$pr3F16Zkd3h8NlrxdKlfaD$HCNAJMypTjeng1zw7EuvMut0INIZYyDD4mkczr3kf64=",
        "first_name": "Manager",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "manager",
        "status": "active",
        "employee_stage": "active_employee",
    },
    {
        "username": "test_trainer",
        "email": "andersanchez1987+trainer@gmail.com",
        "password": "pbkdf2_sha256$600000$ABpGRvpgVZ483wpaVBeNQc$rJo62WCj2wMXCxS+GgHU8NlUFlMmIy05kunLKb5heA8=",
        "first_name": "Trainer",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "trainer",
        "status": "active",
        "employee_stage": "active_employee",
    },
    {
        "username": "test_employee",
        "email": "andersanchez1987+employee@gmail.com",
        "password": "pbkdf2_sha256$600000$Yqgj8S6AfA9GRmMsKqrmB9$ITpuHkn16D0CDrjJl3xgLfeo81dUePWIwWlNXrBlA9s=",
        "first_name": "Employee",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "employee",
        "status": "active",
        "employee_stage": "active_employee",
    },
    {
        "username": "test_auditor",
        "email": "andersanchez1987+auditor@gmail.com",
        "password": "pbkdf2_sha256$600000$vvTsN0xe3YvlqDFCq2GnZm$VPyvu/IdxOuv126cjvUfxoFeF7UbYrry4TdMuBIhy1Y=",
        "first_name": "Auditor",
        "last_name": "",
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "email_verified": True,
        "role": "auditor",
        "status": "active",
        "employee_stage": "active_employee",
    },
]


class Command(BaseCommand):
    help = (
        "Idempotently replicate this dev environment's 'optisoft360' company and "
        "its members (same username/email/password hash) into another environment, "
        "so every account logs in there exactly as it does locally."
    )

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()

        owner_data = next(u for u in USERS_DATA if u["username"] == COMPANY_DATA["owner_username"])
        owner = self._upsert_user(User, owner_data)

        company, created = Company.objects.get_or_create(
            slug=COMPANY_DATA["slug"],
            defaults={
                "name": COMPANY_DATA["name"],
                "owner": owner,
                "website": COMPANY_DATA["website"],
                "industry": COMPANY_DATA["industry"],
                "company_size": COMPANY_DATA["company_size"],
                "description": COMPANY_DATA["description"],
                "is_active": COMPANY_DATA["is_active"],
                "settings": COMPANY_DATA["settings"],
            },
        )
        if not created:
            company.name = COMPANY_DATA["name"]
            company.owner = owner
            company.website = COMPANY_DATA["website"]
            company.industry = COMPANY_DATA["industry"]
            company.company_size = COMPANY_DATA["company_size"]
            company.description = COMPANY_DATA["description"]
            company.is_active = COMPANY_DATA["is_active"]
            company.settings = COMPANY_DATA["settings"]
            company.save()
        self.stdout.write(self.style.WARNING(
            f"Company optisoft360 — {'created' if created else 'updated'} (id={company.id})"
        ))

        for data in USERS_DATA:
            user = owner if data["username"] == owner_data["username"] else self._upsert_user(User, data)

            membership, mcreated = CompanyMembership.objects.get_or_create(
                company=company, user=user,
                defaults={
                    "role": data["role"],
                    "status": data["status"],
                    "employee_stage": data["employee_stage"],
                    "joined_at": timezone.now(),
                },
            )
            if not mcreated:
                membership.role = data["role"]
                membership.status = data["status"]
                membership.employee_stage = data["employee_stage"]
                membership.save()

            self.stdout.write(
                f"  {user.username} — role={data['role']} "
                f"({'membership created' if mcreated else 'membership updated'})"
            )

        self.stdout.write(self.style.SUCCESS(
            "Done. Every account above now logs in here with the same password it uses locally."
        ))

    def _upsert_user(self, User, data):
        user, created = User.objects.get_or_create(
            username=data["username"],
            defaults={"email": data["email"], "first_name": data["first_name"], "last_name": data["last_name"]},
        )
        user.email = data["email"]
        user.first_name = data["first_name"]
        user.last_name = data["last_name"]
        user.is_active = data["is_active"]
        user.is_staff = data["is_staff"]
        user.is_superuser = data["is_superuser"]
        user.email_verified = data["email_verified"]
        user.password = data["password"]  # copied hash, not re-hashed — preserves the real password
        user.save()

        status = "created" if created else "updated"
        self.stdout.write(f"  user {user.username} ({user.email}) — {status}")
        return user

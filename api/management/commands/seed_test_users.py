from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from api.enterprise_models import Company, CompanyMembership

TEST_PASSWORD = "TestAnkard2026!"

# One test account per CompanyMembership role (excluding "owner" — that's always
# a real account, never a seeded test one).
TEST_ROLES = ["admin", "manager", "trainer", "employee", "auditor"]

# All test_ accounts share this inbox via "+" addressing (e.g.
# andersanchez1987+admin@gmail.com) — Gmail (and most providers) deliver
# anything after "+" straight to the base inbox, so every role's notifications
# land in one place without violating User.email's unique constraint.
# Override with --notify-email in another environment/inbox.
DEFAULT_NOTIFY_EMAIL = "andersanchez1987@gmail.com"

# Which company to attach the test memberships to. Tries, in order:
#   1) --company-name / --company-id CLI args
#   2) a company literally named "optisoft360" (this dev environment's company)
#   3) the first Company row found in the DB
# If none exists at all, the users are still created but left without a
# CompanyMembership (a warning is printed) — run this after at least one real
# company exists in that environment.
DEFAULT_COMPANY_NAME = "optisoft360"


class Command(BaseCommand):
    help = (
        "Idempotently seed test_admin/test_manager/test_trainer/test_employee/"
        "test_auditor accounts (same password, email pre-verified) so every "
        "CompanyMembership role can be logged into and compared side by side."
    )

    def add_arguments(self, parser):
        parser.add_argument("--company-id", type=int, default=None)
        parser.add_argument("--company-name", type=str, default=None)
        parser.add_argument("--notify-email", type=str, default=DEFAULT_NOTIFY_EMAIL)

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()

        notify_local, _, notify_domain = options["notify_email"].partition("@")
        if not notify_domain:
            raise ValueError(f"--notify-email must be a full address, got {options['notify_email']!r}")

        company = self._resolve_company(options)
        if company:
            self.stdout.write(self.style.WARNING(f"Target company: {company.id} — {company.name}"))
        else:
            self.stdout.write(self.style.WARNING(
                "No company found — test users will be created WITHOUT a CompanyMembership. "
                "Re-run this command with --company-id once a company exists."
            ))

        for role in TEST_ROLES:
            username = f"test_{role}"
            email = f"{notify_local}+{role}@{notify_domain}"

            user, created = User.objects.get_or_create(
                username=username,
                defaults={"email": email, "first_name": role.capitalize(), "is_active": True},
            )
            if not created:
                user.email = email
                user.is_staff = False
            user.email_verified = True
            user.set_password(TEST_PASSWORD)
            user.save()

            status = "created" if created else "updated"
            self.stdout.write(f"  user {username} ({email}) — {status}")

            if not company:
                continue

            membership, mcreated = CompanyMembership.objects.get_or_create(
                company=company, user=user,
                defaults={
                    "role": role,
                    "status": "active",
                    "employee_stage": "active_employee",
                    "joined_at": timezone.now(),
                },
            )
            if not mcreated:
                membership.role = role
                membership.status = "active"
                membership.employee_stage = "active_employee"
                membership.save()

            self.stdout.write(f"    membership role={role} — {'created' if mcreated else 'updated'}")

        self.stdout.write(self.style.SUCCESS(
            f"Done. Login with test_<role> ({notify_local}+<role>@{notify_domain}) / {TEST_PASSWORD}"
        ))

    def _resolve_company(self, options):
        if options.get("company_id"):
            return Company.objects.filter(id=options["company_id"]).first()
        if options.get("company_name"):
            return Company.objects.filter(name=options["company_name"]).first()
        return (
            Company.objects.filter(name=DEFAULT_COMPANY_NAME).first()
            or Company.objects.order_by("id").first()
        )

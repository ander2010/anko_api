# api/management/commands/seed_plans.py
from django.core.management.base import BaseCommand
from api.models import Plan, PlanLimit

class Command(BaseCommand):
    help = "Seed Free/Premium/Ultra plans and plan limits."

    def handle(self, *args, **kwargs):
        # 1) Plans
        free, _ = Plan.objects.get_or_create(
            tier="free",
            defaults=dict(
                name="Free",
                description="Starter plan",
                price_cents=0,
                max_documents=2,
                max_batteries=3,
                is_active=True,
            ),
        )
        premium, _ = Plan.objects.get_or_create(
            tier="premium",
            defaults=dict(
                name="Premium",
                description="Premium plan",
                price_cents=999,
                max_documents=None,   # ilimitado
                max_batteries=None,   # ilimitado
                is_active=True,
            ),
        )
        ultra, _ = Plan.objects.get_or_create(
            tier="ultra",
            defaults=dict(
                name="Ultra",
                description="Ultra plan",
                price_cents=1999,
                max_documents=None,
                max_batteries=None,
                is_active=True,
            ),
        )

        # helper
        def upsert_limit(plan, key, value_type, int_value=None, bool_value=None, str_value=""):
            PlanLimit.objects.update_or_create(
                plan=plan,
                key=key,
                defaults=dict(
                    value_type=value_type,
                    int_value=int_value,
                    bool_value=bool_value,
                    str_value=str_value,
                ),
            )

        # 2) Limits (según tu PlanGuard.DEFAULTS + tu idea)
        # Free
        upsert_limit(free, "upload_max_mb", "int", int_value=50)
        upsert_limit(free, "questions_per_battery_max", "int", int_value=50)
        upsert_limit(free, "explore_topics_limit", "int", int_value=0)
        upsert_limit(free, "can_use_flashcards", "bool", bool_value=False)
        upsert_limit(free, "can_invite", "bool", bool_value=False)
        upsert_limit(free, "can_collect_batteries", "bool", bool_value=False)
        upsert_limit(free, "can_collect_decks", "bool", bool_value=False)

        # Premium
        upsert_limit(premium, "upload_max_mb", "int", int_value=200)
        upsert_limit(premium, "questions_per_battery_max", "int", int_value=None)  # ilimitado
        upsert_limit(premium, "explore_topics_limit", "int", int_value=10)
        upsert_limit(premium, "can_use_flashcards", "bool", bool_value=True)
        upsert_limit(premium, "can_invite", "bool", bool_value=False)
        upsert_limit(premium, "can_collect_batteries", "bool", bool_value=True)
        upsert_limit(premium, "can_collect_decks", "bool", bool_value=True)

        # Ultra
        upsert_limit(ultra, "upload_max_mb", "int", int_value=300)
        upsert_limit(ultra, "questions_per_battery_max", "int", int_value=None)
        upsert_limit(ultra, "explore_topics_limit", "int", int_value=None)  # ilimitado
        upsert_limit(ultra, "can_use_flashcards", "bool", bool_value=True)
        upsert_limit(ultra, "can_invite", "bool", bool_value=True)
        upsert_limit(ultra, "can_collect_batteries", "bool", bool_value=True)
        upsert_limit(ultra, "can_collect_decks", "bool", bool_value=True)

        self.stdout.write(self.style.SUCCESS("✅ Plans + PlanLimits seeded successfully."))

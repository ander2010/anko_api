import logging
from django.db import transaction
from django.utils import timezone

from api.models import Plan, Subscription

def ensure_free_subscription_for_user(user):
    """
    Crea una Subscription Free si el user no tiene.
    No pisa nada si ya existe.
    """
    free_plan = Plan.objects.filter(tier="free", is_active=True).first()
    if not free_plan:
        # Mejor loggear en vez de romper el registro (o decide romper si quieres)
        logging.getLogger("django").error("Free plan not found (tier='free'). Cannot create subscription.")
        return None

    sub, created = Subscription.objects.get_or_create(
        user=user,
        defaults={
            "plan": free_plan,
            "status": "active",
            "start_at": timezone.now(),
            "current_period_start": timezone.now(),
            "current_period_end": None,
            "provider": "",
            "provider_subscription_id": "",
        },
    )
    return sub

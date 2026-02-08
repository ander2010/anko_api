# api/services/plan_guard.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Optional

from django.utils import timezone
from django.db.models import Q

from rest_framework.exceptions import PermissionDenied

from api.models import Plan, PlanLimit, Subscription, Document, Battery


@dataclass(frozen=True)
class LimitValue:
    int_value: Optional[int] = None
    bool_value: Optional[bool] = None
    str_value: Optional[str] = None


class PlanGuard:
    """
    Enforcements para Free/Premium/Ultra basado en Subscription.plan + PlanLimit.
    Reglas:
      - Si user no tiene subscription -> Free
      - Si subscription existe pero no está activa -> tratar como Free (o bloquear, tu eliges)
    """

    DEFAULTS = {
        # keys recomendadas:
        # upload_max_mb
        # max_documents (global en Plan)
        # max_batteries (global en Plan)
        # questions_per_battery_max
        # explore_topics_limit
        # can_use_flashcards
        # can_invite
        # can_collect_batteries
        # can_collect_decks
        "upload_max_mb": 50,
        "questions_per_battery_max": 50,
        "explore_topics_limit": 0,
        "can_use_flashcards": False,
        "can_invite": False,
        "can_collect_batteries": False,
        "can_collect_decks": False,
    }

    @staticmethod
    def get_active_subscription(user) -> Optional[Subscription]:
        sub = getattr(user, "subscription", None)
        if not sub:
            return None

        # si está vencida o no activa, la tratamos como no activa
        if sub.status not in ("trialing", "active"):
            return None
        if sub.current_period_end and timezone.now() > sub.current_period_end:
            return None
        return sub

    @staticmethod
    def get_plan_for_user(user) -> Plan:
        sub = PlanGuard.get_active_subscription(user)
        if sub:
            return sub.plan

        # fallback: Free (debe existir en DB)
        plan = Plan.objects.filter(tier="free", is_active=True).first()
        if not plan:
            # fallback extra por si no has seed-eado planes aún
            plan = Plan.objects.create(tier="free", name="Free", description="Default Free", price_cents=0)
        return plan

    @staticmethod
    def _get_plan_limit(plan: Plan, key: str) -> LimitValue:
        pl = PlanLimit.objects.filter(plan=plan, key=key).first()
        if not pl:
            # fallback defaults
            dv = PlanGuard.DEFAULTS.get(key)
            if isinstance(dv, bool):
                return LimitValue(bool_value=dv)
            if isinstance(dv, int):
                return LimitValue(int_value=dv)
            if isinstance(dv, str):
                return LimitValue(str_value=dv)
            return LimitValue()

        return LimitValue(int_value=pl.int_value, bool_value=pl.bool_value, str_value=pl.str_value)

    @staticmethod
    def limit_int(plan: Plan, key: str, default: Optional[int] = None) -> Optional[int]:
        v = PlanGuard._get_plan_limit(plan, key)
        if v.int_value is not None:
            return int(v.int_value)
        if default is not None:
            return int(default)
        # si default no se pasó, intenta defaults
        dv = PlanGuard.DEFAULTS.get(key)
        return int(dv) if isinstance(dv, int) else None

    @staticmethod
    def limit_bool(plan: Plan, key: str, default: Optional[bool] = None) -> bool:
        v = PlanGuard._get_plan_limit(plan, key)
        if v.bool_value is not None:
            return bool(v.bool_value)
        if default is not None:
            return bool(default)
        dv = PlanGuard.DEFAULTS.get(key)
        return bool(dv) if isinstance(dv, bool) else False

    # =========================
    # ENFORCERS
    # =========================

    @staticmethod
    def assert_upload_allowed(*, user, files, plan: Optional["Plan"] = None):
        """
        Reglas:
          - upload_max_mb por archivo (PlanLimit.upload_max_mb)
          - FREE: máximo 2 documentos cada 5 días (ventana móvil)
          - Otros planes: si plan.max_documents existe, aplica límite global (como antes)
        """
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        plan = plan or PlanGuard.get_plan_for_user(user)

        # ---------------------------
        # 1) Límite por tamaño
        # ---------------------------
        max_mb = PlanGuard.limit_int(plan, "upload_max_mb", default=50)
        max_bytes = (max_mb or 0) * 1024 * 1024

        for f in files:
            size = getattr(f, "size", None) or 0
            if max_mb is not None and size > max_bytes:
                raise PermissionDenied(f"Plan limit: file exceeds upload_max_mb={max_mb}MB.")

        # ---------------------------
        # 2) Límite por ventana (FREE)
        # ---------------------------
        # Ajusta cómo identificas el plan FREE:
        # - si tu Plan tiene tier: "free"
        # - o name: "Free"
        tier = (getattr(plan, "tier", "") or "").lower()
        is_free = tier == "free" or (getattr(plan, "name", "") or "").lower() == "free"

        if is_free:
            window_days = 5
            window_limit = 2
            since = timezone.now() - timedelta(days=window_days)

            # ✅ Cuenta docs subidos por ESTE usuario en la ventana
            # Requiere Document.uploaded_by y Document.uploaded_at
            recent_count = (
                Document.objects
                .filter(uploaded_by=user, uploaded_at__gte=since)
                .count()
            )

            if recent_count + len(files) > window_limit:
                raise PermissionDenied(
                    f"Free plan limit: you can upload up to {window_limit} documents every {window_days} days."
                )

            return  # ✅ Free no usa max_documents global

        # ---------------------------
        # 3) Otros planes: límite global (como antes)
        # ---------------------------
        if plan.max_documents is not None:
            owned_or_member_docs = Document.objects.filter(
                Q(project__owner=user) | Q(project__members=user)
            ).count()

            if owned_or_member_docs + len(files) > int(plan.max_documents):
                raise PermissionDenied(f"Plan limit: max_documents={plan.max_documents} reached.")

    @staticmethod
    def assert_can_create_battery(*, user, plan: Optional[Plan] = None):
        """
        Regla:
          - max_batteries global (Plan.max_batteries). Free=3, Premium/Ultra ilimitado.
        """
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        plan = plan or PlanGuard.get_plan_for_user(user)

        if plan.max_batteries is not None:
            batteries_count = Battery.objects.filter(project__owner=user).count()
            if batteries_count + 1 > int(plan.max_batteries):
                raise PermissionDenied(f"Plan limit: max_batteries={plan.max_batteries} reached.")

    @staticmethod
    def assert_flashcards_allowed(*, user, plan: Optional[Plan] = None):
        """
        Regla:
          - can_use_flashcards (PlanLimit)
          - Free: false
          - Premium/Ultra: true
        """
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        plan = plan or PlanGuard.get_plan_for_user(user)

        if not PlanGuard.limit_bool(plan, "can_use_flashcards", default=False):
            raise PermissionDenied("This feature requires Premium or Ultra (flashcards).")

    @staticmethod
    def assert_explore_topics_allowed(*, user, requested_topics: int, plan: Optional[Plan] = None):
        """
        Regla:
          - explore_topics_limit: Free 0, Premium 10, Ultra ilimitado (null)
        """
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        plan = plan or PlanGuard.get_plan_for_user(user)

        limit = PlanGuard.limit_int(plan, "explore_topics_limit", default=0)
        if limit is None:
            return  # ilimitado
        if int(requested_topics) > int(limit):
            raise PermissionDenied(f"Plan limit: explore_topics_limit={limit} topics.")

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from django.db import IntegrityError, transaction
from django.utils import timezone

from api.models import PlanUsageCounter


class PlanUsageService:
    METRIC_DOCUMENTS_UPLOADED = "documents_uploaded"
    METRIC_ASK_QUERIES = "ask_queries"
    METRIC_FLASHCARD_JOBS = "flashcard_jobs"

    @staticmethod
    def _period_for_user(user, *, now: Optional[datetime] = None) -> tuple[datetime, datetime]:
        now = now or timezone.now()

        sub = getattr(user, "subscription", None)
        if sub and sub.status in ("trialing", "active"):
            start = sub.current_period_start or now
            end = sub.current_period_end
            if end and end > start:
                return start, end
            # Fallback when provider did not set current_period_end.
            return start, start + timedelta(days=30)

        # Fallback for free/no subscription: calendar month window.
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)
        return start, end

    @staticmethod
    def _get_or_create_current_counter(*, user, metric: str, plan_tier: str, now: Optional[datetime] = None) -> PlanUsageCounter:
        now = now or timezone.now()
        period_start, period_end = PlanUsageService._period_for_user(user, now=now)

        for _ in range(2):
            try:
                with transaction.atomic():
                    counter = (
                        PlanUsageCounter.objects
                        .select_for_update()
                        .filter(
                            user=user,
                            metric=metric,
                            period_start=period_start,
                            period_end=period_end,
                        )
                        .first()
                    )
                    if counter:
                        if plan_tier and counter.plan_tier_snapshot != plan_tier:
                            counter.plan_tier_snapshot = plan_tier
                            counter.save(update_fields=["plan_tier_snapshot", "updated_at"])
                        return counter

                    counter = PlanUsageCounter.objects.create(
                        user=user,
                        metric=metric,
                        used=0,
                        period_start=period_start,
                        period_end=period_end,
                        plan_tier_snapshot=plan_tier or "",
                    )
                    return counter
            except IntegrityError:
                # Concurrent create race, retry fetch once.
                continue

        # Final fetch outside retry path.
        return PlanUsageCounter.objects.get(
            user=user,
            metric=metric,
            period_start=period_start,
            period_end=period_end,
        )

    @staticmethod
    def get_usage(*, user, metric: str, plan_tier: str, now: Optional[datetime] = None) -> int:
        counter = PlanUsageService._get_or_create_current_counter(
            user=user,
            metric=metric,
            plan_tier=plan_tier,
            now=now,
        )
        return int(counter.used)

    @staticmethod
    def consume(
        *,
        user,
        metric: str,
        amount: int,
        limit: int,
        plan_tier: str,
        now: Optional[datetime] = None,
    ) -> tuple[bool, int, int]:
        if amount <= 0:
            return True, 0, limit

        now = now or timezone.now()
        period_start, period_end = PlanUsageService._period_for_user(user, now=now)

        for _ in range(2):
            try:
                with transaction.atomic():
                    counter = (
                        PlanUsageCounter.objects
                        .select_for_update()
                        .filter(
                            user=user,
                            metric=metric,
                            period_start=period_start,
                            period_end=period_end,
                        )
                        .first()
                    )
                    if not counter:
                        counter = PlanUsageCounter.objects.create(
                            user=user,
                            metric=metric,
                            used=0,
                            period_start=period_start,
                            period_end=period_end,
                            plan_tier_snapshot=plan_tier or "",
                        )

                    new_total = int(counter.used) + int(amount)
                    if new_total > int(limit):
                        return False, int(counter.used), int(limit)

                    counter.used = new_total
                    if plan_tier and counter.plan_tier_snapshot != plan_tier:
                        counter.plan_tier_snapshot = plan_tier
                    counter.save(update_fields=["used", "plan_tier_snapshot", "updated_at"])
                    return True, new_total, int(limit)
            except IntegrityError:
                continue

        counter = PlanUsageService._get_or_create_current_counter(
            user=user,
            metric=metric,
            plan_tier=plan_tier,
            now=now,
        )
        return False, int(counter.used), int(limit)

    @staticmethod
    def summary(*, user, metric: str, limit: int, plan_tier: str, now: Optional[datetime] = None) -> dict:
        now = now or timezone.now()
        period_start, period_end = PlanUsageService._period_for_user(user, now=now)
        used = PlanUsageService.get_usage(user=user, metric=metric, plan_tier=plan_tier, now=now)
        remaining = max(int(limit) - int(used), 0)
        return {
            "metric": metric,
            "used": int(used),
            "limit": int(limit),
            "remaining": int(remaining),
            "period_start": period_start,
            "period_end": period_end,
        }

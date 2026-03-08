from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rest_framework.exceptions import PermissionDenied
from django.utils import timezone

from api.models import Battery, Plan, PlanLimit, Subscription
from api.services.plan_usage import PlanUsageService


@dataclass(frozen=True)
class LimitValue:
    int_value: Optional[int] = None
    bool_value: Optional[bool] = None
    str_value: Optional[str] = None


class PlanGuard:
    """Plan enforcements with Free/Premium/Ultra profiles and admin bypass."""

    DEFAULTS = {
        "upload_max_mb": 50,
        "questions_per_battery_max": 50,
        "explore_topics_limit": 0,
        "can_use_flashcards": True,
        "can_invite": False,
        "can_collect_batteries": False,
        "can_collect_decks": False,
    }

    TIER_ALIASES = {
        "free": "free",
        "premium": "premium",
        "ultra": "ultra",
    }

    PLAN_PROFILES = {
        "free": {
            "documents_per_month": 2,
            "pages_per_document_max": 10,
            "ask_queries_per_month": 30,
            "flashcard_jobs_per_month": 1,
            "flashcards_per_job_max": 10,
            "history_days": 3,
        },
        "premium": {
            "documents_per_month": 100,
            "pages_per_document_max": 150,
            "ask_queries_per_month": 2000,
            "flashcard_jobs_per_month": 40,
            "flashcards_per_job_max": 100,
            "history_days": 90,
        },
        "ultra": {
            "documents_per_month": 500,
            "pages_per_document_max": 500,
            "ask_queries_per_month": 15000,
            "flashcard_jobs_per_month": 200,
            "flashcards_per_job_max": 300,
            "history_days": 365,
        },
    }

    @staticmethod
    def get_active_subscription(user) -> Optional[Subscription]:
        sub = getattr(user, "subscription", None)
        if not sub:
            return None

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

        plan = Plan.objects.filter(tier="free", is_active=True).first()
        if not plan:
            plan = Plan.objects.create(
                tier="free",
                name="Free",
                description="Default Free",
                price_cents=0,
            )
        return plan

    @staticmethod
    def _user_role_names(user) -> set[str]:
        try:
            return {name.lower() for name in user.roles.values_list("name", flat=True)}
        except Exception:
            return set()

    @staticmethod
    def should_enforce_for_user(user) -> bool:
        if not user or not user.is_authenticated:
            return False

        role_names = PlanGuard._user_role_names(user)
        is_admin = bool(
            getattr(user, "is_staff", False)
            or getattr(user, "is_superuser", False)
            or ("admin" in role_names)
        )
        return not is_admin

    @staticmethod
    def _effective_tier(plan: Plan) -> str:
        raw = (getattr(plan, "tier", None) or getattr(plan, "name", "") or "").strip().lower()
        mapped = PlanGuard.TIER_ALIASES.get(raw, raw)
        if mapped in PlanGuard.PLAN_PROFILES:
            return mapped
        return "free"

    @staticmethod
    def public_tier(plan: Plan) -> str:
        return PlanGuard._effective_tier(plan)

    @staticmethod
    def map_requested_tier_to_storage(raw_tier: str) -> Optional[str]:
        tier = (raw_tier or "").strip().lower()
        if tier in ("free", "premium", "ultra"):
            return tier
        return None

    @staticmethod
    def _profile_limit_int(plan: Plan, key: str) -> int:
        profile = PlanGuard.PLAN_PROFILES[PlanGuard._effective_tier(plan)]
        default_value = int(profile[key])
        configured = PlanGuard.limit_int(plan, key, default=None)
        return default_value if configured is None else int(configured)

    @staticmethod
    def _format_reset_at(dt) -> str:
        local_dt = timezone.localtime(dt)
        return local_dt.strftime("%Y-%m-%d %H:%M %Z")

    @staticmethod
    def _period_limit_message(*, metric_label: str, used: int, limit: int, reset_at) -> str:
        reset_text = PlanGuard._format_reset_at(reset_at)
        return (
            f"Plan limit reached for {metric_label} ({used}/{limit}). "
            f"Upgrade your plan or wait until {reset_text}."
        )

    @staticmethod
    def _extract_declared_pages(file_obj) -> Optional[int]:
        for attr in ("page_count", "pages", "num_pages", "total_pages"):
            value = getattr(file_obj, attr, None)
            if value is None:
                continue
            try:
                parsed = int(value)
                if parsed >= 0:
                    return parsed
            except (TypeError, ValueError):
                continue
        return None

    @staticmethod
    def _get_plan_limit(plan: Plan, key: str) -> LimitValue:
        pl = PlanLimit.objects.filter(plan=plan, key=key).first()
        if not pl:
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

    @staticmethod
    def assert_upload_allowed(*, user, files, plan: Optional[Plan] = None):
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if not PlanGuard.should_enforce_for_user(user):
            return

        plan = plan or PlanGuard.get_plan_for_user(user)
        plan_tier = PlanGuard._effective_tier(plan)

        max_mb = PlanGuard.limit_int(plan, "upload_max_mb", default=50)
        max_bytes = (max_mb or 0) * 1024 * 1024
        for f in files:
            size = getattr(f, "size", None) or 0
            if max_mb is not None and size > max_bytes:
                raise PermissionDenied(f"Plan limit: file exceeds upload_max_mb={max_mb}MB.")

        max_pages = PlanGuard._profile_limit_int(plan, "pages_per_document_max")
        for f in files:
            pages = PlanGuard._extract_declared_pages(f)
            if pages is not None and pages > max_pages:
                filename = getattr(f, "name", "document")
                raise PermissionDenied(
                    f"Plan limit reached: '{filename}' exceeds {max_pages} pages per document. "
                    f"Upgrade your plan to upload larger files."
                )

        docs_per_month = PlanGuard._profile_limit_int(plan, "documents_per_month")
        used = PlanUsageService.get_usage(
            user=user,
            metric=PlanUsageService.METRIC_DOCUMENTS_UPLOADED,
            plan_tier=plan_tier,
        )
        if used + len(files) > docs_per_month:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_DOCUMENTS_UPLOADED,
                limit=docs_per_month,
                plan_tier=plan_tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="documents",
                    used=used,
                    limit=docs_per_month,
                    reset_at=usage["period_end"],
                )
            )

    @staticmethod
    def assert_can_create_battery(*, user, plan: Optional[Plan] = None):
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if not PlanGuard.should_enforce_for_user(user):
            return

        plan = plan or PlanGuard.get_plan_for_user(user)
        if plan.max_batteries is not None:
            batteries_count = Battery.objects.filter(project__owner=user).count()
            if batteries_count + 1 > int(plan.max_batteries):
                raise PermissionDenied(f"Plan limit: max_batteries={plan.max_batteries} reached.")

    @staticmethod
    def assert_flashcards_allowed(*, user, requested_cards: Optional[int] = None, plan: Optional[Plan] = None):
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if not PlanGuard.should_enforce_for_user(user):
            return

        plan = plan or PlanGuard.get_plan_for_user(user)
        plan_tier = PlanGuard._effective_tier(plan)

        cards_per_job_max = PlanGuard._profile_limit_int(plan, "flashcards_per_job_max")
        if requested_cards is not None and int(requested_cards) > cards_per_job_max:
            raise PermissionDenied(f"Plan limit: flashcards_per_job_max={cards_per_job_max}.")

        jobs_per_month = PlanGuard._profile_limit_int(plan, "flashcard_jobs_per_month")
        used = PlanUsageService.get_usage(
            user=user,
            metric=PlanUsageService.METRIC_FLASHCARD_JOBS,
            plan_tier=plan_tier,
        )
        if used + 1 > jobs_per_month:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_FLASHCARD_JOBS,
                limit=jobs_per_month,
                plan_tier=plan_tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="flashcard jobs",
                    used=used,
                    limit=jobs_per_month,
                    reset_at=usage["period_end"],
                )
            )

    @staticmethod
    def assert_explore_topics_allowed(*, user, requested_topics: int, plan: Optional[Plan] = None):
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if not PlanGuard.should_enforce_for_user(user):
            return

        plan = plan or PlanGuard.get_plan_for_user(user)
        limit = PlanGuard.limit_int(plan, "explore_topics_limit", default=0)
        if limit is None:
            return
        if int(requested_topics) > int(limit):
            raise PermissionDenied(f"Plan limit: explore_topics_limit={limit} topics.")

    @staticmethod
    def assert_ask_allowed(*, user, plan: Optional[Plan] = None):
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if not PlanGuard.should_enforce_for_user(user):
            return

        plan = plan or PlanGuard.get_plan_for_user(user)
        plan_tier = PlanGuard._effective_tier(plan)
        ask_limit = PlanGuard._profile_limit_int(plan, "ask_queries_per_month")
        used = PlanUsageService.get_usage(
            user=user,
            metric=PlanUsageService.METRIC_ASK_QUERIES,
            plan_tier=plan_tier,
        )
        if used + 1 > ask_limit:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_ASK_QUERIES,
                limit=ask_limit,
                plan_tier=plan_tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="/ask queries",
                    used=used,
                    limit=ask_limit,
                    reset_at=usage["period_end"],
                )
            )

    @staticmethod
    def history_days_for_user(*, user, plan: Optional[Plan] = None) -> Optional[int]:
        if not user or not user.is_authenticated:
            return None
        if not PlanGuard.should_enforce_for_user(user):
            return None

        plan = plan or PlanGuard.get_plan_for_user(user)
        return PlanGuard._profile_limit_int(plan, "history_days")

    @staticmethod
    def usage_summary_for_user(*, user, plan: Optional[Plan] = None) -> dict:
        if not user or not user.is_authenticated:
            return {}
        if not PlanGuard.should_enforce_for_user(user):
            return {"bypass": True}

        plan = plan or PlanGuard.get_plan_for_user(user)
        tier = PlanGuard._effective_tier(plan)

        docs_limit = PlanGuard._profile_limit_int(plan, "documents_per_month")
        ask_limit = PlanGuard._profile_limit_int(plan, "ask_queries_per_month")
        jobs_limit = PlanGuard._profile_limit_int(plan, "flashcard_jobs_per_month")

        return {
            "documents_uploaded": PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_DOCUMENTS_UPLOADED,
                limit=docs_limit,
                plan_tier=tier,
            ),
            "ask_queries": PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_ASK_QUERIES,
                limit=ask_limit,
                plan_tier=tier,
            ),
            "flashcard_jobs": PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_FLASHCARD_JOBS,
                limit=jobs_limit,
                plan_tier=tier,
            ),
        }

    @staticmethod
    def record_documents_uploaded(*, user, amount: int, plan: Optional[Plan] = None):
        if amount <= 0 or not PlanGuard.should_enforce_for_user(user):
            return
        plan = plan or PlanGuard.get_plan_for_user(user)
        tier = PlanGuard._effective_tier(plan)
        limit = PlanGuard._profile_limit_int(plan, "documents_per_month")
        applied, used, max_limit = PlanUsageService.consume(
            user=user,
            metric=PlanUsageService.METRIC_DOCUMENTS_UPLOADED,
            amount=amount,
            limit=limit,
            plan_tier=tier,
        )
        if not applied:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_DOCUMENTS_UPLOADED,
                limit=max_limit,
                plan_tier=tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="documents",
                    used=used,
                    limit=max_limit,
                    reset_at=usage["period_end"],
                )
            )

    @staticmethod
    def record_flashcard_job(*, user, amount: int = 1, plan: Optional[Plan] = None):
        if amount <= 0 or not PlanGuard.should_enforce_for_user(user):
            return
        plan = plan or PlanGuard.get_plan_for_user(user)
        tier = PlanGuard._effective_tier(plan)
        limit = PlanGuard._profile_limit_int(plan, "flashcard_jobs_per_month")
        applied, used, max_limit = PlanUsageService.consume(
            user=user,
            metric=PlanUsageService.METRIC_FLASHCARD_JOBS,
            amount=amount,
            limit=limit,
            plan_tier=tier,
        )
        if not applied:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_FLASHCARD_JOBS,
                limit=max_limit,
                plan_tier=tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="flashcard jobs",
                    used=used,
                    limit=max_limit,
                    reset_at=usage["period_end"],
                )
            )

    @staticmethod
    def record_ask_query(*, user, amount: int = 1, plan: Optional[Plan] = None):
        if amount <= 0 or not PlanGuard.should_enforce_for_user(user):
            return
        plan = plan or PlanGuard.get_plan_for_user(user)
        tier = PlanGuard._effective_tier(plan)
        limit = PlanGuard._profile_limit_int(plan, "ask_queries_per_month")
        applied, used, max_limit = PlanUsageService.consume(
            user=user,
            metric=PlanUsageService.METRIC_ASK_QUERIES,
            amount=amount,
            limit=limit,
            plan_tier=tier,
        )
        if not applied:
            usage = PlanUsageService.summary(
                user=user,
                metric=PlanUsageService.METRIC_ASK_QUERIES,
                limit=max_limit,
                plan_tier=tier,
            )
            raise PermissionDenied(
                PlanGuard._period_limit_message(
                    metric_label="/ask queries",
                    used=used,
                    limit=max_limit,
                    reset_at=usage["period_end"],
                )
            )

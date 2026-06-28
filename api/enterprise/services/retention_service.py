"""
Enterprise Retention Service — Phase 3

Implements:
  - Knowledge assessment recording
  - Retention score calculation (with Ebbinghaus time-decay)
  - Risk score calculation
  - Confidence score calculation
  - Spaced repetition scheduling (SM-2)
  - Knowledge gap detection
  - Retention snapshot generation
  - Team/company aggregated metrics
"""

from __future__ import annotations

import math
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import List, Optional

from django.db import transaction
from django.utils import timezone

from api.enterprise_models import Company, LearningEvent, Team
from api.enterprise_retention_models import (
    KnowledgeAssessment,
    KnowledgeGap,
    RetentionSnapshot,
    ReviewSchedule,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ebbinghaus decay: R = e^(-t / S)
# S (stability) grows with each repetition.
# We approximate: each review at score >= 80 multiplies S by ease_factor.
_DECAY_WINDOW_DAYS = 90          # Assessments older than this contribute little
_GAP_THRESHOLD = Decimal("60")   # Retention below 60% = knowledge gap
_HIGH_RISK_THRESHOLD = Decimal("40")
_CRITICAL_THRESHOLD = Decimal("25")

# SM-2 bounds
_MIN_EASE = Decimal("1.30")
_MAX_EASE = Decimal("2.50")
_INITIAL_EASE = Decimal("2.50")


# ---------------------------------------------------------------------------
# RetentionService
# ---------------------------------------------------------------------------

class RetentionService:

    # ------------------------------------------------------------------
    # Assessment recording
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_assessment(
        user,
        company: Company,
        score: Decimal,
        assessment_type: str = "battery",
        items_total: int = 0,
        items_correct: int = 0,
        topic=None,
        battery=None,
        battery_attempt=None,
        learning_path=None,
        learning_module=None,
        metadata: Optional[dict] = None,
    ) -> KnowledgeAssessment:
        """
        Record an assessment event and emit a LearningEvent.
        score must be in 0-100 range.
        """
        retention_score = RetentionService._estimate_retention_after(
            user, company, score, topic=topic
        )
        confidence_score = RetentionService._estimate_confidence(
            user, company, score, topic=topic
        )

        assessment = KnowledgeAssessment.objects.create(
            company=company,
            user=user,
            score=score,
            assessment_type=assessment_type,
            items_total=items_total,
            items_correct=items_correct,
            retention_score=retention_score,
            confidence_score=confidence_score,
            topic=topic,
            battery=battery,
            battery_attempt=battery_attempt,
            learning_path=learning_path,
            learning_module=learning_module,
            metadata=metadata or {},
        )

        LearningEvent.objects.create(
            company=company,
            user=user,
            event_type="battery_completed" if assessment_type == "battery" else "review_completed",
            topic=topic,
            battery=battery,
            learning_path=learning_path,
            score=score,
            metadata={"assessment_id": assessment.id},
        )

        return assessment

    # ------------------------------------------------------------------
    # Retention / Risk / Confidence scores
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_user_retention(
        user,
        company: Company,
        topic=None,
        learning_path=None,
    ) -> Decimal:
        """
        Ebbinghaus-weighted retention score for a user.

        Recent assessments count more.
        Score = Σ(score_i * decay_i) / Σ(decay_i)
        decay_i = e^(-days_ago / 30)
        """
        cutoff = timezone.now() - timedelta(days=_DECAY_WINDOW_DAYS)
        qs = KnowledgeAssessment.objects.filter(
            company=company, user=user, created_at__gte=cutoff
        )
        if topic:
            qs = qs.filter(topic=topic)
        if learning_path:
            qs = qs.filter(learning_path=learning_path)

        assessments = list(qs.values("score", "created_at"))
        if not assessments:
            return Decimal("0")

        now = timezone.now()
        weighted_sum = 0.0
        weight_total = 0.0

        for a in assessments:
            days_ago = max((now - a["created_at"]).days, 0)
            decay = math.exp(-days_ago / 30.0)
            weighted_sum += float(a["score"]) * decay
            weight_total += decay

        if weight_total == 0:
            return Decimal("0")

        raw = Decimal(str(weighted_sum / weight_total))
        return raw.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def calculate_risk_score(
        user,
        company: Company,
        topic=None,
        learning_path=None,
    ) -> Decimal:
        """
        Risk = how likely the employee will have a knowledge failure.

        Components:
          - Low retention (inverted)
          - Time since last assessment (staleness penalty)
        """
        retention = RetentionService.calculate_user_retention(
            user, company, topic=topic, learning_path=learning_path
        )

        # Staleness: how many days since last assessment?
        qs = KnowledgeAssessment.objects.filter(company=company, user=user)
        if topic:
            qs = qs.filter(topic=topic)
        if learning_path:
            qs = qs.filter(learning_path=learning_path)

        last = qs.order_by("-created_at").values("created_at").first()
        if last is None:
            return Decimal("100")  # Never assessed = maximum risk

        days_since = (timezone.now() - last["created_at"]).days
        # Staleness penalty: 0 if reviewed today, up to 40 after 30+ days idle
        staleness = Decimal(str(min(days_since / 30.0 * 40.0, 40.0)))

        # Base risk = 100 - retention
        base_risk = Decimal("100") - retention
        risk = (base_risk + staleness) / Decimal("2")
        risk = max(Decimal("0"), min(Decimal("100"), risk))
        return risk.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def calculate_confidence_score(
        user,
        company: Company,
        topic=None,
    ) -> Decimal:
        """
        Confidence = consistency of scores over recent assessments.
        High variance → low confidence.
        """
        cutoff = timezone.now() - timedelta(days=_DECAY_WINDOW_DAYS)
        qs = KnowledgeAssessment.objects.filter(
            company=company, user=user, created_at__gte=cutoff
        )
        if topic:
            qs = qs.filter(topic=topic)

        scores = [float(a["score"]) for a in qs.values("score")]
        if not scores:
            return Decimal("0")
        if len(scores) == 1:
            return Decimal(str(scores[0])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev = math.sqrt(variance)

        # Confidence = avg_score * (1 - std_dev/50)  — penalize high variance
        confidence = mean * max(0.0, 1.0 - std_dev / 50.0)
        confidence = max(0.0, min(100.0, confidence))
        return Decimal(str(confidence)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    # ------------------------------------------------------------------
    # Snapshot generation
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_retention_snapshot(
        user,
        company: Company,
        topic=None,
        learning_path=None,
    ) -> RetentionSnapshot:
        """
        Create a new RetentionSnapshot row.
        Never updates existing rows — always inserts a new one.
        """
        retention = RetentionService.calculate_user_retention(
            user, company, topic=topic, learning_path=learning_path
        )
        risk = RetentionService.calculate_risk_score(
            user, company, topic=topic, learning_path=learning_path
        )
        confidence = RetentionService.calculate_confidence_score(
            user, company, topic=topic
        )

        qs = KnowledgeAssessment.objects.filter(company=company, user=user)
        if topic:
            qs = qs.filter(topic=topic)
        if learning_path:
            qs = qs.filter(learning_path=learning_path)

        count = qs.count()
        last_obj = qs.order_by("-created_at").values("created_at").first()
        last_date = last_obj["created_at"] if last_obj else None

        # Next review date: if retention < 60, due in 3 days; otherwise 7 days
        days_until_review = 3 if retention < _GAP_THRESHOLD else 7
        next_review = date.today() + timedelta(days=days_until_review)

        return RetentionSnapshot.objects.create(
            company=company,
            user=user,
            topic=topic,
            learning_path=learning_path,
            snapshot_date=date.today(),
            retention_score=retention,
            risk_score=risk,
            confidence_score=confidence,
            assessment_count=count,
            last_assessment_date=last_date,
            next_review_date=next_review,
        )

    @staticmethod
    def create_company_snapshots(company: Company) -> List[RetentionSnapshot]:
        """
        Generate snapshots for every active member of the company.
        Intended for the daily snapshot background job.
        """
        from api.enterprise_models import CompanyMembership

        members = CompanyMembership.objects.filter(
            company=company, status="active"
        ).select_related("user")

        snapshots = []
        for m in members:
            snap = RetentionService.create_retention_snapshot(m.user, company)
            snapshots.append(snap)
        return snapshots

    # ------------------------------------------------------------------
    # Knowledge gap detection
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def detect_knowledge_gaps(
        company: Company,
        threshold: Decimal = _GAP_THRESHOLD,
        close_resolved: bool = True,
    ) -> List[KnowledgeGap]:
        """
        Find active members whose overall retention is below threshold.
        Creates a KnowledgeGap if one doesn't already exist (open).
        Returns the list of newly created gaps.
        """
        from api.enterprise_models import CompanyMembership

        members = CompanyMembership.objects.filter(
            company=company, status="active"
        ).select_related("user")

        created_gaps: List[KnowledgeGap] = []

        for m in members:
            retention = RetentionService.calculate_user_retention(m.user, company)

            if retention < threshold:
                severity = RetentionService._gap_severity(retention)

                # Avoid duplicate open gaps for this user
                existing = KnowledgeGap.objects.filter(
                    company=company, user=m.user, status="open"
                ).first()

                if existing:
                    # Update severity if worse
                    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    if severity_order.get(severity, 0) > severity_order.get(existing.severity, 0):
                        existing.severity = severity
                        existing.retention_score_at_detection = retention
                        existing.save(update_fields=["severity", "retention_score_at_detection", "updated_at"])
                    created_gaps.append(existing)
                else:
                    gap = KnowledgeGap.objects.create(
                        company=company,
                        user=m.user,
                        severity=severity,
                        status="open",
                        retention_score_at_detection=retention,
                    )
                    LearningEvent.objects.create(
                        company=company,
                        user=m.user,
                        event_type="knowledge_gap_detected",
                        metadata={"gap_id": gap.id, "retention": str(retention)},
                    )
                    created_gaps.append(gap)

        return created_gaps

    # ------------------------------------------------------------------
    # Spaced repetition (SM-2)
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def schedule_review(
        user,
        company: Company,
        review_type: str = "battery",
        topic=None,
        battery=None,
        learning_module=None,
        learning_path=None,
        flashcard=None,
        priority: str = "medium",
    ) -> ReviewSchedule:
        """
        Create the first ReviewSchedule row for a (user, content) pair.
        Subsequent reviews are scheduled via complete_review().
        """
        return ReviewSchedule.objects.create(
            company=company,
            user=user,
            review_type=review_type,
            topic=topic,
            battery=battery,
            learning_module=learning_module,
            learning_path=learning_path,
            flashcard=flashcard,
            priority=priority,
            status="pending",
            due_date=date.today() + timedelta(days=1),
            ease_factor=_INITIAL_EASE,
            interval_days=1,
            repetition_count=0,
        )

    @staticmethod
    @transaction.atomic
    def complete_review(
        review: ReviewSchedule,
        user,
        score: Decimal,
    ) -> ReviewSchedule:
        """
        Mark a ReviewSchedule as completed and create the next one (SM-2).

        SM-2 algorithm:
          score >= 80  → correct (easy):  EF += 0.1, interval *= EF
          score >= 60  → correct (hard):  EF unchanged, interval *= EF
          score < 60   → incorrect:       EF -= 0.20, interval = 1
        """
        now = timezone.now()
        review.status = "completed"
        review.completed_at = now
        review.score = score
        review.save(update_fields=["status", "completed_at", "score", "updated_at"])

        # Adjust ease factor
        ef = review.ease_factor
        if score >= 80:
            ef = min(_MAX_EASE, ef + Decimal("0.10"))
            new_interval = max(1, int(float(review.interval_days) * float(ef)))
        elif score >= 60:
            new_interval = max(1, int(float(review.interval_days) * float(ef)))
        else:
            ef = max(_MIN_EASE, ef - Decimal("0.20"))
            new_interval = 1

        next_due = date.today() + timedelta(days=new_interval)
        new_repetitions = review.repetition_count + 1

        # Determine priority based on score
        if score < 40:
            priority = "critical"
        elif score < 60:
            priority = "high"
        elif score < 80:
            priority = "medium"
        else:
            priority = "low"

        next_review = ReviewSchedule.objects.create(
            company=review.company,
            user=user,
            review_type=review.review_type,
            topic=review.topic,
            battery=review.battery,
            learning_module=review.learning_module,
            learning_path=review.learning_path,
            flashcard=review.flashcard,
            priority=priority,
            status="pending",
            due_date=next_due,
            ease_factor=ef,
            interval_days=new_interval,
            repetition_count=new_repetitions,
        )

        LearningEvent.objects.create(
            company=review.company,
            user=user,
            event_type="review_completed",
            topic=review.topic,
            score=score,
            metadata={
                "review_id": review.id,
                "next_review_id": next_review.id,
                "next_due": str(next_due),
            },
        )
        return next_review

    # ------------------------------------------------------------------
    # Aggregated metrics
    # ------------------------------------------------------------------

    @staticmethod
    def get_team_retention(team: Team, company: Company) -> dict:
        """
        Aggregate retention/risk for all members of a team.
        """
        from api.enterprise_models import TeamMembership

        members = TeamMembership.objects.filter(team=team).select_related("user")
        if not members.exists():
            return {
                "team_id": team.id,
                "team_name": team.name,
                "member_count": 0,
                "avg_retention": Decimal("0"),
                "avg_risk": Decimal("0"),
                "at_risk_count": 0,
            }

        retention_scores = []
        risk_scores = []

        for m in members:
            r = RetentionService.calculate_user_retention(m.user, company)
            risk = RetentionService.calculate_risk_score(m.user, company)
            retention_scores.append(r)
            risk_scores.append(risk)

        n = Decimal(str(len(retention_scores)))
        avg_retention = sum(retention_scores) / n
        avg_risk = sum(risk_scores) / n
        at_risk = sum(1 for r in retention_scores if r < _GAP_THRESHOLD)

        return {
            "team_id": team.id,
            "team_name": team.name,
            "member_count": int(n),
            "avg_retention": avg_retention.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "avg_risk": avg_risk.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "at_risk_count": at_risk,
        }

    @staticmethod
    def get_company_retention(company: Company) -> dict:
        """
        Aggregate retention/risk for the entire company.
        """
        from api.enterprise_models import CompanyMembership

        members = CompanyMembership.objects.filter(
            company=company, status="active"
        ).select_related("user")

        if not members.exists():
            return {
                "company_id": company.id,
                "company_name": company.name,
                "employee_count": 0,
                "avg_retention": Decimal("0"),
                "avg_risk": Decimal("0"),
                "at_risk_count": 0,
                "open_gaps": 0,
            }

        retention_scores = []
        risk_scores = []

        for m in members:
            r = RetentionService.calculate_user_retention(m.user, company)
            risk = RetentionService.calculate_risk_score(m.user, company)
            retention_scores.append(r)
            risk_scores.append(risk)

        n = Decimal(str(len(retention_scores)))
        avg_retention = sum(retention_scores) / n
        avg_risk = sum(risk_scores) / n
        at_risk = sum(1 for r in retention_scores if r < _GAP_THRESHOLD)
        open_gaps = KnowledgeGap.objects.filter(company=company, status="open").count()

        return {
            "company_id": company.id,
            "company_name": company.name,
            "employee_count": int(n),
            "avg_retention": avg_retention.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "avg_risk": avg_risk.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "at_risk_count": at_risk,
            "open_gaps": open_gaps,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _gap_severity(retention: Decimal) -> str:
        if retention <= _CRITICAL_THRESHOLD:
            return "critical"
        if retention <= _HIGH_RISK_THRESHOLD:
            return "high"
        if retention < _GAP_THRESHOLD:
            return "medium"
        return "low"

    @staticmethod
    def _estimate_retention_after(user, company, new_score: Decimal, topic=None) -> Decimal:
        """Blend new score with existing retention (simple weighted avg)."""
        existing = RetentionService.calculate_user_retention(user, company, topic=topic)
        if existing == Decimal("0"):
            return new_score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        blended = (existing * Decimal("0.6") + new_score * Decimal("0.4"))
        return blended.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def _estimate_confidence(user, company, new_score: Decimal, topic=None) -> Decimal:
        """Confidence after including the new score."""
        return RetentionService.calculate_confidence_score(user, company, topic=topic)

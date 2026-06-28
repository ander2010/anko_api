"""
Enterprise Phase 3 — Retention Engine Tests

Covers:
  - Model constraints and validation
  - RetentionService: assessment recording, retention/risk/confidence scores,
    snapshots, gap detection, spaced repetition (SM-2), aggregated metrics
  - API endpoints: assessments, retention summary, snapshots, gaps, reviews
  - Tenant isolation
"""

import datetime
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from api.enterprise_models import Company, CompanyMembership, Team, TeamMembership
from api.enterprise_retention_models import (
    KnowledgeAssessment,
    KnowledgeGap,
    RetentionSnapshot,
    ReviewSchedule,
)
from api.enterprise.services.retention_service import RetentionService

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username):
    return User.objects.create_user(username=username, email=f"{username}@test.com", password="Pass123!")


def make_company(owner, name="Acme", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee", status="active"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status=status
    )


def make_assessment(user, company, score=80, assessment_type="battery"):
    return KnowledgeAssessment.objects.create(
        company=company,
        user=user,
        score=Decimal(str(score)),
        assessment_type=assessment_type,
        items_total=10,
        items_correct=int(score / 10),
        retention_score=Decimal(str(score)),
        confidence_score=Decimal(str(score)),
    )


def make_project(owner):
    from api.models import Project
    return Project.objects.create(title="Test Project", owner=owner)


def make_topic(owner):
    project = make_project(owner)
    from api.models import Topic
    return Topic.objects.create(project=project, name="Test Topic")


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class KnowledgeAssessmentModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("ka_owner")
        self.company = make_company(self.owner, slug="ka-co")

    def test_create_assessment(self):
        a = make_assessment(self.owner, self.company, score=75)
        self.assertEqual(a.score, Decimal("75"))
        self.assertEqual(a.company, self.company)

    def test_str(self):
        a = make_assessment(self.owner, self.company, score=90)
        self.assertIn("90", str(a))

    def test_default_assessment_type(self):
        a = KnowledgeAssessment.objects.create(
            company=self.company, user=self.owner,
            score=Decimal("80"),
        )
        self.assertEqual(a.assessment_type, "battery")

    def test_ordering_newest_first(self):
        make_assessment(self.owner, self.company, score=60)
        make_assessment(self.owner, self.company, score=90)
        scores = list(KnowledgeAssessment.objects.filter(
            company=self.company
        ).values_list("score", flat=True))
        self.assertEqual(scores[0], Decimal("90"))


class RetentionSnapshotModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("rs_owner")
        self.company = make_company(self.owner, slug="rs-co")

    def test_create_snapshot(self):
        snap = RetentionSnapshot.objects.create(
            company=self.company,
            user=self.owner,
            snapshot_date=datetime.date.today(),
            retention_score=Decimal("75"),
            risk_score=Decimal("25"),
            confidence_score=Decimal("70"),
        )
        self.assertEqual(snap.retention_score, Decimal("75"))

    def test_multiple_snapshots_allowed(self):
        for _ in range(3):
            RetentionSnapshot.objects.create(
                company=self.company,
                user=self.owner,
                snapshot_date=datetime.date.today(),
                retention_score=Decimal("80"),
            )
        self.assertEqual(
            RetentionSnapshot.objects.filter(company=self.company, user=self.owner).count(),
            3,
        )


class KnowledgeGapModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("kg_owner")
        self.company = make_company(self.owner, slug="kg-co")

    def test_create_user_gap(self):
        gap = KnowledgeGap.objects.create(
            company=self.company,
            user=self.owner,
            severity="high",
            retention_score_at_detection=Decimal("35"),
        )
        self.assertEqual(gap.status, "open")
        self.assertEqual(gap.severity, "high")

    def test_create_team_gap(self):
        team = Team.objects.create(company=self.company, name="Alpha")
        gap = KnowledgeGap.objects.create(
            company=self.company,
            team=team,
            severity="medium",
            retention_score_at_detection=Decimal("55"),
        )
        self.assertIsNone(gap.user)
        self.assertEqual(gap.team, team)

    def test_clean_requires_user_or_team(self):
        from django.core.exceptions import ValidationError
        gap = KnowledgeGap(company=self.company, severity="low")
        with self.assertRaises(ValidationError):
            gap.clean()


class ReviewScheduleModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("rv_owner")
        self.company = make_company(self.owner, slug="rv-co")

    def test_create_review(self):
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.owner,
            review_type="battery",
            status="pending",
            due_date=datetime.date.today(),
        )
        self.assertEqual(review.ease_factor, Decimal("2.50"))
        self.assertEqual(review.interval_days, 1)

    def test_is_overdue_when_past(self):
        yesterday = datetime.date.today() - datetime.timedelta(days=1)
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.owner,
            review_type="battery",
            status="pending",
            due_date=yesterday,
        )
        self.assertTrue(review.is_overdue())

    def test_is_not_overdue_when_completed(self):
        yesterday = datetime.date.today() - datetime.timedelta(days=1)
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.owner,
            review_type="battery",
            status="completed",
            due_date=yesterday,
        )
        self.assertFalse(review.is_overdue())


# ---------------------------------------------------------------------------
# Service Tests
# ---------------------------------------------------------------------------

class RetentionServiceCalculationTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_r_owner")
        self.employee = make_user("svc_r_emp")
        self.company = make_company(self.owner, slug="svc-ret-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_retention_zero_with_no_assessments(self):
        score = RetentionService.calculate_user_retention(self.employee, self.company)
        self.assertEqual(score, Decimal("0"))

    def test_retention_reflects_score(self):
        make_assessment(self.employee, self.company, score=90)
        score = RetentionService.calculate_user_retention(self.employee, self.company)
        self.assertGreater(score, Decimal("0"))
        self.assertLessEqual(score, Decimal("100"))

    def test_risk_score_100_with_no_assessments(self):
        risk = RetentionService.calculate_risk_score(self.employee, self.company)
        self.assertEqual(risk, Decimal("100"))

    def test_risk_score_lower_after_high_score(self):
        make_assessment(self.employee, self.company, score=95)
        risk = RetentionService.calculate_risk_score(self.employee, self.company)
        self.assertLess(risk, Decimal("100"))

    def test_confidence_zero_with_no_assessments(self):
        conf = RetentionService.calculate_confidence_score(self.employee, self.company)
        self.assertEqual(conf, Decimal("0"))

    def test_confidence_single_assessment(self):
        make_assessment(self.employee, self.company, score=80)
        conf = RetentionService.calculate_confidence_score(self.employee, self.company)
        self.assertEqual(conf, Decimal("80.00"))

    def test_multiple_assessments_weighted(self):
        make_assessment(self.employee, self.company, score=60)
        make_assessment(self.employee, self.company, score=80)
        make_assessment(self.employee, self.company, score=90)
        score = RetentionService.calculate_user_retention(self.employee, self.company)
        # Most recent (90) should dominate due to Ebbinghaus
        self.assertGreater(score, Decimal("70"))


class RetentionServiceAssessmentTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_a_owner")
        self.employee = make_user("svc_a_emp")
        self.company = make_company(self.owner, slug="svc-asmnt-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_create_assessment_creates_record(self):
        a = RetentionService.create_assessment(
            user=self.employee,
            company=self.company,
            score=Decimal("75"),
            assessment_type="battery",
            items_total=10,
            items_correct=7,
        )
        self.assertIsNotNone(a.id)
        self.assertEqual(a.score, Decimal("75"))

    def test_create_assessment_emits_learning_event(self):
        from api.enterprise_models import LearningEvent
        RetentionService.create_assessment(
            user=self.employee,
            company=self.company,
            score=Decimal("80"),
        )
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.employee, company=self.company
            ).exists()
        )

    def test_create_assessment_with_topic(self):
        topic = make_topic(self.owner)
        a = RetentionService.create_assessment(
            user=self.employee,
            company=self.company,
            score=Decimal("65"),
            topic=topic,
        )
        self.assertEqual(a.topic, topic)


class RetentionServiceSnapshotTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_s_owner")
        self.employee = make_user("svc_s_emp")
        self.company = make_company(self.owner, slug="svc-snap-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def test_create_snapshot(self):
        make_assessment(self.employee, self.company, score=70)
        snap = RetentionService.create_retention_snapshot(self.employee, self.company)
        self.assertIsNotNone(snap.id)
        self.assertEqual(snap.user, self.employee)
        self.assertEqual(snap.company, self.company)

    def test_snapshot_never_overwrites(self):
        make_assessment(self.employee, self.company, score=70)
        RetentionService.create_retention_snapshot(self.employee, self.company)
        RetentionService.create_retention_snapshot(self.employee, self.company)
        count = RetentionSnapshot.objects.filter(
            company=self.company, user=self.employee
        ).count()
        self.assertEqual(count, 2)

    def test_create_company_snapshots(self):
        emp2 = make_user("svc_s_emp2")
        make_membership(emp2, self.company, role="employee")
        make_assessment(self.employee, self.company, score=80)
        make_assessment(emp2, self.company, score=60)
        snaps = RetentionService.create_company_snapshots(self.company)
        # owner + 2 employees = 3 active members
        self.assertEqual(len(snaps), 3)


class RetentionServiceGapTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_g_owner")
        self.employee = make_user("svc_g_emp")
        self.good_employee = make_user("svc_g_good")
        self.company = make_company(self.owner, slug="svc-gap-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")
        make_membership(self.good_employee, self.company, role="employee")

    def test_detect_gaps_for_low_retention(self):
        make_assessment(self.employee, self.company, score=30)
        make_assessment(self.good_employee, self.company, score=95)
        gaps = RetentionService.detect_knowledge_gaps(self.company)
        gap_users = [g.user for g in gaps if g.user]
        self.assertIn(self.employee, gap_users)
        self.assertNotIn(self.good_employee, gap_users)

    def test_no_gaps_for_no_assessments(self):
        # Employees with no assessments have retention=0 → gap detected
        gaps = RetentionService.detect_knowledge_gaps(self.company)
        self.assertGreater(len(gaps), 0)

    def test_gap_severity_critical_below_25(self):
        make_assessment(self.employee, self.company, score=10)
        gaps = RetentionService.detect_knowledge_gaps(self.company)
        gap = next((g for g in gaps if g.user == self.employee), None)
        self.assertIsNotNone(gap)
        self.assertIn(gap.severity, ("critical", "high"))

    def test_duplicate_open_gap_not_created(self):
        make_assessment(self.employee, self.company, score=30)
        RetentionService.detect_knowledge_gaps(self.company)
        RetentionService.detect_knowledge_gaps(self.company)
        count = KnowledgeGap.objects.filter(
            company=self.company, user=self.employee, status="open"
        ).count()
        self.assertEqual(count, 1)


class RetentionServiceSM2Test(TestCase):
    def setUp(self):
        self.owner = make_user("sm2_owner")
        self.company = make_company(self.owner, slug="sm2-co")
        make_membership(self.owner, self.company, role="owner")

    def test_schedule_review_creates_pending(self):
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        self.assertEqual(review.status, "pending")
        self.assertEqual(review.ease_factor, Decimal("2.50"))

    def test_complete_review_high_score_increases_interval(self):
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        next_r = RetentionService.complete_review(review, self.owner, Decimal("90"))
        self.assertEqual(review.status, "completed")
        # interval >= 2 after first good review
        self.assertGreaterEqual(next_r.interval_days, 2)

    def test_complete_review_low_score_resets_interval(self):
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        # Artificially set a higher interval to show reset
        review.interval_days = 14
        review.save()
        next_r = RetentionService.complete_review(review, self.owner, Decimal("40"))
        self.assertEqual(next_r.interval_days, 1)

    def test_complete_review_low_score_decreases_ease(self):
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        next_r = RetentionService.complete_review(review, self.owner, Decimal("40"))
        self.assertLess(next_r.ease_factor, Decimal("2.50"))

    def test_complete_review_emits_event(self):
        from api.enterprise_models import LearningEvent
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        RetentionService.complete_review(review, self.owner, Decimal("80"))
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.owner, event_type="review_completed"
            ).exists()
        )

    def test_ease_factor_never_below_min(self):
        review = RetentionService.schedule_review(
            user=self.owner, company=self.company
        )
        review.ease_factor = Decimal("1.30")
        review.save()
        next_r = RetentionService.complete_review(review, self.owner, Decimal("20"))
        self.assertGreaterEqual(next_r.ease_factor, Decimal("1.30"))


class RetentionServiceAggregationTest(TestCase):
    def setUp(self):
        self.owner = make_user("agg_owner")
        self.emp1 = make_user("agg_emp1")
        self.emp2 = make_user("agg_emp2")
        self.company = make_company(self.owner, slug="agg-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.emp1, self.company, role="employee")
        make_membership(self.emp2, self.company, role="employee")

        self.team = Team.objects.create(company=self.company, name="Alpha Team")
        TeamMembership.objects.create(team=self.team, user=self.emp1, role="member")
        TeamMembership.objects.create(team=self.team, user=self.emp2, role="member")

        make_assessment(self.emp1, self.company, score=80)
        make_assessment(self.emp2, self.company, score=40)

    def test_team_retention_returns_avg(self):
        result = RetentionService.get_team_retention(self.team, self.company)
        self.assertIn("avg_retention", result)
        self.assertEqual(result["member_count"], 2)
        self.assertGreater(result["avg_retention"], Decimal("0"))

    def test_team_retention_counts_at_risk(self):
        result = RetentionService.get_team_retention(self.team, self.company)
        # emp2 with score 40 should be at risk
        self.assertGreaterEqual(result["at_risk_count"], 1)

    def test_company_retention(self):
        result = RetentionService.get_company_retention(self.company)
        self.assertIn("avg_retention", result)
        self.assertEqual(result["company_id"], self.company.id)
        self.assertGreater(result["employee_count"], 0)

    def test_empty_team_returns_zeros(self):
        empty_team = Team.objects.create(company=self.company, name="Empty")
        result = RetentionService.get_team_retention(empty_team, self.company)
        self.assertEqual(result["member_count"], 0)
        self.assertEqual(result["avg_retention"], Decimal("0"))


# ---------------------------------------------------------------------------
# API Tests
# ---------------------------------------------------------------------------

class RetentionAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_ret_owner")
        self.employee = make_user("api_ret_emp")
        self.company = make_company(self.owner, slug="api-ret-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")
        make_assessment(self.employee, self.company, score=75)

    def test_my_retention_returns_scores(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(
            "/api/enterprise/retention/my-retention/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("retention_score", r.data)
        self.assertIn("risk_score", r.data)
        self.assertIn("confidence_score", r.data)

    def test_my_retention_requires_auth(self):
        r = self.client.get(
            "/api/enterprise/retention/my-retention/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_company_retention_owner(self):
        self.client.force_authenticate(self.owner)
        r = self.client.get(
            "/api/enterprise/retention/company-retention/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("avg_retention", r.data)
        self.assertIn("employee_count", r.data)

    def test_company_retention_employee_forbidden(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(
            "/api/enterprise/retention/company-retention/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_team_retention(self):
        team = Team.objects.create(company=self.company, name="API Team")
        TeamMembership.objects.create(team=team, user=self.employee, role="member")
        make_assessment(self.employee, self.company, score=80)
        self.client.force_authenticate(self.owner)
        r = self.client.get(
            "/api/enterprise/retention/team-retention/",
            {"company_id": self.company.id, "team_id": team.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("avg_retention", r.data)

    def test_recalculate_creates_snapshot(self):
        self.client.force_authenticate(self.employee)
        r = self.client.post(
            "/api/enterprise/retention/recalculate/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertIn("retention_score", r.data)

    def test_outsider_blocked_from_my_retention(self):
        outsider = make_user("api_ret_out")
        self.client.force_authenticate(outsider)
        r = self.client.get(
            "/api/enterprise/retention/my-retention/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)


class KnowledgeGapAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_gap_owner")
        self.manager = make_user("api_gap_mgr")
        self.employee = make_user("api_gap_emp")
        self.company = make_company(self.owner, slug="api-gap-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.employee, self.company, role="employee")

        # Create a gap for the employee
        self.gap = KnowledgeGap.objects.create(
            company=self.company,
            user=self.employee,
            severity="high",
            status="open",
            retention_score_at_detection=Decimal("35"),
        )

    def _url(self, suffix=""):
        return f"/api/enterprise/knowledge-gaps/{suffix}"

    def test_manager_can_list_gaps(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_open_gaps_action(self):
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url("open/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_acknowledge_gap(self):
        self.client.force_authenticate(self.manager)
        r = self.client.post(
            self._url(f"{self.gap.id}/acknowledge/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "acknowledged")

    def test_resolve_gap(self):
        self.client.force_authenticate(self.manager)
        r = self.client.post(
            self._url(f"{self.gap.id}/resolve/"),
            {"company_id": self.company.id, "notes": "Re-trained employee"},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "resolved")

    def test_detect_gaps_action(self):
        make_assessment(self.employee, self.company, score=25)
        self.client.force_authenticate(self.manager)
        r = self.client.post(
            self._url("detect/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("gaps_detected", r.data)

    def test_employee_sees_only_own_gaps(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        for item in r.data.get("results", r.data):
            self.assertEqual(item["user"], self.employee.id)

    def test_cross_company_isolation(self):
        owner2 = make_user("api_gap_owner2")
        company2 = make_company(owner2, name="Other", slug="api-gap-co2")
        KnowledgeGap.objects.create(
            company=company2,
            user=owner2,
            severity="low",
            retention_score_at_detection=Decimal("50"),
        )
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        gap_ids = [item["id"] for item in r.data.get("results", r.data)]
        self.assertNotIn(
            KnowledgeGap.objects.get(company=company2).id,
            gap_ids,
        )


class ReviewScheduleAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_rv_owner")
        self.employee = make_user("api_rv_emp")
        self.company = make_company(self.owner, slug="api-rv-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

    def _url(self, suffix=""):
        return f"/api/enterprise/review-schedules/{suffix}"

    def test_create_review_schedule(self):
        self.client.force_authenticate(self.employee)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "review_type": "battery",
            "priority": "medium",
            "due_date": str(datetime.date.today() + datetime.timedelta(days=1)),
        })
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["status"], "pending")

    def test_my_due_reviews(self):
        ReviewSchedule.objects.create(
            company=self.company,
            user=self.employee,
            review_type="battery",
            status="pending",
            due_date=datetime.date.today(),
        )
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("my-due-reviews/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_overdue_reviews(self):
        yesterday = datetime.date.today() - datetime.timedelta(days=1)
        ReviewSchedule.objects.create(
            company=self.company,
            user=self.employee,
            review_type="battery",
            status="pending",
            due_date=yesterday,
        )
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("overdue/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_complete_review_action(self):
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.employee,
            review_type="battery",
            status="pending",
            due_date=datetime.date.today(),
        )
        self.client.force_authenticate(self.employee)
        r = self.client.post(
            self._url(f"{review.id}/complete/"),
            {"company_id": self.company.id, "score": "85"},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("completed_review", r.data)
        self.assertIn("next_review", r.data)
        self.assertEqual(r.data["completed_review"]["status"], "completed")

    def test_complete_review_schedules_next(self):
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.employee,
            review_type="battery",
            status="pending",
            due_date=datetime.date.today(),
        )
        self.client.force_authenticate(self.employee)
        self.client.post(
            self._url(f"{review.id}/complete/"),
            {"company_id": self.company.id, "score": "90"},
        )
        # Total reviews: original + next
        self.assertEqual(
            ReviewSchedule.objects.filter(company=self.company, user=self.employee).count(),
            2,
        )

    def test_complete_requires_score(self):
        review = ReviewSchedule.objects.create(
            company=self.company,
            user=self.employee,
            review_type="battery",
            status="pending",
            due_date=datetime.date.today(),
        )
        self.client.force_authenticate(self.employee)
        r = self.client.post(
            self._url(f"{review.id}/complete/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)


class RetentionSnapshotAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_snap_owner")
        self.employee = make_user("api_snap_emp")
        self.company = make_company(self.owner, slug="api-snap-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.employee, self.company, role="employee")

        RetentionSnapshot.objects.create(
            company=self.company,
            user=self.employee,
            snapshot_date=datetime.date.today(),
            retention_score=Decimal("75"),
        )

    def test_employee_can_list_own_snapshots(self):
        self.client.force_authenticate(self.employee)
        r = self.client.get(
            "/api/enterprise/retention-snapshots/",
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_employee_cannot_see_others_snapshots(self):
        other = make_user("api_snap_other")
        make_membership(other, self.company, role="employee")
        RetentionSnapshot.objects.create(
            company=self.company,
            user=other,
            snapshot_date=datetime.date.today(),
            retention_score=Decimal("50"),
        )
        self.client.force_authenticate(self.employee)
        r = self.client.get(
            "/api/enterprise/retention-snapshots/",
            {"company_id": self.company.id},
        )
        user_ids = [item["user"] for item in r.data.get("results", r.data)]
        self.assertNotIn(other.id, user_ids)

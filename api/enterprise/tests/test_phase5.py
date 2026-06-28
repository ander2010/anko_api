"""
Enterprise Phase 5 — Certifications Tests

Covers:
  - Model constraints and helpers (is_valid, is_expired, days_until_expiry)
  - CertificationService: eligibility, issue, verify, revoke, auto-issue, stats
  - API endpoints: templates, requirements, certifications, public verify
  - Tenant isolation
"""

import datetime
import uuid
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from api.enterprise_certification_models import (
    CertificateTemplate,
    Certification,
    CertificationRequirement,
)
from api.enterprise_models import Company, CompanyMembership, Team
from api.enterprise.services.certification_service import CertificationService

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username):
    return User.objects.create_user(
        username=username, email=f"{username}@cert.test", password="Pass123!"
    )


def make_company(owner, name="CertCo", slug=None):
    slug = slug or name.lower().replace(" ", "-")
    return Company.objects.create(name=name, slug=slug, owner=owner)


def make_membership(user, company, role="employee"):
    return CompanyMembership.objects.create(
        company=company, user=user, role=role, status="active"
    )


def make_template(company, code="CERT-001", name="Course Completion", **kwargs):
    kwargs.setdefault("template_type", "course_completion")
    kwargs.setdefault("validity_days", 365)
    kwargs.setdefault("is_active", True)
    return CertificateTemplate.objects.create(
        company=company, code=code, name=name, **kwargs
    )


def make_certification(company, user, template, **kwargs):
    kwargs.setdefault("status", "active")
    return Certification.objects.create(
        company=company, user=user, template=template, **kwargs
    )


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class CertificateTemplateModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("tpl_owner")
        self.company = make_company(self.owner, slug="tpl-co")

    def test_create_template(self):
        t = make_template(self.company)
        self.assertEqual(t.code, "CERT-001")
        self.assertTrue(t.is_active)

    def test_unique_code_per_company(self):
        make_template(self.company, code="UNIQ-001")
        with self.assertRaises(Exception):
            make_template(self.company, code="UNIQ-001", name="Other")

    def test_same_code_different_companies(self):
        owner2 = make_user("tpl_owner2")
        company2 = make_company(owner2, slug="tpl-co2")
        make_template(self.company, code="SHARE-001")
        t2 = make_template(company2, code="SHARE-001")
        self.assertEqual(t2.code, "SHARE-001")

    def test_str(self):
        t = make_template(self.company, code="STR-001")
        self.assertIn("STR-001", str(t))


class CertificationModelTest(TestCase):
    def setUp(self):
        self.owner = make_user("cert_owner")
        self.user = make_user("cert_user")
        self.company = make_company(self.owner, slug="cert-co")
        self.template = make_template(self.company, validity_days=30)

    def test_certificate_number_unique(self):
        c1 = make_certification(self.company, self.user, self.template)
        c2 = make_certification(self.company, self.owner, self.template)
        self.assertNotEqual(c1.certificate_number, c2.certificate_number)

    def test_verification_code_generated(self):
        c = make_certification(self.company, self.user, self.template)
        self.assertIsNotNone(c.verification_code)
        self.assertEqual(len(c.verification_code), 12)

    def test_is_valid_active(self):
        c = make_certification(self.company, self.user, self.template)
        c.expires_at = timezone.now() + datetime.timedelta(days=10)
        c.save()
        self.assertTrue(c.is_valid())

    def test_is_valid_expired(self):
        c = make_certification(self.company, self.user, self.template)
        c.expires_at = timezone.now() - datetime.timedelta(days=1)
        c.save()
        self.assertFalse(c.is_valid())

    def test_is_valid_revoked(self):
        c = make_certification(self.company, self.user, self.template, status="revoked")
        self.assertFalse(c.is_valid())

    def test_is_expired(self):
        c = make_certification(self.company, self.user, self.template)
        c.expires_at = timezone.now() - datetime.timedelta(days=1)
        c.save()
        self.assertTrue(c.is_expired())

    def test_days_until_expiry(self):
        c = make_certification(self.company, self.user, self.template)
        c.expires_at = timezone.now() + datetime.timedelta(days=30)
        c.save()
        self.assertAlmostEqual(c.days_until_expiry(), 30, delta=1)

    def test_days_until_expiry_no_expiry(self):
        c = make_certification(self.company, self.user, self.template)
        c.expires_at = None
        c.save()
        self.assertIsNone(c.days_until_expiry())

    def test_str(self):
        c = make_certification(self.company, self.user, self.template)
        self.assertIn("active", str(c))


# ---------------------------------------------------------------------------
# Service: issuance & basic ops
# ---------------------------------------------------------------------------

class CertificationServiceIssueTest(TestCase):
    def setUp(self):
        self.owner = make_user("svc_owner")
        self.user = make_user("svc_user")
        self.company = make_company(self.owner, slug="svc-cert-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.user, self.company, role="employee")

    def test_issue_basic(self):
        template = make_template(self.company, code="ISSUE-001")
        cert = CertificationService.issue_certificate(
            self.user, self.company, template, issued_by=self.owner
        )
        self.assertEqual(cert.status, "active")
        self.assertEqual(cert.user, self.user)
        self.assertIsNotNone(cert.certificate_number)

    def test_issue_with_validity(self):
        template = make_template(self.company, code="VALID-001", validity_days=180)
        cert = CertificationService.issue_certificate(
            self.user, self.company, template
        )
        expected = timezone.now().date() + datetime.timedelta(days=180)
        self.assertEqual(cert.expires_at.date(), expected)

    def test_issue_no_expiry_when_validity_zero(self):
        template = make_template(self.company, code="NOEXP-001", validity_days=0)
        cert = CertificationService.issue_certificate(
            self.user, self.company, template
        )
        self.assertIsNone(cert.expires_at)

    def test_issue_requires_score_pass(self):
        template = make_template(
            self.company, code="SCORE-001",
            requires_score=True, minimum_score=Decimal("70")
        )
        cert = CertificationService.issue_certificate(
            self.user, self.company, template, score=Decimal("85")
        )
        self.assertEqual(cert.score, Decimal("85"))

    def test_issue_requires_score_fail(self):
        template = make_template(
            self.company, code="SCOREF-001",
            requires_score=True, minimum_score=Decimal("70")
        )
        with self.assertRaises(ValueError):
            CertificationService.issue_certificate(
                self.user, self.company, template, score=Decimal("50")
            )

    def test_issue_emits_event(self):
        from api.enterprise_models import LearningEvent
        template = make_template(self.company, code="EVT-001")
        CertificationService.issue_certificate(self.user, self.company, template)
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.user, event_type="certificate_issued"
            ).exists()
        )

    def test_revoke_certificate(self):
        template = make_template(self.company, code="REV-001")
        cert = CertificationService.issue_certificate(self.user, self.company, template)
        revoked = CertificationService.revoke_certificate(cert, self.owner, "policy change")
        self.assertEqual(revoked.status, "revoked")
        self.assertIsNotNone(revoked.revoked_at)
        self.assertEqual(revoked.revocation_reason, "policy change")

    def test_revoke_already_revoked_raises(self):
        template = make_template(self.company, code="REV2-001")
        cert = CertificationService.issue_certificate(self.user, self.company, template)
        CertificationService.revoke_certificate(cert, self.owner)
        with self.assertRaises(ValueError):
            CertificationService.revoke_certificate(cert, self.owner)

    def test_revoke_emits_event(self):
        from api.enterprise_models import LearningEvent
        template = make_template(self.company, code="REVEVT-001")
        cert = CertificationService.issue_certificate(self.user, self.company, template)
        CertificationService.revoke_certificate(cert, self.owner, "revoke reason")
        self.assertTrue(
            LearningEvent.objects.filter(
                user=self.user, event_type="certificate_revoked"
            ).exists()
        )


# ---------------------------------------------------------------------------
# Service: verification
# ---------------------------------------------------------------------------

class CertificationServiceVerifyTest(TestCase):
    def setUp(self):
        self.owner = make_user("ver_owner")
        self.user = make_user("ver_user")
        self.company = make_company(self.owner, slug="ver-cert-co")
        self.template = make_template(self.company, code="VER-001")

    def test_verify_by_certificate_number(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        result = CertificationService.verify_certificate(str(cert.certificate_number))
        self.assertTrue(result["valid"])
        self.assertEqual(result["verification_code"], cert.verification_code)

    def test_verify_by_verification_code(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        result = CertificationService.verify_certificate(cert.verification_code)
        self.assertTrue(result["valid"])
        self.assertEqual(result["template_code"], self.template.code)

    def test_verify_not_found(self):
        result = CertificationService.verify_certificate("DOESNOTEXIST")
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_verify_revoked_returns_invalid(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        CertificationService.revoke_certificate(cert, self.owner)
        result = CertificationService.verify_certificate(cert.verification_code)
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "revoked")

    def test_verify_expired_returns_invalid(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        cert.expires_at = timezone.now() - datetime.timedelta(hours=1)
        cert.save()
        result = CertificationService.verify_certificate(cert.verification_code)
        self.assertFalse(result["valid"])


# ---------------------------------------------------------------------------
# Service: eligibility & auto-issue
# ---------------------------------------------------------------------------

class CertificationServiceEligibilityTest(TestCase):
    def setUp(self):
        self.owner = make_user("elig_owner")
        self.user = make_user("elig_user")
        self.company = make_company(self.owner, slug="elig-cert-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.user, self.company, role="employee")

    def test_eligibility_no_requirements(self):
        template = make_template(self.company, code="ELIG-001")
        result = CertificationService.check_eligibility(self.user, self.company, template)
        self.assertTrue(result["eligible"])
        self.assertEqual(result["total_requirements"], 0)

    def test_auto_issue_no_requirements_eligible(self):
        template = make_template(self.company, code="AUTO-001")
        from api.enterprise_learning_models import LearningPath
        lp = LearningPath.objects.create(
            company=self.company, name="LP1", created_by=self.owner
        )
        CertificationRequirement.objects.create(
            template=template, learning_path=lp, order=0
        )
        # User hasn't completed the path — should NOT auto-issue
        from api.enterprise_learning_models import LearningPathAssignment
        issued = CertificationService.auto_issue_on_path_completion(
            self.user, self.company, lp
        )
        self.assertEqual(len(issued), 0)

    def test_auto_issue_after_path_completion(self):
        template = make_template(self.company, code="AUTOCOMP-001")
        from api.enterprise_learning_models import LearningPath, LearningPathAssignment
        lp = LearningPath.objects.create(
            company=self.company, name="LP2", created_by=self.owner
        )
        CertificationRequirement.objects.create(
            template=template, learning_path=lp, order=0
        )
        # Simulate completion
        LearningPathAssignment.objects.create(
            company=self.company, user=self.user,
            learning_path=lp, assigned_by=self.owner, status="completed"
        )
        issued = CertificationService.auto_issue_on_path_completion(
            self.user, self.company, lp
        )
        self.assertEqual(len(issued), 1)
        self.assertEqual(issued[0].template, template)

    def test_auto_issue_does_not_duplicate(self):
        template = make_template(self.company, code="NODUP-001")
        from api.enterprise_learning_models import LearningPath, LearningPathAssignment
        lp = LearningPath.objects.create(
            company=self.company, name="LP3", created_by=self.owner
        )
        CertificationRequirement.objects.create(
            template=template, learning_path=lp, order=0
        )
        LearningPathAssignment.objects.create(
            company=self.company, user=self.user,
            learning_path=lp, assigned_by=self.owner, status="completed"
        )
        # Issue once
        CertificationService.auto_issue_on_path_completion(self.user, self.company, lp)
        # Issue again — should skip
        second = CertificationService.auto_issue_on_path_completion(
            self.user, self.company, lp
        )
        self.assertEqual(len(second), 0)


# ---------------------------------------------------------------------------
# Service: stats
# ---------------------------------------------------------------------------

class CertificationServiceStatsTest(TestCase):
    def setUp(self):
        self.owner = make_user("stats_owner")
        self.user = make_user("stats_user")
        self.company = make_company(self.owner, slug="stats-cert-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.user, self.company, role="employee")
        self.template = make_template(self.company, code="STATS-001", validity_days=60)

    def test_user_certifications_stats(self):
        CertificationService.issue_certificate(self.user, self.company, self.template)
        result = CertificationService.get_user_certifications(self.user, self.company)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["active"], 1)

    def test_company_stats(self):
        CertificationService.issue_certificate(self.user, self.company, self.template)
        result = CertificationService.get_company_certification_stats(self.company)
        self.assertEqual(result["total_issued"], 1)
        self.assertEqual(result["active"], 1)
        self.assertEqual(result["unique_holders"], 1)

    def test_get_expiring(self):
        cert = CertificationService.issue_certificate(
            self.user, self.company, self.template
        )
        cert.expires_at = timezone.now() + datetime.timedelta(days=10)
        cert.save()
        expiring = CertificationService.get_expiring_certifications(self.company, days=30)
        self.assertEqual(len(expiring), 1)

    def test_mark_expired(self):
        template = make_template(self.company, code="MARKEXP-001", validity_days=1)
        cert = CertificationService.issue_certificate(self.user, self.company, template)
        cert.expires_at = timezone.now() - datetime.timedelta(hours=1)
        cert.save()
        count = CertificationService.mark_expired_certifications(self.company)
        self.assertEqual(count, 1)
        cert.refresh_from_db()
        self.assertEqual(cert.status, "expired")

    def test_certificate_data(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        data = CertificationService.get_certificate_data(cert)
        self.assertIn("certificate_number", data)
        self.assertIn("verification_url", data)
        self.assertIn("holder_name", data)

    def test_verification_url(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        url = CertificationService.generate_verification_url(cert)
        self.assertIn(cert.verification_code, url)


# ---------------------------------------------------------------------------
# API Tests
# ---------------------------------------------------------------------------

class CertificateTemplateAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_tpl_owner")
        self.trainer = make_user("api_tpl_trainer")
        self.employee = make_user("api_tpl_emp")
        self.company = make_company(self.owner, slug="api-tpl-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.trainer, self.company, role="trainer")
        make_membership(self.employee, self.company, role="employee")

    def _url(self, suffix=""):
        return f"/api/enterprise/certificate-templates/{suffix}"

    def test_trainer_can_create_template(self):
        self.client.force_authenticate(self.trainer)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Course Cert",
            "code": "API-CERT-001",
            "template_type": "course_completion",
            "validity_days": 365,
        })
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["code"], "API-CERT-001")

    def test_employee_cannot_create_template(self):
        self.client.force_authenticate(self.employee)
        r = self.client.post(self._url(), {
            "company_id": self.company.id,
            "name": "Unauthorized",
            "code": "NO-AUTH-001",
        })
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_templates(self):
        make_template(self.company, code="LIST-001")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data.get("results", r.data)), 1)

    def test_activate_deactivate(self):
        t = make_template(self.company, code="ACTD-001", is_active=False)
        self.client.force_authenticate(self.owner)
        r = self.client.post(self._url(f"{t.id}/activate/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertTrue(r.data["is_active"])

        r2 = self.client.post(self._url(f"{t.id}/deactivate/"), {"company_id": self.company.id})
        self.assertEqual(r2.status_code, status.HTTP_200_OK)
        self.assertFalse(r2.data["is_active"])

    def test_issue_action(self):
        t = make_template(self.company, code="ISSUE-API-001")
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{t.id}/issue/"),
            {"company_id": self.company.id, "user_id": self.employee.id},
        )
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(r.data["status"], "active")
        self.assertIn("certificate_number", r.data)

    def test_issue_score_below_minimum(self):
        t = make_template(
            self.company, code="SCORE-API-001",
            requires_score=True, minimum_score=Decimal("70")
        )
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{t.id}/issue/"),
            {"company_id": self.company.id, "user_id": self.employee.id, "score": "50"},
        )
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_check_eligibility_action(self):
        t = make_template(self.company, code="ELIG-API-001")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(
            self._url(f"{t.id}/check-eligibility/"),
            {"company_id": self.company.id, "user_id": self.employee.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("eligible", r.data)

    def test_cross_company_isolation(self):
        owner2 = make_user("api_tpl_owner2")
        company2 = make_company(owner2, slug="api-tpl-co2")
        make_template(company2, code="SECRET-CERT-001")
        self.client.force_authenticate(self.trainer)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        codes = [item["code"] for item in r.data.get("results", r.data)]
        self.assertNotIn("SECRET-CERT-001", codes)


class CertificationAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("api_cert_owner")
        self.manager = make_user("api_cert_mgr")
        self.employee = make_user("api_cert_emp")
        self.company = make_company(self.owner, slug="api-cert-co")
        make_membership(self.owner, self.company, role="owner")
        make_membership(self.manager, self.company, role="manager")
        make_membership(self.employee, self.company, role="employee")
        self.template = make_template(self.company, code="API-C-001", validity_days=90)

    def _url(self, suffix=""):
        return f"/api/enterprise/certifications/{suffix}"

    def test_list_certifications_manager_sees_all(self):
        CertificationService.issue_certificate(self.employee, self.company, self.template)
        self.client.force_authenticate(self.manager)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data.get("results", r.data)), 1)

    def test_employee_only_sees_own(self):
        CertificationService.issue_certificate(self.employee, self.company, self.template)
        CertificationService.issue_certificate(self.owner, self.company, self.template)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url(), {"company_id": self.company.id})
        user_ids = [item["user"] for item in r.data.get("results", r.data)]
        for uid in user_ids:
            self.assertEqual(uid, self.employee.id)

    def test_my_certifications_action(self):
        CertificationService.issue_certificate(self.employee, self.company, self.template)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("my-certifications/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_my_stats_action(self):
        CertificationService.issue_certificate(self.employee, self.company, self.template)
        self.client.force_authenticate(self.employee)
        r = self.client.get(self._url("my-stats/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["active"], 1)

    def test_company_stats_action(self):
        CertificationService.issue_certificate(self.employee, self.company, self.template)
        self.client.force_authenticate(self.owner)
        r = self.client.get(self._url("company-stats/"), {"company_id": self.company.id})
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("total_issued", r.data)

    def test_expiring_action(self):
        cert = CertificationService.issue_certificate(
            self.employee, self.company, self.template
        )
        cert.expires_at = timezone.now() + datetime.timedelta(days=5)
        cert.save()
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url("expiring/"),
            {"company_id": self.company.id, "days": 30},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r.data), 1)

    def test_revoke_action(self):
        cert = CertificationService.issue_certificate(
            self.employee, self.company, self.template
        )
        self.client.force_authenticate(self.owner)
        r = self.client.post(
            self._url(f"{cert.id}/revoke/"),
            {"company_id": self.company.id, "reason": "policy change"},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["status"], "revoked")

    def test_certificate_data_action(self):
        cert = CertificationService.issue_certificate(
            self.employee, self.company, self.template
        )
        self.client.force_authenticate(self.manager)
        r = self.client.get(
            self._url(f"{cert.id}/certificate-data/"),
            {"company_id": self.company.id},
        )
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("verification_url", r.data)
        self.assertIn("holder_name", r.data)


class CertificationPublicVerifyAPITest(APITestCase):
    def setUp(self):
        self.owner = make_user("pub_ver_owner")
        self.user = make_user("pub_ver_user")
        self.company = make_company(self.owner, slug="pub-ver-co")
        self.template = make_template(self.company, code="PUB-VER-001")

    def test_verify_valid_by_code(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        r = self.client.get(f"/api/enterprise/verify/{cert.verification_code}/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertTrue(r.data["valid"])

    def test_verify_valid_by_uuid(self):
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        r = self.client.get(f"/api/enterprise/verify/{cert.certificate_number}/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertTrue(r.data["valid"])

    def test_verify_invalid(self):
        r = self.client.get("/api/enterprise/verify/BADCODE123456/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertFalse(r.data["valid"])

    def test_verify_no_auth_required(self):
        # No force_authenticate — should still work
        cert = CertificationService.issue_certificate(self.user, self.company, self.template)
        r = self.client.get(f"/api/enterprise/verify/{cert.verification_code}/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)

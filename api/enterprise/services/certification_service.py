"""
Enterprise Certification Service — Phase 5

Handles the full certification lifecycle:
  - Eligibility checking
  - Certificate issuance (manual + automatic)
  - Verification (by certificate_number or verification_code)
  - Revocation
  - Expiry tracking
  - Company statistics
"""

from __future__ import annotations

import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import List, Optional

from django.db import transaction
from django.utils import timezone

from api.enterprise_certification_models import (
    CertificateTemplate,
    Certification,
    CertificationRequirement,
)
from api.enterprise_models import Company, LearningEvent


class CertificationService:

    # ------------------------------------------------------------------
    # Eligibility
    # ------------------------------------------------------------------

    @staticmethod
    def check_eligibility(user, company: Company, template: CertificateTemplate) -> dict:
        """
        Check whether a user is eligible to receive a certificate.

        Returns:
            {
              eligible: bool,
              reasons: [str],       # why not eligible
              met_requirements: int,
              total_requirements: int,
            }
        """
        requirements = template.requirements.filter(is_mandatory=True)
        reasons: List[str] = []

        for req in requirements:
            if req.learning_path_id:
                from api.enterprise_learning_models import LearningPathAssignment
                completed = LearningPathAssignment.objects.filter(
                    company=company,
                    user=user,
                    learning_path_id=req.learning_path_id,
                    status="completed",
                ).exists()
                if not completed:
                    reasons.append(
                        f"Learning path '{req.learning_path.name}' not completed."
                    )
                elif req.minimum_score is not None:
                    # Check if user has an assessment score for this path
                    from api.enterprise_retention_models import KnowledgeAssessment
                    best = KnowledgeAssessment.objects.filter(
                        company=company,
                        user=user,
                        learning_path_id=req.learning_path_id,
                    ).order_by("-score").values_list("score", flat=True).first()
                    if best is None or best < req.minimum_score:
                        reasons.append(
                            f"Score {req.minimum_score} required for "
                            f"'{req.learning_path.name}' (best: {best})."
                        )

            if req.compliance_program_id:
                from api.enterprise_compliance_models import ComplianceAssignment
                compliant = ComplianceAssignment.objects.filter(
                    company=company,
                    user=user,
                    program_id=req.compliance_program_id,
                    is_compliant=True,
                    status="completed",
                ).exists()
                if not compliant:
                    reasons.append(
                        f"Compliance program '{req.compliance_program.name}' "
                        "not satisfied."
                    )

        total = requirements.count()
        met = total - len(reasons)

        # Score check at template level
        if template.requires_score and template.minimum_score is not None:
            pass  # caller passes score at issuance; checked there

        return {
            "eligible": len(reasons) == 0,
            "reasons": reasons,
            "met_requirements": met,
            "total_requirements": total,
        }

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def issue_certificate(
        user,
        company: Company,
        template: CertificateTemplate,
        issued_by=None,
        score: Optional[Decimal] = None,
        learning_path=None,
        compliance_program=None,
        metadata: Optional[dict] = None,
    ) -> Certification:
        """
        Issue a certificate to a user.
        Score check is applied if template.requires_score.
        """
        if template.requires_score and template.minimum_score is not None:
            if score is None or score < template.minimum_score:
                raise ValueError(
                    f"Score {score} is below minimum {template.minimum_score} "
                    f"required by template '{template.code}'."
                )

        expires_at = None
        if template.validity_days > 0:
            expires_at = timezone.now() + datetime.timedelta(days=template.validity_days)

        cert = Certification.objects.create(
            company=company,
            user=user,
            template=template,
            status="active",
            score=score,
            issued_at=timezone.now(),
            expires_at=expires_at,
            issued_by=issued_by,
            learning_path=learning_path,
            compliance_program=compliance_program,
            metadata=metadata or {},
        )

        LearningEvent.objects.create(
            company=company,
            user=user,
            event_type="certificate_issued",
            metadata={
                "certification_id": cert.id,
                "certificate_number": str(cert.certificate_number),
                "template_code": template.code,
            },
        )
        return cert

    @staticmethod
    def auto_issue_on_path_completion(
        user,
        company: Company,
        learning_path,
        score: Optional[Decimal] = None,
        issued_by=None,
    ) -> List[Certification]:
        """
        Check for templates linked to this learning_path and auto-issue if eligible.
        Called after a LearningPathAssignment is marked complete.
        """
        templates = CertificateTemplate.objects.filter(
            company=company,
            is_active=True,
            requirements__learning_path=learning_path,
        ).distinct()

        issued: List[Certification] = []
        for template in templates:
            eligibility = CertificationService.check_eligibility(user, company, template)
            if not eligibility["eligible"]:
                continue
            if template.requires_score and template.minimum_score is not None:
                if score is None or score < template.minimum_score:
                    continue
            already = Certification.objects.filter(
                company=company, user=user, template=template, status="active"
            ).exists()
            if already:
                continue
            cert = CertificationService.issue_certificate(
                user, company, template,
                issued_by=issued_by,
                score=score,
                learning_path=learning_path,
            )
            issued.append(cert)
        return issued

    @staticmethod
    def auto_issue_on_compliance_completion(
        user,
        company: Company,
        compliance_program,
        score: Optional[Decimal] = None,
        issued_by=None,
    ) -> List[Certification]:
        """
        Check for templates linked to this compliance_program and auto-issue.
        """
        templates = CertificateTemplate.objects.filter(
            company=company,
            is_active=True,
            requirements__compliance_program=compliance_program,
        ).distinct()

        issued: List[Certification] = []
        for template in templates:
            eligibility = CertificationService.check_eligibility(user, company, template)
            if not eligibility["eligible"]:
                continue
            already = Certification.objects.filter(
                company=company, user=user, template=template, status="active"
            ).exists()
            if already:
                continue
            cert = CertificationService.issue_certificate(
                user, company, template,
                issued_by=issued_by,
                score=score,
                compliance_program=compliance_program,
            )
            issued.append(cert)
        return issued

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @staticmethod
    def verify_certificate(identifier: str) -> dict:
        """
        Verify a certificate by certificate_number (UUID) or verification_code.
        Returns a public-facing dict — safe to expose without auth.
        """
        cert = None

        # Try UUID first
        try:
            import uuid as _uuid
            parsed = _uuid.UUID(str(identifier))
            cert = Certification.objects.select_related(
                "user", "template", "company"
            ).get(certificate_number=parsed)
        except (ValueError, Certification.DoesNotExist):
            pass

        # Fallback: verification_code
        if cert is None:
            try:
                cert = Certification.objects.select_related(
                    "user", "template", "company"
                ).get(verification_code=identifier.upper())
            except Certification.DoesNotExist:
                return {"valid": False, "error": "Certificate not found."}

        return {
            "valid": cert.is_valid(),
            "status": cert.status,
            "certificate_number": str(cert.certificate_number),
            "verification_code": cert.verification_code,
            "holder_name": cert.user.get_full_name() or cert.user.username,
            "template_name": cert.template.name,
            "template_code": cert.template.code,
            "issued_at": cert.issued_at.isoformat(),
            "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
            "company_name": cert.company.name,
            "score": str(cert.score) if cert.score is not None else None,
        }

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def revoke_certificate(
        certification: Certification,
        revoked_by,
        reason: str = "",
    ) -> Certification:
        """Revoke an active certificate."""
        if certification.status == "revoked":
            raise ValueError("Certificate is already revoked.")

        certification.status = "revoked"
        certification.revoked_at = timezone.now()
        certification.revoked_by = revoked_by
        certification.revocation_reason = reason
        certification.save(update_fields=[
            "status", "revoked_at", "revoked_by", "revocation_reason",
        ])

        LearningEvent.objects.create(
            company=certification.company,
            user=certification.user,
            event_type="certificate_revoked",
            metadata={
                "certification_id": certification.id,
                "certificate_number": str(certification.certificate_number),
                "reason": reason,
            },
        )
        return certification

    # ------------------------------------------------------------------
    # Expiry management
    # ------------------------------------------------------------------

    @staticmethod
    def mark_expired_certifications(company: Optional[Company] = None) -> int:
        """
        Mark as 'expired' any active certifications past their expires_at.
        Returns count of updated records.
        """
        qs = Certification.objects.filter(
            status="active",
            expires_at__lt=timezone.now(),
        )
        if company:
            qs = qs.filter(company=company)
        count = qs.update(status="expired")
        return count

    @staticmethod
    def get_expiring_certifications(
        company: Company,
        days: int = 30,
    ) -> List[Certification]:
        """Return active certifications expiring within `days` days."""
        threshold = timezone.now() + datetime.timedelta(days=days)
        return list(
            Certification.objects.filter(
                company=company,
                status="active",
                expires_at__isnull=False,
                expires_at__gte=timezone.now(),
                expires_at__lte=threshold,
            ).select_related("user", "template")
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @staticmethod
    def get_user_certifications(user, company: Company) -> dict:
        """Summary of a user's certifications within a company."""
        certs = Certification.objects.filter(company=company, user=user)
        total = certs.count()
        active = certs.filter(status="active").count()
        expired = certs.filter(status="expired").count()
        revoked = certs.filter(status="revoked").count()

        return {
            "user_id": user.id,
            "total": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
        }

    @staticmethod
    def get_company_certification_stats(company: Company) -> dict:
        """Aggregate certification stats for the whole company."""
        all_certs = Certification.objects.filter(company=company)
        total = all_certs.count()
        active = all_certs.filter(status="active").count()
        expired = all_certs.filter(status="expired").count()
        revoked = all_certs.filter(status="revoked").count()

        expiring_soon = len(CertificationService.get_expiring_certifications(company, 30))

        unique_holders = (
            all_certs.filter(status="active")
            .values("user")
            .distinct()
            .count()
        )

        return {
            "company_id": company.id,
            "company_name": company.name,
            "total_issued": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "expiring_soon": expiring_soon,
            "unique_holders": unique_holders,
        }

    # ------------------------------------------------------------------
    # PDF / QR helpers (stub — real implementation uses weasyprint/qrcode)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_verification_url(certification: Certification) -> str:
        """Return a verification URL embedding the verification_code."""
        return f"https://app.ankard.com/verify/{certification.verification_code}"

    @staticmethod
    def get_certificate_data(certification: Certification) -> dict:
        """
        Return all data needed to render the certificate (PDF/HTML).
        """
        return {
            "certificate_number": str(certification.certificate_number),
            "verification_code": certification.verification_code,
            "verification_url": CertificationService.generate_verification_url(
                certification
            ),
            "holder_name": (
                certification.user.get_full_name() or certification.user.username
            ),
            "template_name": certification.template.name,
            "template_type": certification.template.template_type,
            "header_text": certification.template.header_text,
            "body_text": certification.template.body_text,
            "footer_text": certification.template.footer_text,
            "company_name": certification.company.name,
            "issued_at": certification.issued_at.date().isoformat(),
            "expires_at": (
                certification.expires_at.date().isoformat()
                if certification.expires_at else None
            ),
            "score": str(certification.score) if certification.score is not None else None,
            "status": certification.status,
        }

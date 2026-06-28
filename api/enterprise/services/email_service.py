"""
Ankard Enterprise — Email Service

Sends transactional emails and logs every attempt.
All methods are fire-and-forget: exceptions are caught and logged,
never raised to the caller (so a broken email never breaks a business action).
"""

from __future__ import annotations

import logging
from typing import Optional

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)

FRONTEND_URL = getattr(settings, "FRONTEND_URL", "http://localhost:5173")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _send(
    *,
    recipient_email: str,
    recipient_user=None,
    company=None,
    email_type: str,
    subject: str,
    body: str,
    metadata: dict | None = None,
) -> None:
    from api.enterprise_email_models import EmailLog

    log = EmailLog(
        company=company,
        recipient_user=recipient_user,
        recipient_email=recipient_email,
        email_type=email_type,
        subject=subject,
        body_preview=body[:500],
        metadata=metadata or {},
    )
    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            fail_silently=False,
            html_message=_wrap_html(subject, body),
        )
        log.status = "sent"
    except Exception as exc:
        logger.warning("Email send failed to %s (%s): %s", recipient_email, email_type, exc)
        log.status = "failed"
        log.error_message = str(exc)
    finally:
        log.save()


def _wrap_html(subject: str, body: str) -> str:
    body_html = body.replace("\n", "<br>")
    return f"""
    <html><body style="font-family:sans-serif;max-width:600px;margin:auto;padding:24px">
      <h2 style="color:#1a1a2e">{subject}</h2>
      <p>{body_html}</p>
      <hr style="margin-top:32px;border:none;border-top:1px solid #eee">
      <p style="color:#888;font-size:12px">Ankard Enterprise · {FRONTEND_URL}</p>
    </body></html>
    """


# ---------------------------------------------------------------------------
# Assignment notification
# ---------------------------------------------------------------------------

def send_assignment_notification(assignment) -> None:
    """
    Notifica a un usuario (o a todos los miembros de un equipo) que
    se le asignó un proceso o learning path. El link va directo a la asignación.
    No requiere aceptación — es solo un recordatorio con acceso rápido.
    """
    subject_item = (
        assignment.learning_path.name
        if assignment.learning_path_id
        else assignment.learning_module.name
    )
    link = f"{FRONTEND_URL}/assignments/{assignment.id}"
    company = assignment.company

    def _notify(user):
        body = (
            f"Hola {user.get_full_name() or user.username},\n\n"
            f"Se te ha asignado: {subject_item}\n\n"
            f"Puedes acceder directamente aquí:\n{link}\n\n"
            f"Este es un recordatorio. Ya puedes ver la asignación en tu cuenta."
        )
        _send(
            recipient_email=user.email,
            recipient_user=user,
            company=company,
            email_type="assignment_notification",
            subject=f"Nueva asignación: {subject_item}",
            body=body,
            metadata={
                "assignment_id": assignment.id,
                "item_name": subject_item,
                "link": link,
            },
        )

    if assignment.user_id:
        _notify(assignment.user)
    elif assignment.team_id:
        for tm in assignment.team.memberships.select_related("user"):
            if tm.user.email:
                _notify(tm.user)


# ---------------------------------------------------------------------------
# Informational — added to company
# ---------------------------------------------------------------------------

def send_added_to_company(membership) -> None:
    """
    Informa al usuario que fue agregado a una empresa.
    Si la cuenta fue creada automáticamente, le dice que use
    'Olvidé mi contraseña' para activarla.
    """
    user = membership.user
    company = membership.company
    link = f"{FRONTEND_URL}/login"
    body = (
        f"Hola {user.get_full_name() or user.username},\n\n"
        f"Has sido agregado a {company.name} en Ankard como {membership.get_role_display()}.\n\n"
        f"Puedes acceder a tu cuenta aquí:\n{link}\n\n"
        f"Si es la primera vez que recibes este correo, usa 'Olvidé mi contraseña' "
        f"para establecer tu clave."
    )
    _send(
        recipient_email=user.email,
        recipient_user=user,
        company=company,
        email_type="added_to_company",
        subject=f"Te han agregado a {company.name} en Ankard",
        body=body,
        metadata={
            "company_id": company.id,
            "company_name": company.name,
            "role": membership.role,
        },
    )


# ---------------------------------------------------------------------------
# Informational — added to team
# ---------------------------------------------------------------------------

def send_added_to_team(team_membership) -> None:
    """Informa al usuario que fue agregado a un equipo."""
    user = team_membership.user
    team = team_membership.team
    company = team.company
    link = f"{FRONTEND_URL}/settings/empresa"
    body = (
        f"Hola {user.get_full_name() or user.username},\n\n"
        f"Has sido agregado al equipo {team.name}"
        + (f" (unidad: {team.business_unit.name})" if team.business_unit_id else "")
        + f" en {company.name}.\n\n"
        f"Tu rol en el equipo: {team_membership.get_role_display()}.\n\n"
        f"Ver tu perfil:\n{link}"
    )
    _send(
        recipient_email=user.email,
        recipient_user=user,
        company=company,
        email_type="added_to_team",
        subject=f"Te han agregado al equipo {team.name}",
        body=body,
        metadata={
            "team_id": team.id,
            "team_name": team.name,
            "role": team_membership.role,
        },
    )

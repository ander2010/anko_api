# api/emails/access_requests.py
from django.conf import settings
from django.core.mail import send_mail


def _build_link(path: str) -> str:
    base = getattr(settings, "FRONTEND_BASE_URL", "").rstrip("/")
    return f"{base}{path}" if base else path


def send_access_request_email_to_owner(*, owner_email: str, requester_email: str, title: str, approve_url: str, reject_url: str):
    subject = f"Access request: {title}"
    body = (
        f"{requester_email} requested access to: {title}\n\n"
        f"Approve: {approve_url}\n"
        f"Reject: {reject_url}\n"
    )
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [owner_email], fail_silently=False)


def send_access_decision_email_to_requester(*, requester_email: str, title: str, approved: bool):
    subject = f"Access {'approved' if approved else 'rejected'}: {title}"
    body = (
        f"Your request for '{title}' was {'approved' if approved else 'rejected'}.\n"
    )
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [requester_email], fail_silently=False)


def build_owner_action_links(*, token: str):
    # Frontend routes (you can change)
    approve = _build_link(f"/access/approve?token={token}")
    reject = _build_link(f"/access/reject?token={token}")
    return approve, reject

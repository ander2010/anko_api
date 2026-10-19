"""
C3 / C7: deployment checks shown by `python manage.py check --deploy`.
They only warn: nothing changes at runtime.
"""
import os

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

KNOWN_DEFAULT_TOKENS = {"andelef", ""}


@register(Tags.security, deploy=True)
def internal_tokens(app_configs, **kwargs):
    issues = []
    if os.getenv("INTERNAL_SERVICE_TOKEN", "") in KNOWN_DEFAULT_TOKENS:
        issues.append(Warning(
            "INTERNAL_SERVICE_TOKEN is not set: service callbacks use the default token published in the source code.",
            hint="Set the same long random INTERNAL_SERVICE_TOKEN in anko_api and anko_services (see the PR's rollout plan).",
            id="anko.W001",
        ))
    bootstrap = os.getenv("ADMIN_BOOTSTRAP_TOKEN", "")
    if bootstrap and len(bootstrap) < 32:
        issues.append(Warning(
            "ADMIN_BOOTSTRAP_TOKEN is shorter than 32 characters, so /auth/make-admin/ stays disabled.",
            id="anko.W002",
        ))
    if not os.getenv("DJANGO_SECRET_KEY", "").strip():
        issues.append(Error(
            "DJANGO_SECRET_KEY is not set: a random key is used per process (password-reset links break on restart).",
            hint="Set a long random DJANGO_SECRET_KEY in the environment.",
            id="anko.E001",
        ))
    if not os.getenv("EMAIL_HOST_PASSWORD", ""):
        issues.append(Error(
            "EMAIL_HOST_PASSWORD is not set: the API cannot send e-mail (verification, invitations, password reset).",
            id="anko.E002",
        ))
    if getattr(settings, "TOKEN_TTL_HOURS", 0) <= 0:
        issues.append(Warning(
            "API tokens never expire (TOKEN_TTL_HOURS=0).",
            hint="Enable it once clients handle 'Token expired.' (see the PR's rollout plan).",
            id="anko.W003",
        ))
    return issues

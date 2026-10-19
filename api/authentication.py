from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class TokenAuthWithRequestUser(TokenAuthentication):
    """
    Token auth that also writes the authenticated user to the underlying HttpRequest
    so middleware logging can see it after the response.
    """

    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        # C3: optional expiry (TOKEN_TTL_HOURS, off by default).
        ttl = getattr(settings, "TOKEN_TTL_HOURS", 0) or 0
        if ttl > 0 and token.created < timezone.now() - timedelta(hours=ttl):
            token.delete()
            raise AuthenticationFailed("Token expired.")
        return user, token

    def authenticate(self, request):
        result = super().authenticate(request)
        if result:
            user, auth = result
            try:
                # Expose to Django middleware/logs
                request._request.user = user
                request._request.auth = auth
            except Exception:
                pass
        return result

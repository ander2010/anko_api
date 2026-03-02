from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs

from asgiref.sync import sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.db import close_old_connections
from django.utils import timezone
from rest_framework.authtoken.models import Token

import uuid

from api.utils.logging import get_logger, set_request_id


class RequestLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = get_logger("api.request")

    def __call__(self, request):
        start = timezone.now()
        ip = self._get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "")
        request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())
        set_request_id(request_id)
        request.request_id = request_id
        try:
            response = self.get_response(request)
            duration_ms = int((timezone.now() - start).total_seconds() * 1000)
            user_id = getattr(getattr(request, "user", None), "id", None)
            self.logger.info(
                "Request completed method=%s path=%s status=%s duration_ms=%s user_id=%s ip=%s ua=%s",
                request.method,
                request.path,
                getattr(response, "status_code", None),
                duration_ms,
                user_id,
                ip,
                ua,
            )
            try:
                response["X-Request-ID"] = request_id
            except Exception:
                pass
            return response
        except Exception:
            user_id = getattr(getattr(request, "user", None), "id", None)
            self.logger.exception(
                "Unhandled exception path=%s method=%s user_id=%s ip=%s ua=%s",
                request.path,
                request.method,
                user_id,
                ip,
                ua,
            )
            raise
        finally:
            set_request_id(None)

    @staticmethod
    def _get_client_ip(request):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")


@sync_to_async
def _get_user_from_token(token_key: str):
    try:
        token = Token.objects.select_related("user").get(key=token_key)
        return token.user
    except Token.DoesNotExist:
        return AnonymousUser()


class TokenAuthMiddleware:
    """
    WebSocket auth using DRF TokenAuthentication.
    Accepts token via:
      - Query string: ?token=...
      - Header: Authorization: Token <key>
    """

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        close_old_connections()
        token_key = _extract_token(scope)
        scope["user"] = await _get_user_from_token(token_key) if token_key else AnonymousUser()
        return await self.inner(scope, receive, send)


def _extract_token(scope) -> Optional[str]:
    query_string = scope.get("query_string", b"").decode()
    params = parse_qs(query_string)
    if "token" in params and params["token"]:
        return params["token"][0]

    headers = dict(scope.get("headers") or [])
    raw = headers.get(b"authorization", b"").decode()
    if raw.lower().startswith("token "):
        return raw.split(" ", 1)[1].strip()
    return None


def TokenAuthMiddlewareStack(inner):
    return TokenAuthMiddleware(inner)

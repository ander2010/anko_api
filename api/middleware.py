from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs

from asgiref.sync import sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.db import close_old_connections
from rest_framework.authtoken.models import Token


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

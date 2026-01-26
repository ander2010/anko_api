import os
import json
import base64
import hashlib
from typing import Optional

from django.conf import settings
from rest_framework.renderers import JSONRenderer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _get_token_string_from_request(request) -> Optional[str]:
    """
    Soporta:
      - TokenAuthentication: request.auth es Token -> .key
      - Authorization header: "Token <key>" o "Bearer <jwt>" (si quieres)
    """
    if not request:
        return None

    # DRF TokenAuthentication suele poner request.auth = Token instance
    auth_obj = getattr(request, "auth", None)
    if auth_obj is not None:
        key = getattr(auth_obj, "key", None)
        if key:
            return str(key)

    # Header fallback
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header:
        return None

    parts = header.split(" ", 1)
    if len(parts) != 2:
        return None

    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() in ("token", "bearer") and token:
        return token

    return None


def _derive_key_from_token(token: str) -> bytes:
    """
    AES-256 key = SHA256(token)
    """
    token = (token or "").strip()
    if not token:
        raise RuntimeError("Missing token for encryption key derivation")
    return hashlib.sha256(token.encode("utf-8")).digest()  # 32 bytes


def encrypt_payload(data_obj, *, token: str) -> dict:
    """
    data_obj: cualquier dict/list serializable.
    Retorna wrapper con nonce+ciphertext (base64url).
    """
    key = _derive_key_from_token(token)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recomendado para AES-GCM

    plaintext = json.dumps(
        data_obj,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        
        "flor": _b64url_encode(nonce),
        "casa": _b64url_encode(ciphertext),

    }


class EncryptedJSONRenderer(JSONRenderer):
    """
    Cifra el JSON si view.encrypt_response == True
    y si hay token disponible (Authorization header / request.auth).
    """
    def render(self, data, accepted_media_type=None, renderer_context=None):
        ctx = renderer_context or {}
        request = ctx.get("request")
        view = ctx.get("view")

        if not request or not view:
            return super().render(data, accepted_media_type, renderer_context)

        if not getattr(view, "encrypt_response", False):
            return super().render(data, accepted_media_type, renderer_context)

        token = _get_token_string_from_request(request)
        if not token:
            # Si quieres FORZAR cifrado incluso sin token, aquí debes decidir otra estrategia.
            # Para AllowAny endpoints, lo normal es NO cifrar.
            return super().render(data, accepted_media_type, renderer_context)

        wrapped = encrypt_payload({"data": data}, token=token)
        return super().render(wrapped, accepted_media_type, renderer_context)

import os
import json
import base64
import hashlib
import logging
from typing import Optional

from django.conf import settings
from rest_framework.renderers import JSONRenderer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from api.renderers import translate_data_if_needed

logger = logging.getLogger("api.renders")


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
        
        "_n": _b64url_encode(nonce),
        "_t": _b64url_encode(ciphertext),

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

        view_name = type(view).__name__ if view else "None"
        action = getattr(view, "action", "?") if view else "?"
        logger.info("[EncryptedJSONRenderer] render() — view=%s action=%s", view_name, action)

        if not request or not view:
            logger.warning("[EncryptedJSONRenderer] request o view es None — sin cifrado")
            return super().render(data, accepted_media_type, renderer_context)

        encrypt = getattr(view, "encrypt_response", False)
        logger.info("[EncryptedJSONRenderer] encrypt_response=%s", encrypt)

        if not encrypt:
            logger.info("[EncryptedJSONRenderer] encrypt_response=False — pasa directo a JSONRenderer (sin traducción aquí)")
            return super().render(data, accepted_media_type, renderer_context)

        token = _get_token_string_from_request(request)
        logger.info("[EncryptedJSONRenderer] token presente: %s", bool(token))

        if not token:
            logger.warning("[EncryptedJSONRenderer] sin token — sin cifrado")
            return super().render(data, accepted_media_type, renderer_context)

        translate_data_if_needed(data, request, caller="EncryptedJSONRenderer")
        wrapped = encrypt_payload({"data": data}, token=token)
        logger.info("[EncryptedJSONRenderer] payload cifrado correctamente")
        return super().render(wrapped, accepted_media_type, renderer_context)

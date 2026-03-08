from __future__ import annotations

import os
from typing import Any, Optional, Union

import requests

from api.services.audit import log_audit_event

BASE_URL = os.getenv("TRANSLATE_BASE_URL", os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080"))
DEFAULT_SOURCE = os.getenv("TRANSLATE_SOURCE_LANGUAGE", "english")
DEFAULT_TARGET = os.getenv("TRANSLATE_TARGET_LANGUAGE", "spanish")


def post_translate(
    data: Union[str, list, dict],
    *,
    source_language: str = DEFAULT_SOURCE,
    target_language: str = DEFAULT_TARGET,
    timeout: int = 180,
    audit_user_id: Optional[int] = None,
    request_id: str = "",
    audit_operation: str = "translate.request",
    audit_path: str = "/translate",
) -> Any:
    """
    Traduce `data` llamando al servicio /translate y retorna el resultado listo
    para enviar al frontend.

    data puede ser:
      - str   → traduce la cadena directamente
      - list  → traduce los elementos que sean string; el resto se deja igual
      - dict  → traduce los valores string de primer nivel; el resto se deja igual

    Retorna el campo `data` ya traducido del response, o lanza RuntimeError
    si el servicio responde con un error.

    Uso desde una view:
        from api.services.translate import post_translate

        translated = post_translate("Hello world")
        return Response({"text": translated})
    """
    url = BASE_URL.rstrip("/") + "/translate"
    payload = {
        "source_language": source_language,
        "target_language": target_language,
        "data": data,
    }

    # El servicio solo acepta list o dict, nunca str directo.
    # Si es str, lo envolvemos en lista y extraemos el primer elemento al retornar.
    wrap_string = isinstance(data, str)
    if wrap_string:
        payload["data"] = [data]

    try:
        response = requests.post(url, json=payload, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        log_audit_event(
            operation=audit_operation,
            success=False,
            user_id=audit_user_id,
            resource_type="external_service",
            resource_id="translate",
            status_code=None,
            error_message=f"translate service unreachable: {exc}",
            request_id=request_id,
            method="POST",
            path=audit_path,
        )
        raise RuntimeError(f"translate service unreachable: {exc}") from exc

    if not response.ok:
        log_audit_event(
            operation=audit_operation,
            success=False,
            user_id=audit_user_id,
            resource_type="external_service",
            resource_id="translate",
            status_code=response.status_code,
            error_message=response.text[:1000],
            request_id=request_id,
            method="POST",
            path=audit_path,
        )
        raise RuntimeError(
            f"translate service error {response.status_code}: {response.text}"
        )

    body = response.json()
    result = body.get("data", body)

    log_audit_event(
        operation=audit_operation,
        success=True,
        user_id=audit_user_id,
        resource_type="external_service",
        resource_id="translate",
        status_code=response.status_code,
        request_id=request_id,
        method="POST",
        path=audit_path,
    )

    if wrap_string and isinstance(result, list) and result:
        return result[0]
    return result

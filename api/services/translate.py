from __future__ import annotations

import os
import logging
from typing import Any, Optional, Union

import requests

from api.services.audit import log_audit_event

BASE_URL = os.getenv("TRANSLATE_BASE_URL", os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080"))
DEFAULT_SOURCE = os.getenv("TRANSLATE_SOURCE_LANGUAGE", "english")
DEFAULT_TARGET = os.getenv("TRANSLATE_TARGET_LANGUAGE", "spanish")
logger = logging.getLogger("api.services.translate")


def _collect_value_string_refs(data: Union[list, dict], refs: list[tuple[Any, Any]], strings: list[str]) -> None:
    """Collect only string VALUES (never dict keys) from nested list/dict payloads."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                refs.append((data, key))
                strings.append(value)
            elif isinstance(value, (dict, list)):
                _collect_value_string_refs(value, refs, strings)
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            if isinstance(value, str):
                refs.append((data, idx))
                strings.append(value)
            elif isinstance(value, (dict, list)):
                _collect_value_string_refs(value, refs, strings)


def _apply_value_translations(refs: list[tuple[Any, Any]], translated: list[Any]) -> None:
    for i, (container, key) in enumerate(refs):
        if i >= len(translated):
            break
        container[key] = translated[i]


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
    list_of_strings_input = isinstance(data, list) and all(isinstance(x, str) for x in data)

    if wrap_string:
        payload["data"] = [data]
    elif list_of_strings_input:
        # Keep order and avoid mutating caller list; renderer relies on original values.
        payload["data"] = list(data)
    elif isinstance(data, (list, dict)):
        # Hard guard: never send dict keys for translation.
        # We extract only string values and send them as a flat list.
        refs: list[tuple[Any, Any]] = []
        strings: list[str] = []
        _collect_value_string_refs(data, refs, strings)
        payload["data"] = strings

    send_data = payload.get("data")
    if isinstance(send_data, list):
        send_count = len(send_data)
        preview = [str(x)[:120] for x in send_data[:3]]
    elif isinstance(send_data, dict):
        send_count = len(send_data)
        preview = {str(k): str(v)[:120] for k, v in list(send_data.items())[:3]}
    else:
        send_count = 1 if send_data is not None else 0
        preview = str(send_data)[:120] if send_data is not None else None

    logger.info(
        "[translate.request] request_id=%s url=%s source=%s target=%s data_type=%s items=%s preview=%s",
        request_id,
        url,
        source_language,
        target_language,
        type(send_data).__name__,
        send_count,
        preview,
    )

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

    if list_of_strings_input and isinstance(result, list):
        return result

    if isinstance(data, (list, dict)):
        refs: list[tuple[Any, Any]] = []
        strings: list[str] = []
        _collect_value_string_refs(data, refs, strings)
        if not strings or not isinstance(result, list):
            return data
        _apply_value_translations(refs, result)
        return data

    return result

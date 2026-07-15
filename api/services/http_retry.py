from __future__ import annotations

import json
import os
import random
import time
from typing import Any

import requests


DEFAULT_RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _payload_size_bytes(payload: Any) -> int | None:
    try:
        return len(json.dumps(payload).encode("utf-8"))
    except Exception:
        return None


def _response_size_bytes(response: requests.Response) -> int | None:
    content_length = response.headers.get("Content-Length")
    try:
        return int(content_length) if content_length is not None else len(response.content or b"")
    except Exception:
        return None


def _sleep_seconds_for_attempt(attempt: int) -> float:
    initial = max(0.0, _env_float("HOPE_HTTP_BACKOFF_INITIAL_SECONDS", 1.0))
    multiplier = max(1.0, _env_float("HOPE_HTTP_BACKOFF_MULTIPLIER", 2.0))
    max_sleep = max(initial, _env_float("HOPE_HTTP_BACKOFF_MAX_SECONDS", 8.0))
    jitter = max(0.0, _env_float("HOPE_HTTP_BACKOFF_JITTER_SECONDS", 0.25))
    base = min(initial * (multiplier ** max(0, attempt - 1)), max_sleep)
    return base + (random.uniform(0.0, jitter) if jitter > 0 else 0.0)


def _should_retry_status(status_code: int) -> bool:
    return status_code in DEFAULT_RETRYABLE_STATUS_CODES


def post_with_retry(
    url: str,
    *,
    payload: dict[str, Any],
    timeout: int,
    label: str,
    logger,
    headers: dict[str, str] | None = None,
    max_attempts: int | None = None,
) -> requests.Response:
    attempts = max(1, max_attempts or _env_int("HOPE_HTTP_MAX_ATTEMPTS", 3))
    payload_keys = list(payload.keys()) if isinstance(payload, dict) else [type(payload).__name__]
    payload_size = _payload_size_bytes(payload)
    last_error: requests.RequestException | None = None

    for attempt in range(1, attempts + 1):
        start = time.perf_counter()
        try:
            response = requests.post(url, json=payload, timeout=timeout, headers=headers)
            duration_ms = int((time.perf_counter() - start) * 1000)
            response_size = _response_size_bytes(response)
            logger.info(
                "External HTTP %s url=%s status=%s ok=%s duration_ms=%s payload_keys=%s payload_bytes=%s response_bytes=%s attempt=%s/%s",
                label,
                url,
                response.status_code,
                response.ok,
                duration_ms,
                payload_keys,
                payload_size,
                response_size,
                attempt,
                attempts,
            )
            if response.ok:
                return response
            if _should_retry_status(response.status_code) and attempt < attempts:
                sleep_seconds = _sleep_seconds_for_attempt(attempt)
                logger.warning(
                    "External HTTP %s retrying url=%s status=%s attempt=%s/%s sleep_seconds=%.2f",
                    label,
                    url,
                    response.status_code,
                    attempt,
                    attempts,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
                continue
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            last_error = exc
            if attempt < attempts:
                sleep_seconds = _sleep_seconds_for_attempt(attempt)
                logger.warning(
                    "External HTTP %s retrying after error url=%s duration_ms=%s payload_keys=%s payload_bytes=%s error=%s attempt=%s/%s sleep_seconds=%.2f",
                    label,
                    url,
                    duration_ms,
                    payload_keys,
                    payload_size,
                    exc,
                    attempt,
                    attempts,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
                continue
            logger.error(
                "External HTTP %s failed url=%s duration_ms=%s payload_keys=%s payload_bytes=%s error=%s attempt=%s/%s",
                label,
                url,
                duration_ms,
                payload_keys,
                payload_size,
                exc,
                attempt,
                attempts,
            )
            raise

    if last_error is not None:
        raise last_error
    raise requests.RequestException(f"External HTTP {label} failed without a response")

from __future__ import annotations

from typing import Any, Optional

from api.models import AuditLog
from api.utils.logging import get_logger

logger = get_logger("api.audit")


def log_audit_event(
    *,
    operation: str,
    success: bool,
    user_id: Optional[int] = None,
    resource_type: str = "",
    resource_id: str = "",
    status_code: Optional[int] = None,
    error_message: str = "",
    request_id: str = "",
    method: str = "",
    path: str = "",
    ip_address: Optional[str] = None,
    user_agent: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Best-effort audit logging that never breaks the main request flow.
    """
    try:
        AuditLog.objects.create(
            user_id=user_id,
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            status_code=status_code,
            error_message=(error_message or "")[:2000],
            request_id=(request_id or "")[:64],
            method=(method or "")[:16],
            path=(path or "")[:255],
            ip_address=ip_address,
            user_agent=(user_agent or "")[:255],
            metadata=metadata or {},
        )
    except Exception:
        logger.exception("Failed to write audit log for operation=%s", operation)

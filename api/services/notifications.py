from __future__ import annotations

from typing import Any, Dict, Optional

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone

from api.models import Notification, UserNotification, User
from api.utils.logging import get_logger

logger = get_logger(__name__)


def send_user_notification(
    *,
    user: User,
    key: str,
    title: str,
    body: str = "",
    level: str = "info",
    data: Optional[Dict[str, Any]] = None,
    channel: str = "socket",
) -> UserNotification:
    """
    Create Notification + UserNotification and push via WebSocket.
    """
    data = data or {}
    logger.info(
        "Send notification user_id=%s key=%s level=%s channel=%s",
        user.id,
        key,
        level,
        channel,
    )

    notification = Notification.objects.create(
        key=key,
        title=title,
        body=body,
        level=level,
        data=data,
    )

    user_notification = UserNotification.objects.create(
        user=user,
        notification=notification,
        channel=channel,
        status="sent",
        title=title,
        body=body,
        payload=data,
        sent_at=timezone.now(),
    )

    channel_layer = get_channel_layer()
    if channel_layer:
        async_to_sync(channel_layer.group_send)(
            f"user_{user.id}",
            {
                "type": "notify",
                "payload": {
                    "id": user_notification.id,
                    "key": key,
                    "title": title,
                    "body": body,
                    "level": level,
                    "data": data,
                    "created_at": user_notification.created_at.isoformat(),
                },
            },
        )
    else:
        logger.warning("Notification channel layer missing user_id=%s key=%s", user.id, key)

    return user_notification

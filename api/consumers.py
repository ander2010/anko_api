from __future__ import annotations

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.utils import timezone

from api.models import UserNotification
from api.utils.logging import get_logger

logger = get_logger(__name__)


class NotificationConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or user.is_anonymous:
            logger.info("notifications ws denied anonymous")
            await self.close(code=4401)
            return
        self.user = user
        self.group_name = f"user_{user.id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info("notifications ws connected user_id=%s", user.id)

    async def disconnect(self, code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        if hasattr(self, "user"):
            logger.info("notifications ws disconnected user_id=%s code=%s", self.user.id, code)

    async def receive_json(self, content, **kwargs):
        action = content.get("action")
        notification_id = content.get("id")
        if action == "dismiss" and notification_id:
            await self._dismiss(notification_id)
            await self.send_json({"ok": True, "action": "dismiss", "id": notification_id})
            logger.info("notification dismissed user_id=%s id=%s", self.user.id, notification_id)
            return
        if action == "read" and notification_id:
            await self._read(notification_id)
            await self.send_json({"ok": True, "action": "read", "id": notification_id})
            logger.info("notification read user_id=%s id=%s", self.user.id, notification_id)
            return
        await self.send_json({"ok": False, "error": "unknown_action"})
        logger.info("notification unknown_action user_id=%s payload=%s", self.user.id, content)

    async def notify(self, event):
        payload = event.get("payload", {})
        await self.send_json(payload)

    @database_sync_to_async
    def _dismiss(self, notification_id: int):
        UserNotification.objects.filter(
            id=notification_id, user_id=self.user.id, dismissed_at__isnull=True
        ).update(dismissed_at=timezone.now())

    @database_sync_to_async
    def _read(self, notification_id: int):
        UserNotification.objects.filter(
            id=notification_id, user_id=self.user.id, read_at__isnull=True
        ).update(read_at=timezone.now())

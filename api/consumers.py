from __future__ import annotations

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.utils import timezone

from api.models import UserNotification


class NotificationConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or user.is_anonymous:
            await self.close(code=4401)
            return
        self.user = user
        self.group_name = f"user_{user.id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        action = content.get("action")
        notification_id = content.get("id")
        if action == "dismiss" and notification_id:
            await self._dismiss(notification_id)
            await self.send_json({"ok": True, "action": "dismiss", "id": notification_id})
            return
        if action == "read" and notification_id:
            await self._read(notification_id)
            await self.send_json({"ok": True, "action": "read", "id": notification_id})
            return
        await self.send_json({"ok": False, "error": "unknown_action"})

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

"""
Ankard Enterprise — Email Log

Tracks every outbound email sent by the platform.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class EmailLog(models.Model):
    EMAIL_TYPE_CHOICES = [
        # Assignment emails — carry a direct link to the assignment
        ("assignment_notification", "Assignment Notification"),
        ("compliance_assignment_notification", "Compliance Assignment Notification"),
        # Informational — user added somewhere
        ("added_to_company", "Added to Company"),
        ("added_to_team", "Added to Team"),
        ("added_to_business_unit", "Added to Business Unit"),
        # Reminders — defined later
        ("reminder", "Reminder"),
    ]
    STATUS_CHOICES = [
        ("sent", "Sent"),
        ("failed", "Failed"),
    ]

    company = models.ForeignKey(
        "api.Company",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="email_logs",
    )
    recipient_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="received_email_logs",
    )
    recipient_email = models.EmailField()
    email_type = models.CharField(max_length=40, choices=EMAIL_TYPE_CHOICES)
    subject = models.CharField(max_length=255)
    body_preview = models.TextField(blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="sent")
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "enterprise_email_logs"
        ordering = ["-sent_at"]
        indexes = [
            models.Index(fields=["company", "email_type"]),
            models.Index(fields=["recipient_email"]),
            models.Index(fields=["sent_at"]),
        ]

    def __str__(self):
        return f"[{self.email_type}] → {self.recipient_email} ({self.status})"

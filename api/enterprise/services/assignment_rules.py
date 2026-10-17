"""
Shared rules for creating learning-path / module / compliance assignments.

- due_date is a calendar date (YYYY-MM-DD). It is validated here and never
  passed to models as a raw string (that used to make the response serializer
  crash *after* the row was saved -> 500 + duplicates on retry).
- Only one *active* assignment may exist per (user, content); see the
  UniqueConstraints on the models and AssignmentConflict (HTTP 409).
- Non-critical side effects (emails) run after commit and never break the response.
"""
import datetime
import logging

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

# Statuses that count as "still assigned" (a new assignment would be a duplicate).
LEARNING_ACTIVE_STATUSES = ("pending", "in_progress", "overdue")
COMPLIANCE_ACTIVE_STATUSES = ("pending", "in_progress")
SUPERSEDED_STATUS = "superseded"


class AssignmentConflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "assignment_exists"
    default_detail = "This content is already assigned to this user."


class AssignToUserRequestSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    due_date = serializers.DateField(required=False, allow_null=True, input_formats=["%Y-%m-%d"])

    def validate_due_date(self, value):
        return validate_due_date(value)


class AssignToTeamRequestSerializer(serializers.Serializer):
    team_id = serializers.IntegerField()
    due_date = serializers.DateField(required=False, allow_null=True, input_formats=["%Y-%m-%d"])

    def validate_due_date(self, value):
        return validate_due_date(value)


def validate_due_date(value):
    if value and value < timezone.localdate():
        raise serializers.ValidationError("Due date cannot be in the past.")
    return value


def parse_due_date(raw):
    """Parse an optional YYYY-MM-DD string (views that don't use the request serializers)."""
    if raw in (None, ""):
        return None
    field = serializers.DateField(input_formats=["%Y-%m-%d"])
    try:
        value = field.to_internal_value(raw)
    except serializers.ValidationError as exc:
        raise serializers.ValidationError({"due_date": exc.detail})
    try:
        return validate_due_date(value)
    except serializers.ValidationError as exc:
        raise serializers.ValidationError({"due_date": exc.detail})


def due_date_to_datetime(value):
    """Store a calendar due date on DateTimeField models as the end of that day (UTC, aware)."""
    if value is None:
        return None
    return datetime.datetime.combine(value, datetime.time(23, 59, 59), tzinfo=datetime.timezone.utc)


def run_after_commit(label, func, *args, **kwargs):
    """Schedule a non-critical side effect after commit; failures are logged, never raised."""
    def _run():
        try:
            func(*args, **kwargs)
        except Exception:
            logger.exception("Post-commit side effect failed: %s", label)

    transaction.on_commit(_run)

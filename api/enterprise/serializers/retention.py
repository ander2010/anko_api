"""Phase 3 Retention Engine Serializers."""

from __future__ import annotations

from rest_framework import serializers

from api.enterprise_retention_models import (
    KnowledgeAssessment,
    KnowledgeGap,
    RetentionSnapshot,
    ReviewSchedule,
)


class KnowledgeAssessmentSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    topic_name = serializers.CharField(source="topic.name", read_only=True)
    battery_name = serializers.CharField(source="battery.name", read_only=True)

    class Meta:
        model = KnowledgeAssessment
        fields = [
            "id",
            "company",
            "user",
            "user_username",
            "assessment_type",
            "topic",
            "topic_name",
            "battery",
            "battery_name",
            "battery_attempt",
            "learning_path",
            "learning_module",
            "score",
            "max_score",
            "items_total",
            "items_correct",
            "retention_score",
            "confidence_score",
            "metadata",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "user_username",
            "topic_name",
            "battery_name",
            "retention_score",
            "confidence_score",
            "created_at",
        ]


class RetentionSnapshotSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    topic_name = serializers.CharField(source="topic.name", read_only=True)
    learning_path_name = serializers.CharField(source="learning_path.name", read_only=True)

    class Meta:
        model = RetentionSnapshot
        fields = [
            "id",
            "company",
            "user",
            "user_username",
            "topic",
            "topic_name",
            "learning_path",
            "learning_path_name",
            "snapshot_date",
            "retention_score",
            "risk_score",
            "confidence_score",
            "assessment_count",
            "last_assessment_date",
            "next_review_date",
            "metadata",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class KnowledgeGapSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    team_name = serializers.CharField(source="team.name", read_only=True)
    topic_name = serializers.CharField(source="topic.name", read_only=True)
    learning_path_name = serializers.CharField(source="learning_path.name", read_only=True)
    acknowledged_by_username = serializers.CharField(
        source="acknowledged_by.username", read_only=True
    )
    resolved_by_username = serializers.CharField(
        source="resolved_by.username", read_only=True
    )

    class Meta:
        model = KnowledgeGap
        fields = [
            "id",
            "company",
            "user",
            "user_username",
            "team",
            "team_name",
            "topic",
            "topic_name",
            "learning_path",
            "learning_path_name",
            "severity",
            "status",
            "retention_score_at_detection",
            "detected_at",
            "acknowledged_at",
            "acknowledged_by",
            "acknowledged_by_username",
            "resolved_at",
            "resolved_by",
            "resolved_by_username",
            "notes",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "retention_score_at_detection",
            "detected_at",
            "acknowledged_at",
            "acknowledged_by",
            "acknowledged_by_username",
            "resolved_at",
            "resolved_by",
            "resolved_by_username",
            "created_at",
            "updated_at",
        ]


class ReviewScheduleSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    topic_name = serializers.CharField(source="topic.name", read_only=True)
    is_overdue = serializers.SerializerMethodField()

    class Meta:
        model = ReviewSchedule
        fields = [
            "id",
            "company",
            "user",
            "user_username",
            "review_type",
            "status",
            "priority",
            "topic",
            "topic_name",
            "learning_module",
            "learning_path",
            "flashcard",
            "battery",
            "due_date",
            "completed_at",
            "score",
            "ease_factor",
            "interval_days",
            "repetition_count",
            "is_overdue",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "user",
            "user_username",
            "topic_name",
            "status",
            "completed_at",
            "ease_factor",
            "interval_days",
            "repetition_count",
            "is_overdue",
            "created_at",
            "updated_at",
        ]

    def get_is_overdue(self, obj):
        return obj.is_overdue()


class RetentionSummarySerializer(serializers.Serializer):
    """Used by /my-retention/, /team-retention/, etc."""
    user_id = serializers.IntegerField(required=False)
    user_username = serializers.CharField(required=False)
    team_id = serializers.IntegerField(required=False)
    team_name = serializers.CharField(required=False)
    company_id = serializers.IntegerField(required=False)
    company_name = serializers.CharField(required=False)
    employee_count = serializers.IntegerField(required=False)
    member_count = serializers.IntegerField(required=False)
    retention_score = serializers.DecimalField(
        max_digits=6, decimal_places=2, required=False
    )
    avg_retention = serializers.DecimalField(
        max_digits=6, decimal_places=2, required=False
    )
    risk_score = serializers.DecimalField(
        max_digits=6, decimal_places=2, required=False
    )
    avg_risk = serializers.DecimalField(
        max_digits=6, decimal_places=2, required=False
    )
    confidence_score = serializers.DecimalField(
        max_digits=6, decimal_places=2, required=False
    )
    at_risk_count = serializers.IntegerField(required=False)
    open_gaps = serializers.IntegerField(required=False)

"""Phase 6 Analytics Serializers."""

from __future__ import annotations

from rest_framework import serializers


# ---------------------------------------------------------------------------
# Shared sub-serializers
# ---------------------------------------------------------------------------

class LearningStatsSerializer(serializers.Serializer):
    total_assigned = serializers.IntegerField(required=False)
    total_assignments = serializers.IntegerField(required=False)
    completed = serializers.IntegerField()
    in_progress = serializers.IntegerField(required=False)
    pending = serializers.IntegerField(required=False)
    overdue = serializers.IntegerField(required=False)
    completion_rate = serializers.DecimalField(max_digits=6, decimal_places=2)


class RetentionStatsSerializer(serializers.Serializer):
    score = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    avg_score = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    risk_score = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    avg_risk = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    open_gaps = serializers.IntegerField(required=False)
    critical_gaps = serializers.IntegerField(required=False)
    overdue_reviews = serializers.IntegerField(required=False)


class ComplianceStatsSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    compliant = serializers.IntegerField()
    non_compliant = serializers.IntegerField()
    pending = serializers.IntegerField(required=False)
    rate = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    avg_rate = serializers.DecimalField(max_digits=6, decimal_places=2, required=False)
    expiring_soon = serializers.IntegerField(required=False)


class CertificationStatsSerializer(serializers.Serializer):
    active = serializers.IntegerField()
    total = serializers.IntegerField(required=False)
    expiring_soon = serializers.IntegerField(required=False)
    active_total = serializers.IntegerField(required=False)


# ---------------------------------------------------------------------------
# Employee Dashboard
# ---------------------------------------------------------------------------

class ReviewStatsSerializer(serializers.Serializer):
    overdue = serializers.IntegerField()
    due_this_week = serializers.IntegerField(required=False)


class RecentActivitySerializer(serializers.Serializer):
    event_type = serializers.CharField()
    created_at = serializers.DateTimeField()


class EmployeeDashboardSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    learning = LearningStatsSerializer()
    retention = RetentionStatsSerializer()
    reviews = ReviewStatsSerializer()
    compliance = ComplianceStatsSerializer()
    certifications = CertificationStatsSerializer()
    recent_activity = RecentActivitySerializer(many=True)


# ---------------------------------------------------------------------------
# Manager Dashboard
# ---------------------------------------------------------------------------

class AtRiskMemberSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    retention_score = serializers.CharField()
    risk_score = serializers.CharField()


class ManagerDashboardSerializer(serializers.Serializer):
    context = serializers.CharField()
    context_id = serializers.IntegerField()
    total_members = serializers.IntegerField()
    learning = LearningStatsSerializer()
    retention = RetentionStatsSerializer()
    compliance = serializers.DictField()
    certifications = serializers.DictField()
    at_risk_members = AtRiskMemberSerializer(many=True)


# ---------------------------------------------------------------------------
# Trainer Dashboard
# ---------------------------------------------------------------------------

class PathAssessmentSerializer(serializers.Serializer):
    learning_path__id = serializers.IntegerField(source="learning_path_id", required=False)
    learning_path__name = serializers.CharField(required=False)
    avg_score = serializers.DecimalField(max_digits=6, decimal_places=2, allow_null=True)
    count = serializers.IntegerField()


class LearnerAttentionSerializer(serializers.Serializer):
    user__id = serializers.IntegerField(required=False)
    user__username = serializers.CharField(required=False)
    overdue_count = serializers.IntegerField()


class TrainerDashboardSerializer(serializers.Serializer):
    learning_paths = serializers.DictField()
    assignments = serializers.DictField()
    modules = serializers.DictField()
    training_programs = serializers.DictField()
    top_paths_by_assessment = serializers.ListField(child=serializers.DictField())
    learners_needing_attention = serializers.ListField(child=serializers.DictField())


# ---------------------------------------------------------------------------
# Auditor Dashboard
# ---------------------------------------------------------------------------

class ProgramBreakdownSerializer(serializers.Serializer):
    program_code = serializers.CharField()
    program_name = serializers.CharField()
    total = serializers.IntegerField()
    compliant = serializers.IntegerField()
    rate = serializers.DecimalField(max_digits=6, decimal_places=2)


class AuditEventSerializer(serializers.Serializer):
    event_type = serializers.CharField()
    user__username = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()


class AuditorDashboardSerializer(serializers.Serializer):
    compliance = serializers.DictField()
    program_breakdown = ProgramBreakdownSerializer(many=True)
    certifications = serializers.DictField()
    knowledge_gaps = serializers.DictField()
    recent_audit_events = AuditEventSerializer(many=True)


# ---------------------------------------------------------------------------
# Executive Dashboard
# ---------------------------------------------------------------------------

class TeamBreakdownSerializer(serializers.Serializer):
    team_id = serializers.IntegerField()
    team_name = serializers.CharField()
    member_count = serializers.IntegerField()
    avg_compliance_rate = serializers.DecimalField(max_digits=6, decimal_places=2)


class ExecutiveDashboardSerializer(serializers.Serializer):
    company_id = serializers.IntegerField()
    company_name = serializers.CharField()
    health_score = serializers.DecimalField(max_digits=6, decimal_places=2)
    headcount = serializers.IntegerField()
    learning = serializers.DictField()
    retention = serializers.DictField()
    compliance = serializers.DictField()
    certifications = serializers.DictField()
    team_breakdown = TeamBreakdownSerializer(many=True)
    retention_trend = serializers.ListField(child=serializers.DictField())


# ---------------------------------------------------------------------------
# Trend serializers
# ---------------------------------------------------------------------------

class RetentionTrendSerializer(serializers.Serializer):
    date = serializers.CharField()
    avg_retention = serializers.DecimalField(max_digits=6, decimal_places=2)
    avg_risk = serializers.DecimalField(max_digits=6, decimal_places=2)
    snapshot_count = serializers.IntegerField()


class ComplianceTrendSerializer(serializers.Serializer):
    month = serializers.CharField(allow_null=True)
    total = serializers.IntegerField()
    compliant = serializers.IntegerField()
    rate = serializers.DecimalField(max_digits=6, decimal_places=2)


class LearningTrendSerializer(serializers.Serializer):
    week = serializers.CharField(allow_null=True)
    completions = serializers.IntegerField()


class CompanyHealthSerializer(serializers.Serializer):
    company_id = serializers.IntegerField()
    company_name = serializers.CharField()
    health_score = serializers.DecimalField(max_digits=6, decimal_places=2)

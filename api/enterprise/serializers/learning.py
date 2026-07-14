"""
Phase 2 Learning Engine Serializers

Serializers only validate and transform data.
No business logic here — that lives in learning_service.py.
"""

from __future__ import annotations

from rest_framework import serializers

from api.enterprise_learning_models import (
    LearningModule,
    LearningModuleItem,
    LearningModuleProgress,
    LearningPath,
    LearningPathAssignment,
    TrainingProgram,
    TrainingProgramVersion,
)


# ---------------------------------------------------------------------------
# LearningModuleItem
# ---------------------------------------------------------------------------

class LearningModuleItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = LearningModuleItem
        fields = [
            "id",
            "module",
            "item_type",
            "order",
            "is_required",
            "topic",
            "battery",
            "deck",
            "document",
            "metadata",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]

    def validate(self, attrs):
        set_fks = [
            attrs.get("topic"),
            attrs.get("battery"),
            attrs.get("deck"),
            attrs.get("document"),
        ]
        active = [v for v in set_fks if v is not None]
        if len(active) != 1:
            raise serializers.ValidationError(
                "Exactly one of topic, battery, deck, or document must be set."
            )
        return attrs


# ---------------------------------------------------------------------------
# LearningModule
# ---------------------------------------------------------------------------

class LearningModuleSerializer(serializers.ModelSerializer):
    items = LearningModuleItemSerializer(many=True, read_only=True)
    item_count = serializers.SerializerMethodField()

    class Meta:
        model = LearningModule
        fields = [
            "id",
            "company",
            "learning_path",
            "knowledge_source",
            "name",
            "description",
            "order",
            "is_required",
            "estimated_duration_minutes",
            "process_type",
            "difficulty",
            "minimum_passing_score",
            "metadata",
            "item_count",
            "items",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "item_count"]
        extra_kwargs = {
            "company": {"required": False},
            "learning_path": {"required": False, "allow_null": True},
            "knowledge_source": {"required": False, "allow_null": True},
        }

    def get_item_count(self, obj):
        return obj.items.count()

    def validate(self, attrs):
        company = attrs.get("company")
        learning_path = attrs.get("learning_path")
        # On create, must have at least one to derive the company
        if not self.instance and not company and not learning_path:
            raise serializers.ValidationError(
                "Provide either 'company' or 'learning_path'."
            )
        return attrs

    def to_representation(self, instance):
        # If this module wraps a live KnowledgeSource, its name/description always
        # reflect the real process — not a copy frozen at the moment it was added.
        data = super().to_representation(instance)
        if instance.knowledge_source_id and instance.knowledge_source:
            ks = instance.knowledge_source
            data["name"] = ks.title
            if ks.description:
                data["description"] = ks.description
        return data


class LearningModuleLightSerializer(serializers.ModelSerializer):
    """Used in list views — no nested items to keep response light."""

    item_count = serializers.SerializerMethodField()

    class Meta:
        model = LearningModule
        fields = [
            "id",
            "company",
            "learning_path",
            "knowledge_source",
            "name",
            "description",
            "order",
            "is_required",
            "estimated_duration_minutes",
            "process_type",
            "difficulty",
            "minimum_passing_score",
            "item_count",
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.knowledge_source_id and instance.knowledge_source:
            ks = instance.knowledge_source
            data["name"] = ks.title
            if ks.description:
                data["description"] = ks.description
        return data

    def get_item_count(self, obj):
        return obj.items.count()


# ---------------------------------------------------------------------------
# LearningPath
# ---------------------------------------------------------------------------

class LearningPathSerializer(serializers.ModelSerializer):
    """Full serializer with nested modules — used for retrieve and create."""

    modules = LearningModuleSerializer(many=True, read_only=True)
    module_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )
    # Write-only: list of existing proceso IDs to link to this path
    module_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        default=list,
        help_text="IDs of existing procesos to associate with this learning path.",
    )

    class Meta:
        model = LearningPath
        fields = [
            "id",
            "company",
            "business_unit",
            "project",
            "final_battery",
            "name",
            "description",
            "status",
            "estimated_duration_minutes",
            "created_by",
            "created_by_username",
            "metadata",
            "module_count",
            "modules",
            "module_ids",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "created_by",
            "created_by_username",
            "module_count",
            "created_at",
            "updated_at",
        ]

    def get_module_count(self, obj):
        return obj.modules.count()


class LearningPathListSerializer(serializers.ModelSerializer):
    """Light serializer — used for list views, no nested modules."""

    module_count = serializers.SerializerMethodField()
    assignment_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )

    class Meta:
        model = LearningPath
        fields = [
            "id",
            "company",
            "business_unit",
            "project",
            "final_battery",
            "name",
            "description",
            "status",
            "estimated_duration_minutes",
            "created_by",
            "created_by_username",
            "module_count",
            "assignment_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "created_by",
            "created_by_username",
            "module_count",
            "assignment_count",
            "created_at",
            "updated_at",
        ]

    def get_module_count(self, obj):
        return obj.modules.count()

    def get_assignment_count(self, obj):
        return obj.assignments.count()


# ---------------------------------------------------------------------------
# TrainingProgramVersion
# ---------------------------------------------------------------------------

class TrainingProgramVersionSerializer(serializers.ModelSerializer):
    learning_path_name = serializers.CharField(
        source="learning_path.name", read_only=True
    )
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )

    class Meta:
        model = TrainingProgramVersion
        fields = [
            "id",
            "program",
            "version_number",
            "learning_path",
            "learning_path_name",
            "notes",
            "is_current",
            "created_by",
            "created_by_username",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "version_number",
            "is_current",
            "created_by",
            "created_by_username",
            "created_at",
        ]


# ---------------------------------------------------------------------------
# TrainingProgram
# ---------------------------------------------------------------------------

class TrainingProgramSerializer(serializers.ModelSerializer):
    versions = TrainingProgramVersionSerializer(many=True, read_only=True)
    current_version = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )

    class Meta:
        model = TrainingProgram
        fields = [
            "id",
            "company",
            "business_unit",
            "name",
            "description",
            "status",
            "created_by",
            "created_by_username",
            "metadata",
            "current_version",
            "versions",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "created_by",
            "created_by_username",
            "current_version",
            "created_at",
            "updated_at",
        ]

    def get_current_version(self, obj):
        v = obj.versions.filter(is_current=True).first()
        return TrainingProgramVersionSerializer(v).data if v else None


class TrainingProgramListSerializer(serializers.ModelSerializer):
    """Light serializer for list — no nested versions."""

    version_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(
        source="created_by.username", read_only=True
    )

    class Meta:
        model = TrainingProgram
        fields = [
            "id",
            "company",
            "business_unit",
            "name",
            "description",
            "status",
            "created_by",
            "created_by_username",
            "version_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "created_by",
            "created_by_username",
            "version_count",
            "created_at",
            "updated_at",
        ]

    def get_version_count(self, obj):
        return obj.versions.count()


# ---------------------------------------------------------------------------
# LearningPathAssignment
# ---------------------------------------------------------------------------

class LearningPathAssignmentSerializer(serializers.ModelSerializer):
    learning_path_name = serializers.CharField(
        source="learning_path.name", read_only=True
    )
    assigned_by_username = serializers.CharField(
        source="assigned_by.username", read_only=True
    )
    user_username = serializers.CharField(source="user.username", read_only=True)
    team_name = serializers.CharField(source="team.name", read_only=True)
    is_overdue = serializers.SerializerMethodField()
    certificate_template_id = serializers.SerializerMethodField()
    issued_certification_id = serializers.SerializerMethodField()

    class Meta:
        model = LearningPathAssignment
        fields = [
            "id",
            "company",
            "learning_path",
            "learning_path_name",
            "learning_module",
            "user",
            "user_username",
            "team",
            "team_name",
            "assigned_by",
            "assigned_by_username",
            "status",
            "due_date",
            "started_at",
            "completed_at",
            "is_overdue",
            "certificate_template_id",
            "issued_certification_id",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "company",
            "assigned_by",
            "assigned_by_username",
            "status",
            "started_at",
            "completed_at",
            "is_overdue",
            "certificate_template_id",
            "issued_certification_id",
            "learning_path_name",
            "user_username",
            "team_name",
            "created_at",
            "updated_at",
        ]

    def get_is_overdue(self, obj):
        return obj.is_overdue()

    def get_certificate_template_id(self, obj):
        """
        ID of the (first) active CertificateTemplate whose requirements
        include this assignment's learning_path — None if this learning path
        has no certificate configured. Only applies to learning_path-level
        assignments (not single-module ones, which certificates don't target
        today).
        """
        if not obj.learning_path_id:
            return None
        from api.enterprise_certification_models import CertificateTemplate
        template = (
            CertificateTemplate.objects.filter(
                company_id=obj.company_id,
                is_active=True,
                requirements__learning_path_id=obj.learning_path_id,
            )
            .order_by("id")
            .first()
        )
        return template.id if template else None

    def get_issued_certification_id(self, obj):
        """
        ID of the active Certification already issued to this assignment's
        user for this learning_path, if any — lets the frontend link
        straight to it once earned.
        """
        if not obj.learning_path_id or not obj.user_id:
            return None
        from api.enterprise_certification_models import Certification
        cert = Certification.objects.filter(
            user_id=obj.user_id,
            learning_path_id=obj.learning_path_id,
            status="active",
        ).order_by("-issued_at").first()
        return cert.id if cert else None

    def validate(self, attrs):
        user = attrs.get("user")
        team = attrs.get("team")
        if bool(user) == bool(team):
            raise serializers.ValidationError(
                "Exactly one of user or team must be provided."
            )
        return attrs


# ---------------------------------------------------------------------------
# LearningModuleProgress
# ---------------------------------------------------------------------------

class LearningModuleProgressSerializer(serializers.ModelSerializer):
    module_name = serializers.CharField(source="module.name", read_only=True)
    user_username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = LearningModuleProgress
        fields = [
            "id",
            "assignment",
            "module",
            "module_name",
            "user",
            "user_username",
            "status",
            "score",
            "started_at",
            "completed_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "module_name",
            "user_username",
            "created_at",
            "updated_at",
        ]

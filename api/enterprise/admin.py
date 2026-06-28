from django.contrib import admin
from api.enterprise_models import (
    Company,
    BusinessUnit,
    CompanyMembership,
    Team,
    TeamMembership,
    EnterpriseProfile,
    LearningEvent,
    KnowledgeHealthSnapshot,
)
from api.enterprise_learning_models import (
    LearningPath,
    LearningModule,
    LearningModuleItem,
    TrainingProgram,
    TrainingProgramVersion,
    LearningPathAssignment,
    LearningModuleProgress,
)
from api.enterprise_retention_models import (
    KnowledgeAssessment,
    RetentionSnapshot,
    KnowledgeGap,
    ReviewSchedule,
)
from api.enterprise_compliance_models import (
    ComplianceProgram,
    ComplianceRequirement,
    ComplianceAssignment,
    ComplianceReview,
)
from api.enterprise_certification_models import (
    CertificateTemplate,
    CertificationRequirement,
    Certification,
)
from api.enterprise_document_intelligence_models import (
    KnowledgeSource,
    DocumentVersion,
    Procedure,
    ChangeImpactAnalysis,
    KnowledgeNode,
    KnowledgeRelationship,
)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "owner", "industry", "company_size", "is_active", "created_at"]
    list_filter = ["is_active", "industry", "company_size"]
    search_fields = ["name", "slug", "owner__username", "owner__email"]
    prepopulated_fields = {"slug": ("name",)}
    readonly_fields = ["created_at", "updated_at"]


@admin.register(BusinessUnit)
class BusinessUnitAdmin(admin.ModelAdmin):
    list_display = ["name", "code", "company", "manager", "is_active", "created_at"]
    list_filter = ["is_active", "company"]
    search_fields = ["name", "code", "company__name"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(CompanyMembership)
class CompanyMembershipAdmin(admin.ModelAdmin):
    list_display = ["user", "company", "role", "employee_stage", "status", "joined_at", "created_at"]
    list_filter = ["role", "employee_stage", "status", "company"]
    search_fields = ["user__username", "user__email", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["user", "company", "invited_by", "stage_changed_by"]


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ["name", "company", "business_unit", "manager", "is_active", "created_at"]
    list_filter = ["is_active", "company", "business_unit"]
    search_fields = ["name", "company__name"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(TeamMembership)
class TeamMembershipAdmin(admin.ModelAdmin):
    list_display = ["user", "team", "role", "created_at"]
    list_filter = ["role", "team__company"]
    search_fields = ["user__username", "team__name"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["user", "team"]


@admin.register(EnterpriseProfile)
class EnterpriseProfileAdmin(admin.ModelAdmin):
    list_display = ["user", "default_company", "job_title", "department", "employee_code", "employment_status"]
    list_filter = ["employment_status", "default_company"]
    search_fields = ["user__username", "user__email", "employee_code", "job_title"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["user", "default_company", "manager"]


@admin.register(LearningEvent)
class LearningEventAdmin(admin.ModelAdmin):
    list_display = ["event_type", "user", "company", "score", "created_at"]
    list_filter = ["event_type", "company"]
    search_fields = ["user__username", "company__name"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["user", "company", "topic", "battery", "flashcard"]
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(KnowledgeHealthSnapshot)
class KnowledgeHealthSnapshotAdmin(admin.ModelAdmin):
    list_display = [
        "company",
        "snapshot_date",
        "global_retention_score",
        "global_risk_score",
        "compliance_score",
        "active_employees",
        "employees_at_risk",
    ]
    list_filter = ["company"]
    readonly_fields = ["created_at"]
    date_hierarchy = "snapshot_date"


# ---------------------------------------------------------------------------
# Phase 2 — Learning Engine
# ---------------------------------------------------------------------------

@admin.register(LearningPath)
class LearningPathAdmin(admin.ModelAdmin):
    list_display = ["name", "company", "business_unit", "status", "created_by", "created_at"]
    list_filter = ["status", "company"]
    search_fields = ["name", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "business_unit", "created_by", "project"]


@admin.register(LearningModule)
class LearningModuleAdmin(admin.ModelAdmin):
    list_display = ["name", "learning_path", "order", "is_required", "estimated_duration_minutes"]
    list_filter = ["is_required", "learning_path__company"]
    search_fields = ["name", "learning_path__name"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["learning_path", "order"]


@admin.register(LearningModuleItem)
class LearningModuleItemAdmin(admin.ModelAdmin):
    list_display = ["module", "item_type", "order", "is_required", "topic", "battery", "deck", "document"]
    list_filter = ["item_type", "is_required"]
    search_fields = ["module__name"]
    readonly_fields = ["created_at"]
    ordering = ["module", "order"]


@admin.register(TrainingProgram)
class TrainingProgramAdmin(admin.ModelAdmin):
    list_display = ["name", "company", "business_unit", "status", "created_by", "created_at"]
    list_filter = ["status", "company"]
    search_fields = ["name", "company__name"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(TrainingProgramVersion)
class TrainingProgramVersionAdmin(admin.ModelAdmin):
    list_display = ["program", "version_number", "learning_path", "is_current", "created_by", "created_at"]
    list_filter = ["is_current", "program__company"]
    search_fields = ["program__name"]
    readonly_fields = ["created_at"]


@admin.register(LearningPathAssignment)
class LearningPathAssignmentAdmin(admin.ModelAdmin):
    list_display = ["learning_path", "user", "team", "status", "due_date", "started_at", "completed_at"]
    list_filter = ["status", "company"]
    search_fields = ["learning_path__name", "user__username", "team__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "learning_path", "user", "team", "assigned_by"]
    date_hierarchy = "created_at"


@admin.register(LearningModuleProgress)
class LearningModuleProgressAdmin(admin.ModelAdmin):
    list_display = ["user", "module", "assignment", "status", "score", "completed_at"]
    list_filter = ["status"]
    search_fields = ["user__username", "module__name"]
    readonly_fields = ["created_at", "updated_at"]


# ---------------------------------------------------------------------------
# Phase 3 — Retention Engine
# ---------------------------------------------------------------------------

@admin.register(KnowledgeAssessment)
class KnowledgeAssessmentAdmin(admin.ModelAdmin):
    list_display = ["user", "company", "assessment_type", "score", "retention_score", "confidence_score", "created_at"]
    list_filter = ["assessment_type", "company"]
    search_fields = ["user__username", "company__name"]
    readonly_fields = ["retention_score", "confidence_score", "created_at"]
    raw_id_fields = ["user", "company", "topic", "battery", "battery_attempt", "learning_path", "learning_module"]
    date_hierarchy = "created_at"


@admin.register(RetentionSnapshot)
class RetentionSnapshotAdmin(admin.ModelAdmin):
    list_display = ["user", "company", "snapshot_date", "retention_score", "risk_score", "confidence_score"]
    list_filter = ["company", "snapshot_date"]
    search_fields = ["user__username", "company__name"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["user", "company", "topic", "learning_path"]
    date_hierarchy = "snapshot_date"


@admin.register(KnowledgeGap)
class KnowledgeGapAdmin(admin.ModelAdmin):
    list_display = ["user", "team", "company", "severity", "status", "retention_score_at_detection", "detected_at"]
    list_filter = ["severity", "status", "company"]
    search_fields = ["user__username", "team__name", "company__name"]
    readonly_fields = ["detected_at", "acknowledged_at", "resolved_at", "created_at", "updated_at"]
    raw_id_fields = ["user", "team", "company", "topic", "learning_path", "acknowledged_by", "resolved_by"]


@admin.register(ReviewSchedule)
class ReviewScheduleAdmin(admin.ModelAdmin):
    list_display = ["user", "company", "review_type", "status", "priority", "due_date", "score", "repetition_count"]
    list_filter = ["review_type", "status", "priority", "company"]
    search_fields = ["user__username", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["user", "company", "topic", "learning_module", "learning_path", "flashcard", "battery"]
    date_hierarchy = "due_date"


# ---------------------------------------------------------------------------
# Phase 4 — Compliance Engine
# ---------------------------------------------------------------------------

@admin.register(ComplianceProgram)
class ComplianceProgramAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "company", "compliance_type", "frequency", "status", "is_mandatory", "validity_days"]
    list_filter = ["status", "compliance_type", "frequency", "is_mandatory", "company"]
    search_fields = ["code", "name", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "business_unit", "created_by"]


@admin.register(ComplianceRequirement)
class ComplianceRequirementAdmin(admin.ModelAdmin):
    list_display = ["program", "name", "order", "is_mandatory", "learning_path"]
    list_filter = ["is_mandatory", "program__company"]
    search_fields = ["name", "program__name"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["program", "order"]


@admin.register(ComplianceAssignment)
class ComplianceAssignmentAdmin(admin.ModelAdmin):
    list_display = ["program", "user", "team", "status", "is_compliant", "due_date", "expires_at", "renewal_count"]
    list_filter = ["status", "is_compliant", "company"]
    search_fields = ["program__code", "user__username", "team__name"]
    readonly_fields = ["created_at", "updated_at", "completed_at", "last_reviewed_at"]
    raw_id_fields = ["company", "program", "user", "team", "assigned_by", "renewed_from"]
    date_hierarchy = "created_at"


@admin.register(ComplianceReview)
class ComplianceReviewAdmin(admin.ModelAdmin):
    list_display = ["user", "program", "review_type", "status", "score", "reviewed_at", "valid_until"]
    list_filter = ["review_type", "status", "company"]
    search_fields = ["user__username", "program__code"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["company", "user", "program", "assignment", "reviewer"]
    date_hierarchy = "created_at"


# ---------------------------------------------------------------------------
# Phase 5 — Certifications
# ---------------------------------------------------------------------------

@admin.register(CertificateTemplate)
class CertificateTemplateAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "company", "template_type", "validity_days", "requires_score", "is_active"]
    list_filter = ["template_type", "is_active", "requires_score", "company"]
    search_fields = ["code", "name", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "created_by"]


@admin.register(CertificationRequirement)
class CertificationRequirementAdmin(admin.ModelAdmin):
    list_display = ["template", "order", "is_mandatory", "learning_path", "compliance_program", "minimum_score"]
    list_filter = ["is_mandatory", "template__company"]
    search_fields = ["template__code", "description"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["template", "order"]


@admin.register(Certification)
class CertificationAdmin(admin.ModelAdmin):
    list_display = ["certificate_number", "user", "template", "status", "issued_at", "expires_at", "score"]
    list_filter = ["status", "company", "template__template_type"]
    search_fields = ["certificate_number", "verification_code", "user__username", "template__code"]
    readonly_fields = ["certificate_number", "verification_code", "created_at", "issued_at"]
    raw_id_fields = ["company", "user", "template", "learning_path", "compliance_program", "issued_by", "revoked_by"]
    date_hierarchy = "issued_at"


# ---------------------------------------------------------------------------
# Phase 7 — Document Intelligence
# ---------------------------------------------------------------------------

@admin.register(KnowledgeSource)
class KnowledgeSourceAdmin(admin.ModelAdmin):
    list_display = ["title", "company", "source_type", "status", "extracted_topics_count", "extracted_procedures_count", "created_at"]
    list_filter = ["status", "source_type", "company"]
    search_fields = ["title", "company__name"]
    readonly_fields = ["created_at", "updated_at", "processing_started_at", "processing_completed_at"]
    raw_id_fields = ["company", "document", "business_unit", "generated_training", "created_by"]


@admin.register(DocumentVersion)
class DocumentVersionAdmin(admin.ModelAdmin):
    list_display = ["knowledge_source", "version_number", "file_hash", "topic_count", "extracted_at", "created_at"]
    list_filter = ["knowledge_source__company"]
    search_fields = ["knowledge_source__title"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["knowledge_source", "document", "created_by"]


@admin.register(Procedure)
class ProcedureAdmin(admin.ModelAdmin):
    list_display = ["title", "knowledge_source", "company", "order", "is_critical", "created_at"]
    list_filter = ["is_critical", "company"]
    search_fields = ["title", "knowledge_source__title"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "knowledge_source", "topic"]


@admin.register(ChangeImpactAnalysis)
class ChangeImpactAnalysisAdmin(admin.ModelAdmin):
    list_display = ["knowledge_source", "status", "impact_level", "training_regenerated", "analyzed_at", "created_at"]
    list_filter = ["status", "impact_level", "training_regenerated", "company"]
    search_fields = ["knowledge_source__title"]
    readonly_fields = ["created_at", "updated_at", "analyzed_at"]
    raw_id_fields = ["company", "knowledge_source", "old_version", "new_version", "created_by"]


@admin.register(KnowledgeNode)
class KnowledgeNodeAdmin(admin.ModelAdmin):
    list_display = ["title", "node_type", "company", "importance_score", "source", "created_at"]
    list_filter = ["node_type", "company"]
    search_fields = ["title", "company__name"]
    readonly_fields = ["created_at", "updated_at"]
    raw_id_fields = ["company", "source", "topic"]


@admin.register(KnowledgeRelationship)
class KnowledgeRelationshipAdmin(admin.ModelAdmin):
    list_display = ["source_node", "relationship_type", "target_node", "strength", "company", "created_at"]
    list_filter = ["relationship_type", "company"]
    search_fields = ["source_node__title", "target_node__title"]
    readonly_fields = ["created_at"]
    raw_id_fields = ["company", "source_node", "target_node"]

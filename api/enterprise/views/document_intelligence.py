"""Phase 7 — Document Intelligence ViewSets."""

from __future__ import annotations

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.document_intelligence_service import (
    DocumentIntelligenceService,
)
from api.enterprise.services.security_service import validate_company_access
from api.enterprise.views.learning import EnterpriseViewSetMixin
from api.enterprise.serializers.document_intelligence import (
    ChangeImpactAnalysisSerializer,
    DocumentVersionSerializer,
    KnowledgeGraphSerializer,
    KnowledgeNodeSerializer,
    KnowledgeRelationshipSerializer,
    KnowledgeSourceCreateSerializer,
    KnowledgeSourceSerializer,
    ProcessingStatusSerializer,
    ProcedureSerializer,
)


def _resolve_ks(company_id, ks_id):
    from api.enterprise_document_intelligence_models import KnowledgeSource
    try:
        return KnowledgeSource.objects.select_related(
            "document", "company", "created_by"
        ).get(pk=ks_id, company_id=company_id)
    except KnowledgeSource.DoesNotExist:
        raise NotFound("KnowledgeSource not found.")


# ---------------------------------------------------------------------------
# KnowledgeSourceViewSet
# ---------------------------------------------------------------------------

class KnowledgeSourceViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    CRUD + processing actions for KnowledgeSource objects.

    Endpoints:
      GET    /enterprise/knowledge-sources/
      POST   /enterprise/knowledge-sources/
      GET    /enterprise/knowledge-sources/{id}/
      DELETE /enterprise/knowledge-sources/{id}/
      POST   /enterprise/knowledge-sources/{id}/process/
      GET    /enterprise/knowledge-sources/{id}/status/
      POST   /enterprise/knowledge-sources/{id}/generate-training/
      POST   /enterprise/knowledge-sources/{id}/detect-changes/
    """

    permission_classes = [IsAuthenticated]

    def _resolve_company_membership(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        company = Company.objects.get(id=company_id)
        return company, membership

    def _require_trainer(self, membership):
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

    def list(self, request):
        company, membership = self._resolve_company_membership()
        from api.enterprise_document_intelligence_models import KnowledgeSource
        qs = KnowledgeSource.objects.filter(company=company).select_related(
            "document", "created_by"
        ).order_by("-created_at")

        # Optional filters
        status = request.query_params.get("status")
        if status:
            qs = qs.filter(status=status)
        source_type = request.query_params.get("source_type")
        if source_type:
            qs = qs.filter(source_type=source_type)

        return Response(KnowledgeSourceSerializer(qs, many=True).data)

    def create(self, request):
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)

        ser = KnowledgeSourceCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data

        from api.enterprise_document_intelligence_models import KnowledgeSource
        from api.enterprise_models import BusinessUnit

        bu = None
        if d.get("business_unit_id"):
            try:
                bu = BusinessUnit.objects.get(pk=d["business_unit_id"], company=company)
            except BusinessUnit.DoesNotExist:
                raise ValidationError({"business_unit_id": "BusinessUnit not found."})

        ks = KnowledgeSource.objects.create(
            company=company,
            title=d["title"],
            description=d.get("description", ""),
            source_type=d["source_type"],
            business_unit=bu,
            process_type=d.get("process_type", "course"),
            difficulty=d.get("difficulty", "medium"),
            minimum_passing_score=d.get("minimum_passing_score", 70),
            estimated_duration_minutes=d.get("estimated_duration_minutes"),
            status="pending",
            created_by=request.user,
        )
        return Response(KnowledgeSourceSerializer(ks).data, status=201)

    @action(detail=True, methods=["post"], url_path="add-document")
    def add_document(self, request, pk=None):
        """
        Uploads a file, creates a Document, and links it to this KnowledgeSource.
        Accepts multipart/form-data with:
          - file       : the uploaded file (required)
          - version_note: optional text describing this addition (e.g. "Actualización Q2")
        """
        import hashlib

        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        if "file" not in request.FILES:
            raise ValidationError({"file": "A file is required."})

        uploaded_file = request.FILES["file"]
        content = uploaded_file.read()
        uploaded_file.seek(0)

        ext = uploaded_file.name.rsplit(".", 1)[-1].lower() if "." in uploaded_file.name else "bin"
        file_hash = hashlib.sha256(content).hexdigest()

        from api.models import Document
        from api.enterprise_document_intelligence_models import KnowledgeSourceDocument

        document = Document.objects.create(
            filename=uploaded_file.name,
            file=uploaded_file,
            type=ext,
            size=len(content),
            hash=file_hash,
            uploaded_by=request.user,
        )

        KnowledgeSourceDocument.objects.get_or_create(
            knowledge_source=ks,
            document=document,
            defaults={
                "added_by": request.user,
                "version_note": request.data.get("version_note", ""),
            },
        )

        ks.refresh_from_db()
        return Response(KnowledgeSourceSerializer(ks).data, status=201)

    def retrieve(self, request, pk=None):
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)
        return Response(KnowledgeSourceSerializer(ks).data)

    def destroy(self, request, pk=None):
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)
        ks.delete()
        return Response(status=204)

    @action(detail=True, methods=["post"], url_path="process")
    def process(self, request, pk=None):
        """Triggers AI extraction pipeline synchronously (use Celery in prod)."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        if ks.status == "processing":
            raise ValidationError({"detail": "Already processing."})

        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()
        return Response(KnowledgeSourceSerializer(ks).data)

    @action(detail=True, methods=["get"], url_path="status")
    def status(self, request, pk=None):
        """Returns the current processing status."""
        company, membership = self._resolve_company_membership()
        ks = _resolve_ks(company.id, pk)
        data = DocumentIntelligenceService.get_processing_status(ks.pk)
        return Response(ProcessingStatusSerializer(data).data)

    @action(detail=True, methods=["post"], url_path="generate-training")
    def generate_training(self, request, pk=None):
        """Generates a TrainingProgram from the processed KnowledgeSource."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        try:
            program = DocumentIntelligenceService.generate_training_program(ks.pk)
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})

        from api.enterprise.serializers.learning import TrainingProgramSerializer
        return Response(TrainingProgramSerializer(program).data, status=201)

    @action(detail=True, methods=["post"], url_path="detect-changes")
    def detect_changes(self, request, pk=None):
        """Checks for document content changes and creates a ChangeImpactAnalysis."""
        company, membership = self._resolve_company_membership()
        self._require_trainer(membership)
        ks = _resolve_ks(company.id, pk)

        changed, analysis = DocumentIntelligenceService.detect_document_changes(
            ks.pk, created_by=request.user
        )
        if not changed:
            return Response({"changed": False, "analysis": None})

        return Response({
            "changed": True,
            "analysis": ChangeImpactAnalysisSerializer(analysis).data,
        })


# ---------------------------------------------------------------------------
# ProcedureViewSet (read-only, scoped to company)
# ---------------------------------------------------------------------------

class ProcedureViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Read-only listing of extracted procedures.

    Endpoints:
      GET /enterprise/procedures/
      GET /enterprise/procedures/{id}/
    """

    permission_classes = [IsAuthenticated]

    def _get_company(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id)

    def list(self, request):
        company = self._get_company()
        from api.enterprise_document_intelligence_models import Procedure
        qs = Procedure.objects.filter(company=company).select_related(
            "knowledge_source"
        ).order_by("knowledge_source_id", "order")

        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(knowledge_source_id=ks_id)

        is_critical = request.query_params.get("is_critical")
        if is_critical is not None:
            qs = qs.filter(is_critical=is_critical.lower() == "true")

        return Response(ProcedureSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        company = self._get_company()
        from api.enterprise_document_intelligence_models import Procedure
        try:
            proc = Procedure.objects.get(pk=pk, company=company)
        except Procedure.DoesNotExist:
            raise NotFound("Procedure not found.")
        return Response(ProcedureSerializer(proc).data)


# ---------------------------------------------------------------------------
# ChangeImpactAnalysisViewSet
# ---------------------------------------------------------------------------

class ChangeImpactAnalysisViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Impact analysis management.

    Endpoints:
      GET  /enterprise/change-impact/
      GET  /enterprise/change-impact/{id}/
      POST /enterprise/change-impact/{id}/analyze/
      POST /enterprise/change-impact/{id}/apply/
    """

    permission_classes = [IsAuthenticated]

    def _resolve_company_membership(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            membership = validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id), membership

    def _get_analysis(self, company, pk):
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        try:
            return ChangeImpactAnalysis.objects.select_related(
                "knowledge_source", "old_version", "new_version"
            ).get(pk=pk, company=company)
        except ChangeImpactAnalysis.DoesNotExist:
            raise NotFound("ChangeImpactAnalysis not found.")

    def list(self, request):
        company, _ = self._resolve_company_membership()
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        qs = ChangeImpactAnalysis.objects.filter(company=company).order_by("-created_at")

        status = request.query_params.get("status")
        if status:
            qs = qs.filter(status=status)
        impact_level = request.query_params.get("impact_level")
        if impact_level:
            qs = qs.filter(impact_level=impact_level)
        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(knowledge_source_id=ks_id)

        return Response(ChangeImpactAnalysisSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        company, _ = self._resolve_company_membership()
        analysis = self._get_analysis(company, pk)
        return Response(ChangeImpactAnalysisSerializer(analysis).data)

    @action(detail=True, methods=["post"], url_path="analyze")
    def analyze(self, request, pk=None):
        """Runs AI impact analysis comparing old vs new document versions."""
        company, membership = self._resolve_company_membership()
        if membership.role not in ("owner", "admin", "trainer", "manager"):
            raise PermissionDenied("Trainer role or higher required.")

        analysis = self._get_analysis(company, pk)
        if analysis.status == "analyzing":
            raise ValidationError({"detail": "Analysis already in progress."})
        if analysis.status == "completed":
            raise ValidationError({"detail": "Analysis already completed."})

        DocumentIntelligenceService.analyze_change_impact(analysis.pk)
        analysis.refresh_from_db()
        return Response(ChangeImpactAnalysisSerializer(analysis).data)

    @action(detail=True, methods=["post"], url_path="apply")
    def apply(self, request, pk=None):
        """Regenerates training program based on the completed impact analysis."""
        company, membership = self._resolve_company_membership()
        if membership.role not in ("owner", "admin", "trainer"):
            raise PermissionDenied("Trainer role or higher required.")

        analysis = self._get_analysis(company, pk)
        if analysis.status != "completed":
            raise ValidationError(
                {"detail": "Impact analysis must be completed before applying."}
            )
        if analysis.training_regenerated:
            raise ValidationError({"detail": "Training already regenerated for this analysis."})

        try:
            new_program = DocumentIntelligenceService.regenerate_training(
                knowledge_source_id=analysis.knowledge_source_id,
                change_analysis_id=analysis.pk,
            )
        except Exception as exc:
            raise ValidationError({"detail": str(exc)})

        from api.enterprise.serializers.learning import TrainingProgramSerializer
        return Response({
            "message": "Training program regenerated successfully.",
            "training_program": TrainingProgramSerializer(new_program).data,
        })


# ---------------------------------------------------------------------------
# KnowledgeGraphViewSet
# ---------------------------------------------------------------------------

class KnowledgeGraphViewSet(EnterpriseViewSetMixin, viewsets.ViewSet):
    """
    Knowledge graph retrieval.

    Endpoints:
      GET /enterprise/knowledge-graph/graph/
      GET /enterprise/knowledge-graph/nodes/
      GET /enterprise/knowledge-graph/relationships/
    """

    permission_classes = [IsAuthenticated]

    def _get_company(self):
        company_id = self._get_company_id()
        if not company_id:
            raise ValidationError({"company_id": "This field is required."})
        try:
            validate_company_access(self.request.user, company_id)
        except PermissionError as exc:
            raise PermissionDenied(str(exc))
        from api.enterprise_models import Company
        return Company.objects.get(id=company_id)

    @action(detail=False, methods=["get"], url_path="graph")
    def graph(self, request):
        """Returns the full knowledge graph (nodes + relationships)."""
        company = self._get_company()
        ks_id = request.query_params.get("knowledge_source_id")
        ks = None
        if ks_id:
            from api.enterprise_document_intelligence_models import KnowledgeSource
            try:
                ks = KnowledgeSource.objects.get(pk=ks_id, company=company)
            except KnowledgeSource.DoesNotExist:
                raise NotFound("KnowledgeSource not found.")

        data = DocumentIntelligenceService.get_knowledge_graph(company, ks)
        return Response(KnowledgeGraphSerializer(data).data)

    @action(detail=False, methods=["get"], url_path="nodes")
    def nodes(self, request):
        """Lists knowledge nodes for the company."""
        company = self._get_company()
        from api.enterprise_document_intelligence_models import KnowledgeNode
        qs = KnowledgeNode.objects.filter(company=company).order_by("-importance_score")

        node_type = request.query_params.get("node_type")
        if node_type:
            qs = qs.filter(node_type=node_type)
        ks_id = request.query_params.get("knowledge_source_id")
        if ks_id:
            qs = qs.filter(source_id=ks_id)

        return Response(KnowledgeNodeSerializer(qs, many=True).data)

    @action(detail=False, methods=["get"], url_path="relationships")
    def relationships(self, request):
        """Lists knowledge relationships for the company."""
        company = self._get_company()
        from api.enterprise_document_intelligence_models import KnowledgeRelationship
        qs = KnowledgeRelationship.objects.filter(
            company=company
        ).select_related("source_node", "target_node")

        rel_type = request.query_params.get("relationship_type")
        if rel_type:
            qs = qs.filter(relationship_type=rel_type)

        return Response(KnowledgeRelationshipSerializer(qs, many=True).data)

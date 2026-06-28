"""
Ankard Enterprise v1.0 — Phase 7 Document Intelligence Service

Handles AI-powered extraction from documents:
  - Topic and procedure extraction via OpenAI
  - Knowledge graph construction
  - Training program generation from extracted knowledge
  - Change detection and impact analysis
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Optional

import requests as http_requests
from django.utils import timezone

logger = logging.getLogger(__name__)

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_MODEL = "gpt-4o-mini"
_MAX_TEXT_CHARS = 12000


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _call_openai(system: str, user: str, max_tokens: int = 2000) -> dict:
    """
    Calls OpenAI chat completions and returns parsed JSON dict.
    Raises ValueError if API key is missing or response is not valid JSON.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured.")

    payload = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    resp = http_requests.post(
        _OPENAI_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=90,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return json.loads(content)


def _truncate_text(text: str) -> str:
    if len(text) <= _MAX_TEXT_CHARS:
        return text
    return text[:_MAX_TEXT_CHARS] + "\n\n[... document truncated for extraction ...]"


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# DocumentIntelligenceService
# ---------------------------------------------------------------------------

class DocumentIntelligenceService:

    # ------------------------------------------------------------------
    # Main processing pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def process_knowledge_source(knowledge_source_id: int) -> None:
        """
        Full AI extraction pipeline for a KnowledgeSource:
          1. Extracts topics, procedures, and knowledge nodes via OpenAI
          2. Persists Procedure and KnowledgeNode objects
          3. Builds KnowledgeRelationship edges
          4. Creates an initial DocumentVersion snapshot
          5. Updates KnowledgeSource.status → processed / failed
        """
        from api.enterprise_document_intelligence_models import (
            ChangeImpactAnalysis, DocumentVersion, KnowledgeNode,
            KnowledgeRelationship, KnowledgeSource, Procedure,
        )

        try:
            ks = KnowledgeSource.objects.select_related(
                "document", "company"
            ).get(pk=knowledge_source_id)
        except KnowledgeSource.DoesNotExist:
            logger.error("KnowledgeSource %s not found", knowledge_source_id)
            return

        ks.status = "processing"
        ks.processing_started_at = timezone.now()
        ks.save(update_fields=["status", "processing_started_at", "updated_at"])

        try:
            if not ks.document_id:
                raise ValueError(
                    "This KnowledgeSource has no document attached. Attach a document before processing."
                )
            text = ks.document.extracted_text or ""
            if not text.strip():
                raise ValueError(
                    "Document has no extracted text. Process the document first."
                )

            extraction = DocumentIntelligenceService._extract_with_ai(
                title=ks.title,
                source_type=ks.source_type,
                text=text,
            )

            # --- Procedures ---
            procedures_data = extraction.get("procedures", [])
            for i, p in enumerate(procedures_data):
                Procedure.objects.create(
                    company=ks.company,
                    knowledge_source=ks,
                    title=p.get("title", f"Procedure {i + 1}"),
                    description=p.get("description", ""),
                    steps=p.get("steps", []),
                    warnings=p.get("warnings", []),
                    references=p.get("references", []),
                    order=i,
                    is_critical=bool(p.get("is_critical", False)),
                    metadata={"source": "ai_extraction"},
                )

            # --- Knowledge nodes ---
            nodes_data = extraction.get("knowledge_nodes", [])
            node_map: dict[str, KnowledgeNode] = {}
            for n in nodes_data:
                node_title = n.get("title", "")
                if not node_title:
                    continue
                node = KnowledgeNode.objects.create(
                    company=ks.company,
                    source=ks,
                    title=node_title,
                    node_type=n.get("type", "concept"),
                    description=n.get("description", ""),
                    importance_score=min(100, max(0, float(n.get("importance", 50)))),
                    metadata={"key_concepts": n.get("key_concepts", [])},
                )
                node_map[node_title.lower()] = node

            # --- Knowledge relationships ---
            rels_data = extraction.get("knowledge_relationships", [])
            for r in rels_data:
                src_title = (r.get("source") or "").lower()
                tgt_title = (r.get("target") or "").lower()
                src_node = node_map.get(src_title)
                tgt_node = node_map.get(tgt_title)
                if not src_node or not tgt_node or src_node == tgt_node:
                    continue
                rel_type = r.get("type", "related_to")
                valid_types = {c[0] for c in KnowledgeRelationship.RELATIONSHIP_TYPE_CHOICES}
                if rel_type not in valid_types:
                    rel_type = "related_to"
                KnowledgeRelationship.objects.get_or_create(
                    company=ks.company,
                    source_node=src_node,
                    target_node=tgt_node,
                    relationship_type=rel_type,
                    defaults={
                        "strength": min(1.0, max(0.0, float(r.get("strength", 0.5)))),
                        "description": r.get("description", ""),
                    },
                )

            # --- Initial DocumentVersion ---
            content_text = ks.document.extracted_text or ""
            DocumentVersion.objects.create(
                knowledge_source=ks,
                document=ks.document,
                version_number=1,
                file_hash=ks.document.hash or "",
                content_hash=_content_hash(content_text),
                extracted_at=timezone.now(),
                summary=extraction.get("summary", ""),
                key_changes=[],
                topic_count=len(nodes_data),
            )

            # --- Update KnowledgeSource ---
            ks.status = "processed"
            ks.processing_completed_at = timezone.now()
            ks.extracted_procedures_count = len(procedures_data)
            ks.extracted_topics_count = len(nodes_data)
            ks.metadata = {
                "summary": extraction.get("summary", ""),
                "topics": extraction.get("topics", []),
            }
            ks.error_message = ""
            ks.save(update_fields=[
                "status", "processing_completed_at",
                "extracted_procedures_count", "extracted_topics_count",
                "metadata", "error_message", "updated_at",
            ])

        except Exception as exc:
            logger.exception("Document intelligence processing failed for KS %s", knowledge_source_id)
            KnowledgeSource.objects.filter(pk=knowledge_source_id).update(
                status="failed",
                error_message=str(exc),
                updated_at=timezone.now(),
            )

    # ------------------------------------------------------------------
    # AI extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_with_ai(title: str, source_type: str, text: str) -> dict:
        """
        Calls OpenAI to extract structured knowledge from document text.
        Returns a dict with keys: summary, topics, procedures,
        knowledge_nodes, knowledge_relationships.
        """
        truncated = _truncate_text(text)

        system = (
            "You are an enterprise knowledge extraction expert. "
            "Extract structured training data from the provided document. "
            "Always respond with valid JSON."
        )
        user = (
            f"Document type: {source_type}\n"
            f"Document title: {title}\n\n"
            f"Document content:\n{truncated}\n\n"
            "Extract and return JSON with exactly these keys:\n"
            "{\n"
            '  "summary": "2-3 sentence summary of the document",\n'
            '  "topics": [\n'
            '    {"name": "...", "description": "...", "importance": 80, "key_concepts": ["..."]}\n'
            "  ],\n"
            '  "procedures": [\n'
            '    {\n'
            '      "title": "...", "description": "...", "is_critical": false,\n'
            '      "steps": [{"order": 1, "text": "..."}],\n'
            '      "warnings": ["..."], "references": ["..."]\n'
            '    }\n'
            "  ],\n"
            '  "knowledge_nodes": [\n'
            '    {"title": "...", "type": "concept|procedure|regulation|skill|rule", "description": "...", "importance": 70}\n'
            "  ],\n"
            '  "knowledge_relationships": [\n'
            '    {"source": "node_title", "target": "node_title", "type": "requires|related_to|extends|depends_on|supersedes|contradicts", "description": "...", "strength": 0.8}\n'
            "  ]\n"
            "}"
        )

        try:
            return _call_openai(system=system, user=user, max_tokens=3000)
        except Exception as exc:
            logger.warning("OpenAI extraction failed: %s — returning empty extraction", exc)
            return {
                "summary": f"Extraction failed: {exc}",
                "topics": [],
                "procedures": [],
                "knowledge_nodes": [],
                "knowledge_relationships": [],
            }

    # ------------------------------------------------------------------
    # Training program generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_training_program(knowledge_source_id: int) -> Optional[object]:
        """
        Creates a TrainingProgram from an already-processed KnowledgeSource.
        Structure: TrainingProgram → TrainingProgramVersion → LearningPath
          → LearningModule (per procedure) → LearningModuleItem (document)

        Returns the created TrainingProgram or raises ValueError.
        """
        from api.enterprise_document_intelligence_models import KnowledgeSource
        from api.enterprise_learning_models import (
            LearningModule, LearningModuleItem, LearningPath,
            TrainingProgram, TrainingProgramVersion,
        )

        ks = KnowledgeSource.objects.select_related(
            "company", "document", "created_by"
        ).get(pk=knowledge_source_id)

        if ks.status != "processed":
            raise ValueError(
                f"KnowledgeSource must be in 'processed' state. Current: {ks.status}"
            )

        topics_meta = ks.metadata.get("topics", [])
        procedures = list(ks.procedures.order_by("order"))

        # --- TrainingProgram ---
        program = TrainingProgram.objects.create(
            company=ks.company,
            name=f"{ks.title} — Training Program",
            description=ks.description or ks.metadata.get("summary", ""),
            status="draft",
            created_by=ks.created_by,
            metadata={"knowledge_source_id": ks.pk},
        )

        module_config = {
            "process_type": ks.process_type,
            "difficulty": ks.difficulty,
            "minimum_passing_score": ks.minimum_passing_score,
            "estimated_duration_minutes": ks.estimated_duration_minutes,
        }

        # One LearningPath per topic group (or a single path if no topics)
        if topics_meta:
            for topic_data in topics_meta:
                topic_name = topic_data.get("name", "General")
                path = LearningPath.objects.create(
                    company=ks.company,
                    name=topic_name,
                    description=topic_data.get("description", ""),
                    status="draft",
                    created_by=ks.created_by,
                    metadata={
                        "knowledge_source_id": ks.pk,
                        "key_concepts": topic_data.get("key_concepts", []),
                    },
                )
                _create_modules_for_path(path, procedures, ks.document, module_config)
                TrainingProgramVersion.objects.create(
                    program=program,
                    version_number=TrainingProgramVersion.objects.filter(
                        program=program
                    ).count() + 1,
                    learning_path=path,
                    notes=f"Auto-generated from {ks.title}",
                    is_current=True,
                    created_by=ks.created_by,
                )
        else:
            # Single path for all procedures
            path = LearningPath.objects.create(
                company=ks.company,
                name=ks.title,
                description=ks.metadata.get("summary", ""),
                status="draft",
                created_by=ks.created_by,
                metadata={"knowledge_source_id": ks.pk},
            )
            _create_modules_for_path(path, procedures, ks.document, module_config)
            TrainingProgramVersion.objects.create(
                program=program,
                version_number=1,
                learning_path=path,
                notes=f"Auto-generated from {ks.title}",
                is_current=True,
                created_by=ks.created_by,
            )

        ks.generated_training = program
        ks.save(update_fields=["generated_training", "updated_at"])

        return program

    # ------------------------------------------------------------------
    # Document version management
    # ------------------------------------------------------------------

    @staticmethod
    def create_document_version(
        knowledge_source_id: int,
        created_by=None,
    ):
        """
        Creates a new DocumentVersion snapshot for a KnowledgeSource.
        Sets key_changes = [] (populate via detect_document_changes).
        """
        from api.enterprise_document_intelligence_models import (
            DocumentVersion, KnowledgeSource,
        )

        ks = KnowledgeSource.objects.select_related("document").get(
            pk=knowledge_source_id
        )
        latest = (
            DocumentVersion.objects.filter(knowledge_source=ks)
            .order_by("-version_number")
            .first()
        )
        next_version = (latest.version_number + 1) if latest else 1
        content_text = ks.document.extracted_text or ""
        return DocumentVersion.objects.create(
            knowledge_source=ks,
            document=ks.document,
            version_number=next_version,
            file_hash=ks.document.hash or "",
            content_hash=_content_hash(content_text),
            extracted_at=timezone.now(),
            summary=ks.metadata.get("summary", ""),
            topic_count=ks.extracted_topics_count,
            created_by=created_by,
        )

    @staticmethod
    def detect_document_changes(knowledge_source_id: int, created_by=None):
        """
        Compares the current document hash against the latest DocumentVersion.
        If the content changed, creates a new DocumentVersion and a
        ChangeImpactAnalysis with status='pending'.

        Returns (changed: bool, change_analysis_or_None).
        """
        from api.enterprise_document_intelligence_models import (
            ChangeImpactAnalysis, DocumentVersion, KnowledgeSource,
        )

        ks = KnowledgeSource.objects.select_related("document").get(
            pk=knowledge_source_id
        )
        latest = (
            DocumentVersion.objects.filter(knowledge_source=ks)
            .order_by("-version_number")
            .first()
        )
        current_content = ks.document.extracted_text or ""
        current_hash = _content_hash(current_content)

        if latest and latest.content_hash == current_hash:
            return False, None

        # Content changed — create new version + impact analysis
        new_version = DocumentIntelligenceService.create_document_version(
            knowledge_source_id=knowledge_source_id,
            created_by=created_by,
        )
        analysis = ChangeImpactAnalysis.objects.create(
            company=ks.company,
            knowledge_source=ks,
            old_version=latest,
            new_version=new_version,
            status="pending",
            created_by=created_by,
        )
        return True, analysis

    # ------------------------------------------------------------------
    # Impact analysis
    # ------------------------------------------------------------------

    @staticmethod
    def analyze_change_impact(change_analysis_id: int) -> None:
        """
        Runs AI comparison between old and new document versions.
        Updates ChangeImpactAnalysis with impact_level, affected topics,
        affected learning paths, and recommendations.
        """
        from api.enterprise_document_intelligence_models import (
            ChangeImpactAnalysis, KnowledgeSource,
        )
        from api.enterprise_learning_models import LearningPath

        try:
            analysis = ChangeImpactAnalysis.objects.select_related(
                "knowledge_source__company",
                "old_version",
                "new_version",
            ).get(pk=change_analysis_id)
        except ChangeImpactAnalysis.DoesNotExist:
            logger.error("ChangeImpactAnalysis %s not found", change_analysis_id)
            return

        analysis.status = "analyzing"
        analysis.save(update_fields=["status", "updated_at"])

        try:
            old_summary = (
                analysis.old_version.summary if analysis.old_version else "No previous version"
            )
            new_summary = (
                analysis.new_version.summary if analysis.new_version else "New document"
            )

            result = DocumentIntelligenceService._analyze_diff_with_ai(
                knowledge_source_title=analysis.knowledge_source.title,
                old_summary=old_summary,
                new_summary=new_summary,
            )

            # Map affected learning paths by title
            ks = analysis.knowledge_source
            lp_ids = list(
                LearningPath.objects.filter(
                    company=ks.company,
                    metadata__knowledge_source_id=ks.pk,
                ).values_list("id", flat=True)
            )

            analysis.status = "completed"
            analysis.impact_level = result.get("impact_level", "medium")
            analysis.affected_topics = result.get("affected_topics", [])
            analysis.affected_learning_path_ids = lp_ids
            analysis.affected_procedures = result.get("affected_procedures", [])
            analysis.summary = result.get("summary", "")
            analysis.recommendations = result.get("recommendations", [])
            analysis.analyzed_at = timezone.now()
            analysis.error_message = ""
            analysis.save(update_fields=[
                "status", "impact_level", "affected_topics",
                "affected_learning_path_ids", "affected_procedures",
                "summary", "recommendations", "analyzed_at",
                "error_message", "updated_at",
            ])

        except Exception as exc:
            logger.exception("Impact analysis failed for %s", change_analysis_id)
            ChangeImpactAnalysis.objects.filter(pk=change_analysis_id).update(
                status="failed",
                error_message=str(exc),
                updated_at=timezone.now(),
            )

    @staticmethod
    def _analyze_diff_with_ai(
        knowledge_source_title: str,
        old_summary: str,
        new_summary: str,
    ) -> dict:
        system = (
            "You are an enterprise training impact analyst. "
            "Compare two versions of a document and assess the training impact. "
            "Always respond with valid JSON."
        )
        user = (
            f"Document: {knowledge_source_title}\n\n"
            f"PREVIOUS VERSION SUMMARY:\n{old_summary}\n\n"
            f"NEW VERSION SUMMARY:\n{new_summary}\n\n"
            "Analyze what changed and return JSON with exactly these keys:\n"
            "{\n"
            '  "key_changes": ["specific change 1", "specific change 2"],\n'
            '  "impact_level": "low|medium|high|critical",\n'
            '  "affected_topics": ["topic name 1"],\n'
            '  "affected_procedures": ["procedure title 1"],\n'
            '  "summary": "1-2 sentence summary of what changed and why it matters",\n'
            '  "recommendations": ["action recommendation 1"]\n'
            "}"
        )
        try:
            return _call_openai(system=system, user=user, max_tokens=1000)
        except Exception as exc:
            logger.warning("AI diff analysis failed: %s — using defaults", exc)
            return {
                "key_changes": [],
                "impact_level": "medium",
                "affected_topics": [],
                "affected_procedures": [],
                "summary": f"Automated analysis unavailable: {exc}",
                "recommendations": ["Review document changes manually and update training."],
            }

    # ------------------------------------------------------------------
    # Training regeneration
    # ------------------------------------------------------------------

    @staticmethod
    def regenerate_training(knowledge_source_id: int, change_analysis_id: int) -> object:
        """
        Archives the existing training program and generates a new one.
        Marks the ChangeImpactAnalysis as training_regenerated.

        Returns the new TrainingProgram.
        """
        from api.enterprise_document_intelligence_models import (
            ChangeImpactAnalysis, KnowledgeSource,
        )

        ks = KnowledgeSource.objects.select_related(
            "generated_training"
        ).get(pk=knowledge_source_id)

        # Archive existing training
        if ks.generated_training and ks.generated_training.status != "archived":
            ks.generated_training.status = "archived"
            ks.generated_training.save(update_fields=["status", "updated_at"])

        # Re-process to get fresh AI extraction
        DocumentIntelligenceService.process_knowledge_source(knowledge_source_id)

        # Reload after processing
        ks.refresh_from_db()
        new_program = DocumentIntelligenceService.generate_training_program(
            knowledge_source_id
        )

        # Mark impact analysis as resolved
        ChangeImpactAnalysis.objects.filter(pk=change_analysis_id).update(
            training_regenerated=True,
            training_regenerated_at=timezone.now(),
            updated_at=timezone.now(),
        )

        return new_program

    # ------------------------------------------------------------------
    # Knowledge graph retrieval
    # ------------------------------------------------------------------

    @staticmethod
    def get_knowledge_graph(company, knowledge_source=None) -> dict:
        """
        Returns the full knowledge graph for a company.
        Optionally filtered by a specific KnowledgeSource.

        Returns: {nodes: [...], relationships: [...], node_count, edge_count}
        """
        from api.enterprise_document_intelligence_models import (
            KnowledgeNode, KnowledgeRelationship,
        )

        node_qs = KnowledgeNode.objects.filter(company=company)
        if knowledge_source:
            node_qs = node_qs.filter(source=knowledge_source)

        nodes = list(node_qs.values(
            "id", "title", "node_type", "description", "importance_score",
        ))

        node_ids = [n["id"] for n in nodes]
        rels = list(
            KnowledgeRelationship.objects.filter(
                company=company,
                source_node_id__in=node_ids,
                target_node_id__in=node_ids,
            ).values(
                "id", "source_node_id", "target_node_id",
                "relationship_type", "strength", "description",
            )
        )

        return {
            "node_count": len(nodes),
            "edge_count": len(rels),
            "nodes": nodes,
            "relationships": rels,
        }

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    @staticmethod
    def get_processing_status(knowledge_source_id: int) -> dict:
        from api.enterprise_document_intelligence_models import KnowledgeSource

        ks = KnowledgeSource.objects.get(pk=knowledge_source_id)
        return {
            "id": ks.pk,
            "status": ks.status,
            "processing_started_at": ks.processing_started_at,
            "processing_completed_at": ks.processing_completed_at,
            "extracted_topics_count": ks.extracted_topics_count,
            "extracted_procedures_count": ks.extracted_procedures_count,
            "error_message": ks.error_message or None,
            "has_training": ks.generated_training_id is not None,
        }


# ---------------------------------------------------------------------------
# Private helper — builds modules for a learning path
# ---------------------------------------------------------------------------

def _create_modules_for_path(path, procedures, document, module_config: dict) -> None:
    from api.enterprise_learning_models import LearningModule, LearningModuleItem

    process_type = module_config.get("process_type", "course")
    difficulty = module_config.get("difficulty", "medium")
    min_score = module_config.get("minimum_passing_score", 70)
    duration = module_config.get("estimated_duration_minutes")

    if not procedures:
        module = LearningModule.objects.create(
            learning_path=path,
            name="Study Material",
            description="Review the document content.",
            order=0,
            is_required=True,
            process_type=process_type,
            difficulty=difficulty,
            minimum_passing_score=min_score,
            estimated_duration_minutes=duration,
        )
        if document:
            LearningModuleItem.objects.create(
                module=module,
                item_type="document",
                order=0,
                is_required=True,
                document=document,
            )
        return

    for i, proc in enumerate(procedures):
        module = LearningModule.objects.create(
            learning_path=path,
            name=proc.title,
            description=proc.description,
            order=i,
            is_required=proc.is_critical or True,
            process_type=process_type,
            difficulty=difficulty,
            minimum_passing_score=min_score,
            estimated_duration_minutes=duration,
            metadata={
                "procedure_id": proc.pk,
                "steps_count": len(proc.steps),
                "is_critical": proc.is_critical,
            },
        )
        if document:
            LearningModuleItem.objects.create(
                module=module,
                item_type="document",
                order=0,
                is_required=True,
                document=document,
            )

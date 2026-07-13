"""
Phase 7 — Document Intelligence Tests

Tests cover:
  - Model constraints and field defaults
  - DocumentIntelligenceService: process, generate training, detect changes, impact analysis
  - API: knowledge sources, procedures, change impact, knowledge graph
  - Tenant isolation
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

User = get_user_model()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_user(username="u", **kwargs):
    kwargs.setdefault("email", f"{username}@test7.com")
    return User.objects.create_user(username=username, password="pw", **kwargs)


def make_company(owner, name="ACME Corp", slug=None):
    from api.enterprise_models import Company
    return Company.objects.create(
        name=name,
        slug=slug or name.lower().replace(" ", "-"),
        owner=owner,
    )


def make_membership(user, company, role="admin"):
    from api.enterprise_models import CompanyMembership
    return CompanyMembership.objects.create(
        user=user, company=company, role=role, status="active"
    )


def make_project(owner):
    from api.models import Project
    return Project.objects.create(title="Test Project", owner=owner)


def make_document(project, owner, text="This is test content about safety procedures."):
    from api.models import Document
    doc = Document(
        project=project,
        filename="safety.pdf",
        type="pdf",
        size=len(text),
        status="ready",
        hash=hashlib.sha256(text.encode()).hexdigest()[:16],
        uploaded_by=owner,
        extracted_text=text,
    )
    doc.save()
    return doc


def make_knowledge_source(company, document, creator, **kwargs):
    from api.enterprise_document_intelligence_models import KnowledgeSource
    return KnowledgeSource.objects.create(
        company=company,
        document=document,
        title=kwargs.get("title", "Safety Manual"),
        description=kwargs.get("description", ""),
        source_type=kwargs.get("source_type", "manual"),
        status=kwargs.get("status", "pending"),
        created_by=creator,
    )


_FAKE_EXTRACTION = {
    "summary": "A document about safety procedures in the workplace.",
    "topics": [
        {"name": "Emergency Evacuation", "description": "How to evacuate safely.", "importance": 90, "key_concepts": ["exit routes", "muster points"]},
        {"name": "Fire Safety", "description": "Fire prevention basics.", "importance": 80, "key_concepts": ["extinguisher", "alarm"]},
    ],
    "procedures": [
        {
            "title": "Evacuation Procedure",
            "description": "Steps to evacuate the building.",
            "is_critical": True,
            "steps": [{"order": 1, "text": "Hear the alarm"}, {"order": 2, "text": "Use nearest exit"}],
            "warnings": ["Do not use elevators"],
            "references": ["Fire Safety Code 2024"],
        },
        {
            "title": "Fire Extinguisher Use",
            "description": "PASS technique for extinguisher use.",
            "is_critical": False,
            "steps": [{"order": 1, "text": "Pull the pin"}, {"order": 2, "text": "Aim low"}],
            "warnings": [],
            "references": [],
        },
    ],
    "knowledge_nodes": [
        {"title": "Emergency Exit", "type": "concept", "description": "Designated exit routes.", "importance": 85},
        {"title": "PASS Technique", "type": "procedure", "description": "Pull Aim Squeeze Sweep.", "importance": 75},
        {"title": "Muster Point", "type": "concept", "description": "Assembly area.", "importance": 70},
    ],
    "knowledge_relationships": [
        {"source": "Emergency Exit", "target": "Muster Point", "type": "related_to", "description": "Exit leads to muster point.", "strength": 0.9},
        {"source": "PASS Technique", "target": "Emergency Exit", "type": "requires", "description": "Must know exits first.", "strength": 0.6},
    ],
}

_FAKE_DIFF_RESULT = {
    "key_changes": ["Updated evacuation routes", "New muster point added"],
    "impact_level": "high",
    "affected_topics": ["Emergency Evacuation"],
    "affected_procedures": ["Evacuation Procedure"],
    "summary": "Significant changes to evacuation routes.",
    "recommendations": ["Retrain all employees on updated routes."],
}


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class KnowledgeSourceModelTest(TestCase):

    def setUp(self):
        self.owner = make_user("owner7")
        self.company = make_company(self.owner)
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)

    def test_create_knowledge_source(self):
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        self.assertEqual(ks.status, "pending")
        self.assertEqual(ks.extracted_topics_count, 0)
        self.assertEqual(ks.extracted_procedures_count, 0)
        self.assertIsNone(ks.generated_training)
        self.assertEqual(str(ks), f"Safety Manual ({self.company})")

    def test_knowledge_source_source_type_choices(self):
        from api.enterprise_document_intelligence_models import KnowledgeSource
        for stype in ("policy", "procedure", "regulation", "manual", "training_material", "other"):
            ks = KnowledgeSource.objects.create(
                company=self.company,
                document=self.doc,
                title=f"KS {stype}",
                source_type=stype,
                status="pending",
            )
            self.assertEqual(ks.source_type, stype)

    def test_document_version_unique_constraint(self):
        from api.enterprise_document_intelligence_models import DocumentVersion, KnowledgeSource
        from django.db import IntegrityError
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentVersion.objects.create(
            knowledge_source=ks, document=self.doc, version_number=1
        )
        with self.assertRaises(IntegrityError):
            DocumentVersion.objects.create(
                knowledge_source=ks, document=self.doc, version_number=1
            )

    def test_procedure_ordering(self):
        from api.enterprise_document_intelligence_models import KnowledgeSource, Procedure
        ks = make_knowledge_source(self.company, self.doc, self.owner, status="processed")
        for i in [2, 0, 1]:
            Procedure.objects.create(
                company=self.company, knowledge_source=ks,
                title=f"Proc {i}", order=i
            )
        orders = list(Procedure.objects.filter(company=self.company).values_list("order", flat=True))
        self.assertEqual(orders, [0, 1, 2])

    def test_knowledge_relationship_unique_constraint(self):
        from api.enterprise_document_intelligence_models import KnowledgeNode, KnowledgeRelationship, KnowledgeSource
        from django.db import IntegrityError
        ks = make_knowledge_source(self.company, self.doc, self.owner, status="processed")
        n1 = KnowledgeNode.objects.create(company=self.company, title="Node A", source=ks)
        n2 = KnowledgeNode.objects.create(company=self.company, title="Node B", source=ks)
        KnowledgeRelationship.objects.create(
            company=self.company, source_node=n1, target_node=n2,
            relationship_type="requires"
        )
        with self.assertRaises(IntegrityError):
            KnowledgeRelationship.objects.create(
                company=self.company, source_node=n1, target_node=n2,
                relationship_type="requires"
            )

    def test_change_impact_analysis_defaults(self):
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis, KnowledgeSource
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        cia = ChangeImpactAnalysis.objects.create(
            company=self.company, knowledge_source=ks
        )
        self.assertEqual(cia.status, "pending")
        self.assertIsNone(cia.impact_level)
        self.assertFalse(cia.training_regenerated)
        self.assertEqual(cia.affected_topics, [])
        self.assertEqual(cia.recommendations, [])


# ---------------------------------------------------------------------------
# Service Tests
# ---------------------------------------------------------------------------

class DocumentIntelligenceServiceTest(TestCase):

    def setUp(self):
        self.owner = make_user("svc_owner7")
        self.company = make_company(self.owner, name="SvcCo7")
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_knowledge_source_creates_procedures(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import KnowledgeSource, Procedure
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()
        self.assertEqual(ks.status, "processed")
        self.assertEqual(ks.extracted_procedures_count, 2)
        procs = Procedure.objects.filter(knowledge_source=ks)
        self.assertEqual(procs.count(), 2)
        crit = procs.filter(is_critical=True)
        self.assertEqual(crit.count(), 1)
        self.assertEqual(crit.first().title, "Evacuation Procedure")

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_creates_knowledge_nodes(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import KnowledgeNode, KnowledgeSource
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        nodes = KnowledgeNode.objects.filter(company=self.company, source=ks)
        self.assertEqual(nodes.count(), 3)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_creates_knowledge_relationships(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import KnowledgeRelationship, KnowledgeSource
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        rels = KnowledgeRelationship.objects.filter(company=self.company)
        self.assertEqual(rels.count(), 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_creates_initial_document_version(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import DocumentVersion, KnowledgeSource
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        versions = DocumentVersion.objects.filter(knowledge_source=ks)
        self.assertEqual(versions.count(), 1)
        self.assertEqual(versions.first().version_number, 1)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_sets_metadata_summary(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()
        self.assertIn("summary", ks.metadata)
        self.assertIn("topics", ks.metadata)

    def test_process_fails_gracefully_without_extracted_text(self):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import KnowledgeSource
        # Document with no extracted_text
        doc2 = make_document(self.project, self.owner, text="")
        doc2.extracted_text = ""
        doc2.save()
        ks = make_knowledge_source(self.company, doc2, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()
        self.assertEqual(ks.status, "failed")
        self.assertIn("extracted text", ks.error_message.lower())

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_process_can_use_hope_extraction_without_extracted_text(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService

        doc2 = make_document(self.project, self.owner, text="")
        doc2.extracted_text = ""
        doc2.save(update_fields=["extracted_text"])
        ks = make_knowledge_source(self.company, doc2, self.owner)

        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        ks.refresh_from_db()

        self.assertEqual(ks.status, "processed")
        self.assertEqual(ks.extracted_topics_count, 3)
        self.assertEqual(ks.extracted_procedures_count, 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_generate_training_program_creates_program(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_learning_models import TrainingProgram
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        program = DocumentIntelligenceService.generate_training_program(ks.pk)
        self.assertIsNotNone(program)
        self.assertIn("Training Program", program.name)
        ks.refresh_from_db()
        self.assertIsNotNone(ks.generated_training_id)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_generate_training_creates_learning_paths_per_topic(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_learning_models import LearningPath, TrainingProgramVersion
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        program = DocumentIntelligenceService.generate_training_program(ks.pk)
        # 2 topics → 2 learning paths → 2 versions
        versions = TrainingProgramVersion.objects.filter(program=program)
        self.assertEqual(versions.count(), 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_generate_training_creates_modules_with_document_items(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_learning_models import LearningModuleItem
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        DocumentIntelligenceService.generate_training_program(ks.pk)
        items = LearningModuleItem.objects.filter(
            module__learning_path__company=self.company,
            item_type="document",
            document=self.doc,
        )
        self.assertGreater(items.count(), 0)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_generate_training_raises_if_not_processed(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner, status="pending")
        with self.assertRaises(ValueError) as ctx:
            DocumentIntelligenceService.generate_training_program(ks.pk)
        self.assertIn("processed", str(ctx.exception))

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_detect_document_changes_no_change(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        # Document unchanged → no change detected
        changed, analysis = DocumentIntelligenceService.detect_document_changes(ks.pk)
        self.assertFalse(changed)
        self.assertIsNone(analysis)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_detect_document_changes_with_change(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)

        # Simulate document content change
        self.doc.extracted_text = "Updated content about new fire safety regulations."
        self.doc.save()

        changed, analysis = DocumentIntelligenceService.detect_document_changes(ks.pk)
        self.assertTrue(changed)
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.status, "pending")
        self.assertIsNotNone(analysis.old_version)
        self.assertIsNotNone(analysis.new_version)
        self.assertEqual(analysis.new_version.version_number, 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._analyze_diff_with_ai",
        return_value=_FAKE_DIFF_RESULT,
    )
    def test_analyze_change_impact(self, mock_diff, mock_extract):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)

        self.doc.extracted_text = "Updated fire safety content with new procedures."
        self.doc.save()
        _, analysis = DocumentIntelligenceService.detect_document_changes(ks.pk)

        DocumentIntelligenceService.analyze_change_impact(analysis.pk)
        analysis.refresh_from_db()

        self.assertEqual(analysis.status, "completed")
        self.assertEqual(analysis.impact_level, "high")
        self.assertIn("Emergency Evacuation", analysis.affected_topics)
        self.assertIsNotNone(analysis.analyzed_at)

    def test_get_knowledge_graph_empty(self):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        graph = DocumentIntelligenceService.get_knowledge_graph(self.company)
        self.assertEqual(graph["node_count"], 0)
        self.assertEqual(graph["edge_count"], 0)
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["relationships"], [])

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_get_knowledge_graph_with_data(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        graph = DocumentIntelligenceService.get_knowledge_graph(self.company)
        self.assertEqual(graph["node_count"], 3)
        self.assertEqual(graph["edge_count"], 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_get_knowledge_graph_filtered_by_source(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        graph = DocumentIntelligenceService.get_knowledge_graph(self.company, ks)
        self.assertEqual(graph["node_count"], 3)

    def test_get_processing_status(self):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        status = DocumentIntelligenceService.get_processing_status(ks.pk)
        self.assertEqual(status["status"], "pending")
        self.assertEqual(status["extracted_topics_count"], 0)
        self.assertFalse(status["has_training"])


# ---------------------------------------------------------------------------
# API Tests — KnowledgeSourceViewSet
# ---------------------------------------------------------------------------

class KnowledgeSourceAPITest(TestCase):

    def setUp(self):
        self.owner = make_user("api_owner7")
        self.company = make_company(self.owner)
        self.membership = make_membership(self.owner, self.company, role="admin")
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)
        self.base_url = f"/api/enterprise/knowledge-sources/?company_id={self.company.id}"

    def test_create_knowledge_source(self):
        resp = self.client.post(
            f"/api/enterprise/knowledge-sources/?company_id={self.company.id}",
            {
                "document_id": self.doc.pk,
                "title": "Safety Manual",
                "source_type": "manual",
                "description": "Company safety documentation",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data["title"], "Safety Manual")
        self.assertEqual(resp.data["status"], "pending")

    def test_list_knowledge_sources(self):
        make_knowledge_source(self.company, self.doc, self.owner)
        resp = self.client.get(self.base_url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)

    def test_retrieve_knowledge_source(self):
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        resp = self.client.get(f"/api/enterprise/knowledge-sources/{ks.pk}/?company_id={self.company.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["id"], ks.pk)

    def test_delete_knowledge_source(self):
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        resp = self.client.delete(f"/api/enterprise/knowledge-sources/{ks.pk}/?company_id={self.company.id}")
        self.assertEqual(resp.status_code, 204)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService.process_knowledge_source"
    )
    def test_process_action(self, mock_process):
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        resp = self.client.post(
            f"/api/enterprise/knowledge-sources/{ks.pk}/process/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        mock_process.assert_called_once_with(ks.pk)

    def test_process_action_rejected_while_processing(self):
        ks = make_knowledge_source(self.company, self.doc, self.owner, status="processing")
        resp = self.client.post(
            f"/api/enterprise/knowledge-sources/{ks.pk}/process/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 400)

    def test_status_action(self):
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        resp = self.client.get(
            f"/api/enterprise/knowledge-sources/{ks.pk}/status/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("status", resp.data)
        self.assertIn("has_training", resp.data)

    def test_filter_by_status(self):
        make_knowledge_source(self.company, self.doc, self.owner, status="pending", title="KS1")
        make_knowledge_source(self.company, self.doc, self.owner, status="processed", title="KS2")
        resp = self.client.get(f"{self.base_url}&status=pending")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)
        self.assertEqual(resp.data[0]["status"], "pending")

    def test_create_with_invalid_document(self):
        resp = self.client.post(
            f"/api/enterprise/knowledge-sources/?company_id={self.company.id}",
            {"document_id": 99999, "title": "X", "source_type": "other"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_unauthenticated_rejected(self):
        client = APIClient()
        resp = client.get(self.base_url)
        self.assertEqual(resp.status_code, 401)


# ---------------------------------------------------------------------------
# API Tests — ProcedureViewSet
# ---------------------------------------------------------------------------

class ProcedureAPITest(TestCase):

    def setUp(self):
        self.owner = make_user("proc_owner7")
        self.company = make_company(self.owner, name="ProcCo7")
        make_membership(self.owner, self.company, role="admin")
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_list_procedures(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner, status="pending")
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/procedures/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_filter_procedures_by_knowledge_source(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/procedures/?company_id={self.company.id}&knowledge_source_id={ks.pk}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_filter_critical_procedures(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/procedures/?company_id={self.company.id}&is_critical=true"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)
        self.assertTrue(resp.data[0]["is_critical"])


# ---------------------------------------------------------------------------
# API Tests — ChangeImpactAnalysisViewSet
# ---------------------------------------------------------------------------

class ChangeImpactAPITest(TestCase):

    def setUp(self):
        self.owner = make_user("cia_owner7")
        self.company = make_company(self.owner, name="CIACo7")
        make_membership(self.owner, self.company, role="admin")
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def _make_analysis(self, mock_ai=None):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        self.doc.extracted_text = "Changed content."
        self.doc.save()
        _, analysis = DocumentIntelligenceService.detect_document_changes(ks.pk)
        return ks, analysis

    def test_list_change_impact_analyses(self):
        with patch(
            "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
            return_value=_FAKE_EXTRACTION,
        ):
            self._make_analysis()
        resp = self.client.get(
            f"/api/enterprise/change-impact/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 1)
        self.assertEqual(resp.data[0]["status"], "pending")

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._analyze_diff_with_ai",
        return_value=_FAKE_DIFF_RESULT,
    )
    def test_analyze_action(self, mock_diff):
        with patch(
            "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
            return_value=_FAKE_EXTRACTION,
        ):
            _, analysis = self._make_analysis()
        resp = self.client.post(
            f"/api/enterprise/change-impact/{analysis.pk}/analyze/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "completed")
        self.assertEqual(resp.data["impact_level"], "high")

    def test_analyze_already_completed_rejected(self):
        from api.enterprise_document_intelligence_models import ChangeImpactAnalysis
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        from api.enterprise_document_intelligence_models import DocumentVersion
        v = DocumentVersion.objects.create(
            knowledge_source=ks, document=self.doc, version_number=1
        )
        analysis = ChangeImpactAnalysis.objects.create(
            company=self.company,
            knowledge_source=ks,
            status="completed",
        )
        resp = self.client.post(
            f"/api/enterprise/change-impact/{analysis.pk}/analyze/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# API Tests — KnowledgeGraphViewSet
# ---------------------------------------------------------------------------

class KnowledgeGraphAPITest(TestCase):

    def setUp(self):
        self.owner = make_user("graph_owner7")
        self.company = make_company(self.owner, name="GraphCo7")
        make_membership(self.owner, self.company, role="admin")
        self.project = make_project(self.owner)
        self.doc = make_document(self.project, self.owner)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)

    def test_empty_graph(self):
        resp = self.client.get(
            f"/api/enterprise/knowledge-graph/graph/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["node_count"], 0)
        self.assertEqual(resp.data["edge_count"], 0)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_graph_with_data(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/knowledge-graph/graph/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["node_count"], 3)
        self.assertEqual(resp.data["edge_count"], 2)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_nodes_endpoint(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/knowledge-graph/nodes/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 3)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_filter_nodes_by_type(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/knowledge-graph/nodes/?company_id={self.company.id}&node_type=concept"
        )
        self.assertEqual(resp.status_code, 200)
        for n in resp.data:
            self.assertEqual(n["node_type"], "concept")

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_relationships_endpoint(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        ks = make_knowledge_source(self.company, self.doc, self.owner)
        DocumentIntelligenceService.process_knowledge_source(ks.pk)
        resp = self.client.get(
            f"/api/enterprise/knowledge-graph/relationships/?company_id={self.company.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data), 2)


# ---------------------------------------------------------------------------
# Tenant Isolation Tests
# ---------------------------------------------------------------------------

class Phase7TenantIsolationTest(TestCase):

    def setUp(self):
        self.owner_a = make_user("ti_owner_a7")
        self.owner_b = make_user("ti_owner_b7")
        self.company_a = make_company(self.owner_a, name="TI-A7", slug="ti-a7")
        self.company_b = make_company(self.owner_b, name="TI-B7", slug="ti-b7")
        make_membership(self.owner_a, self.company_a, role="admin")
        make_membership(self.owner_b, self.company_b, role="admin")
        self.project_a = make_project(self.owner_a)
        self.project_b = make_project(self.owner_b)
        self.doc_a = make_document(self.project_a, self.owner_a, text="Company A document.")
        self.doc_b = make_document(self.project_b, self.owner_b, text="Company B document.")
        self.ks_a = make_knowledge_source(self.company_a, self.doc_a, self.owner_a, title="KS-A")
        self.ks_b = make_knowledge_source(self.company_b, self.doc_b, self.owner_b, title="KS-B")

    def test_company_a_cannot_see_company_b_sources(self):
        client = APIClient()
        client.force_authenticate(user=self.owner_a)
        resp = client.get(
            f"/api/enterprise/knowledge-sources/?company_id={self.company_a.id}"
        )
        self.assertEqual(resp.status_code, 200)
        ids = [r["id"] for r in resp.data]
        self.assertIn(self.ks_a.pk, ids)
        self.assertNotIn(self.ks_b.pk, ids)

    def test_company_a_cannot_retrieve_company_b_source(self):
        client = APIClient()
        client.force_authenticate(user=self.owner_a)
        resp = client.get(
            f"/api/enterprise/knowledge-sources/{self.ks_b.pk}/?company_id={self.company_a.id}"
        )
        self.assertEqual(resp.status_code, 404)

    @patch(
        "api.enterprise.services.document_intelligence_service.DocumentIntelligenceService._extract_with_ai",
        return_value=_FAKE_EXTRACTION,
    )
    def test_knowledge_graph_scoped_to_company(self, mock_ai):
        from api.enterprise.services.document_intelligence_service import DocumentIntelligenceService
        DocumentIntelligenceService.process_knowledge_source(self.ks_a.pk)
        DocumentIntelligenceService.process_knowledge_source(self.ks_b.pk)

        client_a = APIClient()
        client_a.force_authenticate(user=self.owner_a)
        resp = client_a.get(
            f"/api/enterprise/knowledge-graph/nodes/?company_id={self.company_a.id}"
        )
        self.assertEqual(resp.status_code, 200)
        # All returned nodes belong to company A
        from api.enterprise_document_intelligence_models import KnowledgeNode
        node_ids = [n["id"] for n in resp.data]
        for nid in node_ids:
            node = KnowledgeNode.objects.get(pk=nid)
            self.assertEqual(node.company_id, self.company_a.id)

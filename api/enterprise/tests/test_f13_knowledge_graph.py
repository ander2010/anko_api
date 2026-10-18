"""F-13: the knowledge graph is built from the process structure (topics, tags, procedures)."""
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from rest_framework.test import APITestCase

from api.enterprise.services.knowledge_graph_builder import build_knowledge_graph, sync_graph_for_documents
from api.enterprise.tests.process_fixtures import make_process_with_generated_topic
from api.enterprise_document_intelligence_models import KnowledgeNode, KnowledgeRelationship, Procedure
from api.enterprise_models import Company, CompanyMembership
from api.models import User

GRAPH = "/api/enterprise/knowledge-graph/graph/"


class KnowledgeGraphTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_routes_rbac", verbosity=0)
        cls.owner = User.objects.create_user("f13", "f13@test.com", "Pass123!")
        cls.company = Company.objects.create(name="F13", slug="f13", owner=cls.owner)
        CompanyMembership.objects.create(user=cls.owner, company=cls.company, role="owner", status="active")

    def setUp(self):
        self.client.force_authenticate(self.owner)
        self.ks, self.topic, self.doc, _ = make_process_with_generated_topic(
            self.company, self.owner, tags=("safety", "Helmets"))
        Procedure.objects.create(company=self.company, knowledge_source=self.ks, title="Lockout", is_critical=True)
        self.q = f"?company_id={self.company.id}"

    def graph(self):
        return self.client.get(f"{GRAPH}{self.q}&knowledge_source_id={self.ks.id}").data

    def types(self):
        return sorted(KnowledgeNode.objects.filter(source=self.ks).values_list("node_type", flat=True))

    def test_build_creates_process_topic_concepts_and_procedure(self):
        stats = build_knowledge_graph(self.ks)
        self.assertEqual(self.types(), ["concept", "concept", "document", "procedure", "topic"])
        self.assertEqual(KnowledgeRelationship.objects.filter(source_node__source=self.ks).count(), 4)
        self.assertEqual((stats["topics"], stats["concepts"], stats["procedures"]), (1, 2, 1))
        self.ks.refresh_from_db()
        self.assertEqual(self.ks.extracted_topics_count, 1)
        g = self.graph()
        self.assertEqual((g["node_count"], g["edge_count"]), (5, 4))
        self.assertIn("source_id", g["nodes"][0])

    def test_rebuild_is_idempotent_and_keeps_ai_nodes(self):
        ai = KnowledgeNode.objects.create(company=self.company, source=self.ks, title="AI concept", node_type="concept")
        build_knowledge_graph(self.ks)
        again = build_knowledge_graph(self.ks)
        self.assertEqual((again["nodes_created"], again["nodes_updated"], again["relationships_created"]), (0, 0, 0))
        Procedure.objects.all().delete()
        third = build_knowledge_graph(self.ks)
        self.assertEqual(third["nodes_deleted"], 1)
        self.assertTrue(KnowledgeNode.objects.filter(pk=ai.pk).exists())

    def test_manual_topic_is_added_to_the_graph(self):
        build_knowledge_graph(self.ks)
        r = self.client.post(f"/api/enterprise/knowledge-sources/{self.ks.id}/topics/{self.q}",
                             {"title": "QA-TEST EPP", "tags": ["boots", "helmets"]}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        titles = set(KnowledgeNode.objects.filter(source=self.ks).values_list("title", flat=True))
        self.assertTrue({"QA-TEST EPP", "boots", "Helmets"} <= titles)
        self.assertEqual(KnowledgeNode.objects.filter(source=self.ks, node_type="concept").count(), 3)  # helmets shared

    def test_auto_generate_finalize_hook_and_error_isolation(self):
        sync_graph_for_documents([self.doc.id])
        self.assertEqual(len(self.types()), 5)
        with patch("api.enterprise.services.knowledge_graph_builder.build_knowledge_graph", side_effect=RuntimeError("boom")):
            sync_graph_for_documents([self.doc.id])  # must not raise

    def test_dry_run_command_saves_nothing_and_real_run_does(self):
        out = StringIO()
        call_command("build_knowledge_graph", "--all", "--dry-run", stdout=out)
        self.assertIn("DRY RUN", out.getvalue())
        self.assertIn("+5", out.getvalue())
        self.assertFalse(KnowledgeNode.objects.exists())
        call_command("build_knowledge_graph", "--ks", str(self.ks.id), stdout=StringIO())
        self.assertEqual(KnowledgeNode.objects.count(), 5)

    def test_rebuild_endpoint_permissions(self):
        r = self.client.post(f"/api/enterprise/knowledge-graph/rebuild/{self.q}&knowledge_source_id={self.ks.id}")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual((r.data["node_count"], r.data["edge_count"]), (5, 4))
        employee = User.objects.create_user("f13e", "f13e@test.com", "Pass123!")
        CompanyMembership.objects.create(user=employee, company=self.company, role="employee", status="active")
        self.client.force_authenticate(employee)
        self.assertEqual(self.client.post(f"/api/enterprise/knowledge-graph/rebuild/{self.q}").status_code, 403)
        self.assertEqual(self.client.get(f"{GRAPH}{self.q}").status_code, 200)  # viewing is unchanged

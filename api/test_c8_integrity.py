"""C8: topic names unique at DB level; the integrity report is read-only."""
from io import StringIO

from django.core.management import call_command
from django.db import IntegrityError, transaction
from rest_framework.test import APITestCase

from api.enterprise_document_intelligence_models import KnowledgeSource, KnowledgeSourceTopic
from api.enterprise_models import Company
from api.models import Deck, TagGroup, User


class IntegrityTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user("c8", "c8@test.com", "Pass123!")
        self.company = Company.objects.create(name="C8", slug="c8", owner=self.owner)
        self.ks = KnowledgeSource.objects.create(company=self.company, title="P")

    def test_topic_title_unique_per_process_case_insensitive(self):
        KnowledgeSourceTopic.objects.create(knowledge_source=self.ks, tag_group=TagGroup.objects.create(name="a"), title="EPP")
        with self.assertRaises(IntegrityError), transaction.atomic():
            KnowledgeSourceTopic.objects.create(knowledge_source=self.ks, tag_group=TagGroup.objects.create(name="b"), title="epp")
        other = KnowledgeSource.objects.create(company=self.company, title="Q")
        KnowledgeSourceTopic.objects.create(knowledge_source=other, tag_group=TagGroup.objects.create(name="c"), title="EPP")

    def test_integrity_report_is_read_only(self):
        KnowledgeSource.objects.filter(pk=self.ks.pk).update(minimum_passing_score=150)
        orphan = Deck.objects.create(project=None, owner=self.owner, title="orphan")
        out = StringIO()
        call_command("audit_data_integrity", "--details", stdout=out)
        text = out.getvalue()
        self.assertIn("KnowledgeSource.minimum_passing_score outside 0-100: 1", text)
        self.assertIn(f"ids=[{orphan.id}]", text)
        self.assertIn("Nothing was modified", text)
        self.ks.refresh_from_db()
        self.assertEqual(self.ks.minimum_passing_score, 150)
        self.assertTrue(Deck.objects.filter(pk=orphan.pk).exists())

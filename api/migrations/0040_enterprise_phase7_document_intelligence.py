"""
Phase 7 — Document Intelligence

Creates tables:
  enterprise_knowledge_sources
  enterprise_document_versions
  enterprise_procedures
  enterprise_change_impact_analyses
  enterprise_knowledge_nodes
  enterprise_knowledge_relationships
"""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0039_enterprise_phase5_certifications"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ------------------------------------------------------------------
        # enterprise_knowledge_sources
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="KnowledgeSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("source_type", models.CharField(
                    choices=[
                        ("policy", "Policy"),
                        ("procedure", "Procedure"),
                        ("regulation", "Regulation"),
                        ("manual", "Manual"),
                        ("training_material", "Training Material"),
                        ("other", "Other"),
                    ],
                    default="other",
                    max_length=30,
                )),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("processing", "Processing"),
                        ("processed", "Processed"),
                        ("failed", "Failed"),
                    ],
                    default="pending",
                    max_length=20,
                )),
                ("processing_started_at", models.DateTimeField(blank=True, null=True)),
                ("processing_completed_at", models.DateTimeField(blank=True, null=True)),
                ("extracted_topics_count", models.PositiveIntegerField(default=0)),
                ("extracted_procedures_count", models.PositiveIntegerField(default=0)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("business_unit", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to="api.businessunit",
                )),
                ("company", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to="api.company",
                )),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("document", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="knowledge_sources",
                    to="api.document",
                )),
                ("generated_training", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="knowledge_sources",
                    to="api.trainingprogram",
                )),
            ],
            options={
                "db_table": "enterprise_knowledge_sources",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["company", "status"], name="ent_ks_company_status_idx"),
                    models.Index(fields=["company", "source_type"], name="ent_ks_company_type_idx"),
                ],
            },
        ),

        # ------------------------------------------------------------------
        # enterprise_document_versions
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="DocumentVersion",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("version_number", models.PositiveIntegerField(default=1)),
                ("file_hash", models.CharField(blank=True, max_length=64)),
                ("content_hash", models.CharField(blank=True, max_length=64)),
                ("extracted_at", models.DateTimeField(blank=True, null=True)),
                ("summary", models.TextField(blank=True)),
                ("key_changes", models.JSONField(blank=True, default=list)),
                ("topic_count", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("document", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="document_versions",
                    to="api.document",
                )),
                ("knowledge_source", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="versions",
                    to="api.knowledgesource",
                )),
            ],
            options={
                "db_table": "enterprise_document_versions",
                "ordering": ["-version_number"],
            },
        ),
        migrations.AddConstraint(
            model_name="documentversion",
            constraint=models.UniqueConstraint(
                fields=["knowledge_source", "version_number"],
                name="uniq_doc_version_per_source",
            ),
        ),

        # ------------------------------------------------------------------
        # enterprise_procedures
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="Procedure",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("steps", models.JSONField(default=list)),
                ("warnings", models.JSONField(default=list)),
                ("references", models.JSONField(default=list)),
                ("order", models.PositiveIntegerField(default=0)),
                ("is_critical", models.BooleanField(default=False)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("company", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to="api.company",
                )),
                ("knowledge_source", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="procedures",
                    to="api.knowledgesource",
                )),
                ("topic", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="procedures",
                    to="api.topic",
                )),
            ],
            options={
                "db_table": "enterprise_procedures",
                "ordering": ["order"],
                "indexes": [
                    models.Index(fields=["company", "knowledge_source"], name="ent_proc_company_ks_idx"),
                    models.Index(fields=["company", "is_critical"], name="ent_proc_company_critical_idx"),
                ],
            },
        ),

        # ------------------------------------------------------------------
        # enterprise_change_impact_analyses
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="ChangeImpactAnalysis",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("analyzing", "Analyzing"),
                        ("completed", "Completed"),
                        ("failed", "Failed"),
                    ],
                    default="pending",
                    max_length=20,
                )),
                ("impact_level", models.CharField(
                    blank=True,
                    choices=[
                        ("low", "Low"),
                        ("medium", "Medium"),
                        ("high", "High"),
                        ("critical", "Critical"),
                    ],
                    max_length=10,
                    null=True,
                )),
                ("affected_topics", models.JSONField(default=list)),
                ("affected_learning_path_ids", models.JSONField(default=list)),
                ("affected_procedures", models.JSONField(default=list)),
                ("summary", models.TextField(blank=True)),
                ("recommendations", models.JSONField(default=list)),
                ("analyzed_at", models.DateTimeField(blank=True, null=True)),
                ("error_message", models.TextField(blank=True)),
                ("training_regenerated", models.BooleanField(default=False)),
                ("training_regenerated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("company", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to="api.company",
                )),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("knowledge_source", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="change_analyses",
                    to="api.knowledgesource",
                )),
                ("new_version", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="impact_as_new",
                    to="api.documentversion",
                )),
                ("old_version", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="impact_as_old",
                    to="api.documentversion",
                )),
            ],
            options={
                "db_table": "enterprise_change_impact_analyses",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["company", "status"], name="ent_cia_company_status_idx"),
                    models.Index(fields=["company", "impact_level"], name="ent_cia_company_impact_idx"),
                ],
            },
        ),

        # ------------------------------------------------------------------
        # enterprise_knowledge_nodes
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="KnowledgeNode",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("node_type", models.CharField(
                    choices=[
                        ("concept", "Concept"),
                        ("procedure", "Procedure"),
                        ("regulation", "Regulation"),
                        ("skill", "Skill"),
                        ("topic", "Topic"),
                        ("document", "Document"),
                        ("rule", "Rule"),
                    ],
                    default="concept",
                    max_length=20,
                )),
                ("description", models.TextField(blank=True)),
                ("importance_score", models.DecimalField(decimal_places=2, default=50, max_digits=5)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("company", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to="api.company",
                )),
                ("source", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="knowledge_nodes",
                    to="api.knowledgesource",
                )),
                ("topic", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="knowledge_nodes",
                    to="api.topic",
                )),
            ],
            options={
                "db_table": "enterprise_knowledge_nodes",
                "ordering": ["-importance_score"],
                "indexes": [
                    models.Index(fields=["company", "node_type"], name="ent_kn_company_type_idx"),
                    models.Index(fields=["company", "importance_score"], name="ent_kn_company_score_idx"),
                ],
            },
        ),

        # ------------------------------------------------------------------
        # enterprise_knowledge_relationships
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="KnowledgeRelationship",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("relationship_type", models.CharField(
                    choices=[
                        ("requires", "Requires"),
                        ("related_to", "Related To"),
                        ("contradicts", "Contradicts"),
                        ("extends", "Extends"),
                        ("supersedes", "Supersedes"),
                        ("depends_on", "Depends On"),
                    ],
                    max_length=20,
                )),
                ("strength", models.DecimalField(decimal_places=3, default=0.5, max_digits=4)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("company", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to="api.company",
                )),
                ("source_node", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="outgoing",
                    to="api.knowledgenode",
                )),
                ("target_node", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="incoming",
                    to="api.knowledgenode",
                )),
            ],
            options={
                "db_table": "enterprise_knowledge_relationships",
            },
        ),
        migrations.AddConstraint(
            model_name="knowledgerelationship",
            constraint=models.UniqueConstraint(
                fields=["source_node", "target_node", "relationship_type"],
                name="uniq_knowledge_relationship",
            ),
        ),
    ]

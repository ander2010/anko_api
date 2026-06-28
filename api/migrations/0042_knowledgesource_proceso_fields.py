"""
Migration 0042 — KnowledgeSource: add proceso configuration fields
  + process_type, difficulty, minimum_passing_score, estimated_duration_minutes
  + make document nullable (proceso can be created before uploading a document)
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0041_enterprise_phase8_company_api"),
    ]

    operations = [
        # Make document nullable — proceso can exist without a document
        migrations.AlterField(
            model_name="knowledgesource",
            name="document",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="knowledge_sources",
                to="api.document",
            ),
        ),
        # Proceso configuration fields
        migrations.AddField(
            model_name="knowledgesource",
            name="process_type",
            field=models.CharField(
                choices=[
                    ("study_material", "Study Material"),
                    ("tutorial", "Tutorial"),
                    ("course", "Course"),
                ],
                default="course",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="knowledgesource",
            name="difficulty",
            field=models.CharField(
                choices=[
                    ("easy", "Easy"),
                    ("medium", "Medium"),
                    ("hard", "Hard"),
                ],
                default="medium",
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name="knowledgesource",
            name="minimum_passing_score",
            field=models.PositiveIntegerField(blank=True, default=70, null=True),
        ),
        migrations.AddField(
            model_name="knowledgesource",
            name="estimated_duration_minutes",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]

"""
Phase 8 — Company Management API + Module Improvements

Changes:
  LearningModule: +process_type, +difficulty, +minimum_passing_score
  LearningPath:   +final_battery FK
"""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0040_enterprise_phase7_document_intelligence"),
    ]

    operations = [
        # ------------------------------------------------------------------
        # LearningPath — final_battery FK
        # ------------------------------------------------------------------
        migrations.AddField(
            model_name="learningpath",
            name="final_battery",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="final_battery_paths",
                to="api.battery",
            ),
        ),

        # ------------------------------------------------------------------
        # LearningModule — process_type, difficulty, minimum_passing_score
        # ------------------------------------------------------------------
        migrations.AddField(
            model_name="learningmodule",
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
            model_name="learningmodule",
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
            model_name="learningmodule",
            name="minimum_passing_score",
            field=models.PositiveIntegerField(blank=True, default=70, null=True),
        ),
    ]

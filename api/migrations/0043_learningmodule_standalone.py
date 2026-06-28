"""
Migration 0043 — LearningModule: standalone proceso support

Changes:
  1. Add company FK (nullable) to LearningModule
  2. Populate company from existing learning_path.company for all current records
  3. Make learning_path nullable (proceso can exist without a learning path)
"""

from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


def populate_module_company(apps, schema_editor):
    """Copy company from learning_path to each LearningModule."""
    LearningModule = apps.get_model("api", "LearningModule")
    for module in LearningModule.objects.select_related("learning_path").filter(
        learning_path__isnull=False
    ):
        module.company = module.learning_path.company
        module.save(update_fields=["company"])


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0042_knowledgesource_proceso_fields"),
    ]

    operations = [
        # 1. Add company column (nullable so existing rows don't fail)
        migrations.AddField(
            model_name="learningmodule",
            name="company",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="learning_modules",
                to="api.company",
            ),
        ),
        # 2. Populate company from existing learning_path.company
        migrations.RunPython(
            populate_module_company,
            reverse_code=migrations.RunPython.noop,
        ),
        # 3. Make learning_path nullable
        migrations.AlterField(
            model_name="learningmodule",
            name="learning_path",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="modules",
                to="api.learningpath",
            ),
        ),
        # 4. Update index to include company
        migrations.AddIndex(
            model_name="learningmodule",
            index=models.Index(
                fields=["company", "created_at"],
                name="enterprise_lm_company_created_idx",
            ),
        ),
    ]

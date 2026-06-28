"""
Migration 0044 — LearningPathAssignment: support assigning a proceso directly

Changes:
  - learning_path becomes nullable (was required)
  - learning_module FK added (optional, alternative to learning_path)
"""

from __future__ import annotations

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0043_learningmodule_standalone"),
    ]

    operations = [
        # Make learning_path nullable
        migrations.AlterField(
            model_name="learningpathassignment",
            name="learning_path",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="assignments",
                to="api.learningpath",
            ),
        ),
        # Add learning_module FK
        migrations.AddField(
            model_name="learningpathassignment",
            name="learning_module",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="assignments",
                to="api.learningmodule",
            ),
        ),
    ]

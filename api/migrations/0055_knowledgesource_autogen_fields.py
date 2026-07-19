"""
Migration 0055 — KnowledgeSource: add auto-generation preference fields
  + cards_per_group, questions_per_group, question_format

These are the defaults applied when POST /process-runs/auto-generate/
runs for this proceso's documents, chosen by the user on the New Process
wizard's Configuration step (previously hardcoded in the frontend call).
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0054_alter_emaillog_email_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="knowledgesource",
            name="cards_per_group",
            field=models.PositiveIntegerField(default=20),
        ),
        migrations.AddField(
            model_name="knowledgesource",
            name="questions_per_group",
            field=models.PositiveIntegerField(default=15),
        ),
        migrations.AddField(
            model_name="knowledgesource",
            name="question_format",
            field=models.CharField(
                choices=[
                    ("true_false", "True/False"),
                    ("multiple_choice", "Multiple Choice"),
                    ("variety", "Variety"),
                ],
                default="multiple_choice",
                max_length=20,
            ),
        ),
    ]

"""
F-09: topics created by hand inside a process ("+ Add topic").

Only creates a new table; existing data is not modified.

Hand-written: makemigrations would also drop the UNUSED-CLEANUP models' tables.
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("api", "0059_learn_sessions"),
    ]

    operations = [
        migrations.CreateModel(
            name="KnowledgeSourceTopic",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("order", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("knowledge_source", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="manual_topics", to="api.knowledgesource")),
                ("tag_group", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="knowledge_source_topic", to="api.taggroup")),
            ],
            options={
                "db_table": "enterprise_knowledge_source_topics",
                "ordering": ["order", "id"],
            },
        ),
    ]

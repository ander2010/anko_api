"""
Round 3 (additive only): language detection (16) and quarantine of old disallowed uploads (B2).

Adds nullable/defaulted columns; no existing row is modified.
Hand-written: makemigrations would also drop the UNUSED-CLEANUP models' tables.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0060_knowledge_source_topics"),
    ]

    operations = [
        migrations.AddField(model_name="document", name="language",
                            field=models.CharField(blank=True, default="", max_length=12)),
        migrations.AddField(model_name="document", name="quarantined_at",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="document", name="quarantine_reason",
                            field=models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField(model_name="document", name="quarantine_original_key",
                            field=models.CharField(blank=True, default="", max_length=500)),
        migrations.AddField(model_name="knowledgesource", name="language",
                            field=models.CharField(blank=True, default="", max_length=12)),
    ]

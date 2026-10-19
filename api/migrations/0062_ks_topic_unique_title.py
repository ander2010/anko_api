"""
C8 (additive): topic names unique per process, case-insensitive, at database level.

The API already rejects duplicates (F-09), so existing rows comply; the table is new.
Hand-written: makemigrations would also drop the UNUSED-CLEANUP models' tables.
"""
import django.db.models.functions.text
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0061_document_language_quarantine"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="knowledgesourcetopic",
            constraint=models.UniqueConstraint(
                models.F("knowledge_source"), django.db.models.functions.text.Lower("title"),
                name="uniq_ks_topic_title_ci",
            ),
        ),
    ]

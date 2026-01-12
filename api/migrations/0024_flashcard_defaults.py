from django.db import migrations


SQL = r"""
ALTER TABLE api_flashcard
  ALTER COLUMN created_at SET DEFAULT NOW(),
  ALTER COLUMN updated_at SET DEFAULT NOW();
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0024_alter_flashcard_notes"),
    ]

    operations = [
        migrations.RunSQL(SQL, reverse_sql=""),
    ]

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0021_drop_sections_table"),
    ]

    operations = [
        migrations.RunSQL(
            "DROP TABLE IF EXISTS flashcards CASCADE;",
            reverse_sql="",
        ),
    ]

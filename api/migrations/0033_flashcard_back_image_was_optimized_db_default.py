from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0032_flashcard_image_optimization_fields"),
    ]

    operations = [
        migrations.RunSQL(
            sql=(
                "ALTER TABLE api_flashcard "
                "ALTER COLUMN back_image_was_optimized SET DEFAULT FALSE;"
            ),
            reverse_sql=(
                "ALTER TABLE api_flashcard "
                "ALTER COLUMN back_image_was_optimized DROP DEFAULT;"
            ),
        ),
    ]

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0020_point_pipeline_to_api_document"),
    ]

    operations = [
        migrations.RunSQL(
            "DROP TABLE IF EXISTS sections CASCADE;",
            reverse_sql="",
        ),
    ]

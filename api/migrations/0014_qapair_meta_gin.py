from django.db import migrations
from django.contrib.postgres.indexes import GinIndex


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0013_documentuploadevent"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="qapair",
            index=GinIndex(fields=["meta"], name="qapairs_meta_gin"),
        ),
    ]

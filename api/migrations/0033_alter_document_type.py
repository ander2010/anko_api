from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0032_flashcard_image_optimization_fields"),
    ]

    operations = [
        migrations.AlterField(
            model_name="document",
            name="type",
            field=models.CharField(max_length=20),
        ),
    ]

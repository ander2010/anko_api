from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0031_flashcard_back_image_size_bytes"),
    ]

    operations = [
        migrations.AddField(
            model_name="flashcard",
            name="back_image_original_size_bytes",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flashcard",
            name="back_image_was_optimized",
            field=models.BooleanField(default=False),
        ),
    ]

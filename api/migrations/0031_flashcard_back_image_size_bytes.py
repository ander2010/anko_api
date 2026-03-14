from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0030_flashcard_back_image_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="flashcard",
            name="back_image_size_bytes",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]

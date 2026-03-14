from django.db import migrations, models

import api.models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0029_rename_notificatio_key_1d38d4_idx_notificatio_key_b9d77c_idx_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="flashcard",
            name="back_image",
            field=models.ImageField(blank=True, null=True, upload_to=api.models.flashcard_back_image_upload_to),
        ),
        migrations.AddField(
            model_name="flashcard",
            name="back_image_height",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flashcard",
            name="back_image_width",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]

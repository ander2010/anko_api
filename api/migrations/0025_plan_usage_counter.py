from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0024_drop_recreate_notifications"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlanUsageCounter",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "metric",
                    models.CharField(
                        choices=[
                            ("documents_uploaded", "Documents Uploaded"),
                            ("ask_queries", "Ask Queries"),
                            ("flashcard_jobs", "Flashcard Jobs"),
                        ],
                        db_index=True,
                        max_length=40,
                    ),
                ),
                ("used", models.PositiveIntegerField(default=0)),
                ("period_start", models.DateTimeField(db_index=True)),
                ("period_end", models.DateTimeField(db_index=True)),
                ("plan_tier_snapshot", models.CharField(blank=True, default="", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="plan_usage_counters",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "plan_usage_counters",
            },
        ),
        migrations.AddConstraint(
            model_name="planusagecounter",
            constraint=models.UniqueConstraint(
                fields=("user", "metric", "period_start", "period_end"),
                name="uniq_usage_user_metric_period",
            ),
        ),
        migrations.AddIndex(
            model_name="planusagecounter",
            index=models.Index(fields=["user", "metric", "period_end"], name="plan_usage_c_user_id_6a0d40_idx"),
        ),
    ]

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0025_plan_usage_counter"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("operation", models.CharField(db_index=True, max_length=120)),
                ("resource_type", models.CharField(blank=True, default="", max_length=80)),
                ("resource_id", models.CharField(blank=True, default="", max_length=120)),
                ("success", models.BooleanField(db_index=True, default=False)),
                ("status_code", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("error_message", models.TextField(blank=True, default="")),
                ("request_id", models.CharField(blank=True, db_index=True, default="", max_length=64)),
                ("method", models.CharField(blank=True, default="", max_length=16)),
                ("path", models.CharField(blank=True, db_index=True, default="", max_length=255)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, default="", max_length=255)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "audit_logs",
            },
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["created_at", "success"], name="audit_logs_created_0b359a_idx"),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["user", "created_at"], name="audit_logs_user_id_fbfd51_idx"),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["operation", "created_at"], name="audit_logs_operati_b6eb3e_idx"),
        ),
    ]

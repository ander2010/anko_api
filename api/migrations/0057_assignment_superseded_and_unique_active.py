"""
F-02: prevent duplicate active assignments.

1. Adds the "superseded" status plus superseded_by / status_before_superseded.
2. Consolidates existing duplicates (no rows deleted; reversible).
3. Adds partial unique constraints so only one active assignment can exist.

Preview first:  python manage.py consolidate_duplicate_assignments   (dry-run)
Rollback:       python manage.py migrate api 0056   (restores superseded rows)

Hand-written on purpose: makemigrations would also pick up the models commented out
by UNUSED-CLEANUP and drop their tables, which must not happen in this change.
"""
import django.db.models.deletion
from django.db import migrations, models

LP_ACTIVE = models.Q(status__in=("pending", "in_progress", "overdue"))
COMPLIANCE_ACTIVE = models.Q(status__in=("pending", "in_progress"))

LP_STATUS = [
    ("pending", "Pending"),
    ("in_progress", "In Progress"),
    ("completed", "Completed"),
    ("overdue", "Overdue"),
    ("superseded", "Superseded"),
]
COMPLIANCE_STATUS = [
    ("pending", "Pending"),
    ("in_progress", "In Progress"),
    ("completed", "Completed"),
    ("expired", "Expired"),
    ("non_compliant", "Non-Compliant"),
    ("waived", "Waived"),
    ("superseded", "Superseded"),
]


def consolidate_duplicates(apps, schema_editor):
    from api.enterprise.services.assignment_dedup import consolidate

    report = consolidate(
        apps.get_model("api", "LearningPathAssignment"),
        apps.get_model("api", "LearningModuleProgress"),
        apps.get_model("api", "ComplianceAssignment"),
        apply=True,
    )
    print(
        f"\n  superseded duplicates: learning={report['learning']['changed']} "
        f"compliance={report['compliance']['changed']}"
    )


def restore_duplicates(apps, schema_editor):
    from api.enterprise.services.assignment_dedup import revert

    report = revert(
        apps.get_model("api", "LearningPathAssignment"),
        apps.get_model("api", "ComplianceAssignment"),
        apply=True,
    )
    print(f"\n  restored: learning={report['learning']['rows']} compliance={report['compliance']['rows']}")


def superseded_fields(model_name, related_name):
    return [
        migrations.AddField(
            model_name=model_name,
            name="status_before_superseded",
            field=models.CharField(blank=True, default="", max_length=20),
        ),
        migrations.AddField(
            model_name=model_name,
            name="superseded_by",
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                related_name=related_name, to=f"api.{model_name}",
            ),
        ),
    ]


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0056_alter_supportrequest_user"),
    ]

    operations = [
        *superseded_fields("learningpathassignment", "superseded_duplicates"),
        *superseded_fields("complianceassignment", "superseded_duplicates"),
        migrations.AlterField(
            model_name="learningpathassignment",
            name="status",
            field=models.CharField(choices=LP_STATUS, default="pending", max_length=20),
        ),
        migrations.AlterField(
            model_name="complianceassignment",
            name="status",
            field=models.CharField(choices=COMPLIANCE_STATUS, default="pending", max_length=20),
        ),
        migrations.RunPython(consolidate_duplicates, restore_duplicates),
        migrations.AddConstraint(
            model_name="learningpathassignment",
            constraint=models.UniqueConstraint(
                condition=LP_ACTIVE & models.Q(user__isnull=False, learning_path__isnull=False),
                fields=("user", "learning_path"),
                name="uniq_active_user_learning_path",
            ),
        ),
        migrations.AddConstraint(
            model_name="learningpathassignment",
            constraint=models.UniqueConstraint(
                condition=LP_ACTIVE & models.Q(user__isnull=False, learning_module__isnull=False, learning_path__isnull=True),
                fields=("user", "learning_module"),
                name="uniq_active_user_learning_module",
            ),
        ),
        migrations.AddConstraint(
            model_name="learningpathassignment",
            constraint=models.UniqueConstraint(
                condition=LP_ACTIVE & models.Q(user__isnull=True, team__isnull=False, learning_path__isnull=False),
                fields=("team", "learning_path"),
                name="uniq_active_team_learning_path",
            ),
        ),
        migrations.AddConstraint(
            model_name="learningpathassignment",
            constraint=models.UniqueConstraint(
                condition=LP_ACTIVE & models.Q(user__isnull=True, team__isnull=False, learning_module__isnull=False, learning_path__isnull=True),
                fields=("team", "learning_module"),
                name="uniq_active_team_learning_module",
            ),
        ),
        migrations.AddConstraint(
            model_name="complianceassignment",
            constraint=models.UniqueConstraint(
                condition=COMPLIANCE_ACTIVE & models.Q(user__isnull=False),
                fields=("user", "program"),
                name="uniq_active_user_compliance_program",
            ),
        ),
        migrations.AddConstraint(
            model_name="complianceassignment",
            constraint=models.UniqueConstraint(
                condition=COMPLIANCE_ACTIVE & models.Q(user__isnull=True, team__isnull=False),
                fields=("team", "program"),
                name="uniq_active_team_compliance_program",
            ),
        ),
    ]

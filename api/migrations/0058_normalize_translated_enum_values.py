"""
F-03: stored enum values must be stable English keys. Converts translated values
("Claro." -> "course", "pendientes" -> "pending", ...) and records each change in
enum_value_backups so the reverse migration can restore them.

Preview first:  python manage.py normalize_enum_values          (dry-run)
Rollback:       python manage.py migrate api 0057

Hand-written (see 0057 for why makemigrations must not be used right now).
"""
from django.db import migrations, models


def forward(apps, schema_editor):
    from api.services.enum_normalization import normalize

    findings = normalize(
        lambda name: apps.get_model("api", name), apps.get_model("api", "EnumValueBackup"), apply=True,
    )
    changed = sum(item.get("changed", 0) for item in findings)
    unknown = [f"{i['table']}.{i['field']}={i['value']!r}" for i in findings if not i["target"]]
    print(f"\n  normalized enum rows: {changed}; unknown values left untouched: {unknown or 'none'}")


def backward(apps, schema_editor):
    from api.services.enum_normalization import restore

    restored = restore(lambda name: apps.get_model("api", name), apps.get_model("api", "EnumValueBackup"))
    print(f"\n  restored enum rows: {restored}")


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0057_assignment_superseded_and_unique_active"),
    ]

    operations = [
        migrations.CreateModel(
            name="EnumValueBackup",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("table_name", models.CharField(max_length=100)),
                ("row_id", models.BigIntegerField()),
                ("field_name", models.CharField(max_length=60)),
                ("old_value", models.CharField(max_length=255)),
                ("new_value", models.CharField(max_length=60)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "enum_value_backups",
                "indexes": [models.Index(fields=["table_name", "row_id"], name="enum_value__table_n_idx")],
            },
        ),
        migrations.RunPython(forward, backward),
    ]

"""
Report (default) or apply the normalization of translated enum values (F-03).

    python manage.py normalize_enum_values           # dry-run: lists every invalid value per field
    python manage.py normalize_enum_values --apply   # after migration 0058 (idempotent)

Migration 0058 already applies it; roll back with `migrate api 0057` to restore originals.
"""
from django.apps import apps
from django.core.management.base import BaseCommand

from api.services.enum_normalization import normalize


class Command(BaseCommand):
    help = "Preview (default) or apply the conversion of translated enum values to their keys."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Write the changes (recorded in enum_value_backups).")

    def handle(self, *args, apply=False, **options):
        EnumValueBackup = apps.get_model("api", "EnumValueBackup")
        findings = normalize(lambda name: apps.get_model("api", name), EnumValueBackup, apply=apply)
        self.stdout.write(self.style.WARNING("APPLIED" if apply else "DRY-RUN (nothing changed)"))
        if not findings:
            self.stdout.write("No translated or invalid enum values found.")
        for item in findings:
            target = item["target"] or "UNKNOWN (left untouched, review manually)"
            self.stdout.write(f"{item['table']}.{item['field']}: {item['value']!r} -> {target}  ({item['rows']} rows)")
        total = sum(i["rows"] for i in findings if i["target"])
        self.stdout.write(f"Rows {'changed' if apply else 'to change'}: {total}")

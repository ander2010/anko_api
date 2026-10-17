"""
F-03: normalize enum values that were stored translated ("Claro." -> "course").

Stored enum values must always be the stable English key from the field's
``choices``. This module finds values that are not valid keys and maps them
with an explicit table (or a case-insensitive key match). Unknown values are
reported and left untouched for manual review.

Every change is written to ``EnumValueBackup`` so it can be reverted.
Used by migration 0058 and ``manage.py normalize_enum_values`` (dry-run by default).
"""
from collections import Counter

# Model label -> enum fields to check.
ENUM_FIELDS = {
    "KnowledgeSource": ("process_type", "difficulty", "source_type", "status", "question_format"),
    "LearningModule": ("process_type", "difficulty"),
    "Document": ("status",),
}

# Known translated variants (machine translation of the key/label) -> key.
TRANSLATED_VALUES = {
    "process_type": {
        "Claro.": "course", "Claro": "course", "claro": "course", "Por supuesto": "course",
        "curso": "course", "Curso": "course",
        "Tutoría": "tutorial", "tutoría": "tutorial",
        "material de estudio": "study_material", "Material de estudio": "study_material",
        "Material de Estudio": "study_material", "material_de_estudio": "study_material",
    },
    "difficulty": {
        "fácil": "easy", "Fácil": "easy", "facil": "easy", "Facil": "easy",
        "mediano": "medium", "Mediano": "medium", "medio": "medium", "Medio": "medium",
        "media": "medium", "Media": "medium",
        "difícil": "hard", "Difícil": "hard", "dificil": "hard", "Dificil": "hard", "duro": "hard", "Duro": "hard",
    },
    "source_type": {
        "otros": "other", "Otros": "other", "otro": "other", "Otro": "other",
        "política": "policy", "Política": "policy", "politica": "policy",
        "procedimiento": "procedure", "Procedimiento": "procedure",
        "regulación": "regulation", "Regulación": "regulation", "reglamento": "regulation", "Reglamento": "regulation",
        "material de formación": "training_material", "Material de formación": "training_material",
        "material de capacitación": "training_material", "Material de capacitación": "training_material",
    },
    "status": {
        "pendientes": "pending", "pendiente": "pending", "Pendiente": "pending", "Pendientes": "pending",
        "procesamiento": "processing", "Procesamiento": "processing", "procesando": "processing", "Procesando": "processing",
        "procesado": "processed", "Procesado": "processed",
        "listo": "ready", "Listo": "ready", "lista": "ready",
        "fallido": "failed", "Fallido": "failed", "falló": "failed", "error": "failed", "Error": "failed",
    },
    "question_format": {
        "verdadero_falso": "true_false", "Verdadero/Falso": "true_false", "verdadero/falso": "true_false",
        "opción múltiple": "multiple_choice", "Opción múltiple": "multiple_choice", "opcion_multiple": "multiple_choice",
        "variedad": "variety", "Variedad": "variety",
    },
}


def _resolve(field, value, valid):
    """Return the key for a stored value, or None if it can't be mapped safely."""
    mapped = TRANSLATED_VALUES.get(field, {}).get(value)
    if mapped in valid:
        return mapped
    lowered = str(value).strip().lower()
    if lowered in valid:
        return lowered
    return None


def plan(get_model):
    """
    Scan every enum field. Returns a list of dicts:
    {model, table, field, value, rows, target}  (target None = unknown, left untouched)
    """
    findings = []
    for model_name, fields in ENUM_FIELDS.items():
        Model = get_model(model_name)
        for field in fields:
            valid = {key for key, _ in Model._meta.get_field(field).choices}
            counts = Counter(
                row[field] for row in Model.objects.exclude(**{f"{field}__in": valid}).values(field)
            )
            for value, rows in counts.items():
                if value in (None, ""):
                    continue
                findings.append({
                    "model": model_name,
                    "table": Model._meta.db_table,
                    "field": field,
                    "value": value,
                    "rows": rows,
                    "target": _resolve(field, value, valid),
                })
    return findings


def normalize(get_model, EnumValueBackup, *, apply):
    """Apply the plan (when ``apply``) recording every row change. Returns the plan."""
    findings = plan(get_model)
    if not apply:
        return findings
    for item in findings:
        if not item["target"]:
            continue
        Model = get_model(item["model"])
        qs = Model.objects.filter(**{item["field"]: item["value"]})
        backups = [
            EnumValueBackup(
                table_name=item["table"], row_id=row_id, field_name=item["field"],
                old_value=item["value"], new_value=item["target"],
            )
            for row_id in qs.values_list("pk", flat=True)
        ]
        EnumValueBackup.objects.bulk_create(backups)
        item["changed"] = qs.update(**{item["field"]: item["target"]})
    return findings


def restore(get_model, EnumValueBackup):
    """Revert every recorded change. Returns the number of rows restored."""
    tables = {get_model(name)._meta.db_table: get_model(name) for name in ENUM_FIELDS}
    restored = 0
    for backup in EnumValueBackup.objects.all().order_by("-id"):
        Model = tables.get(backup.table_name)
        if Model is None:
            continue
        restored += Model.objects.filter(
            pk=backup.row_id, **{backup.field_name: backup.new_value}
        ).update(**{backup.field_name: backup.old_value})
    EnumValueBackup.objects.all().delete()
    return restored

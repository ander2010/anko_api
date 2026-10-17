"""
Consolidate duplicate *active* assignments (F-02).

Duplicates are never deleted: extra rows get status="superseded", keep their
previous status in ``status_before_superseded`` and point to the kept row via
``superseded_by``. ``revert`` restores them. Both operations are idempotent.

Used by migration 0057 (with historical models) and by
``manage.py consolidate_duplicate_assignments`` (dry-run by default).

The dry-run only reads columns that exist before the migration, so it can be
run first to see how many rows the migration will change.
"""
from collections import defaultdict

LEARNING_ACTIVE = ("pending", "in_progress", "overdue")
COMPLIANCE_ACTIVE = ("pending", "in_progress")
SUPERSEDED = "superseded"

_STATUS_RANK = {"in_progress": 0, "overdue": 1, "pending": 2}


def _groups(rows, key_fields):
    groups = defaultdict(list)
    for row in rows:
        key = tuple(row[f] for f in key_fields)
        if all(v is None for v in key[:1]):
            continue
        groups[key].append(row)
    return [g for g in groups.values() if len(g) > 1]


def find_learning_duplicates(LearningPathAssignment, LearningModuleProgress):
    """Return [(keeper_id, [duplicate_ids]), ...] for learning path / module assignments."""
    fields = ("id", "user_id", "team_id", "learning_path_id", "learning_module_id", "status", "created_at")
    rows = list(LearningPathAssignment.objects.filter(status__in=LEARNING_ACTIVE).values(*fields))
    completed = defaultdict(int)
    for item in LearningModuleProgress.objects.filter(
        assignment_id__in=[r["id"] for r in rows], status="completed",
    ).values("assignment_id"):
        completed[item["assignment_id"]] += 1

    user_rows = [r for r in rows if r["user_id"] is not None]
    team_rows = [r for r in rows if r["user_id"] is None and r["team_id"] is not None]
    groups = _groups(user_rows, ("user_id", "learning_path_id", "learning_module_id"))
    groups += _groups(team_rows, ("team_id", "learning_path_id", "learning_module_id"))

    result = []
    for group in groups:
        # Keep the one with most progress; then the more advanced status; then the oldest.
        group.sort(key=lambda r: (-completed[r["id"]], _STATUS_RANK.get(r["status"], 9), r["created_at"], r["id"]))
        result.append((group[0]["id"], [r["id"] for r in group[1:]]))
    return result


def find_compliance_duplicates(ComplianceAssignment):
    fields = ("id", "user_id", "team_id", "program_id", "status", "created_at")
    rows = list(ComplianceAssignment.objects.filter(status__in=COMPLIANCE_ACTIVE).values(*fields))
    user_rows = [r for r in rows if r["user_id"] is not None]
    team_rows = [r for r in rows if r["user_id"] is None and r["team_id"] is not None]
    groups = _groups(user_rows, ("user_id", "program_id")) + _groups(team_rows, ("team_id", "program_id"))
    result = []
    for group in groups:
        group.sort(key=lambda r: (_STATUS_RANK.get(r["status"], 9), r["created_at"], r["id"]))
        result.append((group[0]["id"], [r["id"] for r in group[1:]]))
    return result


def _supersede(Model, duplicates):
    changed = 0
    for keeper_id, duplicate_ids in duplicates:
        for row in Model.objects.filter(id__in=duplicate_ids).exclude(status=SUPERSEDED).values("id", "status"):
            Model.objects.filter(id=row["id"]).update(
                status=SUPERSEDED,
                status_before_superseded=row["status"],
                superseded_by_id=keeper_id,
            )
            changed += 1
    return changed


def consolidate(LearningPathAssignment, LearningModuleProgress, ComplianceAssignment, *, apply):
    """Returns {"learning": {...}, "compliance": {...}} with groups / rows to change."""
    learning = find_learning_duplicates(LearningPathAssignment, LearningModuleProgress)
    compliance = find_compliance_duplicates(ComplianceAssignment)
    report = {
        "learning": {"groups": len(learning), "rows": sum(len(d) for _, d in learning), "details": learning},
        "compliance": {"groups": len(compliance), "rows": sum(len(d) for _, d in compliance), "details": compliance},
    }
    if apply:
        report["learning"]["changed"] = _supersede(LearningPathAssignment, learning)
        report["compliance"]["changed"] = _supersede(ComplianceAssignment, compliance)
    return report


def revert(LearningPathAssignment, ComplianceAssignment, *, apply):
    """Restore superseded rows to their previous status. Returns rows affected per model."""
    report = {}
    for label, Model in (("learning", LearningPathAssignment), ("compliance", ComplianceAssignment)):
        qs = Model.objects.filter(status=SUPERSEDED).exclude(status_before_superseded="")
        rows = list(qs.values("id", "status_before_superseded"))
        report[label] = {"rows": len(rows)}
        if apply:
            for row in rows:
                Model.objects.filter(id=row["id"]).update(
                    status=row["status_before_superseded"],
                    status_before_superseded="",
                    superseded_by_id=None,
                )
    return report

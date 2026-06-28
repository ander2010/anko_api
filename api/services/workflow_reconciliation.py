from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ReconciliationPolicy(StrEnum):
    MERGE = "merge"
    OVERRIDE = "override"
    KEEP_BOTH = "keep_both"


@dataclass(slots=True)
class ReconciliationPreview:
    # Placeholder response model for the first workflow preflight stage.
    # We keep the structure now so later conflict detection can fill it without
    # forcing another contract change.
    has_conflicts: bool
    suggested_policy: ReconciliationPolicy
    document_conflicts: list[dict[str, Any]] = field(default_factory=list)
    workspace_conflicts: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def preview_workspace_reconciliation(
    *,
    document_ids: list[int],
    workspace_id: int | None = None,
) -> ReconciliationPreview:
    """
    Placeholder for workspace/document conflict detection.

    Current behavior:
    - returns a stable preview shape
    - suggests `OVERRIDE` by default
    - does not yet perform duplicate/similarity analysis

    Future behavior:
    - detect overlapping documents already present in the workspace
    - detect replacement/version scenarios
    - decide whether to suggest merge / override / keep_both
    """
    _ = workspace_id  # reserved for the future implementation

    normalized_ids = sorted({int(doc_id) for doc_id in document_ids if doc_id is not None})
    return ReconciliationPreview(
        has_conflicts=False,
        suggested_policy=ReconciliationPolicy.OVERRIDE,
        notes=[
            "placeholder reconciliation preview",
            f"documents_received={len(normalized_ids)}",
        ],
    )

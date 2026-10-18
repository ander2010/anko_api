"""
C1: which companies a project-less deck/battery belongs to.

Decks and batteries of a process (KnowledgeSource) have no Project, so the old
rule "project is None and the user belongs to *some* company" let any member of
any company study, list or answer them. A project-less item now belongs to the
companies that reach it through:
  - a topic of their processes (DeckSourceTagGroup / BatterySourceTagGroup ->
    a hand-made KnowledgeSourceTopic, or an Auto-generate run over the process docs),
  - the Auto-generate run that produced it (ProcessArtifact deck/battery),
  - an item of one of their learning modules (LearningModuleItem).
"""
from __future__ import annotations


def _companies_of_runs(runs) -> set[int]:
    from api.enterprise_document_intelligence_models import KnowledgeSource, KnowledgeSourceDocument

    company_ids: set[int] = set()
    for resource_id in runs:
        try:
            doc_ids = {int(v) for v in str(resource_id or "").split(",") if v.strip()}
        except ValueError:
            continue
        if not doc_ids:
            continue
        ks_ids = set(
            KnowledgeSourceDocument.objects.filter(document_id__in=doc_ids).values_list("knowledge_source_id", flat=True)
        )
        company_ids |= set(KnowledgeSource.objects.filter(id__in=ks_ids).values_list("company_id", flat=True))
    return company_ids


def content_company_ids(*, deck=None, battery=None) -> set[int]:
    from api.enterprise_document_intelligence_models import KnowledgeSourceTopic
    from api.enterprise_learning_models import LearningModuleItem
    from api.models import BatterySourceTagGroup, DeckSourceTagGroup, ProcessArtifact

    if deck is not None:
        tag_group_ids = set(DeckSourceTagGroup.objects.filter(deck=deck).values_list("tag_group_id", flat=True))
        kind, obj, item_filter = "deck", deck, {"deck": deck}
    else:
        tag_group_ids = set(BatterySourceTagGroup.objects.filter(battery=battery).values_list("tag_group_id", flat=True))
        kind, obj, item_filter = "battery", battery, {"battery": battery}

    company_ids = set(
        KnowledgeSourceTopic.objects.filter(tag_group_id__in=tag_group_ids)
        .values_list("knowledge_source__company_id", flat=True)
    )
    artifacts = ProcessArtifact.objects.filter(
        run__workflow_key="collection_auto_generate", run__resource_type="document_batch",
    )
    run_resources = set(
        artifacts.filter(artifact_type=kind, resource_id=str(obj.id)).values_list("run__resource_id", flat=True)
    ) | set(
        artifacts.filter(artifact_type="tag_group", resource_id__in=[str(t) for t in tag_group_ids])
        .values_list("run__resource_id", flat=True)
    )
    company_ids |= _companies_of_runs(run_resources)
    company_ids |= set(
        LearningModuleItem.objects.filter(**item_filter).values_list("module__company_id", flat=True)
    )
    company_ids.discard(None)
    return company_ids


def user_can_access_company_content(user, *, deck=None, battery=None) -> bool:
    """True if the user is an active member of a company the project-less item belongs to."""
    from api.enterprise_models import CompanyMembership

    if getattr(user, "is_staff", False):
        return True  # platform admins already operate across companies (EnterpriseViewSetMixin)
    company_ids = content_company_ids(deck=deck, battery=battery)
    if not company_ids:
        return False
    return CompanyMembership.objects.filter(user=user, status="active", company_id__in=company_ids).exists()

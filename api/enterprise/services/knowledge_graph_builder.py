"""
F-13: builds the knowledge graph of a process from the structure it already has.

Nodes (all with source=<KnowledgeSource>):
  - the process itself      -> node_type "document"  (metadata.kind = "knowledge_source")
  - every topic (generated + hand-made) -> "topic"
  - every tag of a topic    -> "concept"  (one node per tag per process, case-insensitive)
  - every Procedure row     -> "procedure"
Edges ("related_to"): process -> topic, topic -> concept, process -> procedure.

Idempotent: every node it writes carries metadata {"builder": "structure", "key": ...}
and is matched by that key on the next run, so rebuilding updates in place and
removes only its own nodes that no longer exist. Nodes from the AI extraction
(DocumentIntelligenceService.process_knowledge_source) are never touched.
"""
from __future__ import annotations

import logging
from decimal import Decimal

from django.db import transaction

logger = logging.getLogger(__name__)

BUILDER = "structure"
EDGE = "related_to"


class _DryRun(Exception):
    pass


def _topics_of(ks) -> list[dict]:
    """[{tag_group_id, title, description, tags}] for generated + hand-made topics."""
    from api.enterprise.views.document_intelligence import _ks_generated_topics, _ks_manual_topics
    from api.models import TagGroup

    _, generated_ids, generated = _ks_generated_topics(ks)
    names = dict(TagGroup.objects.filter(id__in=generated_ids).values_list("id", "name"))
    topics = [
        {"tag_group_id": int(t["id"]), "title": names.get(int(t["id"])) or f"Topic {i}", "description": "", "tags": t["tags"] or []}
        for i, t in enumerate(generated, start=1)
    ]
    seen = {t["tag_group_id"] for t in topics}
    for manual in _ks_manual_topics(ks):
        if manual.tag_group_id in seen:
            continue
        topics.append({
            "tag_group_id": manual.tag_group_id,
            "title": manual.title,
            "description": manual.description,
            "tags": [item.value for item in manual.tag_group.items.all()],
        })
    return topics


def build_knowledge_graph(ks, *, dry_run: bool = False) -> dict:
    """Syncs the structure graph of one KnowledgeSource. Returns counts (also in dry-run)."""
    from api.enterprise_document_intelligence_models import KnowledgeNode, KnowledgeRelationship, Procedure

    stats = {
        "knowledge_source_id": ks.id, "topics": 0, "concepts": 0, "procedures": 0,
        "nodes_created": 0, "nodes_updated": 0, "nodes_deleted": 0,
        "relationships_created": 0, "relationships_deleted": 0, "dry_run": dry_run,
    }
    try:
        with transaction.atomic():
            existing = {
                n.metadata.get("key"): n
                for n in KnowledgeNode.objects.filter(company=ks.company, source=ks, metadata__builder=BUILDER)
            }
            wanted_keys: set[str] = set()
            wanted_edges: set[tuple[int, int]] = set()

            def upsert(key, *, node_type, title, description="", importance=50, extra=None):
                wanted_keys.add(key)
                fields = {
                    "node_type": node_type, "title": title[:255], "description": description or "",
                    "importance_score": Decimal(str(importance)),
                    "metadata": {"builder": BUILDER, "key": key, **(extra or {})},
                }
                node = existing.get(key)
                if node is None:
                    node = KnowledgeNode.objects.create(company=ks.company, source=ks, **fields)
                    existing[key] = node
                    stats["nodes_created"] += 1
                elif any(getattr(node, f) != v for f, v in fields.items()):
                    for f, v in fields.items():
                        setattr(node, f, v)
                    node.save(update_fields=[*fields, "updated_at"])
                    stats["nodes_updated"] += 1
                return node

            def link(source, target, strength):
                wanted_edges.add((source.id, target.id))
                _, created = KnowledgeRelationship.objects.get_or_create(
                    source_node=source, target_node=target, relationship_type=EDGE,
                    defaults={"company": ks.company, "strength": Decimal(str(strength))},
                )
                stats["relationships_created"] += int(created)

            root = upsert(f"ks:{ks.id}", node_type="document", title=ks.title, description=ks.description,
                          importance=90, extra={"kind": "knowledge_source"})

            topics = _topics_of(ks)
            tag_usage: dict[str, int] = {}
            tag_spelling: dict[str, str] = {}
            for topic in topics:
                for tag in topic["tags"]:
                    low = tag.strip().lower()
                    if low:
                        tag_usage[low] = tag_usage.get(low, 0) + 1
                        tag_spelling.setdefault(low, tag.strip())

            concepts = {
                low: upsert(f"concept:{ks.id}:{low}", node_type="concept", title=tag_spelling[low],
                            importance=min(90, 40 + 10 * count))
                for low, count in tag_usage.items()
            }
            for topic in topics:
                node = upsert(f"topic:{topic['tag_group_id']}", node_type="topic", title=topic["title"],
                              description=topic["description"] or ", ".join(topic["tags"][:5]), importance=70,
                              extra={"tag_group_id": topic["tag_group_id"]})
                link(root, node, 0.9)
                for tag in {t.strip().lower() for t in topic["tags"] if t.strip()}:
                    link(node, concepts[tag], 0.6)

            procedures = list(Procedure.objects.filter(knowledge_source=ks))
            for proc in procedures:
                node = upsert(f"procedure:{proc.id}", node_type="procedure", title=proc.title,
                              description=proc.description, importance=80 if proc.is_critical else 60,
                              extra={"procedure_id": proc.id})
                link(root, node, 0.8)

            stale = [n.id for key, n in existing.items() if key not in wanted_keys]
            if stale:
                stats["nodes_deleted"] = KnowledgeNode.objects.filter(id__in=stale).count()
                KnowledgeNode.objects.filter(id__in=stale).delete()  # cascades their edges
            ours = [n.id for key, n in existing.items() if key in wanted_keys]
            for rel in KnowledgeRelationship.objects.filter(
                source_node_id__in=ours, target_node_id__in=ours, relationship_type=EDGE,
            ):
                if (rel.source_node_id, rel.target_node_id) not in wanted_edges:
                    rel.delete()
                    stats["relationships_deleted"] += 1

            stats.update(topics=len(topics), concepts=len(concepts), procedures=len(procedures))
            if ks.extracted_topics_count != len(topics):
                ks.extracted_topics_count = len(topics)
                ks.save(update_fields=["extracted_topics_count", "updated_at"])

            if dry_run:
                raise _DryRun
    except _DryRun:
        pass
    return stats


def sync_graph_for_documents(document_ids) -> None:
    """
    Rebuilds the graph of every process whose documents include all of `document_ids`
    (an Auto-generate run). Never raises: the graph must not break the pipeline.
    """
    try:
        from api.enterprise_document_intelligence_models import KnowledgeSource
        doc_ids = {int(d) for d in document_ids}
        if not doc_ids:
            return
        candidates = KnowledgeSource.objects.filter(source_documents__document_id__in=doc_ids).distinct()
        for ks in candidates:
            linked = set(ks.source_documents.values_list("document_id", flat=True))
            if doc_ids <= linked:
                build_knowledge_graph(ks)
    except Exception:  # noqa: BLE001
        logger.exception("knowledge graph sync failed for documents %s", document_ids)


def safe_build(ks) -> None:
    """build_knowledge_graph that only logs on failure (used after topic edits)."""
    try:
        build_knowledge_graph(ks)
    except Exception:  # noqa: BLE001
        logger.exception("knowledge graph sync failed for knowledge source %s", ks.id)

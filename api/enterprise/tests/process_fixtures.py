"""Shared fixtures: a KnowledgeSource whose topic was produced by Auto-generate."""
from api.enterprise_document_intelligence_models import KnowledgeSource, KnowledgeSourceDocument
from api.models import Document, ProcessArtifact, ProcessRun, Section, TagGroup


def make_process_with_generated_topic(company, owner, *, title="QA-TEST-Claude", tags=("safety", "helmets")):
    doc = Document.objects.create(
        filename="QA-TEST-procedimiento-seguridad.md", type="md", size=10, hash=f"fx-{title}",
        uploaded_by=owner, status="ready",
    )
    section = Section.objects.create(document=doc, title="Safety", content="Wear helmets on site.", order=1)
    ks = KnowledgeSource.objects.create(company=company, document=doc, title=title, created_by=owner)
    KnowledgeSourceDocument.objects.create(knowledge_source=ks, document=doc, added_by=owner)
    topic = TagGroup.objects.create(name="Topic 1")
    run = ProcessRun.objects.create(
        workflow_key="collection_auto_generate", resource_type="document_batch",
        resource_id=str(doc.id), status="completed", initiated_by=owner,
    )
    ProcessArtifact.objects.create(
        run=run, artifact_key=f"tag_group:{topic.id}", artifact_type="tag_group",
        resource_id=str(topic.id), payload={"tags": list(tags)},
    )
    return ks, topic, doc, section

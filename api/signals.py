# api/signals.py
import logging
from django.db import transaction, connection
from django.db.models.signals import pre_delete, post_delete
from django.dispatch import receiver

from .models import Document, Tag

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Document)
def document_pre_delete(sender, instance: Document, **kwargs):
    """
    Borra el archivo del storage cuando se elimina el Document.
    """
    try:
        if getattr(instance, "file", None):
            instance.file.delete(save=False)
    except Exception as e:
        logger.warning("Failed deleting file from storage. doc_id=%s err=%s", instance.id, e)


@receiver(post_delete, sender=Document)
def document_post_delete(sender, instance: Document, **kwargs):
    """
    Limpieza de tablas SIN FK (managed=False) que referencian por document_id.
    Usamos on_commit para no ejecutar cleanup si la transacción hace rollback.
    """
    doc_id = instance.id

    def cleanup():
        # ✅ Tag (managed=False, sin FK) -> borrar por document_id
        try:
            deleted_count, _ = Tag.objects.filter(document_id=str(doc_id)).delete()
            logger.info("Deleted Tag rows for doc_id=%s deleted=%s", doc_id, deleted_count)
        except Exception as e:
            # si la columna no existe realmente en DB o hay error SQL
            logger.warning("Tag cleanup failed for doc_id=%s err=%s", doc_id, e)

    # ✅ importante si el delete ocurre dentro de transaction.atomic()
    if transaction.get_connection().in_atomic_block:
        transaction.on_commit(cleanup)
    else:
        cleanup()

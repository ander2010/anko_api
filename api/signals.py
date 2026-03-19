# api/signals.py
import os

from django.db import transaction, connection
from django.db.models.signals import pre_delete, post_delete
from django.dispatch import receiver

from .models import Document, Flashcard, Tag
from api.utils.logging import get_logger

logger = get_logger(__name__)


def _delete_empty_storage_folder(storage, folder_name: str):
    folder_name = (folder_name or "").strip("/")
    if not folder_name:
        return

    try:
        if hasattr(storage, "path"):
            folder_path = storage.path(folder_name)
            if os.path.isdir(folder_path) and not os.listdir(folder_path):
                os.rmdir(folder_path)
            return
    except Exception as e:
        logger.warning("Failed resolving filesystem folder cleanup. folder=%s err=%s", folder_name, e)

    bucket = getattr(storage, "bucket", None)
    if bucket is None:
        return

    prefix = f"{folder_name}/"
    marker_keys = {folder_name, prefix}

    try:
        remaining_keys = [
            obj.key
            for obj in bucket.objects.filter(Prefix=prefix)
            if obj.key not in marker_keys
        ]
        if remaining_keys:
            return

        delete_keys = [{"Key": key} for key in marker_keys if storage.exists(key)]
        if delete_keys:
            bucket.delete_objects(Delete={"Objects": delete_keys, "Quiet": True})
    except Exception as e:
        logger.warning("Failed deleting storage folder markers. folder=%s err=%s", folder_name, e)


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


@receiver(pre_delete, sender=Flashcard)
def flashcard_pre_delete(sender, instance: Flashcard, **kwargs):
    image_field = getattr(instance, "back_image", None)
    image_name = getattr(image_field, "name", "") if image_field else ""
    if not image_name:
        return

    folder_name = image_name.rsplit("/", 1)[0] if "/" in image_name else ""
    storage = getattr(image_field, "storage", None)

    try:
        image_field.delete(save=False)
    except Exception as e:
        logger.warning("Failed deleting flashcard image from storage. flashcard_id=%s err=%s", instance.id, e)
        return

    if storage and folder_name:
        _delete_empty_storage_folder(storage, folder_name)


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

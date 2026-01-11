# Point pipeline tables to api_document and remove legacy documents table
from django.db import migrations

SQL = r"""
-- Drop existing FKs that point to public.documents
ALTER TABLE IF EXISTS chunks DROP CONSTRAINT IF EXISTS chunks_document_id_fkey;
ALTER TABLE IF EXISTS qa_pairs DROP CONSTRAINT IF EXISTS qa_pairs_document_id_fkey;
ALTER TABLE IF EXISTS sections DROP CONSTRAINT IF EXISTS sections_document_id_fkey;
ALTER TABLE IF EXISTS api_section DROP CONSTRAINT IF EXISTS api_section_document_id_fkey;

-- If the legacy documents table exists and is unused, drop it
DROP TABLE IF EXISTS documents;

-- Recreate FKs pointing to api_document(id)
ALTER TABLE IF EXISTS chunks
  ADD CONSTRAINT chunks_document_id_fkey FOREIGN KEY (document_id) REFERENCES api_document(id) ON DELETE CASCADE;
ALTER TABLE IF EXISTS qa_pairs
  ADD CONSTRAINT qa_pairs_document_id_fkey FOREIGN KEY (document_id) REFERENCES api_document(id) ON DELETE CASCADE;
ALTER TABLE IF EXISTS sections
  ADD CONSTRAINT sections_document_id_fkey FOREIGN KEY (document_id) REFERENCES api_document(id) ON DELETE CASCADE;
ALTER TABLE IF EXISTS api_section
  ADD CONSTRAINT api_section_document_id_fkey FOREIGN KEY (document_id) REFERENCES api_document(id) ON DELETE CASCADE;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0019_rebuild_documents_table"),
    ]

    operations = [
        migrations.RunSQL(SQL, reverse_sql=""),
    ]

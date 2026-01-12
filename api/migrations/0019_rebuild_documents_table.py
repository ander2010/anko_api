# Rebuild documents table to match the Document model and drop legacy document_id
from django.db import migrations

SQL = r"""
-- Drop dependent FKs
ALTER TABLE IF EXISTS chunks DROP CONSTRAINT IF EXISTS chunks_document_id_fkey;
ALTER TABLE IF EXISTS qa_pairs DROP CONSTRAINT IF EXISTS qa_pairs_document_id_fkey;
ALTER TABLE IF EXISTS sections DROP CONSTRAINT IF EXISTS sections_document_id_fkey;
ALTER TABLE IF EXISTS api_section DROP CONSTRAINT IF EXISTS api_section_document_id_fkey;

-- Clear dependent data (legacy IDs are incompatible)
TRUNCATE TABLE chunks, qa_pairs, sections, api_section, api_topic_related_sections RESTART IDENTITY CASCADE;

-- Recreate documents with Django-model schema
DROP TABLE IF EXISTS documents;
CREATE TABLE documents (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL,
  filename VARCHAR(255) NOT NULL,
  file VARCHAR(100) NOT NULL,
  type VARCHAR(10) NOT NULL,
  size INTEGER NOT NULL,
  uploaded_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  processing_error TEXT,
  extracted_text TEXT,
  hash VARCHAR(64) NOT NULL UNIQUE,
  job_id VARCHAR(255)
);

-- FK to projects
ALTER TABLE documents
  ADD CONSTRAINT documents_project_id_fkey FOREIGN KEY (project_id) REFERENCES api_project(id) ON DELETE CASCADE;

-- Recreate FKs from dependents
ALTER TABLE chunks
  ADD CONSTRAINT chunks_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
ALTER TABLE qa_pairs
  ADD CONSTRAINT qa_pairs_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
ALTER TABLE sections
  ADD CONSTRAINT sections_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
ALTER TABLE api_section
  ADD CONSTRAINT api_section_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;

-- Helpful index
CREATE INDEX IF NOT EXISTS documents_job_id_idx ON documents(job_id);
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0018_remove_section_external_document_id_and_more"),
    ]

    operations = [
        migrations.RunSQL(SQL, reverse_sql=""),
    ]

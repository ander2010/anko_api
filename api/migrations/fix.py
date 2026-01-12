from django.db import migrations

SQL = r"""
-- Drop existing FKs only if the tables exist
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='chunks') THEN
    ALTER TABLE chunks DROP CONSTRAINT IF EXISTS chunks_document_id_fkey;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs') THEN
    ALTER TABLE qa_pairs DROP CONSTRAINT IF EXISTS qa_pairs_document_id_fkey;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='tags') THEN
    ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_document_id_fkey;
  END IF;
END$$;

-- Clean out non-numeric document_ids only when the table exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='chunks') THEN
    DELETE FROM chunks WHERE CAST(document_id AS text) !~ '^[0-9]+$';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs') THEN
    DELETE FROM qa_pairs WHERE CAST(document_id AS text) !~ '^[0-9]+$';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='documents') THEN
    DELETE FROM documents WHERE CAST(document_id AS text) !~ '^[0-9]+$';
  END IF;
END$$;

-- Change document_id to BIGINT and add job_id on documents
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='documents') THEN
    ALTER TABLE documents ALTER COLUMN document_id TYPE BIGINT USING document_id::bigint;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS job_id text;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='chunks') THEN
    ALTER TABLE chunks ALTER COLUMN document_id TYPE BIGINT USING document_id::bigint;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs') THEN
    ALTER TABLE qa_pairs ALTER COLUMN document_id TYPE BIGINT USING document_id::bigint;
  END IF;
END$$;

-- Recreate sections from scratch
DROP TABLE IF EXISTS sections CASCADE;
CREATE TABLE sections (
  id SERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL,
  job_id TEXT,
  title TEXT,
  content TEXT,
  "order" INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Recreate FKs if parents/children exist
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='documents') THEN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='chunks') THEN
      ALTER TABLE chunks ADD CONSTRAINT chunks_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs') THEN
      ALTER TABLE qa_pairs ADD CONSTRAINT qa_pairs_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE;
    END IF;
    ALTER TABLE sections ADD CONSTRAINT sections_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE;
  END IF;
END$$;

-- Drop unused tags table
DROP TABLE IF EXISTS tags;
"""

class Migration(migrations.Migration):

    dependencies = [
        ("api", "0011_alter_flashcard_options_document_job_id_and_more"),  # keep your previously applied migration
    ]

    operations = [
        migrations.RunSQL(
            "ALTER TABLE IF EXISTS api_section DROP COLUMN IF EXISTS external_document_id;",
            reverse_sql="",
        ),
        migrations.RunSQL(SQL, reverse_sql=""),
    ]

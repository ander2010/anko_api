# Align qa_pairs table with current QaPair model
from django.db import migrations, models
import django.db.models.deletion

SQL = r"""
-- Create qa_pairs if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs'
  ) THEN
    CREATE TABLE qa_pairs (
      id BIGSERIAL PRIMARY KEY,
      document_id BIGINT NOT NULL,
      qa_index INTEGER,
      question TEXT,
      correct_response TEXT,
      context TEXT,
      metadata JSONB,
      job_id VARCHAR(255),
      chunk_id VARCHAR(255),
      chunk_index INTEGER,
      created_at TIMESTAMP,
      updated_at TIMESTAMP,
      CONSTRAINT uix_doc_qa_index UNIQUE (document_id, qa_index),
      CONSTRAINT qa_pairs_document_id_fkey FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE
    );
  END IF;
END$$;

-- Wipe old data to avoid type casts/default issues
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='qa_pairs') THEN
    DELETE FROM qa_pairs;
  END IF;
END$$;

-- Rename legacy column if present
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='qa_pairs' AND column_name='meta'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='qa_pairs' AND column_name='metadata'
  ) THEN
    ALTER TABLE qa_pairs RENAME COLUMN meta TO metadata;
  END IF;
END$$;

-- Ensure document_id uses BIGINT
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='qa_pairs' AND column_name='document_id') THEN
    ALTER TABLE qa_pairs
      ALTER COLUMN document_id TYPE BIGINT USING document_id::bigint;
  END IF;
END$$;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0015_pipeline_repair"),
    ]

    operations = [
        migrations.RunSQL(SQL, reverse_sql=""),
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[
                migrations.RemoveField(
                    model_name="qapair",
                    name="document_id",
                ),
                migrations.AddField(
                    model_name="qapair",
                    name="document",
                    field=models.ForeignKey(
                        db_column="document_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="qa_pairs",
                        to="api.document",
                        db_index=True,
                    ),
                ),
            ],
        ),
        migrations.AlterField(
            model_name="qapair",
            name="metadata",
            field=models.JSONField(blank=True, null=True),
        ),
    ]

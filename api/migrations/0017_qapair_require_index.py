# Enforce non-null qa_index on qa_pairs
from django.db import migrations, models


SQL = r"""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='qa_pairs' AND column_name='qa_index') THEN
    UPDATE qa_pairs SET qa_index = 0 WHERE qa_index IS NULL;
    ALTER TABLE qa_pairs ALTER COLUMN qa_index SET NOT NULL;
  END IF;
END$$;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0016_qapair_align_with_models"),
    ]

    operations = [
        migrations.RunSQL(SQL, reverse_sql=""),
        migrations.AlterField(
            model_name="qapair",
            name="qa_index",
            field=models.IntegerField(),
        ),
    ]

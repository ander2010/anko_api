from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0005_alter_user_email"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
DO $$
DECLARE
  c RECORD;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'api_emailverification'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE api_emailverification DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE api_emailverification
    ADD CONSTRAINT api_emailverification_user_id_fk
      FOREIGN KEY (user_id) REFERENCES api_user(id) ON DELETE CASCADE;
END $$;
""",
            reverse_sql="""
DO $$
DECLARE
  c RECORD;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'api_emailverification'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE api_emailverification DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE api_emailverification
    ADD CONSTRAINT api_emailverification_user_id_fk
      FOREIGN KEY (user_id) REFERENCES api_user(id) ON DELETE NO ACTION;
END $$;
""",
        ),
    ]

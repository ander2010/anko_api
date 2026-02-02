from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0006_emailverification_cascade"),
        ("authtoken", "0001_initial"),
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
    WHERE conrelid = 'authtoken_token'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE authtoken_token DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE authtoken_token
    ADD CONSTRAINT authtoken_token_user_id_fk
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
    WHERE conrelid = 'authtoken_token'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE authtoken_token DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE authtoken_token
    ADD CONSTRAINT authtoken_token_user_id_fk
      FOREIGN KEY (user_id) REFERENCES api_user(id) ON DELETE NO ACTION;
END $$;
""",
        ),
    ]

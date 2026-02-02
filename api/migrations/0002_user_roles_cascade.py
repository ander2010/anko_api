from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name="UserRole",
                    fields=[
                        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                        ("role", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="api.role")),
                        ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="api.user")),
                    ],
                    options={
                        "db_table": "api_user_roles",
                        "unique_together": {("user", "role")},
                    },
                ),
                migrations.AlterField(
                    model_name="user",
                    name="roles",
                    field=models.ManyToManyField(blank=True, related_name="users", through="api.userrole", to="api.role"),
                ),
            ],
            database_operations=[],
        ),
        migrations.RunSQL(
            sql="""
DO $$
DECLARE
  c RECORD;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'api_user_roles'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE api_user_roles DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE api_user_roles
    ADD CONSTRAINT api_user_roles_user_id_fk
      FOREIGN KEY (user_id) REFERENCES api_user(id) ON DELETE CASCADE,
    ADD CONSTRAINT api_user_roles_role_id_fk
      FOREIGN KEY (role_id) REFERENCES api_role(id) ON DELETE CASCADE;
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
    WHERE conrelid = 'api_user_roles'::regclass
      AND contype = 'f'
  LOOP
    EXECUTE format('ALTER TABLE api_user_roles DROP CONSTRAINT %I', c.conname);
  END LOOP;

  ALTER TABLE api_user_roles
    ADD CONSTRAINT api_user_roles_user_id_fk
      FOREIGN KEY (user_id) REFERENCES api_user(id) ON DELETE NO ACTION,
    ADD CONSTRAINT api_user_roles_role_id_fk
      FOREIGN KEY (role_id) REFERENCES api_role(id) ON DELETE NO ACTION;
END $$;
""",
        ),
    ]

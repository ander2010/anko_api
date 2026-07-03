from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0049_processrun_cancel_requested_at_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='KnowledgeSourceDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('version_note', models.TextField(blank=True)),
                ('added_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('document', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='knowledge_source_links',
                    to='api.document',
                )),
                ('knowledge_source', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='source_documents',
                    to='api.knowledgesource',
                )),
            ],
            options={
                'db_table': 'enterprise_knowledge_source_documents',
                'ordering': ['added_at'],
                'unique_together': {('knowledge_source', 'document')},
            },
        ),
    ]

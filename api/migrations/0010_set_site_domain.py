from django.db import migrations


def set_site_domain(apps, schema_editor):
    Site = apps.get_model("sites", "Site")
    site, _ = Site.objects.get_or_create(id=1)
    site.domain = "ankard.com"
    site.name = "Ankard"
    site.save()


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("sites", "0002_alter_domain_unique"),
        ("api", "0009_invite_accepted_by_cascade"),
    ]

    operations = [
        migrations.RunPython(set_site_domain, noop_reverse),
    ]

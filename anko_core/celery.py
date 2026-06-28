from __future__ import annotations

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anko_core.settings")

app = Celery("anko_core")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

"""
F-05: Learn mode state in the DB (sessions, answers, per-user schedules).

Only creates new tables; no existing data is modified (legacy 0-2 ratings in
api_flashcardreview, written by anko_services, are left untouched).

Hand-written: makemigrations would also drop the UNUSED-CLEANUP models' tables.
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

RATING_CHOICES = [(1, "Again"), (2, "Hard"), (3, "Good"), (4, "Easy")]


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("api", "0058_normalize_translated_enum_values"),
    ]

    operations = [
        migrations.CreateModel(
            name="LearnSession",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("job_id", models.CharField(max_length=64)),
                ("last_seq", models.PositiveIntegerField(default=0)),
                ("last_response", models.JSONField(blank=True, default=dict)),
                ("state", models.JSONField(blank=True, default=dict)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("deck", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="learn_sessions", to="api.deck")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="learn_sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "learn_sessions",
                "constraints": [models.UniqueConstraint(fields=("user", "job_id"), name="uniq_learn_session_user_job")],
            },
        ),
        migrations.CreateModel(
            name="LearnAnswer",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("seq", models.PositiveIntegerField()),
                ("rating", models.PositiveSmallIntegerField(blank=True, choices=RATING_CHOICES, null=True)),
                ("skipped", models.BooleanField(default=False)),
                ("time_to_answer_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("card", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="learn_answers", to="api.flashcard")),
                ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="answers", to="api.learnsession")),
            ],
            options={
                "db_table": "learn_answers",
                "constraints": [models.UniqueConstraint(fields=("session", "seq"), name="uniq_learn_answer_session_seq")],
            },
        ),
        migrations.CreateModel(
            name="FlashcardSchedule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("state", models.CharField(choices=[("new", "New"), ("learning", "Learning"), ("review", "Review"), ("relearning", "Relearning")], default="new", max_length=20)),
                ("interval_days", models.FloatField(default=0)),
                ("reps", models.PositiveIntegerField(default=0)),
                ("lapses", models.PositiveIntegerField(default=0)),
                ("last_rating", models.PositiveSmallIntegerField(blank=True, choices=RATING_CHOICES, null=True)),
                ("last_reviewed_at", models.DateTimeField(blank=True, null=True)),
                ("due_at", models.DateTimeField(blank=True, null=True)),
                ("card", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="schedules", to="api.flashcard")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="flashcard_schedules", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "flashcard_schedules",
                "constraints": [models.UniqueConstraint(fields=("user", "card"), name="uniq_flashcard_schedule_user_card")],
            },
        ),
    ]

import os
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings
import uuid
class User(AbstractUser):
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
     # Nuevo (opcional): RBAC
    roles = models.ManyToManyField("Role", blank=True, related_name="users")

    def __str__(self):
        return self.username



class Resource(models.Model):
    key = models.SlugField(max_length=60, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.key


class Permission(models.Model):
    ACTION_CHOICES = [
        ("view", "View"),
        ("create", "Create"),
        ("update", "Update"),
        ("delete", "Delete"),
        ("manage", "Manage"),
        ("custom", "Custom"),
    ]

    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="permissions")
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    code = models.SlugField(max_length=80, blank=True)

    class Meta:
        unique_together = ("resource", "action", "code")

    def __str__(self):
        base = f"{self.resource.key}:{self.action}"
        return base + (f":{self.code}" if self.code else "")


class Role(models.Model):
    name = models.CharField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, blank=True, related_name="roles")

    def __str__(self):
        return self.name


# ==========================================================
# PLANES + LIMITES + SUBSCRIPCIÓN (nuevo)
# ==========================================================

class Plan(models.Model):
    TIER = [
        ("free", "Free"),
        ("premium", "Premium"),
        ("ultra", "Ultra"),
    ]

    tier = models.CharField(max_length=20, choices=TIER, unique=True)
    name = models.CharField(max_length=80)
    description = models.TextField(blank=True)

    price_cents = models.PositiveIntegerField(default=0)
    currency = models.CharField(max_length=10, default="USD")
    billing_period = models.CharField(max_length=20, default="monthly")

    # límites globales (null = ilimitado)
    max_documents = models.IntegerField(null=True, blank=True)   # Free=2
    max_batteries = models.IntegerField(null=True, blank=True)   # Free=3 (battery = quiz)

    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.tier})"


class PlanLimit(models.Model):
    """
    Key/value flexible por plan.

    Keys recomendados:
      upload_max_mb = 50/200/300
      questions_per_battery_max = 50/null/null
      explore_topics_limit = 0/10/null
      can_use_flashcards = false/true/true
      can_invite = false/false/true
      can_collect_batteries = false/true/true
      can_collect_decks = false/true/true
    """
    VALUE_TYPE = [
        ("int", "Integer"),
        ("bool", "Boolean"),
        ("str", "String"),
    ]

    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name="limits")
    key = models.SlugField(max_length=60)
    value_type = models.CharField(max_length=10, choices=VALUE_TYPE, default="int")

    int_value = models.IntegerField(null=True, blank=True)
    bool_value = models.BooleanField(null=True, blank=True)
    str_value = models.CharField(max_length=200, blank=True)

    class Meta:
        unique_together = ("plan", "key")

    def __str__(self):
        return f"{self.plan.tier}:{self.key}"


class Subscription(models.Model):
    """
    1 activa por usuario (OneToOne).
    """
    STATUS = [
        ("trialing", "Trialing"),
        ("active", "Active"),
        ("past_due", "Past Due"),
        ("canceled", "Canceled"),
        ("expired", "Expired"),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="subscription")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="subscriptions")
    status = models.CharField(max_length=20, choices=STATUS, default="active")

    start_at = models.DateTimeField(default=timezone.now)
    current_period_start = models.DateTimeField(default=timezone.now)
    current_period_end = models.DateTimeField(null=True, blank=True)

    provider = models.CharField(max_length=30, blank=True)  # stripe/paypal
    provider_subscription_id = models.CharField(max_length=120, blank=True)

    @property
    def is_access_active(self) -> bool:
        if self.status not in ("trialing", "active"):
            return False
        if self.current_period_end and timezone.now() > self.current_period_end:
            return False
        return True

    def __str__(self):
        return f"{self.user} - {self.plan.tier} - {self.status}"

def document_upload_to(instance, filename):
    """
    Build the upload path for a document file.

    The final storage path will be:
        documents/{user_id}/{uuid}_{original_filename}

    The global storage configuration (e.g. AWS_LOCATION="anko")
    will automatically prefix this path.
    """

    # Prefer the uploader user if it was set by the view/serializer
    user_id = getattr(instance, "_uploader_id", None)

    # Fallback to project owner if uploader is not provided
    if not user_id and instance.project_id:
        user_id = instance.project.owner_id

    safe_filename = os.path.basename(filename)
    # unique_filename = f"{uuid.uuid4()}_{safe_filename}"
    unique_filename = f"{safe_filename}"

    return f"anko/documents/{user_id}/{unique_filename}"

class Project(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived = models.BooleanField(default=False)
    logo = models.ImageField(upload_to='project_logos/', null=True, blank=True)
    members = models.ManyToManyField(User, related_name='joined_projects')

    def __str__(self):
        return self.title

class Document(models.Model):
    TYPE_CHOICES = [
        ('PDF', 'PDF'),
        ('DOCX', 'DOCX'),
        ('TXT', 'TXT'),
    ]
    STATUS_CHOICES = [
        ('pending', 'pending'),
        ('processing', 'processing'),
        ('ready', 'ready'),
        ('failed', 'failed'),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='documents')
    filename = models.CharField(max_length=255)
    # file = models.FileField(upload_to='documents/')
    file = models.FileField(upload_to=document_upload_to)

    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    size = models.PositiveIntegerField(help_text="Size in bytes")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    processing_error = models.TextField(null=True, blank=True)
    extracted_text = models.TextField(null=True, blank=True)
    hash = models.CharField(max_length=64, unique=True, help_text="File hash for deduplication")
    job_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    
    def save(self, *args, **kwargs):
        if self.file and not self.size:
            self.size = self.file.size
        super().save(*args, **kwargs)

    def __str__(self):
        return self.filename
   


class Section(models.Model):
    id = models.BigAutoField(primary_key=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='sections')
    job_id = models.TextField(null=True, blank=True, db_index=True)
    title = models.TextField(blank=True, default="")
    content = models.TextField(blank=True, default="")
    order = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.document.filename} - {self.title}"


class Topic(models.Model):
    STATUS_CHOICES = [
        ('active', 'active'),
        ('archived', 'archived'),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='topics')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    related_sections = models.ManyToManyField(
        "Section",
        related_name="topics",
        blank=True,
    )
    question_count_target = models.PositiveIntegerField(default=20)

    def __str__(self):
        return self.name

class Rule(models.Model):
    STRATEGY_CHOICES = [
        ('singleChoice', 'singleChoice'),
        ('multiSelect', 'multiSelect'),
        ('trueFalse', 'trueFalse'),
        ('mixed', 'mixed'),
    ]
    DIFFICULTY_CHOICES = [
        ('Easy', 'Easy'),
        ('Medium', 'Medium'),
        ('Hard', 'Hard'),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='rules')
    name = models.CharField(max_length=255)
    topic_scope = models.ForeignKey(Topic, null=True, blank=True, on_delete=models.SET_NULL, help_text="If null, applies globally to project")
    global_count = models.PositiveIntegerField(default=10)
    time_limit = models.PositiveIntegerField(help_text="Time in minutes")
    distribution_strategy = models.CharField(max_length=20, choices=STRATEGY_CHOICES)
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES, default='Medium')

    def __str__(self):
        return self.name

class Battery(models.Model):
    VISIBILITY_CHOICES = [
        ("private", "Private"),
        ("shared", "Shared"),
        ("public", "Public"),
    ]
    STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('Ready', 'Ready'),
    ]
    DIFFICULTY_CHOICES = [
        ('Easy', 'Easy'),
        ('Medium', 'Medium'),
        ('Hard', 'Hard'),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='batteries')
    rule = models.ForeignKey(Rule, null=True, blank=True, on_delete=models.SET_NULL)
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Draft')
    created_at = models.DateTimeField(auto_now_add=True)
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES)
    visibility = models.CharField(max_length=20, choices=VISIBILITY_CHOICES, default="private")

    # questions = models.JSONField(help_text="Stored generated questions snapshot")
    external_job_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    def __str__(self):
        return self.name

class BatteryQuestion(models.Model):
    QUESTION_TYPE_CHOICES = [
        ('singleChoice', 'singleChoice'),
        ('multiSelect', 'multiSelect'),
        ('trueFalse', 'trueFalse'),
    ]

    battery = models.ForeignKey(Battery, on_delete=models.CASCADE, related_name="questions_rel")
    topic = models.ForeignKey(Topic, null=True, blank=True, on_delete=models.SET_NULL, related_name="battery_questions")

    type = models.CharField(max_length=20, choices=QUESTION_TYPE_CHOICES)
    question = models.TextField()
    explanation = models.TextField(blank=True, default="")
    points = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    order = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Battery {self.battery_id} Q{self.order} ({self.type})"


class BatteryOption(models.Model):
    question = models.ForeignKey(BatteryQuestion, on_delete=models.CASCADE, related_name="options")

    option_id = models.CharField(max_length=10)  # "a", "b", "c" o "true"/"false"
    text = models.TextField()
    correct = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"Q{self.question_id} - {self.option_id}"


class BatteryAttempt(models.Model):
    STATUS_CHOICES = [
        ("in_progress", "in_progress"),
        ("finished", "finished"),
        ("abandoned", "abandoned"),
    ]

    battery = models.ForeignKey(Battery, on_delete=models.CASCADE, related_name="attempts")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="battery_attempts")

    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="in_progress")

    total_questions = models.PositiveIntegerField(default=0)
    correct_count = models.PositiveIntegerField(default=0)

    total_score = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    max_score = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    percent = models.DecimalField(max_digits=6, decimal_places=2, default=0)

    def __str__(self):
        return f"Attempt {self.id} - Battery {self.battery_id} - {self.user_id}"

    def finish(self, total_score, max_score, correct_count, total_questions):
        self.finished_at = timezone.now()
        self.status = "finished"
        self.total_score = total_score
        self.max_score = max_score
        self.correct_count = correct_count
        self.total_questions = total_questions
        self.percent = (total_score / max_score * 100) if max_score else 0
        self.save()

class BatteryAttemptAnswer(models.Model):
    attempt = models.ForeignKey(BatteryAttempt, on_delete=models.CASCADE, related_name="answers")
    question = models.ForeignKey(BatteryQuestion, on_delete=models.CASCADE, related_name="attempt_answers")

    # singleChoice/trueFalse
    selected_option = models.ForeignKey(
        BatteryOption, null=True, blank=True, on_delete=models.SET_NULL, related_name="selected_in_single_attempts"
    )

    # multiSelect
    selected_options = models.ManyToManyField(
        BatteryOption, blank=True, related_name="selected_in_multi_attempts"
    )

    is_correct = models.BooleanField(default=False)
    points_earned = models.DecimalField(max_digits=8, decimal_places=2, default=0)

    def __str__(self):
        return f"Attempt {self.attempt_id} - Q{self.question_id}"
    


# ==========================================================
# NUEVO: Compartir / Guardar / Invitar para BATTERIES (quizzes)
# ==========================================================

class BatteryShare(models.Model):
    ACCESS = [
        ("view", "View Only"),
        ("copy", "View + Copy"),
        ("edit", "Edit"),
    ]

    battery = models.ForeignKey(Battery, on_delete=models.CASCADE, related_name="shares")
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shared_batteries")
    access = models.CharField(max_length=20, choices=ACCESS, default="view")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("battery", "shared_with")


class SavedBattery(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="saved_batteries")
    battery = models.ForeignKey(Battery, on_delete=models.CASCADE, related_name="saved_by")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "battery")


class Invite(models.Model):
    STATUS = [
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("expired", "Expired"),
        ("revoked", "Revoked"),
    ]

    inviter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_invites")
    email = models.EmailField()
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    battery_to_share = models.ForeignKey(Battery, on_delete=models.SET_NULL, null=True, blank=True, related_name="invite_links")
    share_access = models.CharField(max_length=20, default="view")

    status = models.CharField(max_length=20, choices=STATUS, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="accepted_invites"
    )
    accepted_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self):
        if self.status != "pending":
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True


# ==========================================================
# NUEVO: FLASHCARDS (Premium/Ultra)
# ==========================================================


# class Deck(models.Model):
#     VISIBILITY = [
#         ("private", "Private"),
#         ("shared", "Shared"),
#         ("public", "Public"),
#     ]
#     project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='decks')
#     owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="decks")
#     title = models.CharField(max_length=200)
#     notes = models.TextField(blank=True)
#     visibility = models.CharField(max_length=20, choices=VISIBILITY, default="private")
#     created_at = models.DateTimeField(auto_now_add=True)

    # def __str__(self):
    #     return f"{self.title} ({self.owner})"

class Deck(models.Model):
    VISIBILITY = [
        ("private", "Private"),
        ("shared", "Shared"),
        ("public", "Public"),
    ]

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="decks",
        null=True, blank=True
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="decks"
    )

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # 🔑 Relación NO obligatoria con Section
    sections = models.ManyToManyField(
        "Section",
        related_name="decks",
        blank=True
    )

    visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY,
        default="private"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    # ✅ Job externo asociado (último o actual)
    external_job_id = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    def __str__(self):
        return f"{self.title} ({self.owner})"

class Flashcard(models.Model):
    card_id = models.CharField(max_length=255,  null=True)  # pipeline PK
    user_id = models.CharField(max_length=255,null=True)   # para multi-user en mismo job
    job_id = models.CharField(max_length=255,null=True, blank=True)
    front = models.TextField()
    back = models.TextField()
    source_doc_id = models.CharField(max_length=255, null=True, blank=True)
    tags = models.JSONField(default=list)
    difficulty = models.CharField(max_length=50, null=True, blank=True)
    kind = models.CharField(max_length=50, default="new")
    status = models.CharField(max_length=50, default="learning")
    learning_step_index = models.IntegerField(default=0)
    repetition = models.IntegerField(default=0)
    interval_days = models.IntegerField(default=0)
    ease_factor = models.FloatField(default=2.5)
    due_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Your additions
    deck = models.ForeignKey(Deck, null=True, blank=True, on_delete=models.SET_NULL, related_name="cards")
    notes = models.TextField(blank=True, null=True, default="")

    class Meta:
        
        verbose_name = "Flashcard"
        verbose_name_plural = "Flashcards"

class DeckShare(models.Model):
    ACCESS = [
        ("view", "View Only"),
        ("copy", "View + Copy"),
        ("edit", "Edit"),
    ]

    deck = models.ForeignKey(Deck, on_delete=models.CASCADE, related_name="shares")
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shared_decks")
    access = models.CharField(max_length=20, choices=ACCESS, default="view")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("deck", "shared_with")


class SavedDeck(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="saved_decks")
    deck = models.ForeignKey(Deck, on_delete=models.CASCADE, related_name="saved_by")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "deck")



class SupportRequest(models.Model):
    STATUS_NEW = "new"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_DONE = "done"

    STATUS_CHOICES = [
        (STATUS_NEW, "New"),
        (STATUS_IN_PROGRESS, "In progress"),
        (STATUS_DONE, "Done"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="support_requests",
    )

    name = models.CharField(max_length=120, blank=True)
    phone = models.CharField(max_length=40, blank=True)

    # la guardamos para snapshot (por si el user cambia email luego)
    email = models.EmailField()

    message = models.TextField()

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_NEW)
    source = models.CharField(max_length=50, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user_id} - {self.status} - {self.created_at:%Y-%m-%d}"

class Chunk(models.Model):
    id = models.BigAutoField(primary_key=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='chunks', db_column='document_id', db_index=True)
    chunk_index = models.IntegerField()
    chunk_id = models.CharField(max_length=255, unique=True)
    text = models.TextField(blank=True, default="")
    embedding = models.JSONField(default=list)
    meta = models.JSONField(default=dict)
    question_ids = models.JSONField(default=list)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = "chunks"
        managed = True
        unique_together = (("document", "chunk_index"),)


class QaPair(models.Model):
    id = models.BigAutoField(primary_key=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='qa_pairs', db_column='document_id', db_index=True)
    qa_index = models.IntegerField()
    question = models.TextField(null=True, blank=True)
    correct_response = models.TextField(null=True, blank=True)
    context = models.TextField(null=True, blank=True)
    meta = models.JSONField(null=True, blank=True)
    job_id = models.CharField(max_length=255, db_index=True, null=True, blank=True)
    chunk_id = models.CharField(max_length=255, null=True, blank=True)
    chunk_index = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "qa_pairs"
        managed = True
        unique_together = (("document", "qa_index"),)


    def __str__(self):
        return f"[{self.job_id}] #{self.qa_index} {self.question[:40] if self.question else ''}"



# we going to deleted 
class Tag(models.Model):
    document_id = models.TextField(db_index=True)
    tag = models.TextField()

    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "tags"   # 👈 nombre real de tu tabla
        managed = False        # 👈 NO crea migraciones / NO intenta crear tabla
class Notification(models.Model):
    job_id = models.CharField(max_length=255, primary_key=True)
    meta = models.JSONField(default=dict)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True, default=dict)

    class Meta:
        db_table = "notifications"
        managed = False

    def __str__(self):
        return f"Notification {self.job_id}"


class ConversationMessage(models.Model):
    id = models.AutoField(primary_key=True)
    session_id = models.CharField(max_length=255)
    user_id = models.CharField(max_length=255, null=True, blank=True)
    job_id = models.CharField(max_length=255, null=True, blank=True)
    question = models.TextField(null=True, blank=True)
    answer = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "conversation_messages"
        managed = False

    def __str__(self):
        return f"{self.session_id} - {self.id}"

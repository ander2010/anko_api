from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    def __str__(self):
        return self.username

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
    file = models.FileField(upload_to='documents/')
    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    size = models.PositiveIntegerField(help_text="Size in bytes")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    processing_error = models.TextField(null=True, blank=True)
    extracted_text = models.TextField(null=True, blank=True)
    hash = models.CharField(max_length=64, unique=True, help_text="File hash for deduplication")
    def save(self, *args, **kwargs):
        if self.file and not self.size:
            self.size = self.file.size
        super().save(*args, **kwargs)

    def __str__(self):
        return self.filename

class Section(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='sections')
    title = models.CharField(max_length=255)
    content = models.TextField()
    order = models.PositiveIntegerField()

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
    related_documents = models.ManyToManyField(Document, related_name='topics')
    question_count_target = models.PositiveIntegerField(default=20)

    def __str__(self):
        return self.name

class Rule(models.Model):
    STRATEGY_CHOICES = [
        ('singleChoice', 'singleChoice'),
        ('multiSelect', 'multiSelect'),
        ('trueFalse', 'trueFalse'),
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
    # questions = models.JSONField(help_text="Stored generated questions snapshot")

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



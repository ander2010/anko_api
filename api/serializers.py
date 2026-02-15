from django.conf import settings
from rest_framework import serializers
from .models import AccessRequest, ConversationMessage, SupportRequest, User, Project, Document, Section, Topic, Rule, Battery, BatteryOption, BatteryQuestion,BatteryAttempt, BatteryAttemptAnswer
from django.contrib.auth import get_user_model
from dj_rest_auth.forms import AllAuthPasswordResetForm
from .models import (
    Resource, Permission, Role,
    Plan, PlanLimit, Subscription,
    BatteryShare, SavedBattery, Invite,
    Deck, Flashcard, DeckShare, SavedDeck,
    Tag, QaPair
)

import re
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
import logging
from dj_rest_auth.serializers import PasswordResetSerializer

User = get_user_model()

def _validate_password_complexity(value):
    if not re.search(r"[a-z]", value):
        raise serializers.ValidationError("Must include a lowercase letter.")
    if not re.search(r"[A-Z]", value):
        raise serializers.ValidationError("Must include an uppercase letter.")
    if not re.search(r"\d", value):
        raise serializers.ValidationError("Must include a number.")
    if not re.search(r"[^\w\s]", value):
        raise serializers.ValidationError("Must include a special character.")

class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'avatar', 'first_name', 'last_name','roles']
        read_only_fields = ["id"]

    def validate_password(self, value):
        try:
            _validate_password_complexity(value)
            # Puedes pasar user=None si aún no existe, o cargar el user si es un UPDATE
            validate_password(value, user=self.instance)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value



    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)   
        user.save()
        return user

class ProjectSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField(read_only=True)
    members = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    documents_count = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Project
        fields = [
            "id",
            "title",
            "description",
            "owner",
            "members",
            "documents_count",
            "created_at",
            "updated_at",
            "archived",
            "logo",
        ]
        read_only_fields = ["id", "owner", "members", "documents_count", "created_at", "updated_at"]

    def get_owner(self, obj):
        return {"id": obj.owner.id, "username": obj.owner.username}

    def get_documents_count(self, obj):
        # Si tu FK en Document NO tiene related_name="documents", usa obj.document_set.count()
        if hasattr(obj, "documents"):
            return obj.documents.count()
        return obj.document_set.count()




class DocumentEsSerializer(serializers.ModelSerializer):
    

    class Meta:
        model = Document
        fields = ["id",
        "filename",
        
        "type",
        "size",
        "uploaded_at",
        "status",
        "processing_error",
        "extracted_text",
        # "hash",
        # "job_id",
        "project"]
        # + agrega filename y url porque son fields extra




class DocumentSerializer(serializers.ModelSerializer):
    filename = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = "__all__"  # mantiene todos tus campos
        # + agrega filename y url porque son fields extra

    def get_filename(self, obj):
        if not obj.file:
            return None
        try:
            return obj.file.name.split("/")[-1]
        except Exception:
            return None

    def get_url(self, obj):
        if not obj.file:
            return None
        request = self.context.get("request")
        try:
            u = obj.file.url
        except Exception:
            return None
        return request.build_absolute_uri(u) if request else u


class SectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        fields = '__all__'

class TopicSerializer(serializers.ModelSerializer):
    related_sections = serializers.PrimaryKeyRelatedField(
        queryset=Section.objects.all(),  # 👈 NO none()
        many=True,
        required=False
    )

    class Meta:
        model = Topic
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        request = self.context.get("request")
        if not request:
            return

        project_id = (
            request.query_params.get("project")  # ✅ para GET (browsable API)
            or request.data.get("project")       # ✅ para POST
            or getattr(self.instance, "project_id", None)  # ✅ PATCH
        )

        if project_id:
            self.fields["related_sections"].queryset = Section.objects.filter(
                document__project_id=project_id
            )



class RuleSerializer(serializers.ModelSerializer):
    topic_scope = serializers.PrimaryKeyRelatedField(
        queryset=Topic.objects.all(),
        required=False,
        allow_null=True
    )

    class Meta:
        model = Rule
        fields = "__all__"
        extra_kwargs = {
            # si quieres permitir que el front no mande difficulty (ya tiene default)
            "difficulty": {"required": False},
        }

    def validate(self, attrs):
        # project puede venir en attrs (POST) o en instance (PATCH)
        project = attrs.get("project") or getattr(self.instance, "project", None)
        topic = attrs.get("topic_scope")

        if topic and project and topic.project_id != project.id:
            raise serializers.ValidationError({
                "topic_scope": "This topic does not belong to the selected project."
            })
        return attrs

class BatteryOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BatteryOption
        fields = ["id", "option_id", "text", "correct", "order"]


class BatteryQuestionSerializer(serializers.ModelSerializer):
    options = BatteryOptionSerializer(many=True, read_only=True)
    topicId = serializers.IntegerField(source="topic_id", read_only=True)
    topicName = serializers.CharField(source="topic.name", read_only=True)

    class Meta:
        model = BatteryQuestion
        fields = [
            "id",
            "type",
            "topicId",
            "topicName",
            "question",
            "options",
            "points",
            "explanation",
            "order",
            "created_at",
        ]

class SectionMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        fields = ["id", "title", "content", "order"]


class DocumentWithSectionsSerializer(serializers.ModelSerializer):
    sections = SectionMiniSerializer(many=True, read_only=True)

    class Meta:
        model = Document
        fields = [
            "id",
            "filename",
            "type",
            "size",
            "uploaded_at",
            "status",
            "sections",
        ]

class BatterySerializer(serializers.ModelSerializer):
    questions = BatteryQuestionSerializer(source="questions_rel", many=True, read_only=True)

    attempts_count = serializers.SerializerMethodField()
    last_attempt = serializers.SerializerMethodField()

    owner_id = serializers.IntegerField(source="project.owner_id", read_only=True)
    approved_count = serializers.SerializerMethodField()
    rejected_count = serializers.SerializerMethodField()

    class Meta:
        model = Battery
        fields = [
            "id",
            "project",
            "rule",
            "name",
            "status",
            "created_at",
            "difficulty",
            "visibility",
            "description",
            "external_job_id",
            "questions",
            "attempts_count",
            "last_attempt",
            "owner_id",
            "approved_count",
            "rejected_count",
        ]

    def get_approved_count(self, obj):
        return obj.access_requests.filter(status="approved").count()

    def get_rejected_count(self, obj):
        return obj.access_requests.filter(status="rejected").count()

    def get_attempts_count(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return obj.attempts.filter(user=request.user).count()
        return obj.attempts.count()

    def get_last_attempt(self, obj):
        request = self.context.get("request")
        qs = obj.attempts.all().order_by("-started_at")
        if request and request.user.is_authenticated:
            qs = qs.filter(user=request.user)

        last = qs.first()
        return BatteryAttemptSerializer(last).data if last else None


class BatteryAttemptAnswerSerializer(serializers.ModelSerializer):
    questionId = serializers.IntegerField(source="question_id", read_only=True)

    # para frontend: devolver ids seleccionados
    selectedOptionId = serializers.IntegerField(source="selected_option_id", read_only=True)
    selectedOptionIds = serializers.SerializerMethodField()

    class Meta:
        model = BatteryAttemptAnswer
        fields = ["id", "questionId", "selectedOptionId", "selectedOptionIds", "is_correct", "points_earned"]

    def get_selectedOptionIds(self, obj):
        return list(obj.selected_options.values_list("id", flat=True))


class BatteryAttemptSerializer(serializers.ModelSerializer):
    batteryId = serializers.IntegerField(source="battery_id", read_only=True)
    userId = serializers.IntegerField(source="user_id", read_only=True)
    answers = BatteryAttemptAnswerSerializer(many=True, read_only=True)

    class Meta:
        model = BatteryAttempt
        fields = [
            "id",
            "batteryId",
            "userId",
            "status",
            "started_at",
            "finished_at",
            "total_questions",
            "correct_count",
            "total_score",
            "max_score",
            "percent",
            "answers",
        ]


# =========================
# RBAC
# =========================



class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = "__all__"


class PermissionSerializer(serializers.ModelSerializer):
    resourceKey = serializers.CharField(source="resource.key", read_only=True)

    class Meta:
        model = Permission
        fields = ["id", "resource", "resourceKey", "action", "code"]


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(),
        many=True,
        required=False
    )

    class Meta:
        model = Role
        fields = ["id", "name", "description", "permissions"]


# =========================
# Plans / Limits / Subscription
# =========================

class PlanLimitSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlanLimit
        fields = ["id", "plan", "key", "value_type", "int_value", "bool_value", "str_value"]


class PlanSerializer(serializers.ModelSerializer):
    limits = PlanLimitSerializer(many=True, read_only=True)

    class Meta:
        model = Plan
        fields = [
            "id",
            "tier",
            "name",
            "description",
            "price_cents",
            "currency",
            "billing_period",
            "max_documents",
            "max_batteries",
            "is_active",
            "limits",
        ]
class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ["id", "user", "plan", "status", "provider", "provider_subscription_id",
                  "start_at", "current_period_start", "current_period_end"]
        read_only_fields = ["user"]

# class SubscriptionSerializer(serializers.ModelSerializer):
#     userId = serializers.IntegerField(source="user_id", read_only=True)

#     planId = serializers.IntegerField(source="plan_id", read_only=True)
#     plan = PlanSerializer(read_only=True)

#     isAccessActive = serializers.BooleanField(source="is_access_active", read_only=True)

#     class Meta:
#         model = Subscription
#         fields = [
#             "id",
#             "userId",
#             "planId",
#             "plan",
#             "status",
#             "start_at",
#             "current_period_start",
#             "current_period_end",
#             "provider",
#             "provider_subscription_id",
#             "isAccessActive",
#         ]
#         read_only_fields = ["userId", "isAccessActive"]


# =========================
# Sharing / Saved / Invite (Batteries)
# =========================

class BatteryShareSerializer(serializers.ModelSerializer):
    batteryId = serializers.IntegerField(source="battery_id", read_only=True)
    sharedWithId = serializers.IntegerField(source="shared_with_id", read_only=True)
    sharedWithUsername = serializers.CharField(source="shared_with.username", read_only=True)

    class Meta:
        model = BatteryShare
        fields = [
            "id",
            "battery",
            "batteryId",
            "shared_with",
            "sharedWithId",
            "sharedWithUsername",
            "access",
            "created_at",
        ]
        read_only_fields = ["created_at", "batteryId", "sharedWithId", "sharedWithUsername"]


class SavedBatterySerializer(serializers.ModelSerializer):
    batteryId = serializers.IntegerField(source="battery_id", read_only=True)

    # opcional para UI
    batteryName = serializers.CharField(source="battery.name", read_only=True)
    batteryOwnerId = serializers.IntegerField(source="battery.project.owner_id", read_only=True)

    class Meta:
        model = SavedBattery
        fields = ["id", "battery", "batteryId", "batteryName", "batteryOwnerId", "created_at"]
        read_only_fields = ["created_at", "batteryId", "batteryName", "batteryOwnerId"]


class InviteSerializer(serializers.ModelSerializer):
    inviterId = serializers.IntegerField(source="inviter_id", read_only=True)
    token = serializers.UUIDField(read_only=True)

    batteryToShareId = serializers.IntegerField(source="battery_to_share_id", read_only=True)
    acceptedById = serializers.IntegerField(source="accepted_by_id", read_only=True)

    class Meta:
        model = Invite
        fields = [
            "id",
            "inviterId",
            "email",
            "token",
            "battery_to_share",
            "batteryToShareId",
            "share_access",
            "status",
            "created_at",
            "expires_at",
            "acceptedById",
            "accepted_at",
        ]
        read_only_fields = ["inviterId", "token", "status", "created_at", "acceptedById", "accepted_at"]


# =========================
# Flashcards
# =========================

class FlashcardSerializer(serializers.ModelSerializer):
    deckId = serializers.IntegerField(source="deck_id", read_only=True)

    class Meta:
        model = Flashcard
        fields = ["id", "deck", "deckId", "front", "back", "notes", "created_at"]
        read_only_fields = ["created_at", "deckId"]


class DeckSerializer(serializers.ModelSerializer):
    ownerId = serializers.IntegerField(source="owner_id", read_only=True)
    cardsCount = serializers.SerializerMethodField()
    cards = FlashcardSerializer(many=True, read_only=True)
    approved_count = serializers.SerializerMethodField()
    rejected_count = serializers.SerializerMethodField()

    class Meta:
        model = Deck
        fields = ["id", "ownerId", "title", "visibility", "created_at", "description", "cardsCount", "cards","project","sections","external_job_id", "approved_count", "rejected_count"]
        read_only_fields = ["created_at", "ownerId", "cardsCount", "cards","external_job_id"]

    def get_cardsCount(self, obj):
        return obj.cards.count()

    def get_approved_count(self, obj):
        return obj.access_requests.filter(status="approved").count()

    def get_rejected_count(self, obj):
        return obj.access_requests.filter(status="rejected").count()


class DeckShareSerializer(serializers.ModelSerializer):
    deckId = serializers.IntegerField(source="deck_id", read_only=True)
    sharedWithId = serializers.IntegerField(source="shared_with_id", read_only=True)
    sharedWithUsername = serializers.CharField(source="shared_with.username", read_only=True)

    class Meta:
        model = DeckShare
        fields = [
            "id",
            "deck",
            "deckId",
            "shared_with",
            "sharedWithId",
            "sharedWithUsername",
            "access",
            "created_at",
        ]
        read_only_fields = ["created_at", "deckId", "sharedWithId", "sharedWithUsername"]


class SavedDeckSerializer(serializers.ModelSerializer):
    deckId = serializers.IntegerField(source="deck_id", read_only=True)
    deckTitle = serializers.CharField(source="deck.title", read_only=True)

    class Meta:
        model = SavedDeck
        fields = ["id", "deck", "deckId", "deckTitle", "created_at"]
        read_only_fields = ["created_at", "deckId", "deckTitle"]


# =========================
# managed=False tables (si las quieresfv exponer)
# =========================

class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = "__all__"


class QaPairSerializer(serializers.ModelSerializer):
    class Meta:
        model = QaPair
        fields = "__all__"
class AllowedRoutesSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    is_admin = serializers.BooleanField()
    roles = serializers.ListField(child=serializers.CharField())
    allowed_routes = serializers.ListField(child=serializers.CharField())


class SupportRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportRequest
        fields = [
            "id",
            "user",
            "name",
            "phone",
            "email",
            "message",
            "status",
            "source",
            "created_at",
            "resolved_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "email",
            "status",
            "created_at",
            "resolved_at",
        ]

    def validate_message(self, value: str):
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Describe el problema con más detalle.")
        return value


class NextCardRequestSerializer(serializers.Serializer):
    # Si no lo mandas, lo tomamos del deck.external_job_id
    job_id = serializers.CharField(required=False, allow_blank=True)
    user_id = serializers.CharField(required=False, allow_blank=True)
    last_seq = serializers.IntegerField(required=False, default=0)
    token = serializers.CharField(required=False, allow_blank=True, default="")


class CardFeedbackRequestSerializer(serializers.Serializer):
    job_id = serializers.CharField(required=False, allow_blank=True)
    user_id = serializers.CharField(required=False, allow_blank=True)
    seq = serializers.IntegerField(required=True)
    card_id = serializers.IntegerField(required=True)
    rating = serializers.IntegerField(required=True)  # 0 hard, 1 good, 2 easy
    time_to_answer_ms = serializers.IntegerField(required=False, default=500)
    token = serializers.CharField(required=False, allow_blank=True, default="")


class ConversationMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConversationMessage
        fields = [
            "id",
            "user_id",
            "job_id",
            "question",
            "answer",
            "created_at",
        ]




class FrontendPasswordResetSerializer(PasswordResetSerializer):

    def get_email_options(self):
        """Override this method to change default e-mail options"""
        def url_generator(request, user, temp_key):
            uid = user.pk  
            frontend = settings.FRONTEND_URL or  "https://ankard.com"
            return f"{frontend}/reset-password/{uid}/{temp_key}"
        
        return {"url_generator":url_generator}

    def validate_email(self, value):
        value = super().validate_email(value)
        email = None
        user_count = 0
        try:
            email = self.reset_form.cleaned_data.get("email")
            users = list(self.reset_form.get_users(email)) if email else []
            user_count = len(users)
        except Exception:
            pass
        logging.getLogger("django").warning(
            "password_reset serializer email=%s matched_users=%s",
            email,
            user_count,
        )
        return value


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        _validate_password_complexity(value)

        # Avoid info contained in user table (username, email, etc.)
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        validate_password(value, user=user)

        return value


# api/serializers/access.py
# from django.db.models import Count
# from rest_framework import serializers
# from api.models import Battery, Deck, AccessRequest, BatteryShare, DeckShare


class PublicBatteryCardSerializer(serializers.ModelSerializer):
    question_count = serializers.IntegerField(read_only=True)
    shared_count = serializers.IntegerField(read_only=True)
    accepted_count = serializers.IntegerField(read_only=True)  # we’ll treat “share exists” as accepted

    owner_id = serializers.IntegerField(source="project.owner_id", read_only=True)

    class Meta:
        model = Battery
        fields = [
            "id",
            "name",
            "description",
            "difficulty",
            "visibility",
            "created_at",
            "owner_id",
            "question_count",
            "shared_count",
            "accepted_count",
        ]


class PublicDeckCardSerializer(serializers.ModelSerializer):
    card_count = serializers.IntegerField(read_only=True)
    shared_count = serializers.IntegerField(read_only=True)
    accepted_count = serializers.IntegerField(read_only=True)

    # owner_id = serializers.IntegerField(source="owner_id", read_only=True)

    class Meta:
        model = Deck
        fields = [
            "id",
            "title",
            "description",
            "visibility",
            "created_at",
            "owner_id",
            "card_count",
            "shared_count",
            "accepted_count",
        ]


class AccessRequestCreateSerializer(serializers.Serializer):
    battery_id = serializers.IntegerField(required=False)
    deck_id = serializers.IntegerField(required=False)
    requested_access = serializers.ChoiceField(choices=AccessRequest.ACCESS, default="view")
    message = serializers.CharField(required=False, allow_blank=True, default="")

    def validate(self, attrs):
        battery_id = attrs.get("battery_id")
        deck_id = attrs.get("deck_id")
        if bool(battery_id) == bool(deck_id):
            raise serializers.ValidationError("Provide exactly one of battery_id or deck_id.")
        return attrs


class AccessRequestSerializer(serializers.ModelSerializer):
    # helpful display fields
    battery_name = serializers.CharField(source="battery.name", read_only=True)
    deck_title = serializers.CharField(source="deck.title", read_only=True)

    class Meta:
        model = AccessRequest
        fields = [
            "id",
            "token",
            "resource_type",
            "battery",
            "deck",
            "battery_name",
            "deck_title",
            "requester",
            "owner",
            "requested_access",
            "message",
            "status",
            "created_at",
            "decided_at",
        ]
        read_only_fields = ["id", "token", "resource_type", "requester", "owner", "status", "created_at", "decided_at"]

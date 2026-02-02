from django.conf import settings
from rest_framework import serializers
from .models import ConversationMessage, SupportRequest, User, Project, Document, Section, Topic, Rule, Battery, BatteryOption, BatteryQuestion,BatteryAttempt, BatteryAttemptAnswer
from django.contrib.auth import get_user_model
from .models import (
    Resource, Permission, Role,
    Plan, PlanLimit, Subscription,
    BatteryShare, SavedBattery, Invite,
    Deck, Flashcard, DeckShare, SavedDeck,
    Tag, QaPair
)

from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
import uuid
from dj_rest_auth.serializers import PasswordResetSerializer

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'avatar', 'first_name', 'last_name','roles']
        read_only_fields = ["id"]

    def validate_password(self, value):
        try:
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

    class Meta:
        model = Battery
        fields = "__all__"

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

    class Meta:
        model = Deck
        fields = ["id", "ownerId", "title", "visibility", "created_at", "cardsCount", "cards","project","sections","external_job_id"]
        read_only_fields = ["created_at", "ownerId", "cardsCount", "cards","external_job_id"]

    def get_cardsCount(self, obj):
        return obj.cards.count()


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
        """
        Esto controla los params del PasswordResetForm.save().
        Si pasas `url_generator`, dj-rest-auth usará ESA función para armar el link.
        """
        def url_generator(request, user, temp_key):
            # temp_key es el token
            uid = user.pk  # en tu email sale "1", o sea esto es lo que estás usando
            frontend = getattr(settings, "FRONTEND_URL", "http://localhost:5173").rstrip("/")
            return f"{frontend}/reset-password/{uid}/{temp_key}"

        return {"url_generator": url_generator}

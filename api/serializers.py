from rest_framework import serializers
from .models import User, Project, Document, Section, Topic, Rule, Battery, BatteryOption, BatteryQuestion
from django.contrib.auth import get_user_model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'avatar', 'first_name', 'last_name']

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
    related_documents = serializers.PrimaryKeyRelatedField(
        queryset=Document.objects.none(),
        many=True,
        required=False
    )

    class Meta:
        model = Topic
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        request = self.context.get("request")
        project_id = None

        if request:
            # en create vendrá en request.data
            project_id = request.data.get("project") or request.query_params.get("project")

        if project_id:
            self.fields["related_documents"].queryset = Document.objects.filter(project_id=project_id)
        else:
            self.fields["related_documents"].queryset = Document.objects.all()


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


class BatterySerializer(serializers.ModelSerializer):
    # ✅ el frontend quiere battery.questions como array
    questions = BatteryQuestionSerializer(source="questions_rel", many=True, read_only=True)

    class Meta:
        model = Battery
        fields = "__all__"
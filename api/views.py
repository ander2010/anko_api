from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db.models import Prefetch
from collections import defaultdict
from django.contrib.auth import authenticate
from .models import User, Project, Document, Section, Topic, Rule, Battery,BatteryOption,BatteryQuestion,BatteryAttempt
from decimal import Decimal
from django.db.models import Q
from .services.question_generator import generate_questions_for_rule
from django.db import transaction
from .serializers import (
    DocumentWithSectionsSerializer, UserSerializer, ProjectSerializer, DocumentSerializer, 
    SectionSerializer, TopicSerializer, RuleSerializer, BatterySerializer,BatteryOptionSerializer,BatteryQuestionSerializer, BatteryAttemptSerializer
)

class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    @action(detail=False, methods=['post'])
    def register(self, request):
        data = request.data
        # Ensure we received a JSON object / dict — serializers expect a mapping
        if not isinstance(data, dict):
            return Response(
                {'error': f'Invalid data. Expected a JSON object (dict), but got {type(data).__name__}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def login(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if username is None or password is None:
            return Response({'error': 'username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        if str(username).strip() == '' or str(password).strip() == '':
            return Response({'error': 'username and password cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'user': UserSerializer(user).data})
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()  # ✅ necesario para router basename
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="documents-with-sections")
    def documents_with_sections(self, request, pk=None):
        project = self.get_object()

        qs = (
            project.documents.all()               # ✅ documents (plural)
            .order_by("-uploaded_at")
            .prefetch_related(
                Prefetch("sections", queryset=Section.objects.all().order_by("order", "id"))
            )
        )

        ser = DocumentWithSectionsSerializer(qs, many=True, context={"request": request})
        return Response({"projectId": project.id, "documents": ser.data})



    def get_queryset(self):
        """
        Solo devuelve proyectos donde el usuario es owner o miembro.
        """
        user = self.request.user
        return (
            Project.objects.filter(Q(owner=user) | Q(members=user))  # ✅ usa Q importado
            .distinct()
            .order_by("-updated_at")
        )

    def perform_create(self, serializer):
        project = serializer.save(owner=self.request.user)
        project.members.add(self.request.user)


    @action(detail=True, methods=["get", "post"], url_path="documents")
    def documents(self, request, pk=None):
        project = self.get_object()

        if request.method == "GET":
            qs = project.documents.all().order_by("-uploaded_at") if hasattr(project, "documents") else project.document_set.all().order_by("-uploaded_at")
            ser = DocumentSerializer(qs, many=True, context={"request": request})
            return Response(ser.data)

        files = request.FILES.getlist("files")
        if not files:
            return Response(
                {"error": "No files provided. Use multipart/form-data with key 'files'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        created = []
        with transaction.atomic():
            for f in files:
                # ⚠️ en tu modelo Document, 'filename', 'type' y 'hash' son requeridos.
                # Aquí asumo que ya los estás seteando en tu implementación real.
                doc = Document.objects.create(
                    project=project,
                    file=f,
                    filename=getattr(f, "name", "document"),
                    type="PDF",  # <- ajusta según extensión real
                    size=getattr(f, "size", 0) or 0,
                    hash="TEMP_HASH",  # <- aquí debes calcularlo de verdad
                )
                created.append(doc)

                # ✅ crear 5 secciones temporales
                sections = [
                    Section(
                        document=doc,
                        title=f"Section {i}",
                        content="TEMP CONTENT (will be replaced by external service)",
                        order=i,
                    )
                    for i in range(1, 6)
                ]
                Section.objects.bulk_create(sections)

        ser = DocumentSerializer(created, many=True, context={"request": request})
        return Response({"uploaded": ser.data}, status=status.HTTP_201_CREATED)
        # for f in files:
        #     doc = Document.objects.create(
        #         project=project,
        #         file=f,
        #         size=getattr(f, "size", 0) or 0,  # tu NOT NULL fix
        #     )
        #     created.append(doc)

        # ser = DocumentSerializer(created, many=True, context={"request": request})
        # return Response({"uploaded": ser.data}, status=status.HTTP_201_CREATED)

class DocumentViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Document.objects.filter(
            Q(project__owner=user) | Q(project__members=user)
        ).distinct()


class SectionViewSet(viewsets.ModelViewSet):
    queryset = Section.objects.all()
    serializer_class = SectionSerializer

   
class TopicViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    serializer_class = TopicSerializer

    @action(detail=True, methods=["get"], url_path="grouped-sections")
    def grouped_sections(self, request, pk=None):
        topic = self.get_object()

        sections = (
            topic.related_sections
            .select_related("document")
            .order_by("document_id", "order", "id")
        )

        grouped = defaultdict(lambda: {"document": None, "sections": []})

        for s in sections:
            doc = s.document
            if grouped[doc.id]["document"] is None:
                grouped[doc.id]["document"] = {
                    "id": doc.id,
                    "filename": doc.filename,
                    "uploaded_at": doc.uploaded_at,
                    "status": doc.status,
                }
            grouped[doc.id]["sections"].append({
                "id": s.id,
                "title": s.title,
                "content": s.content,
                "order": s.order,
            })

        return Response({
            "topicId": topic.id,
            "projectId": topic.project_id,
            "documents": list(grouped.values()),
        })
    

    def get_queryset(self):
        qs = Topic.objects.all()
        project_id = self.request.query_params.get("project")
        if project_id:
            qs = qs.filter(project_id=project_id)
        return qs


class RuleViewSet(viewsets.ModelViewSet):
    serializer_class = RuleSerializer

    def get_queryset(self):
        qs = Rule.objects.all()
        project_id = self.request.query_params.get("project")
        if project_id:
            qs = qs.filter(project_id=project_id)
        return qs

class BatteryViewSet(viewsets.ModelViewSet):
    queryset = Battery.objects.all()
    serializer_class = BatterySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        project_id = self.request.query_params.get("project")
        if project_id:
            qs = qs.filter(project_id=project_id)
        return qs

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        project_id = request.data.get("project")
        rule_id = request.data.get("rule")
        difficulty = request.data.get("difficulty")

        if not project_id:
            return Response({"detail": "project is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not rule_id:
            return Response({"detail": "rule is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            rule = Rule.objects.select_related("topic_scope").get(id=rule_id, project_id=project_id)
        except Rule.DoesNotExist:
            return Response({"detail": "Rule not found for this project"}, status=status.HTTP_400_BAD_REQUEST)

        # topic: si rule.topic_scope existe, usamos ese. Si no, elegimos uno random del proyecto.
        # if rule.topic_scope_id:
        #     topic = rule.topic_scope
        # else:
        #     topics = list(Topic.objects.filter(project_id=project_id, status="active"))
        #     topic = random.choice(topics) if topics else None

        # if not topic:
        #     return Response(
        #         {"detail": "No topics available for this project (create at least 1 active topic)"},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )
        topics = []
        if rule.topic_scope_id:
            topics = [rule.topic_scope]
        else:
            topics = list(Topic.objects.filter(project_id=project_id, status="active"))

        if not topics:
            return Response(
                {"detail": "No topics available for this project (create at least 1 active topic)"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        name = request.data.get("name") or f"Battery - {rule.name}"
        difficulty_final = difficulty or rule.difficulty or "Medium"

        battery = Battery.objects.create(
            project_id=project_id,
            rule=rule,
            name=name,
            status="Draft",
            difficulty=difficulty_final,
        )

        count = int(rule.global_count or 0)
        generated = []

        # distribución simple (round-robin) entre topics
        for i in range(count):
            t = topics[i % len(topics)]
            q = generate_questions_for_rule(rule=rule, topic=t, count=1)[0]
            q["order"] = i  # asegura orden global correcto
            generated.append(q)


        # crear preguntas
        question_objs = []
        for q in generated:
            question_objs.append(
                BatteryQuestion(
                    battery=battery,
                    topic=q["topic"],
                    type=q["type"],
                    question=q["question"],
                    explanation=q["explanation"],
                    points=q["points"],
                    order=q["order"],
                )
            )

        BatteryQuestion.objects.bulk_create(question_objs)

        # recuperar con ids y crear opciones
        created_questions = list(BatteryQuestion.objects.filter(battery=battery).order_by("order"))
        option_objs = []

        for qobj in created_questions:
            qdata = next((x for x in generated if x["order"] == qobj.order), None)
            if not qdata:
                continue
            for opt in qdata["options"]:
                option_objs.append(
                    BatteryOption(
                        question=qobj,
                        option_id=opt["option_id"],
                        text=opt["text"],
                        correct=opt["correct"],
                        order=opt["order"],
                    )
                )

        BatteryOption.objects.bulk_create(option_objs)

        return Response(self.get_serializer(battery).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def mark_ready(self, request, pk=None):
        battery = self.get_object()
        battery.status = "Ready"
        battery.save(update_fields=["status"])
        return Response(self.get_serializer(battery).data)

    @action(detail=True, methods=["post"])
    def mark_draft(self, request, pk=None):
        battery = self.get_object()
        battery.status = "Draft"
        battery.save(update_fields=["status"])
        return Response(self.get_serializer(battery).data)
    

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def start_attempt(self, request, pk=None):
        battery = self.get_object()

        total_questions = battery.questions_rel.count()

        attempt = BatteryAttempt.objects.create(
            battery=battery,
            user=request.user,
            total_questions=total_questions,
            status="in_progress",
        )

        return Response(BatteryAttemptSerializer(attempt).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def finish_attempt(self, request, pk=None):
        battery = self.get_object()
        attempt_id = request.data.get("attempt_id")

        if not attempt_id:
            return Response({"detail": "attempt_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            attempt = BatteryAttempt.objects.get(id=attempt_id, battery=battery, user=request.user)
        except BatteryAttempt.DoesNotExist:
            return Response({"detail": "Attempt not found"}, status=status.HTTP_404_NOT_FOUND)

        # resumen (mínimo) que manda el frontend al finalizar
        total_score = Decimal(str(request.data.get("total_score", "0")))
        max_score = Decimal(str(request.data.get("max_score", "0")))
        correct_count = int(request.data.get("correct_count", 0))
        total_questions = int(request.data.get("total_questions", battery.questions_rel.count()))

        attempt.finish(
            total_score=total_score,
            max_score=max_score,
            correct_count=correct_count,
            total_questions=total_questions,
        )

        return Response(BatteryAttemptSerializer(attempt).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def attempts(self, request, pk=None):
        battery = self.get_object()
        qs = battery.attempts.filter(user=request.user).order_by("-started_at")
        return Response(BatteryAttemptSerializer(qs, many=True).data)
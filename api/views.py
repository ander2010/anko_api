import os
import uuid
import json
import hashlib
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db.models import Prefetch
from django.http import StreamingHttpResponse
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

from .models import Tag

import requests
from websocket import create_connection, WebSocketTimeoutException
from rest_framework.renderers import BaseRenderer
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


class SSERenderer(BaseRenderer):
    media_type = "text/event-stream"
    format = "sse"
    charset = None  # SSE es texto, pero así DRF no intenta tocar encoding raro

    def render(self, data, accepted_media_type=None, renderer_context=None):
        # Si devolvemos StreamingHttpResponse, DRF no debería renderizar data,
        # pero esto evita que negotiation falle.
        return data


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()  # ✅ necesario para router basename
    serializer_class = ProjectSerializer
    permission_classes = [AllowAny]

    @action(
    detail=False,
    methods=["get"],
    permission_classes=[AllowAny],
    renderer_classes=[SSERenderer],         # 🔥 CLAVE
    url_path="progress-stream",
)
    def progress_stream(self, request):
        job_id = request.query_params.get("job_id")
        if not job_id:
            return StreamingHttpResponse(
                "event: error\ndata: job_id is required\n\n",
                content_type="text/event-stream",
                status=400,
            )

        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080").rstrip("/")
        ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        ws_url = f"{ws_base}/ws/progress/{job_id}"

        def event_stream():
            ws = None
            try:
                ws = create_connection(ws_url, timeout=10)

                # evento inicial
                yield f"event: connected\ndata: {json.dumps({'job_id': job_id})}\n\n"

                while True:
                    try:
                        msg = ws.recv()
                        yield f"data: {msg}\n\n"
                    except WebSocketTimeoutException:
                        yield "event: ping\ndata: {}\n\n"

            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            finally:
                if ws:
                    ws.close()

        response = StreamingHttpResponse(
            event_stream(),
            content_type="text/event-stream",
        )
        response["Cache-Control"] = "no-cache"
        response["X-Accel-Buffering"] = "no"

        return response


    @staticmethod
    def normalize_base_url(url: str) -> str:
        return url.rstrip("/")


    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="testtowebsockett")
    def testtowebsockett(self, request):
        print("🔥 testtowebsockett endpoint called")
        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
        base_url = self.normalize_base_url(base_url)
       

        # 1) POST
        url = f"{base_url}/process-request"

        job_id = str(uuid.uuid4())
        doc_id = "barcelona-en.pdf"
        payload = {
            "job_id": job_id,
            "doc_id": doc_id,
            "file_path": "documents/barcelona-en.pdf",
            "process": "process_pdf",
            "options": {},
        }

        print(f"➡️ POST {url}")
        print("➡️ payload:", json.dumps(payload, indent=2))

        try:
            response = requests.post(url, json=payload, timeout=60)
            print(f"POST {url} -> {response.status_code}")

            try:
                data = response.json()
                print("✅ Response JSON:\n", json.dumps(data, indent=2))
                job_id = data.get("job_id", job_id)
            except Exception:
                print("✅ Response TEXT:\n", response.text)
                return Response(
                    {"success": False, "status_code": response.status_code, "raw_text": response.text},
                    status=status.HTTP_502_BAD_GATEWAY if not response.ok else status.HTTP_200_OK,
                )

            if not response.ok:
                return Response(
                    {"success": False, "status_code": response.status_code, "response": data},
                    status=status.HTTP_502_BAD_GATEWAY,
                )

            # 2) Websocket URL (para que lo abras en Postman / frontend)
            ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
            ws_url = f"{ws_base}/ws/progress/{job_id}"

            print("🔌 Connect to the progress Websocket (e.g., in Postman):")
            print(ws_url)

            # devolvemos todo + ws_url
            return Response(
                {
                    **data,
                    "ws_url": ws_url,
                },
                status=status.HTTP_200_OK,
            )

        except requests.RequestException as e:
            print("❌ RequestException:", str(e))
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

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



    def _process_document_external(self, stored_file_path: str, doc_id: str):
        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
        base_url = self.normalize_base_url(base_url)
        url = f"{base_url}/process-request"

        job_id = str(uuid.uuid4())

        payload = {
            "job_id": job_id,
            "doc_id": doc_id,
            "file_path": stored_file_path,   # 👈 IMPORTANTÍSIMO
            "process": "process_pdf",
            "options": {},
        }

        print("➡️ POST", url)
        print("➡️ payload:", json.dumps(payload, indent=2))

        r = requests.post(url, json=payload, timeout=60)
        print("✅ external status:", r.status_code)
        print("✅ external raw:", r.text[:2000])

        data = r.json()
        job_id = data.get("job_id", job_id)

        ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        ws_url = f"{ws_base}/ws/progress/{job_id}"

        return data, ws_url


    @action(detail=True, methods=["get", "post"], url_path="documents")
    def documents(self, request, pk=None):
        project = self.get_object()

        # =========================
        # GET: listar documentos
        # =========================
        if request.method == "GET":
            qs = (
                project.documents.all().order_by("-uploaded_at")
                if hasattr(project, "documents")
                else project.document_set.all().order_by("-uploaded_at")
            )
            ser = DocumentSerializer(qs, many=True, context={"request": request})
            return Response(ser.data)

        # =========================
        # POST: subir documentos
        # =========================
        files = request.FILES.getlist("files")
        if not files:
            return Response(
                {"error": "No files provided. Use multipart/form-data with key 'files'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        created_docs = []
        processing = []  # doc + ws_url + respuesta del microservicio

        with transaction.atomic():
            for f in files:
                # ✅ HASH REAL DEL CONTENIDO
                hasher = hashlib.sha256()

                # por seguridad, intenta volver al inicio antes de leer chunks
                try:
                    f.seek(0)
                except Exception:
                    pass

                for chunk in f.chunks():
                    hasher.update(chunk)

                file_hash = hasher.hexdigest()

                # vuelve al inicio para que Django guarde el archivo correctamente
                try:
                    f.seek(0)
                except Exception:
                    pass

                # ⚠️ OJO: tu hash es UNIQUE GLOBAL en DB (api_document_hash_key),
                # así que no filtres por project aquí, busca solo por hash.
                doc = Document.objects.filter(hash=file_hash).first()

                if not doc:
                    doc = Document.objects.create(
                        project=project,
                        file=f,
                        filename=getattr(f, "name", "document"),
                        type="PDF",
                        size=getattr(f, "size", 0) or 0,
                        hash=file_hash,
                    )

                    # ✅ crear 5 secciones temporales (solo si es nuevo doc)
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

                # Si el doc existía pero pertenece a otro proyecto, lo asociamos a este.
                # (Esto es un "parche" porque tu hash es unique global.)
                if doc.project_id != project.id:
                    doc.project = project
                    doc.save(update_fields=["project"])

                created_docs.append(doc)

                # ✅ nombre real en storage
                stored_path = doc.file.name  # ej: "documents/xxxxx.pdf"

                # ✅ id estable para microservicio (puedes usar doc.id o file_hash)
                external_doc_id = str(doc.id)

                # ✅ llamar al microservicio + ws
                try:
                    external_data, ws_url = self._process_document_external(
                        stored_file_path=stored_path,
                        doc_id=external_doc_id,
                    )
                except Exception as e:
                    external_data = {"success": False, "error": str(e)}
                    ws_url = None

                processing.append(
                    {
                        "document": DocumentSerializer(doc, context={"request": request}).data,
                        "ws_url": ws_url,
                        "external": external_data,
                    }
                )

        return Response(
            {
                "uploaded": DocumentSerializer(created_docs, many=True, context={"request": request}).data,
                "processing": processing,
            },
            status=status.HTTP_201_CREATED,
        )
    # @action(detail=True, methods=["get", "post"], url_path="documents")
    # def documents(self, request, pk=None):
    #     project = self.get_object()

    #     if request.method == "GET":
    #         qs = project.documents.all().order_by("-uploaded_at") if hasattr(project, "documents") else project.document_set.all().order_by("-uploaded_at")
    #         ser = DocumentSerializer(qs, many=True, context={"request": request})
    #         return Response(ser.data)

    #     files = request.FILES.getlist("files")
    #     if not files:
    #         return Response(
    #             {"error": "No files provided. Use multipart/form-data with key 'files'."},
    #             status=status.HTTP_400_BAD_REQUEST,
    #         )

    #     created_docs = []
    #     processing = []  # 👈 aquí guardamos doc + ws_url + external response

    #     with transaction.atomic():
    #         for f in files:
    #             # ✅ HASH REAL DEL CONTENIDO (UNIQUE)
    #             hasher = hashlib.sha256()
    #             for chunk in f.chunks():
    #                 hasher.update(chunk)
    #             file_hash = hasher.hexdigest()

    #             # ✅ si ya existe por hash (UNIQUE), no vueles. Reutiliza.
    #             doc = Document.objects.filter(hash=file_hash, project=project).first()
    #             if not doc:
    #                 doc = Document.objects.create(
    #                     project=project,
    #                     file=f,
    #                     filename=getattr(f, "name", "document"),
    #                     type="PDF",
    #                     size=getattr(f, "size", 0) or 0,
    #                     hash=file_hash,
    #                 )

    #                 # ✅ crear 5 secciones temporales (solo si es nuevo doc)
    #                 sections = [
    #                     Section(
    #                         document=doc,
    #                         title=f"Section {i}",
    #                         content="TEMP CONTENT (will be replaced by external service)",
    #                         order=i,
    #                     )
    #                     for i in range(1, 6)
    #                 ]
    #                 Section.objects.bulk_create(sections)

    #             created_docs.append(doc)

    #             # ✅ nombre real en storage (esto es lo que el microservicio debe poder leer)
    #             stored_path = doc.file.name  # ej: "documents/xxxxx.pdf"

    #             # ✅ doc_id para el microservicio (usa algo estable y único)
    #             external_doc_id = str(doc.id)

    #             # ✅ Llamada al microservicio + ws
    #             try:
    #                 external_data, ws_url = self._process_document_external(
    #                     stored_file_path=stored_path,
    #                     doc_id=external_doc_id,
    #                 )
    #             except Exception as e:
    #                 external_data = {"success": False, "error": str(e)}
    #                 ws_url = None

    #             processing.append({
    #                 "document": DocumentSerializer(doc, context={"request": request}).data,
    #                 "ws_url": ws_url,
    #                 "external": external_data,
    #             })

    #     return Response(
    #         {
    #             "uploaded": DocumentSerializer(created_docs, many=True, context={"request": request}).data,
    #             "processing": processing,
    #         },
    #         status=status.HTTP_201_CREATED,
    #     )


        # ser = DocumentSerializer(created, many=True, context={"request": request})
        # return Response({"uploaded": ser.data}, status=status.HTTP_201_CREATED)
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
    permission_classes = [AllowAny]


    @action(detail=True, methods=["post", "get"], url_path="tags")
    @transaction.atomic
    def tags(self, request, pk=None):
        """
        /api/documents/<id>/tags/
        Copia tags (tabla Tag) -> Section (title/content=tag) sobrescribiendo secciones del documento.
        """
        document_id = str(pk)  # 👈 usamos el ID de la URL directamente

        # 1️⃣ Obtener tags del documento
        tags = list(
        Tag.objects
        .filter(document_id=document_id)
        .order_by("created_at")
        .values_list("tag", flat=True)
    )

        # 2️⃣ Borrar secciones existentes del documento
        Section.objects.filter(document_id=document_id).delete()


        if not tags:
            return Response(
                {"document_id": document_id, "deleted_sections": True, "created": 0, "sections": []},
                status=status.HTTP_200_OK,
            )

        # 3) crear nuevas secciones desde tags
        new_sections = []
        for i, t in enumerate(tags, start=1):
            if not t:
                continue
            new_sections.append(
                Section(
                    document_id=document_id,
                    title=t,
                    content=t,
                    order=i,
                )
            )

        Section.objects.bulk_create(new_sections)

        # 4) devolver secciones nuevas
        created_qs = Section.objects.filter(document_id=document_id).order_by("order", "id")
        ser = SectionSerializer(created_qs, many=True, context={"request": request})

        return Response(
            {
                "document_id": document_id,
                "deleted_sections": True,
                "created": created_qs.count(),
                "sections": ser.data,
            },
            status=status.HTTP_200_OK,
        )
    



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
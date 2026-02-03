from django.conf import settings
from dj_rest_auth.views import PasswordResetView
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


# from multiprocessing.dummy import connection
from datetime import timedelta
import logging
from urllib import request
from django.db import connection
from redis import Redis
from django.conf import settings
import os
#from dj_rest_auth.views import PasswordResetView
from rest_framework.permissions import AllowAny

import uuid
import json
import hashlib
from django.db.models import Count, Q
import time
from django.utils import timezone
from api.utils.cripto import encrypt_user_id
import websockets
from typing import Any, Dict, Optional
import re
import asyncio
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from asgiref.sync import async_to_sync
from urllib.parse import quote
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from websocket import WebSocketConnectionClosedException
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db.models import Prefetch
from django.http import StreamingHttpResponse
from collections import defaultdict
from django.contrib.auth import authenticate, login
from .models import ConversationMessage, EmailVerification, QaPair, SupportRequest, User, Project, Document, Section, Topic, Rule, Battery,BatteryOption,BatteryQuestion,BatteryAttempt, UserSession
from decimal import Decimal
from django.db.models import Q
from .services.question_generator import generate_questions_for_rule
from django.db import transaction
from .serializers import (
    AllowedRoutesSerializer, CardFeedbackRequestSerializer, ChangePasswordSerializer, ConversationMessageSerializer, DocumentEsSerializer, DocumentWithSectionsSerializer, FrontendPasswordResetSerializer, NextCardRequestSerializer, SupportRequestSerializer, UserSerializer, ProjectSerializer, DocumentSerializer, 
    SectionSerializer, TopicSerializer, RuleSerializer, BatterySerializer,BatteryOptionSerializer,BatteryQuestionSerializer, BatteryAttemptSerializer
)
from urllib.parse import quote, urlencode
from .services.flashcards_ws import ws_get_next_card, ws_send_card_feedback
from api.services.plan_guard import PlanGuard
from .models import Tag
from api.mixins import EncryptSelectedActionsMixin

from .models import (
    Resource, Permission, Role,
    Plan, PlanLimit, Subscription,
    BatteryShare, SavedBattery, Invite,
    Deck, Flashcard, DeckShare, SavedDeck,
    Tag, QaPair
)

from .serializers import (
    ResourceSerializer, PermissionSerializer, RoleSerializer,
    PlanSerializer, PlanLimitSerializer, SubscriptionSerializer,
    BatteryShareSerializer, SavedBatterySerializer, InviteSerializer,
    DeckSerializer, FlashcardSerializer, DeckShareSerializer, SavedDeckSerializer,
    TagSerializer, QaPairSerializer
)
from .models import SummaryDocument
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail

import requests
from websocket import create_connection, WebSocketTimeoutException
from rest_framework.renderers import BaseRenderer

logging.basicConfig(level=logging.INFO)
class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer



    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="change-password")
    def change_password(self, request):
        ser = ChangePasswordSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        user = request.user
        old_password = ser.validated_data["old_password"]
        new_password = ser.validated_data["new_password"]

        if not user.check_password(old_password):
            return Response({"detail": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)  # ✅ HASH
        user.save(update_fields=["password"])

        # (opcional) invalidar tokens existentes
        Token.objects.filter(user=user).delete()

        return Response({"ok": True}, status=status.HTTP_200_OK)

        
    @staticmethod
    def _send_verify_email( user, token):
    # Ajusta a tu frontend real:
        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

        subject = "Verify your email"
        message = (
            f"Hi {user.username},\n\n"
            f"Please verify your email by clicking the link below:\n\n"
            f"{verify_url}\n\n"
            f"This link expires in 24 hours.\n"
        )

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )




    @action(detail=False, methods=["post"], permission_classes=[AllowAny], url_path="resend-verification")
    def resend_verification(self, request):
        email = (request.data.get("username") or "").strip().lower()
        if not email:
            return Response({"detail": "email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(username__iexact=email).first()

        # no revelar si existe o no
        if not user:
            return Response({"ok": True}, status=status.HTTP_200_OK)

        if user.email_verified:
            return Response({"detail": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ FIX: defaults para que no cree con expires_at NULL
        ev, created = EmailVerification.objects.get_or_create(
            user=user,
            defaults={
                "token": uuid.uuid4(),
                "expires_at": timezone.now() + timedelta(hours=24),
                "verified_at": None,
            },
        )

        
        if not created:
            ev.token = uuid.uuid4()
            ev.expires_at = timezone.now() + timedelta(hours=24)
            ev.verified_at = None
            ev.save(update_fields=["token", "expires_at", "verified_at"])

        self._send_verify_email(user, ev.token)
        return Response({"ok": True}, status=status.HTTP_200_OK)




    @action(detail=False, methods=["post"], permission_classes=[AllowAny], url_path="verify-email")
    def verify_email(self, request):
        raw_token = request.data.get("token")

        if not raw_token:
            return Response({"detail": "token is required"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ convertir string -> UUID (evita bugs)
        try:
            token_uuid = uuid.UUID(str(raw_token).strip())
        except Exception:
            return Response({"detail": "Invalid token format"}, status=status.HTTP_400_BAD_REQUEST)

        ev = get_object_or_404(EmailVerification, token=token_uuid)

        if not ev.is_valid():
            return Response({"detail": "Token expired or already used"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ marcar verificado
        ev.verified_at = timezone.now()
        ev.save(update_fields=["verified_at"])

        user = ev.user
        user.email_verified = True
        user.save(update_fields=["email_verified"])

        # ✅ ahora sí: emitir token auth
        token_obj, _ = Token.objects.get_or_create(user=user)

        return Response(
            {"ok": True, "token": token_obj.key, "user": UserSerializer(user).data},
            status=status.HTTP_200_OK,
        )


    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def register(self, request):
        data = request.data

        serializer = UserSerializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        # 🔒 email aún NO verificado
        user.email_verified = False
        user.save(update_fields=["email_verified"])

        # ✅ rol client
        client_role, _ = Role.objects.get_or_create(name="client")
        user.roles.add(client_role)

        # ❌ importante: elimina token de auth si existiera
        Token.objects.filter(user=user).delete()

        # ✅ crea o regenera verificación
        ev, _ = EmailVerification.objects.get_or_create(user=user)
        ev.token = uuid.uuid4()
        ev.expires_at = timezone.now() + timedelta(hours=24)
        ev.verified_at = None
        ev.save(update_fields=["token", "expires_at", "verified_at"])

        self._send_verify_email(user, ev.token)

        return Response(
            {
                "ok": True,
                "detail": "Account created. Please verify your email to login.",
                "email_verification": "sent",
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def login(self, request):
        username = (request.data.get("username") or "").strip()
        password = (request.data.get("password") or "").strip()

        if not username or not password:
            return Response(
                {"error": "username and password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ BLOQUEO si no verificó
        if not user.email_verified:
            return Response(
                {"error": "Email not verified", "code": "email_not_verified"},
                status=status.HTTP_403_FORBIDDEN,
            )

        login(request, user)

        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {"token": token.key, "user": UserSerializer(user).data},
            status=status.HTTP_200_OK,
        )

    # @action(detail=False, methods=['post'])
    # def register(self, request):
    #     data = request.data

    #     if not isinstance(data, dict):
    #         return Response(
    #             {'error': 'Invalid data. Expected JSON object.'},
    #             status=status.HTTP_400_BAD_REQUEST,
    #         )

    #     serializer = UserSerializer(data=data)
    #     if not serializer.is_valid():
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    #     user = serializer.save()

    #     # 🔒 email NO verificado aún
    #     user.email_verified = False
    #     user.save(update_fields=["email_verified"])

    #     # ✅ Rol client
    #     client_role, _ = Role.objects.get_or_create(name="client")
    #     user.roles.add(client_role)

    #     # 🔑 Token auth
    #     token, _ = Token.objects.get_or_create(user=user)

    #     # 📧 Crear verificación email
    #     ev, _ = EmailVerification.objects.update_or_create(
    #         user=user,
    #         defaults={
    #             "expires_at": timezone.now() + timedelta(hours=24),
    #             "verified_at": None,
    #         },
    #     )

    #     # 📤 Enviar email
    #     self._send_verify_email(user, ev.token)

    #     return Response(
    #         {
    #             "token": token.key,
    #             "user": UserSerializer(user).data,
    #             "email_verification": "sent",
    #         },
    #         status=status.HTTP_201_CREATED,
    #     )
    # @action(detail=False, methods=['post'])
    # def register(self, request):
    #     data = request.data
    #     # Ensure we received a JSON object / dict — serializers expect a mapping
    #     if not isinstance(data, dict):
    #         return Response(
    #             {'error': f'Invalid data. Expected a JSON object (dict), but got {type(data).__name__}.'},
    #             status=status.HTTP_400_BAD_REQUEST,
    #         )

    #     serializer = UserSerializer(data=data)
    #     if serializer.is_valid():
    #         user = serializer.save()
    #         # ✅ ASIGNAR ROL CLIENT
    #         client_role, _ = Role.objects.get_or_create(name="client")
    #         user.roles.add(client_role)
    #         token, created = Token.objects.get_or_create(user=user)
    #         return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @action(detail=False, methods=['post'])
    # def login(self, request):
    #     username = request.data.get('username')
    #     password = request.data.get('password')
    #     if username is None or password is None:
    #         return Response({'error': 'username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
    #     if str(username).strip() == '' or str(password).strip() == '':
    #         return Response({'error': 'username and password cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
    #     user = authenticate(username=username, password=password)
    #     if user is not None:
    #         token, created = Token.objects.get_or_create(user=user)
    #         return Response({'token': token.key, 'user': UserSerializer(user).data})
    #     return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["get", "patch"], url_path="me", permission_classes=[IsAuthenticated])
    def me(self, request):
        user = request.user
        

        if request.method == "GET":
            serializer = self.get_serializer(user)
            return Response(serializer.data)

        # PATCH
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    # @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    # def me(self, request):
    #     serializer = UserSerializer(request.user)
    #     return Response(serializer.data)

    
def flashcard_redis_key(job_id: str) -> str:
    return f"flashcards:cards:{job_id}"
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


def _normalize_base_url(url: str) -> str:
    return (url or "").rstrip("/")


def _build_ws_url_for_progress(base_url: str, job_id: str) -> str:
    base_url = _normalize_base_url(base_url)
    ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
    return f"{ws_base}/ws/progress/{job_id}"


def _build_chat_ws_url(base_url: str, session_id: str) -> str:
    base_url = _normalize_base_url(base_url)
    ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
    return f"{ws_base}/ws/chat/{session_id}"


async def _receive_final(ws: websockets.WebSocketClientProtocol) -> Dict[str, Any]:
    done_status = {"COMPLETED", "FAILED", "ERROR", "DONE", "FINISHED", "SUCCESS"}
    async for msg in ws:
        try:
            data = json.loads(msg)
        except Exception:
            return {"error": "invalid websocket payload", "raw": msg}

        # “final” style
        if data.get("type") == "final":
            return data

        # status style
        if str(data.get("status", "")).upper() in done_status:
            return data

        # error style
        if data.get("error"):
            return data

    return {"error": "websocket closed without final response"}


async def _ask_via_chat_ws(base_url: str, payload: dict, session_id: str) -> Dict[str, Any]:
    chat_ws_url = _build_chat_ws_url(base_url, session_id)

    # Nota: ping_interval=None para que no meta pings si tu server no los maneja
    async with websockets.connect(chat_ws_url, ping_interval=None) as ws:
        await ws.send(json.dumps(payload))
        final_msg = await _receive_final(ws)
        final_msg["_transport"] = "ws"
        final_msg["_chat_ws_url"] = chat_ws_url
        return final_msg


def _ask_via_http(base_url: str, payload: dict) -> Dict[str, Any]:
    url = f"{_normalize_base_url(base_url)}/ask"
    resp = requests.post(url, json=payload, timeout=120)

    out: Dict[str, Any] = {
        "_transport": "http",
        "request_url": url,
        "status_code": resp.status_code,
        "request_payload": payload,
    }

    try:
        out["response_json"] = resp.json()
    except Exception:
        out["response_text"] = resp.text

    out["ok"] = bool(resp.ok)
    return out

class ProjectViewSet(EncryptSelectedActionsMixin, viewsets.ModelViewSet):
    queryset = Project.objects.all()  # ✅ necesario para router basename
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]
    encrypted_actions = {
        "list",
        # "retrieve",
        # "documents",
        "documents_with_sections",
        # "session_messages",
        "counts",
    }
    @action(
        detail=False,
        methods=["get"],
        permission_classes=[IsAuthenticated],
        url_path="chat/session-messages",
    )
    def session_messages(self, request):
        """
        GET /api/projects/chat/session-messages/?index=1

        index: 1..5
          1 => sesión más reciente del usuario
          2 => anteúltima
          ...
        Devuelve 10 últimos mensajes (desc) de esa sesión.
        """

        # 1) validar index
        raw_index = request.query_params.get("index", "1")
        try:
            index = int(raw_index)
        except ValueError:
            return Response(
                {"detail": "index must be an integer between 1 and 5"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if index < 1 or index > 5:
            return Response(
                {"detail": "index must be between 1 and 5"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2) traer sesiones del usuario (más reciente primero)
        # Si quieres “última añadida” usa created_at.
        # Si quieres “más activa recientemente” usa updated_at.
        sessions_qs = (
            UserSession.objects
            .filter(user=request.user)
            .order_by("-created_at")   # o "-updated_at"
        )

        offset = index - 1
        session_obj = sessions_qs[offset:offset + 1].first()

        if not session_obj:
            return Response(
                {"detail": f"No session found for index={index}"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 3) últimos 10 mensajes de esa sesión
        msgs_qs = (
            ConversationMessage.objects
            .filter(session=session_obj)
            .order_by("-created_at")[:10]
        )

        data = ConversationMessageSerializer(msgs_qs, many=True).data

        return Response(
            {
                "index": index,
                "selected_session_pk": session_obj.id,
                "selected_session_id": session_obj.session_id,  # tu campo string
                "messages": data,
            },
            status=status.HTTP_200_OK,
        )




    @action(detail=True, methods=["GET"], url_path="counts", url_name="project-counts")
    def counts(self, request, pk=None):
        """
        GET /api/projects/{id}/counts/

        Returns counts for decks and batteries for this project.
        """
        qs = (
            Project.objects
            .filter(id=pk)
            .annotate(
                decks_count=Count("decks", distinct=True),
                batteries_count=Count("batteries", distinct=True),
            )
            .values("id", "decks_count", "batteries_count")
        )

        data = qs.first()
        if not data:
            return Response({"detail": "Project not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response(data, status=status.HTTP_200_OK)


    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="ask")
    def ask(self, request):
        """
        POST /api/projects/ask/

        Body:
        {
          "question": "...." (required),
          "context": ["doc1","doc2"] or "doc1" (optional; default ["test"]),
          "top_k": 10 (optional),
          "min_importance": 0.2 (optional),
          "session_id": "uuid" (optional; default auto),
          "user_id": "uuid|string" (optional; default request.user.id)
        }

        Behavior:
        - Try WS /ws/chat/<session_id> first (like ask_client.py)
        - Fallback to HTTP POST /ask if WS fails
        - Returns job_id + ws_url(progress) + response details
        """
        base_url = os.getenv("ASK_BASE_URL", os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080"))

        body = request.data or {}
        question = (body.get("question") or "").strip()
        if not question:
            return Response({"detail": "question is required"}, status=status.HTTP_400_BAD_REQUEST)

        # context puede venir como string o lista
        context = body.get("context")
        if not context:
            context_list = ["test"]
        elif isinstance(context, list):
            context_list = context
        else:
            context_list = [str(context)]

        top_k = body.get("top_k")
        min_importance = body.get("min_importance")
        session_id = (body.get("session_id") or str(uuid.uuid4())).strip()

        # user_id: si no lo mandan, usa el id del usuario autenticado
        user_id = body.get("user_id") or str(request.user.id)

        payload = {
            "question": question,
            "context": context_list,
            "top_k": top_k,
            "min_importance": min_importance,
            "session_id": session_id,
            "user_id": user_id,
        }

        session_obj, created = UserSession.objects.get_or_create(
        session_id=session_id,
        defaults={"user": request.user},
        )

        # Optional safety: prevent session hijacking across users
        if session_obj.user_id != request.user.id:
            return Response(
                {"detail": "session_id does not belong to the authenticated user"},
                status=status.HTTP_403_FORBIDDEN,
            )
        

        # 1) intenta por WS
        try:
            final_msg = asyncio.run(_ask_via_chat_ws(base_url, payload, session_id))
            job_id = final_msg.get("job_id")
            answer = final_msg.get("answer")  # <-- from your example payload

        # Save conversation message (don’t block response if saving fails)
            try:
                ConversationMessage.objects.create(
                    session=session_obj,
                    user_id=user_id,
                    job_id=job_id,
                    question=question,
                    answer=answer,
                )
            except Exception:
                logging.exception("Failed to save ConversationMessage for session_id=%s", session_id)   
                pass

            resp_payload = {
                "ok": True if not final_msg.get("error") else False,
                "transport": "ws",
                "session_id": session_id,
                "job_id": job_id,
                "ws_url": _build_ws_url_for_progress(base_url, job_id) if job_id else None,
                "final": final_msg,
                "request_payload": payload,
            }
            return Response(resp_payload, status=status.HTTP_200_OK)

        except Exception as exc:
            # 2) fallback HTTP
            http_result = _ask_via_http(base_url, payload)

            # intenta extraer job_id si vino en JSON
            job_id = None
            rj = http_result.get("response_json")
            if isinstance(rj, dict):
                job_id = rj.get("job_id")

            return Response(
                {
                    "ok": bool(http_result.get("ok")),
                    "transport": "http",
                    "session_id": session_id,
                    "job_id": job_id,
                    "ws_url": _build_ws_url_for_progress(base_url, job_id) if job_id else None,
                    "http": http_result,
                    "ws_error": str(exc),
                },
                status=status.HTTP_200_OK if http_result.get("ok") else status.HTTP_502_BAD_GATEWAY,
            )
        
        

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

        base_url = os.getenv("WS_PROCESS_REQUEST_BASE_URL", "http://localhost:8080").rstrip("/")
        ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        ws_url = f"{ws_base}/ws/progress/{job_id}"
        logging.info(f"Connecting to WS progress stream at {ws_url} for job_id {job_id}")

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
                logging.error(f"Error in WS progress stream for job_id {job_id}: {e}")
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
       
        base_url = os.getenv("WS_PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
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



        try:
            response = requests.post(url, json=payload, timeout=60)
            

            try:
                data = response.json()
             
                job_id = data.get("job_id", job_id)
            except Exception:
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

            

            # devolvemos todo + ws_url
            return Response(
                {
                    **data,
                    "ws_url": ws_url,
                },
                status=status.HTTP_200_OK,
            )

        except requests.RequestException as e:
            
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
        user = self.request.user

        user_id = self.request.query_params.get("user")          # ejemplo: ?user=12
        username = self.request.query_params.get("username")     # ejemplo: ?username=ander

        is_admin = (
            user.is_superuser
            or user.is_staff
            or user.roles.filter(name="admin").exists()
        )

        qs = Project.objects.all()

        # 1) Si NO mandan user/username: SOLO admin ve todo
        if not user_id and not username:
            if is_admin:
                return qs.order_by("-updated_at")
            return qs.filter(Q(owner=user) | Q(members=user)).distinct().order_by("-updated_at")

        # 2) Si mandan filtro: resolvemos target_user
        target_user = None
        if user_id:
            try:
                target_user = User.objects.get(id=int(user_id))
            except (ValueError, User.DoesNotExist):
                return Project.objects.none()

        if username:
            try:
                target_user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Project.objects.none()

        # 3) Seguridad: si no es admin, SOLO puede pedir sus propios proyectos
        if not is_admin and target_user.id != user.id:
            return Project.objects.none()

        # 4) Filtrar por owner o member del target_user
        return (
            qs.filter(Q(owner=target_user) | Q(members=target_user))
            .distinct()
            .order_by("-updated_at")
        )

    def perform_create(self, serializer):
        project = serializer.save(owner=self.request.user)
        project.members.add(self.request.user)



    def _process_document_external(self, stored_file_path: str, doc_id: int):
        base_url = os.getenv("WS_PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
        base_url = self.normalize_base_url(base_url)
        url = f"{os.getenv('PROCESS_REQUEST_BASE_URL', 'http://localhost:8080')}/process-request"

        logging.info(f"Calling external process-request at {url}")
        job_id = str(uuid.uuid4())

        payload = {
            "job_id": job_id,
            "doc_id": doc_id,
            "file_path": stored_file_path,   
            "process": "process_pdf",
            "options": {},
        }

   

        r = requests.post(url, json=payload, timeout=60)
     

        data = r.json()
        job_id = data.get("job_id", job_id)

        ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        ws_url = f"{ws_base}/ws/progress/{job_id}"
        logging.info(f"External process-request responded with job_id: {job_id}, ws_url: {ws_url}")
        return data, ws_url


    @action(detail=True, methods=["get", "post"], url_path="documents")
    def documents(self, request, pk=None):
        logging.info(f"documents action called with method {request.method} by user {request.user.id}")
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
            ser = DocumentEsSerializer(qs, many=True, context={"request": request})
            return Response(ser.data)

        # =========================
        # POST: subir documentos
        # =========================
        files = request.FILES.getlist("files")
        logging.info(f"Received {len(files)} files for upload")
        if not files:
            return Response(
                {"error": "No files provided. Use multipart/form-data with key 'files'."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        logging.info(f"User {request.user.id} is uploading {len(files)} files to project {project.id}")
        PlanGuard.assert_upload_allowed(user=request.user, files=files)
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
                # doc = Document.objects.filter(hash=file_hash).first()
                doc = Document.objects.filter(project=project, hash=file_hash).first()


                if not doc:
                    doc = Document(
                    project=project,
                    file=f,
                    filename=getattr(f, "name", "document"),
                    type="PDF",
                    size=getattr(f, "size", 0) or 0,
                    hash=file_hash,
                )
                    doc._uploader_id = request.user.id  # ✅ ANTES
                    doc.save()

                    # ✅ crear 5 secciones temporales (solo si es nuevo doc)
                    # sections = [
                    #     Section(
                    #         document=doc,
                    #         title=f"Section {i}",
                    #         content="TEMP CONTENT (will be replaced by external service)",
                    #         order=i,
                    #     )
                    #     for i in range(1, 6)
                    # ]
                    # Section.objects.bulk_create(sections)

                # Si el doc existía pero pertenece a otro proyecto, lo asociamos a este.
                # (Esto es un "parche" porque tu hash es unique global.)
                # if doc.project_id != project.id:
                #     doc.project = project
                #     doc.save(update_fields=["project"])

                created_docs.append(doc)

                # ✅ nombre real en storage
                stored_path = doc.file.name  # ej: "documents/xxxxx.pdf"

                # ✅ id estable para microservicio (puedes usar doc.id o file_hash)
                external_doc_id = doc.id

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
                        "document": DocumentEsSerializer(doc, context={"request": request}).data,
                        "ws_url": ws_url,
                        "external": external_data,
                    }
                )

        return Response(
            {
                "uploaded": DocumentEsSerializer(created_docs, many=True, context={"request": request}).data,
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


def build_ws_url(base_url: str, job_id: str) -> str:
    base_url = normalize_base_url(base_url)
    ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
    return f"{ws_base}/ws/progress/{job_id}"

def normalize_base_url(url: str) -> str:
        return url.rstrip("/")


class DocumentViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["post"], url_path="register")
    def register(self, request):
        project_id = request.data.get("project_id")
        filename = request.data.get("filename")
        file_key = request.data.get("file_key")
        file_size = request.data.get("size")
        file_type = request.data.get("type", "PDF")
        file_hash = request.data.get("hash")

        if not all([project_id, filename, file_key, file_hash]):
            return Response(
                {"detail": "Missing required fields (project_id, filename, file_key, hash)"},
                status=status.HTTP_400_BAD_REQUEST
            )

        project = get_object_or_404(Project, id=project_id)
        # Check access
        if project.owner != request.user and not project.members.filter(id=request.user.id).exists():
            return Response({"detail": "No access to project"}, status=status.HTTP_403_FORBIDDEN)

        doc = Document.objects.filter(project=project, hash=file_hash).first()
        if not doc:
            doc = Document(
                project=project,
                filename=filename,
                type=file_type,
                size=file_size or 0,
                hash=file_hash,
                status='pending'
            )
            doc.file.name = file_key
            doc._uploader_id = request.user.id
            doc.save()
        
        try:
            base_url = os.getenv("WS_PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
            base_url = (base_url or "").rstrip("/")
            url = f"{os.getenv('PROCESS_REQUEST_BASE_URL', 'http://localhost:8080')}/process-request"

            job_id = str(uuid.uuid4())
            payload = {
                "job_id": job_id,
                "doc_id": doc.id,
                "file_path": doc.file.name,   
                "process": "process_pdf",
                "options": {},
            }
            r = requests.post(url, json=payload, timeout=60)
            data = r.json()
            job_id = data.get("job_id", job_id)

            ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
            ws_url = f"{ws_base}/ws/progress/{job_id}"
        except Exception as e:
            data = {"success": False, "error": str(e)}
            ws_url = None

        return Response({
            "document": DocumentSerializer(doc, context={"request": request}).data,
            "ws_url": ws_url,
            "external": data,
        }, status=status.HTTP_201_CREATED)
    
    def get_queryset(self):
        user = self.request.user
        return Document.objects.filter(
            Q(project__owner=user) | Q(project__members=user)
        ).distinct()
    
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="summary")
    def summary(self, request, pk=None):
        """
        GET /api/documents/<id>/summary/

        Returns:
        {
          "document_id": 123,
          "summary": "...",
          "created_at": "...",
          "updated_at": "..."
        }
        """
        doc = self.get_object()  # respeta tu get_queryset() (owner/members)

        # Busca el summary asociado (OneToOne)
        sd = SummaryDocument.objects.filter(document=doc).only(
            "summary", "created_at", "updated_at", "document_id"
        ).first()

        if not sd:
            return Response(
                {"detail": "Summary not found for this document", "document_id": doc.id},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "document_id": doc.id,
                "summary": sd.summary or "",
                "created_at": sd.created_at,
                "updated_at": sd.updated_at,
            },
            status=status.HTTP_200_OK,
        )



    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="download-url")
    def download_url(self, request, pk=None):
        doc = self.get_object()


        # seguridad extra (por si cambias get_queryset)
        user = request.user
        can_view = (
            doc.project.owner_id == user.id
            or doc.project.members.filter(id=user.id).exists()
        )
        if not can_view:
            raise PermissionDenied("You do not have access to this document.")

        if not doc.file:
            return Response(
                {"detail": "Document has no file"},
                status=status.HTTP_404_NOT_FOUND
            )

        # mode puede ser: view | download (default view)
        mode = (request.query_params.get("mode") or "view").lower()
        if mode not in ("view", "download"):
            return Response(
                {"detail": "Invalid mode. Use 'view' or 'download'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        raw_key = doc.file.name
        storage_key = normalize_storage_key(raw_key)

        # storage_key = doc.file.name  # ej: "anko/documents/test.pdf"
        # Escapar por si hay espacios o caracteres raros

        user_token = encrypt_user_id(user.id)

        query = urlencode({
            "file": storage_key,
            "seed": user_token,
        })

        url = f"https://italk2.me/content_view/{mode}?{query}"



        # base = "https://italk2.me/content_view"
        # # url = f"{base}/{mode}?file={storage_key_q}"
        # url = f"{base}/{mode}?{query}"

        return Response({
            "id": doc.id,
            "filename": doc.filename,        # ej: "test.pdf"
            "storage_key": storage_key,      # ej: "anko/documents/test.pdf"
            "mode": mode,                    # "view" | "download"
            "url": url,
        })
    
    


    @action(detail=True, methods=["post", "get"], url_path="tags")
    @transaction.atomic
    def tags(self, request, pk=None):
        """
        /api/documents/<id>/tags/
        Copia tags (tabla Tag) -> Section (title/content=tag) sobrescribiendo secciones del documento.
        """
        document_id = int(pk)

        sections = Section.objects.filter(document_id=document_id).order_by("order", "id")

        serializer = SectionSerializer(
            sections,
            many=True,
            context={"request": request},
        )

        return Response(
            {
                "document_id": document_id,
                "count": sections.count(),
                "sections": serializer.data,
            },
            status=status.HTTP_200_OK,
        )
    #     document_id = pk  # 👈 usamos el ID de la URL directamente

    #     # 1️⃣ Obtener tags del documento
    #     tags = list(
    #     Tag.objects
    #     .filter(document_id=document_id)
    #     .order_by("created_at")
    #     .values_list("tag", flat=True)
    # )

    #     # 2️⃣ Borrar secciones existentes del documento
    #     Section.objects.filter(document_id=document_id).delete()


    #     if not tags:
    #         return Response(
    #             {"document_id": document_id, "deleted_sections": True, "created": 0, "sections": []},
    #             status=status.HTTP_200_OK,
    #         )

    #     # 3) crear nuevas secciones desde tags
    #     new_sections = []
    #     for i, t in enumerate(tags, start=1):
    #         if not t:
    #             continue
    #         new_sections.append(
    #             Section(
    #                 document_id=document_id,
    #                 title=t,
    #                 content=t,
    #                 order=i,
    #             )
    #         )

    #     Section.objects.bulk_create(new_sections)

    #     # 4) devolver secciones nuevas
    #     created_qs = Section.objects.filter(document_id=document_id).order_by("order", "id")
    #     ser = SectionSerializer(created_qs, many=True, context={"request": request})

    #     return Response(
    #         {
    #             "document_id": document_id,
    #             "deleted_sections": True,
    #             "created": created_qs.count(),
    #             "sections": ser.data,
    #         },
    #         status=status.HTTP_200_OK,
    #     )
    



    def get_queryset(self):
        user = self.request.user
        return Document.objects.filter(
            Q(project__owner=user) | Q(project__members=user)
        ).distinct()


class SectionViewSet(viewsets.ModelViewSet):
    queryset = Section.objects.all()
    serializer_class = SectionSerializer

   
class TopicViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
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
def normalize_storage_key(key: str) -> str:
    key = (key or "").lstrip("/")

    bucket = (
        getattr(settings, "AWS_STORAGE_BUCKET_NAME", "anko")
        or "anko"
    ).strip().strip("/")

    
    if not key.startswith(bucket + "/"):
        key = f"{bucket}/{key}"

    return key



class BatteryViewSet(EncryptSelectedActionsMixin,viewsets.ModelViewSet):
    queryset = Battery.objects.all()
    serializer_class = BatterySerializer
    permission_classes = [IsAuthenticated]




    

    encrypted_actions = {
        "list",          # GET /batteries/
        "retrieve",      # GET /batteries/{id}/
        "attempts",      # GET custom action
        "results",       # GET custom action
        "stats",         # GET custom action
    }
    


    def _split_multi_answers(correct_response: str) -> list[str]:
        """
        Para multi_select: separa por coma/; / salto de línea.
        """

        def _safe_str(x) -> str:
            return "" if x is None else str(x)
        raw = _safe_str(correct_response).strip()
        if not raw:
            return []
        parts = re.split(r"[,\n;]+", raw)
        return [p.strip() for p in parts if p.strip()]


    def _map_question_type(raw: str) -> str:
        raw = (raw or "").strip().lower()
        if raw in ["true_false", "truefalse", "tf"]:
            return "trueFalse"
        if raw in ["single_choice", "singlechoice", "single"]:
            return "singleChoice"
        if raw in ["multi_select", "multiselect", "multi", "multi_choice", "multiple_choice", "multiple", "checkbox"]:
            return "multiSelect"
        if raw in ["mixed"]:
            # “mixed” lo tratamos como singleChoice por defecto
            return "singleChoice"
        return "singleChoice"


    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="save-questions-from-qa")
    def save_questions_from_qa(self, request, pk=None):
        battery = self.get_object()

        job_id = request.data.get("job_id") or getattr(battery, "external_job_id", None)
        question_format = request.data.get("question_format") or "true_false"
        overwrite = bool(request.data.get("overwrite", True))
        points_default = request.data.get("points_default", 1)

        try:
            result = BatteryViewSet.save_questions_from_qa_pairs(
                battery=battery,
                job_id=str(job_id),
                question_format=str(question_format),
                overwrite=overwrite,
                points_default=points_default,
            )

            if result.get("questions_created", 0) > 0:
                battery.status = "Ready"
                if not getattr(battery, "external_job_id", None):
                    battery.external_job_id = str(job_id)
                    battery.save(update_fields=["status", "external_job_id"])
                else:
                    battery.save(update_fields=["status"])

            return Response({"ok": True, "battery_id": battery.id, "job_id": str(job_id), "result": result})
        except Exception as e:
            return Response(
                {"ok": False, "detail": "Failed saving questions from qa_pairs", "error": str(e), "battery_id": battery.id, "job_id": str(job_id)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        

    @staticmethod
    @transaction.atomic
    def save_questions_from_qa_pairs(
        *,
        battery,
        job_id: str,
        question_format: str = "true_false",
        points_default=1,
        overwrite: bool = True,
    ) -> dict:

        def _safe_str(x) -> str:
            return "" if x is None else str(x)

        def _normalize_bool_text(s: str) -> str:
            s = (s or "").strip().lower()
            if s in {"true", "t", "verdadero", "v", "1", "yes", "y"}:
                return "true"
            if s in {"false", "f", "falso", "0", "no", "n"}:
                return "false"
            return s

        def _map_question_type(raw: str) -> str:
            raw = (raw or "").strip().lower()
            if raw in ["true_false", "truefalse", "tf"]:
                return "trueFalse"
            if raw in ["single_choice", "singlechoice", "single"]:
                return "singleChoice"
            if raw in ["multi_select", "multiselect", "multi", "multi_choice", "multiple_choice", "multiple", "checkbox"]:
                return "multiSelect"
            if raw in ["mixed"]:
                return "singleChoice"
            return "singleChoice"

        def _split_multi_answers(correct_response: str) -> list[str]:
            raw = _safe_str(correct_response).strip()
            if not raw:
                return []
            parts = re.split(r"[,\n;]+", raw)
            return [p.strip() for p in parts if p.strip()]

        job_id = _safe_str(job_id).strip()
        if not job_id:
            raise ValueError("job_id is required")

        # 1) Traer filas de qa_pairs (tuplas)
        with connection.cursor() as cursor:
            cursor.execute(
            """
            SELECT document_id, qa_index, question, correct_response, meta, created_at
            FROM qa_pairs
            WHERE job_id = %s
            ORDER BY qa_index, created_at
            """,
            [job_id],
        )
            rows = cursor.fetchall()

        if overwrite:
            BatteryOption.objects.filter(question__battery=battery).delete()
            BatteryQuestion.objects.filter(battery=battery).delete()

        if not rows:
            return {
                "battery_id": battery.id,
                "job_id": job_id,
                "qa_pairs_found": 0,
                "questions_created": 0,
                "options_created": 0,
            }

        qtype_default = _map_question_type(question_format)

        # 2) Crear BatteryQuestion en bulk
        q_objs = []
        prepared = []

        for idx, r in enumerate(rows):
            document_id, qa_index, question_text, correct_response, meta_raw, created_at = r

            question_text = _safe_str(question_text).strip()
            correct_response = _safe_str(correct_response).strip()

            if not question_text:
                continue

            # metadata es JSON string
            meta = {}
            if meta_raw:
                try:
                    meta = json.loads(meta_raw) if isinstance(meta_raw, str) else (meta_raw or {})
                except Exception:
                    meta = {}

            meta_type = None
            if isinstance(meta, dict):
                meta_type = meta.get("question_format") or meta.get("format") or meta.get("type")

            qtype = _map_question_type(meta_type) if meta_type else qtype_default
            order_val = int(qa_index) if qa_index is not None else idx

            q_objs.append(
                BatteryQuestion(
                    battery=battery,
                    topic=None,
                    type=qtype,
                    question=question_text,
                    explanation=_safe_str(meta.get("explanation") if isinstance(meta, dict) else ""),
                    points=Decimal(str(points_default)),
                    order=order_val,
                )
            )

            prepared.append(
                {
                    "qtype": qtype,
                    "correct_response": correct_response,
                    "metadata": meta,
                }
            )

        if not q_objs:
            return {
                "battery_id": battery.id,
                "job_id": job_id,
                "qa_pairs_found": len(rows),
                "questions_created": 0,
                "options_created": 0,
            }

        BatteryQuestion.objects.bulk_create(q_objs)

        created_questions = list(
            BatteryQuestion.objects.filter(battery=battery).order_by("order", "id")
        )

        # 3) Crear opciones
        opt_objs = []

        for qobj, pdata in zip(created_questions, prepared):
            qtype = pdata["qtype"]
            correct_response = pdata["correct_response"]
            meta = pdata["metadata"] or {}

            # Si metadata trae options
            if isinstance(meta, dict) and meta.get("options"):
                options = meta.get("options")

                # options: ["True","False"] (strings)
                if isinstance(options, list) and options and isinstance(options[0], str):
                    correct_norm = correct_response.strip().lower()
                    for i, opt_text in enumerate(options, start=1):
                        opt_text_str = _safe_str(opt_text).strip()
                        opt_objs.append(
                            BatteryOption(
                                question=qobj,
                                option_id=str(i),
                                text=opt_text_str,
                                correct=(opt_text_str.lower() == correct_norm),
                                order=i,
                            )
                        )
                    continue

                # options: [{"option_id":...,"text":...}]
                if isinstance(options, list) and options and isinstance(options[0], dict):
                    for i, opt in enumerate(options, start=1):
                        opt_objs.append(
                            BatteryOption(
                                question=qobj,
                                option_id=_safe_str(opt.get("option_id") or opt.get("id") or i),
                                text=_safe_str(opt.get("text") or ""),
                                correct=bool(opt.get("correct")),
                                order=int(opt.get("order") or i),
                            )
                        )
                    continue

            # Fallbacks
            if qtype == "trueFalse":
                norm = _normalize_bool_text(correct_response)
                is_true = norm == "true"
                is_false = norm == "false"
                if not (is_true or is_false):
                    is_true = True
                    is_false = False

                opt_objs.append(BatteryOption(question=qobj, option_id="true", text="True", correct=is_true, order=1))
                opt_objs.append(BatteryOption(question=qobj, option_id="false", text="False", correct=is_false, order=2))

            elif qtype == "multiSelect":
                corrects = {c.lower() for c in _split_multi_answers(correct_response)}
                if not corrects:
                    opt_objs.append(BatteryOption(question=qobj, option_id="a", text="N/A", correct=True, order=1))
                else:
                    for i, ans in enumerate(sorted(corrects), start=1):
                        opt_objs.append(
                            BatteryOption(
                                question=qobj,
                                option_id=chr(96 + i),
                                text=ans,
                                correct=True,
                                order=i,
                            )
                        )
            else:
                if not correct_response:
                    correct_response = "N/A"
                opt_objs.append(BatteryOption(question=qobj, option_id="a", text=correct_response, correct=True, order=1))
                opt_objs.append(BatteryOption(question=qobj, option_id="b", text="Other", correct=False, order=2))

        if opt_objs:
            BatteryOption.objects.bulk_create(opt_objs)

        return {
            "battery_id": battery.id,
            "job_id": job_id,
            "qa_pairs_found": len(rows),
            "questions_created": len(created_questions),
            "options_created": len(opt_objs),
        }




    
    @action(detail=True, methods=["get"], permission_classes=[AllowAny], renderer_classes=[SSERenderer], url_path="progress-stream-bat")
    def progress_stream_bat(self, request, pk=None):
        battery = self.get_object()
        job_id = getattr(battery, "external_job_id", None)

        base_url = os.getenv("WS_PROCESS_REQUEST_BASE_URL", "http://localhost:8080").rstrip("/")
        ws_base = base_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)

        def sse_one(event_name: str, payload: dict, http_status=200):
            # helper para devolver SSE incluso en errores
            def gen():
                yield f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"
            resp = StreamingHttpResponse(gen(), content_type="text/event-stream", status=http_status)
            resp["Cache-Control"] = "no-cache"
            resp["X-Accel-Buffering"] = "no"
            return resp

        if not job_id:
            # ✅ NO Response() — siempre SSE
            return sse_one(
                "error",
                {"detail": "Battery has no external_job_id. Start the job first.", "battery_id": battery.id},
                http_status=status.HTTP_400_BAD_REQUEST,
            )

        ws_url = f"{ws_base}/ws/progress/{job_id}"

        def event_stream():
            yield f"event: init\ndata: {json.dumps({'battery_id': battery.id, 'job_id': job_id, 'ws_url': ws_url})}\n\n"

            try:
                ws = create_connection(ws_url, timeout=20)
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': 'failed_to_connect_ws', 'detail': str(e), 'ws_url': ws_url})}\n\n"
                return

            last_keepalive = time.time()
            try:
                while True:
                    if time.time() - last_keepalive > 15:
                        yield "event: ping\ndata: {}\n\n"
                        last_keepalive = time.time()

                    try:
                        msg = ws.recv()
                    except WebSocketConnectionClosedException:
                        yield f"event: end\ndata: {json.dumps({'status': 'ws_closed'})}\n\n"
                        break
                    except Exception as e:
                        yield f"event: error\ndata: {json.dumps({'error': 'ws_recv_failed', 'detail': str(e)})}\n\n"
                        break

                    try:
                        payload = json.loads(msg) if isinstance(msg, str) else msg
                    except Exception:
                        payload = {"raw": msg}

                    yield f"event: progress\ndata: {json.dumps(payload)}\n\n"

                    status_val = str(payload.get("status", "")).upper()
                    if status_val in {"DONE", "COMPLETED", "FINISHED", "SUCCESS", "FAILED", "ERROR"}:
                        yield f"event: end\ndata: {json.dumps({'final_status': status_val})}\n\n"
                        break
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

        resp = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
        resp["Cache-Control"] = "no-cache"
        resp["X-Accel-Buffering"] = "no"
        return resp


    def _map_question_type(raw: str) -> str:
        raw = (raw or "").strip().lower()
        if raw in ["true_false", "truefalse", "tf"]:
            return "trueFalse"
        if raw in ["single_choice", "singlechoice", "single"]:
            return "singleChoice"
        if raw in ["multi_select", "multiselect", "multi", "multi_choice", "multiple_choice", "multiple", "checkbox"]:
            return "multiSelect"
        # default safe
        return "singleChoice"
    



    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="start-generate")
    @transaction.atomic
    def start_generate(self, request):
        """
        POST /api/batteries/start-generate/

        Body:
        {
          "project": 2,
          "rule": 5 (opcional),
          "doc_id": "7",
          "query_text": ["Barca"] o "Barca",
          "tags": null o ["x"],
          "quantity": 3,
          "difficulty": "medium",
          "question_format": "true_false",
          "top_k": null,
          "min_importance": null
        }

        Returns: battery + job_id + ws_url
        """
        PlanGuard.assert_can_create_battery(user=request.user)
        project_id = request.data.get("project")
        rule_id = request.data.get("rule")
        # doc_id = request.data.get("doc_id")

        section_ids = request.data.get("sections") or []
        if not isinstance(section_ids, list) or not section_ids:
            return Response(
                {"detail": "sections is required and must be a non-empty list of section ids"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not project_id:
            return Response({"detail": "project is required"}, status=status.HTTP_400_BAD_REQUEST)
        # if not doc_id:
        #     return Response({"detail": "doc_id is required"}, status=status.HTTP_400_BAD_REQUEST)


        # 1) cargar sections
        sections_qs = Section.objects.filter(id__in=section_ids).only("id", "title", "document_id").order_by("id")
        sections = list(sections_qs)

        if len(sections) != len(set(section_ids)):
            found_ids = {s.id for s in sections}
            missing = [sid for sid in section_ids if sid not in found_ids]
            return Response(
                {"detail": "Some sections were not found", "missing_section_ids": missing},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 2) validar que todos pertenezcan al mismo document
        doc_ids = list({s.document_id for s in sections})
        if len(doc_ids) != 1:
            return Response(
                {
                    "detail": "All sections must belong to the same document",
                    "document_ids_found": doc_ids,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        document_id = doc_ids[0]
        derived_tags = [s.title.strip() for s in sections if (s.title or "").strip()]

        # fallback seguro
        if not derived_tags:
            derived_tags = ["general"]



    
        rule = None
        if rule_id:
            try:
                rule = Rule.objects.get(id=rule_id, project_id=project_id)
            except Rule.DoesNotExist:
                return Response({"detail": "Rule not found for this project"}, status=status.HTTP_400_BAD_REQUEST)

        difficulty = (request.data.get("difficulty") or "medium").lower()
        difficulty_db = {"easy": "Easy", "medium": "Medium", "hard": "Hard"}.get(difficulty, "Medium")

        battery = Battery.objects.create(
            project_id=project_id,
            rule=rule,
            name=request.data.get("name") or (f"Battery - {rule.name}" if rule else "Battery - Generated"),
            status="Draft",
            difficulty=difficulty_db,
            # external_doc_id=str(document_id),
        )

        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
        url = f"{normalize_base_url(base_url)}/process-request"

        job_id = str(uuid.uuid4())

        query_text = request.data.get("query_text")
        if isinstance(query_text, list) and len(query_text) == 1:
            query_text_payload = query_text[0]
        else:
            query_text_payload = query_text

        payload = {
            "job_id": job_id,
            "doc_id": str(document_id),
            "process": "generate_question",
            "tags": derived_tags,
            "query_text": query_text_payload,
            "top_k": request.data.get("top_k"),
            "min_importance": request.data.get("min_importance"),
            "quantity_question": int(request.data.get("quantity", 3)),
            "difficulty": difficulty,
            "question_format": request.data.get("question_format") or "true_false",
            "options": {},
        }

        try:
            resp = requests.post(url, json=payload, timeout=120)
        except requests.RequestException as e:
            return Response(
                {"detail": "Failed calling microservice", "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        try:
            data = resp.json()
        except Exception:
            data = {"raw_text": resp.text}

        ws_job_id = (data.get("job_id") if isinstance(data, dict) else None) or job_id
        ws_url = build_ws_url(base_url, ws_job_id)

        # guarda job_id en battery (si añadiste el field)
        battery.external_job_id = ws_job_id
        battery.save(update_fields=["external_job_id"])

        return Response(
            {
                "battery": BatterySerializer(battery, context={"request": request}).data,
                "job_id": ws_job_id,
                "ws_url": ws_url,
                "microservice_response": data,
            },
            status=status.HTTP_201_CREATED if resp.ok else status.HTTP_202_ACCEPTED,
        )
    
    
    # @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="generate-from-service")
    # @transaction.atomic
    # def generate_from_service(self, request):
    #     """
    #     POST /api/batteries/generate-from-service/

    #     Body esperado (igual que el script de tu amigo):
    #     {
    #       "project": 2,
    #       "rule": 5,                 (opcional si quieres atarlo a una rule)
    #       "doc_id": "7"              (o "test", o filename)  <-- lo que el microservicio entienda
    #       "query_text": ["Barca"] or "Barca",
    #       "tags": null or ["tag1","tag2"],
    #       "quantity": 3,
    #       "difficulty": "medium",
    #       "question_format": "true_false",
    #       "top_k": null,
    #       "min_importance": null
    #     }
    #     """
    #     project_id = request.data.get("project")
    #     rule_id = request.data.get("rule")
    #     doc_id = request.data.get("doc_id")  # 👈 IMPORTANTÍSIMO: este debe coincidir con lo que tu microservicio entiende
    #     query_text = request.data.get("query_text")
    #     tags = request.data.get("tags")
    #     quantity = int(request.data.get("quantity", 3))
    #     difficulty = (request.data.get("difficulty") or "medium").lower()
    #     question_format = request.data.get("question_format") or "true_false"
    #     top_k = request.data.get("top_k")
    #     min_importance = request.data.get("min_importance")

    #     if not project_id:
    #         return Response({"detail": "project is required"}, status=status.HTTP_400_BAD_REQUEST)
    #     if not doc_id:
    #         return Response({"detail": "doc_id is required (must match microservice doc_id)"}, status=status.HTTP_400_BAD_REQUEST)

    #     rule = None
    #     if rule_id:
    #         try:
    #             rule = Rule.objects.get(id=rule_id, project_id=project_id)
    #         except Rule.DoesNotExist:
    #             return Response({"detail": "Rule not found for this project"}, status=status.HTTP_400_BAD_REQUEST)

    #     # Normaliza query_text a string o lista (como el script)
    #     if isinstance(query_text, list) and len(query_text) == 1:
    #         query_text_payload = query_text[0]
    #     else:
    #         query_text_payload = query_text

    #     # Crear Battery (usa tu esquema actual)
    #     battery = Battery.objects.create(
    #         project_id=project_id,
    #         rule=rule,
    #         name=request.data.get("name") or (f"Battery - {rule.name}" if rule else "Battery - Generated"),
    #         status="Draft",
    #         difficulty={"easy": "Easy", "medium": "Medium", "hard": "Hard"}.get(difficulty, "Medium"),
    #     )

    #     base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080")
    #     url = f"{normalize_base_url(base_url)}/process-request"

    #     job_id = str(uuid.uuid4())
    #     payload = {
    #         "job_id": job_id,
    #         "doc_id": doc_id,
    #         "process": "generate_question",
    #         "tags": tags,
    #         "query_text": query_text_payload,
    #         "top_k": top_k,
    #         "min_importance": min_importance,
    #         "quantity_question": quantity,
    #         "difficulty": difficulty,
    #         "question_format": question_format,
    #         "options": {},
    #     }

    #     try:
    #         resp = requests.post(url, json=payload, timeout=120)
    #     except requests.RequestException as e:
    #         return Response(
    #             {
    #                 "detail": "Failed calling question microservice",
    #                 "error": str(e),
    #                 "battery_id": battery.id,
    #                 "job_id": job_id,
    #                 "ws_url": build_ws_url(base_url, job_id),
    #             },
    #             status=status.HTTP_502_BAD_GATEWAY,
    #         )

    #     try:
    #         data = resp.json()
    #     except Exception:
    #         return Response(
    #             {
    #                 "detail": "Microservice returned non-JSON",
    #                 "status_code": resp.status_code,
    #                 "text": resp.text,
    #                 "battery_id": battery.id,
    #                 "job_id": job_id,
    #                 "ws_url": build_ws_url(base_url, job_id),
    #             },
    #             status=status.HTTP_502_BAD_GATEWAY if not resp.ok else status.HTTP_200_OK,
    #         )

    #     ws_job_id = data.get("job_id") or job_id
    #     ws_url = build_ws_url(base_url, ws_job_id)

    #     # ✅ Aquí viene la clave:
    #     # Si el microservicio YA devuelve preguntas en data, las guardamos.
    #     # Si no devuelve, devolvemos ws_url para que el frontend espere y luego llame a otro endpoint.
    #     questions = data.get("questions") or data.get("result") or None

    #     if not questions:
    #         return Response(
    #             {
    #                 "detail": "Job queued. Connect to ws_url and later sync questions into battery.",
    #                 "battery": BatterySerializer(battery, context={"request": request}).data,
    #                 "job_id": ws_job_id,
    #                 "ws_url": ws_url,
    #                 "microservice_response": data,
    #             },
    #             status=status.HTTP_202_ACCEPTED,
    #         )

    #     # --- Guardar questions en tus modelos ---
    #     # Debes adaptar el mapping a la forma exacta que devuelva el microservicio.
    #     # Yo asumo algo como:
    #     # questions = [
    #     #   {"type":"trueFalse","question":"...","explanation":"...","points":1,"options":[{"option_id":"true","text":"True","correct":True,"order":1}, ...]},
    #     # ]
    #     q_objs = []
    #     for idx, q in enumerate(questions):
    #         q_objs.append(
    #             BatteryQuestion(
    #                 battery=battery,
    #                 topic=None,  # si tu microservicio manda topic_id lo mapeamos
    #                 type=_map_question_type(q.get("type") or question_format),
    #                 question=q.get("question") or "",
    #                 explanation=q.get("explanation") or "",
    #                 points=q.get("points") or 0,
    #                 order=idx,
    #             )
    #         )
    #     BatteryQuestion.objects.bulk_create(q_objs)

    #     created_questions = list(BatteryQuestion.objects.filter(battery=battery).order_by("order"))
    #     opt_objs = []
    #     for qobj, qdata in zip(created_questions, questions):
    #         for opt in (qdata.get("options") or []):
    #             opt_objs.append(
    #                 BatteryOption(
    #                     question=qobj,
    #                     option_id=str(opt.get("option_id") or opt.get("id") or ""),
    #                     text=opt.get("text") or "",
    #                     correct=bool(opt.get("correct")),
    #                     order=int(opt.get("order") or 0),
    #                 )
    #             )
    #     BatteryOption.objects.bulk_create(opt_objs)

    #     return Response(
    #         {
    #             "battery": BatterySerializer(battery, context={"request": request}).data,
    #             "job_id": ws_job_id,
    #             "ws_url": ws_url,
    #             "microservice_response": data,
    #         },
    #         status=status.HTTP_201_CREATED,
    #     )





    def get_queryset(self):
        qs = super().get_queryset()
        project_id = self.request.query_params.get("project")
        if project_id:
            qs = qs.filter(project_id=project_id)
        return qs

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        PlanGuard.assert_can_create_battery(user=request.user)
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
    


# ==========================================================
# RBAC (Resources / Permissions / Roles)
# ==========================================================

class ResourceViewSet(viewsets.ModelViewSet):
    queryset = Resource.objects.all().order_by("key")
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.select_related("resource").all().order_by("resource__key", "action", "code")
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated]


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.prefetch_related("permissions").all().order_by("name")
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]


# ==========================================================
# Plans / Limits / Subscription
# ==========================================================

class PlanViewSet(viewsets.ModelViewSet):
    queryset = Plan.objects.prefetch_related("limits").all().order_by("tier")
    serializer_class = PlanSerializer
    permission_classes = [AllowAny]  # normalmente el listado de planes es público

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="me/limits")
    def my_limits(self, request):
        plan = PlanGuard.get_plan_for_user(request.user)

        data = {
            "plan": {"tier": plan.tier, "name": plan.name},
            "max_documents": plan.max_documents,
            "max_batteries": plan.max_batteries,
            "limits": {
                "upload_max_mb": PlanGuard.limit_int(plan, "upload_max_mb"),
                "questions_per_battery_max": PlanGuard.limit_int(plan, "questions_per_battery_max"),
                "explore_topics_limit": PlanGuard.limit_int(plan, "explore_topics_limit"),
                "can_use_flashcards": PlanGuard.limit_bool(plan, "can_use_flashcards"),
                "can_invite": PlanGuard.limit_bool(plan, "can_invite"),
                "can_collect_batteries": PlanGuard.limit_bool(plan, "can_collect_batteries"),
                "can_collect_decks": PlanGuard.limit_bool(plan, "can_collect_decks"),
            },
        }
        return Response(data)


class PlanLimitViewSet(viewsets.ModelViewSet):
    queryset = PlanLimit.objects.select_related("plan").all().order_by("plan__tier", "key")
    serializer_class = PlanLimitSerializer
    permission_classes = [IsAuthenticated]


class SubscriptionViewSet(viewsets.ModelViewSet):
    queryset = Subscription.objects.select_related("user", "plan").all()
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # usuario normal solo ve su subscription; staff/admin ve todas
        user = self.request.user
        if user.is_staff or user.is_superuser:
            return super().get_queryset()
        return super().get_queryset().filter(user=user)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="me")
    def me(self, request):
        sub = getattr(request.user, "subscription", None)
        if not sub:
            return Response({"detail": "No subscription found for this user"}, status=status.HTTP_404_NOT_FOUND)
        return Response(self.get_serializer(sub).data)

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="set-plan")
    def set_plan(self, request):
        """
        POST /api/subscriptions/set-plan/
        Body: { "tier": "free|premium|ultra" }
        Cambia el plan del usuario (demo/simple). En producción lo maneja Stripe/Paypal webhooks.
        """
        tier = (request.data.get("tier") or "").strip().lower()
        if tier not in ("free", "premium", "ultra"):
            return Response({"detail": "tier must be free|premium|ultra"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            plan = Plan.objects.get(tier=tier, is_active=True)
        except Plan.DoesNotExist:
            return Response({"detail": "Plan not found or inactive"}, status=status.HTTP_404_NOT_FOUND)

        sub, _ = Subscription.objects.get_or_create(user=request.user, defaults={"plan": plan})
        sub.plan = plan
        sub.status = "active"
        sub.current_period_start = timezone.now()
        sub.save(update_fields=["plan", "status", "current_period_start"])

        return Response(self.get_serializer(sub).data, status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

# ==========================================================
# Sharing / Saved / Invites (Batteries)
# ==========================================================

class BatteryShareViewSet(viewsets.ModelViewSet):
    queryset = BatteryShare.objects.select_related("battery", "shared_with").all()
    serializer_class = BatteryShareSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # shares donde: yo soy el receptor O yo soy el dueño del battery
        return (
            super()
            .get_queryset()
            .filter(Q(shared_with=user) | Q(battery__project__owner=user))
            .distinct()
        )

    def perform_create(self, serializer):
        # valida que el usuario sea dueño del battery
        battery = serializer.validated_data["battery"]
        if battery.project.owner_id != self.request.user.id:
            raise serializers.ValidationError("Only the project owner can share this battery.")
        serializer.save()


class SavedBatteryViewSet(viewsets.ModelViewSet):
    queryset = SavedBattery.objects.select_related("user", "battery", "battery__project").all()
    serializer_class = SavedBatterySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class InviteViewSet(viewsets.ModelViewSet):
    queryset = Invite.objects.select_related("inviter", "battery_to_share", "accepted_by").all()
    serializer_class = InviteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # invitaciones que yo mandé, o que yo acepté
        return super().get_queryset().filter(Q(inviter=user) | Q(accepted_by=user)).distinct()

    def perform_create(self, serializer):
        # Solo Ultra debería poder invitar (luego lo amarramos a PlanLimit)
        serializer.save(inviter=self.request.user)

    @action(detail=False, methods=["post"], permission_classes=[AllowAny], url_path="accept")
    def accept(self, request):
        """
        POST /api/invites/accept/
        Body: { "token": "<uuid>" }
        """
        token = request.data.get("token")
        if not token:
            return Response({"detail": "token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            invite = Invite.objects.select_related("battery_to_share").get(token=token)
        except Invite.DoesNotExist:
            return Response({"detail": "Invite not found"}, status=status.HTTP_404_NOT_FOUND)

        if not invite.is_valid():
            return Response({"detail": "Invite is not valid (expired/revoked/accepted)"}, status=status.HTTP_400_BAD_REQUEST)

        # Si está autenticado, registramos accepted_by
        if request.user.is_authenticated:
            invite.status = "accepted"
            invite.accepted_by = request.user
            invite.accepted_at = timezone.now()
            invite.save(update_fields=["status", "accepted_by", "accepted_at"])
            return Response(InviteSerializer(invite).data)

        # Si no está autenticado, el frontend debe redirigir a register/login
        return Response(
            {"detail": "Invite is valid. Please login/register to accept.", "invite": InviteSerializer(invite).data},
            status=status.HTTP_200_OK,
        )


# ==========================================================
# Flashcards
# ==========================================================

class DeckViewSet(EncryptSelectedActionsMixin, viewsets.ModelViewSet):
    queryset = Deck.objects.select_related("owner").prefetch_related("cards").all()
    serializer_class = DeckSerializer
    permission_classes = [IsAuthenticated]
    
    encrypted_actions = {
        "list",        # GET /decks/
        "retrieve",    # GET /decks/{id}/
    }

    @action(
    detail=False,
    methods=["post"],
    permission_classes=[IsAuthenticated],
    url_path="add-flashcards"
)
    @transaction.atomic
    def add_flashcards(self, request):
        data = request.data or {}

        deck_id = data.get("deck_id")
        cards = data.get("cards") or []

        if not deck_id:
            return Response({"detail": "deck_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not isinstance(cards, list) or not cards:
            return Response(
                {"detail": "cards must be a non-empty list"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # --------- Load deck ----------
        try:
            deck = Deck.objects.get(id=deck_id)
        except Deck.DoesNotExist:
            return Response({"detail": "Deck not found"}, status=status.HTTP_404_NOT_FOUND)

        # 🔒 Solo owner puede modificar el deck
        if deck.owner_id != request.user.id:
            return Response(
                {"detail": "Only the deck owner can add flashcards"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if len(cards) > 2000:
            return Response({"detail": "Too many cards (max 2000)"}, status=status.HTTP_400_BAD_REQUEST)

        # --------- Clean cards ----------
        clean_cards = []
        for i, c in enumerate(cards):
            if not isinstance(c, dict):
                return Response(
                    {"detail": f"cards[{i}] must be an object"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            front = (c.get("front") or "").strip()
            back = (c.get("back") or "").strip()
            notes = c.get("notes") or ""

            if not front or not back:
                continue

            clean_cards.append(
                {
                    "front": front,
                    "back": back,
                    "notes": notes,
                }
            )

        if not clean_cards:
            return Response(
                {"detail": "No valid cards to create"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # --------- job_id ----------
        # reutiliza el del deck si existe, si no crea uno nuevo
        job_id = deck.external_job_id or str(uuid.uuid4())

        if not deck.external_job_id:
            deck.external_job_id = job_id
            deck.save(update_fields=["external_job_id"])

        # --------- Bulk create ----------
        now = timezone.now()
        objs = [
            Flashcard(
                deck=deck,
                front=c["front"],
                back=c["back"],
                notes=c["notes"],
                job_id=job_id,
                user_id=str(request.user.id),
                kind="new",
                status="learning",
                created_at=now,
                updated_at=now,
                card_id = str(uuid.uuid4())
            )
            for c in clean_cards
        ]

        Flashcard.objects.bulk_create(objs, batch_size=1000)

        return Response(
            {
                "deck_id": deck.id,
                "job_id": job_id,
                "cards_added": len(objs),
            },
            status=status.HTTP_201_CREATED,
        )


    @action(detail=True, methods=["post"], url_path="next-card")
    def next_card(self, request, pk=None):
        deck = self.get_object()

        ser = NextCardRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        job_id = ser.validated_data.get("job_id") or deck.external_job_id
        if not job_id:
            return Response(
                {"detail": "Deck has no external_job_id and job_id was not provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_id = ser.validated_data.get("user_id") or str(request.user.id) or str(uuid.uuid4())
        last_seq = ser.validated_data.get("last_seq", 0)
        token = ser.validated_data.get("token", "")

        msg = async_to_sync(ws_get_next_card)(
            job_id=str(job_id),
            user_id=str(user_id),
            last_seq=int(last_seq),
            token=str(token),
            timeout_sec=25,
        )

        mt = msg.get("message_type")
        if mt == "card":
            return Response(
                {
                    "job_id": str(job_id),
                    "seq": msg.get("seq"),
                    "card": msg.get("card"),
                },
                status=status.HTTP_200_OK,
            )

        if mt == "done":
            return Response({"job_id": str(job_id), "status": "done"}, status=status.HTTP_200_OK)

        if mt == "error":
            return Response({"job_id": str(job_id), "status": "error", "detail": msg}, status=status.HTTP_502_BAD_GATEWAY)

        return Response({"job_id": str(job_id), "status": mt, "detail": msg}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="card-feedback")
    def card_feedback(self, request, pk=None):
        deck = self.get_object()

        ser = CardFeedbackRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        job_id = ser.validated_data.get("job_id") or deck.external_job_id
        if not job_id:
            return Response(
                {"detail": "Deck has no external_job_id and job_id was not provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_id = ser.validated_data.get("user_id") or str(request.user.id) or str(uuid.uuid4())

        msg = async_to_sync(ws_send_card_feedback)(
            job_id=str(job_id),
            user_id=str(user_id),
            seq=int(ser.validated_data["seq"]),
            card_id=int(ser.validated_data["card_id"]),
            rating=int(ser.validated_data["rating"]),
            time_to_answer_ms=int(ser.validated_data.get("time_to_answer_ms", 500)),
            token=str(ser.validated_data.get("token", "")),
            timeout_sec=15,
        )

        mt = msg.get("message_type")
        if mt == "ok":
            return Response({"status": "ok", "detail": msg}, status=status.HTTP_200_OK)

        return Response({"status": mt, "detail": msg}, status=status.HTTP_502_BAD_GATEWAY)

    

    def get_queryset(self):
        qs = Deck.objects.filter(owner=self.request.user)

        project_id = self.request.query_params.get("project")
        if project_id:
            qs = qs.filter(project_id=project_id)

        return qs

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        # PlanGuard.assert_flashcards_allowed(user=request.user)



    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="create-and-start-job")
    @transaction.atomic
    def create_and_start_job(self, request):
        data = request.data
        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080").rstrip("/")
        # --- Deck required ---
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        if not project_id:
            return Response({"detail": "project_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not title:
            return Response({"detail": "title is required"}, status=status.HTTP_400_BAD_REQUEST)

        description = data.get("description") or ""
        visibility = data.get("visibility") or "private"

        # --- Optional: section_ids ---
        section_ids = data.get("section_ids") or []
        if not isinstance(section_ids, list):
            return Response({"detail": "section_ids must be a list of integers (or omitted)"}, status=status.HTTP_400_BAD_REQUEST)

        # --- Cards count (N) -> quantity for microservice ---
        cards_count = data.get("cards_count", 0)
        try:
            cards_count = int(cards_count)
        except (TypeError, ValueError):
            return Response({"detail": "cards_count must be an integer"}, status=status.HTTP_400_BAD_REQUEST)
        if cards_count <= 0:
            return Response({"detail": "cards_count must be > 0"}, status=status.HTTP_400_BAD_REQUEST)
        if cards_count > 500:
            return Response({"detail": "cards_count too large (max 500)"}, status=status.HTTP_400_BAD_REQUEST)

        # --- Project ---
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response({"detail": "project not found"}, status=status.HTTP_404_NOT_FOUND)

        # opcional: validar ownership del project
        if hasattr(project, "owner_id") and project.owner_id != request.user.id:
            return Response({"detail": "You do not own this project."}, status=status.HTTP_403_FORBIDDEN)

        # --- Create Deck ---
        deck = Deck.objects.create(
            project=project,
            owner=request.user,
            title=title,
            description=description,
            visibility=visibility,
        )

        # --- Attach Sections (optional) ---
        attached_section_ids = []
        if section_ids:
            qs = Section.objects.filter(id__in=section_ids)
            found_ids = list(qs.values_list("id", flat=True))
            missing = [sid for sid in section_ids if sid not in set(found_ids)]
            if missing:
                return Response(
                    {"detail": "Some section_ids do not exist.", "missing_section_ids": missing},
                    status=status.HTTP_400_BAD_REQUEST
                )
            deck.sections.set(qs)
            attached_section_ids = found_ids

        # --- Payload para microservicio ---
        document_ids = data.get("document_ids") or []
        if not isinstance(document_ids, list):
            return Response({"detail": "document_ids must be a list (or omitted)"}, status=status.HTTP_400_BAD_REQUEST)

        tags = data.get("tags") or []
        if not isinstance(tags, list):
            return Response({"detail": "tags must be a list (or omitted)"}, status=status.HTTP_400_BAD_REQUEST)

        difficulty = data.get("difficulty") or "medium"

        svc_payload = {
            "document_ids": document_ids,
            "tags": tags,
            "quantity": cards_count,
            "difficulty": difficulty,
            "user_id": str(request.user.id),
        }

        # --- Call microservice ---
        try:
            resp = requests.post(f"{base_url}/flashcards/create", json=svc_payload, timeout=30)
            resp.raise_for_status()
            svc_data = resp.json()
        except requests.RequestException as e:
            return Response(
                {"detail": "Failed calling flashcards service", "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        job_id = svc_data.get("job_id")
        if not job_id:
            return Response({"detail": "flashcards service did not return job_id", "service_response": svc_data},
                            status=status.HTTP_502_BAD_GATEWAY)

        # construir ws urls
        host = base_url.split("://", 1)[-1].lstrip("/")
        ws_flashcards = f"ws://{host}/ws/flashcards/{job_id}"
        ws_progress = f"ws://{host}/ws/progress/{job_id}"

        return Response(
            {
                "project_id": project_id,
                "deck": {
                    "id": deck.id,
                    "title": deck.title,
                    "description": deck.description,
                    "visibility": deck.visibility,
                    "owner_id": deck.owner_id,
                    "section_ids": attached_section_ids,
                    "sections_count": len(attached_section_ids),
                },
                "job": {
                    "job_id": job_id,
                    "ws_flashcards": ws_flashcards,
                    "ws_progress": ws_progress,
                    # por si te sirve guardar request
                    "requested_quantity": cards_count,
                    "difficulty": difficulty,
                    "tags": tags,
                    "document_ids": document_ids,
                },
            },
            status=status.HTTP_201_CREATED
        )
    

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="create-with-flashcards")
    @transaction.atomic
    def create_with_flashcards(self, request):
        data = request.data or {}

        # --------- Deck fields ----------
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        visibility = (data.get("visibility") or "private").strip()

        if not project_id:
            return Response({"detail": "project_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not title:
            return Response({"detail": "title is required"}, status=status.HTTP_400_BAD_REQUEST)

        # --------- Validate project + ownership ----------
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response({"detail": "project not found"}, status=status.HTTP_404_NOT_FOUND)

        # 🔒 recomendado: solo owner del project puede crear decks ahí
        if hasattr(project, "owner_id") and project.owner_id != request.user.id:
            return Response({"detail": "You do not own this project."}, status=status.HTTP_403_FORBIDDEN)

        # --------- Optional: section_ids ----------
        section_ids = data.get("section_ids") or []
        if not isinstance(section_ids, list):
            return Response({"detail": "section_ids must be a list"}, status=status.HTTP_400_BAD_REQUEST)

        sections_qs = Section.objects.none()
        attached_section_ids = []
        if section_ids:
            sections_qs = Section.objects.filter(id__in=section_ids).only("id", "title")
            found_ids = list(sections_qs.values_list("id", flat=True))
            missing = [sid for sid in section_ids if sid not in set(found_ids)]
            if missing:
                return Response({"detail": "Some section_ids do not exist", "missing_section_ids": missing},
                                status=status.HTTP_400_BAD_REQUEST)
            attached_section_ids = found_ids

        # --------- Cards payload ----------
        cards = data.get("cards") or []
        if not isinstance(cards, list) or not cards:
            return Response({"detail": "cards is required and must be a non-empty list"}, status=status.HTTP_400_BAD_REQUEST)

        if len(cards) > 2000:
            return Response({"detail": "Too many cards (max 2000)"}, status=status.HTTP_400_BAD_REQUEST)

        # Validación mínima
        clean_cards = []
        for i, c in enumerate(cards):
            if not isinstance(c, dict):
                return Response({"detail": f"cards[{i}] must be an object"}, status=status.HTTP_400_BAD_REQUEST)

            front = (c.get("front") or "").strip()
            back = (c.get("back") or "").strip()
            notes = c.get("notes") or ""

            if not front or not back:
                continue
                # return Response({"detail": f"cards[{i}] front and back are required"}, status=status.HTTP_400_BAD_REQUEST)

            clean_cards.append({"front": front, "back": back, "notes": notes})
        job_id = uuid.uuid4()
        # --------- Create deck ----------
        deck = Deck.objects.create(
            project=project,
            owner=request.user,
            title=title,
            description=description,
            visibility=visibility,
            external_job_id=job_id,
            
        )

        if attached_section_ids:
            deck.sections.set(sections_qs)
        

        
        objs = [
        Flashcard(
            deck=deck,
            front=c["front"],
            back=c["back"],
            notes=c["notes"],
            job_id=str(job_id),                     # ✅ same for all
            user_id=str(request.user.id),      # ✅ optional but recommended for your multi-user logic
            card_id=str(uuid.uuid4()),               # ✅ unique per card
           
        )
        for c in clean_cards
    ]

        # --------- Bulk create flashcards ----------
        # objs = [Flashcard(deck=deck, front=c["front"], back=c["back"], notes=c["notes"]) for c in clean_cards]
        Flashcard.objects.bulk_create(objs)

        # --------- Response ----------
        deck_data = DeckSerializer(deck, context={"request": request}).data
        cards_qs = Flashcard.objects.filter(deck=deck).order_by("created_at", "id")
        cards_data = FlashcardSerializer(cards_qs, many=True, context={"request": request}).data

        return Response(
            {
                "deck": deck_data,
                "cards_created": len(cards_data),
                "cards": cards_data,
                "section_ids": attached_section_ids,
            },
            status=status.HTTP_201_CREATED
        )
    


    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="create-with-cards")
    @transaction.atomic
    def create_with_cards(self, request):
        data = request.data
        base_url = os.getenv("PROCESS_REQUEST_BASE_URL", "http://localhost:8080").rstrip("/")

        # --- Deck required ---
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        if not project_id:
            return Response({"detail": "project_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not title:
            return Response({"detail": "title is required"}, status=status.HTTP_400_BAD_REQUEST)

        description = data.get("description") or ""
        visibility = data.get("visibility") or "private"

        # --- Optional: section_ids ---
        section_ids = data.get("section_ids") or []
        if not isinstance(section_ids, list):
            return Response(
                {"detail": "section_ids must be a list of integers (or omitted)"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # --- Optional: document_ids (solo reflejo, igual que antes) ---
        document_ids = data.get("document_ids")
        if document_ids is None:
            document_ids = []
        if not isinstance(document_ids, list):
            return Response(
                {"detail": "document_ids must be a list of ids (or omitted)"},
                status=status.HTTP_400_BAD_REQUEST
            )
        document_filenames = []
        document_id_str = []

        if document_ids:
            docs_qs = (
                Document.objects
                .filter(id__in=document_ids)
                .only("id", "filename")
            )

            found_ids = list(docs_qs.values_list("id", flat=True))
            missing = [did for did in document_ids if did not in set(found_ids)]
            
            if missing:
                return Response(
                    {
                        "detail": "Some document_ids do not exist",
                        "missing_document_ids": missing,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            document_id_str = [str(doc_id) for doc_id in document_ids]
       
        cards_count = data.get("cards_count", 0)
        try:
            cards_count = int(cards_count)
        except (TypeError, ValueError):
            return Response({"detail": "cards_count must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        if cards_count <= 0:
            return Response({"detail": "cards_count must be > 0"}, status=status.HTTP_400_BAD_REQUEST)
        if cards_count > 500:
            return Response({"detail": "cards_count too large (max 500)"}, status=status.HTTP_400_BAD_REQUEST)

        # --- Project ---
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response({"detail": "project not found"}, status=status.HTTP_404_NOT_FOUND)

        # 🔒 Si Project tiene owner, enforce (opcional pero recomendado)
        if hasattr(project, "owner_id") and project.owner_id != request.user.id:
            return Response({"detail": "You do not own this project."}, status=status.HTTP_403_FORBIDDEN)

        # --- Create Deck ---
        deck = Deck.objects.create(
            project=project,
            owner=request.user,
            title=title,
            description=description,
            visibility=visibility,
        )

        # --- Attach Sections (optional) ---
        attached_section_ids = []
        tags = []  # 👈 ahora tags sale de sections

        if section_ids:
            qs = Section.objects.filter(id__in=section_ids).only("id", "title")
            found_ids = list(qs.values_list("id", flat=True))
            found_set = set(found_ids)

            missing = [sid for sid in section_ids if sid not in found_set]
            if missing:
                return Response(
                    {"detail": "Some section_ids do not exist.", "missing_section_ids": missing},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            deck.sections.set(qs)
            attached_section_ids = found_ids

            # ✅ tags = títulos de las secciones
            titles = list(qs.values_list("title", flat=True))
            tags = [t.strip() for t in titles if (t or "").strip()]
            # opcional: únicos preservando orden
            seen = set()
            tags = [t for t in tags if not (t in seen or seen.add(t))]
        else:
            # Fallback opcional (si quieres permitir tags manuales cuando NO hay sections)
            tags = data.get("tags") or []
        
        difficulty = (data.get("difficulty") or "medium").lower()

        svc_payload = {
        #      "document_ids": ["test"],
        # "tags": ["Barcelona"],
            "document_ids": document_ids,            
            "tags": tags,
            "quantity": cards_count,                
            "difficulty": difficulty,
            "user_id": str(request.user.id),          
        }

        # --- Call microservice ---
        try:
            resp = requests.post(f"{base_url}/flashcards/create", json=svc_payload, timeout=30)
            resp.raise_for_status()
            svc_data = resp.json()
        except requests.RequestException as e:
            # Como está en transaction.atomic, al devolver error se hace rollback del deck
            return Response(
                {"detail": "Failed calling flashcards service", "error": str(e)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        job_id = svc_data.get("job_id")
        if not job_id:
            return Response(
                {"detail": "flashcards service did not return job_id", "service_response": svc_data},
                status=status.HTTP_502_BAD_GATEWAY
            )

        # construir ws urls
        host = base_url.split("://", 1)[-1].lstrip("/")
        ws_flashcards = f"ws://{host}/ws/flashcards/{job_id}"
        ws_progress = f"ws://{host}/ws/progress/{job_id}"
        deck.external_job_id = job_id
        deck.save(update_fields=["external_job_id"])
        # --- Response (MISMO estilo del primero + job/ws) ---
        flashcards_count = cards_count
        sections_count = len(attached_section_ids)

        return Response(
            {
                "project_id": project_id,
                "deck": {
                    "id": deck.id,
                    "title": deck.title,
                    "description": deck.description,
                    "visibility": deck.visibility,
                    "owner_id": deck.owner_id,
                    "section_ids": attached_section_ids,
                    "sections_count": sections_count,
                    "flashcards_count": flashcards_count,
                    "document_ids": document_ids,
                },
                "cards_created": flashcards_count,   # mantiene compat con tu frontend
                "job": {
                    "job_id": job_id,
                    "ws_flashcards": ws_flashcards,
                    "ws_progress": ws_progress,
                    "requested_quantity": cards_count,
                    "difficulty": difficulty,
                    "tags": tags,
                    "document_ids": document_ids,
                    # opcional: por si luego quieres debug
                    "microservice_response": svc_data,
                },
            },
            status=status.HTTP_201_CREATED
        )
        # data = request.data

        # # --- Deck required ---
        # project_id = data.get("project_id")
        # title = (data.get("title") or "").strip()
        # if not project_id:
        #     return Response({"detail": "project_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        # if not title:
        #     return Response({"detail": "title is required"}, status=status.HTTP_400_BAD_REQUEST)

        # description = data.get("description") or ""
        # visibility = data.get("visibility") or "private"

        # # --- Optional: section_ids ---
        # section_ids = data.get("section_ids")
        # if section_ids is None:
        #     section_ids = []
        # if not isinstance(section_ids, list):
        #     return Response({"detail": "section_ids must be a list of integers (or omitted)"}, status=status.HTTP_400_BAD_REQUEST)

        # # --- Optional: document_ids (solo reflejo) ---
        # document_ids = data.get("document_ids")
        # if document_ids is not None and not isinstance(document_ids, list):
        #     return Response({"detail": "document_ids must be a list of integers (or omitted)"}, status=status.HTTP_400_BAD_REQUEST)

        # # --- Cards count (N) ---
        # cards_count = data.get("cards_count", 0)
        # try:
        #     cards_count = int(cards_count)
        # except (TypeError, ValueError):
        #     return Response({"detail": "cards_count must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        # if cards_count < 0:
        #     return Response({"detail": "cards_count must be >= 0"}, status=status.HTTP_400_BAD_REQUEST)
        # if cards_count > 500:  # límite razonable anti abuso
        #     return Response({"detail": "cards_count too large (max 500)"}, status=status.HTTP_400_BAD_REQUEST)

        # # --- Project ---
        # try:
        #     project = Project.objects.get(id=project_id)
        # except Project.DoesNotExist:
        #     return Response({"detail": "project not found"}, status=status.HTTP_404_NOT_FOUND)

        # # 🔒 Si Project tiene owner, enforce (opcional pero recomendado)
        # if hasattr(project, "owner_id") and project.owner_id != request.user.id:
        #     return Response({"detail": "You do not own this project."}, status=status.HTTP_403_FORBIDDEN)

        # # --- Create Deck ---
        # deck = Deck.objects.create(
        #     project=project,
        #     owner=request.user,
        #     title=title,
        #     description=description,
        #     visibility=visibility,
        # )

        # # --- Attach Sections (optional) ---
        # attached_section_ids = []
        # if section_ids:
        #     qs = Section.objects.filter(id__in=section_ids)
        #     found_ids = list(qs.values_list("id", flat=True))
        #     missing = [sid for sid in section_ids if sid not in set(found_ids)]
        #     if missing:
        #         return Response(
        #             {"detail": "Some section_ids do not exist (or are not allowed).", "missing_section_ids": missing},
        #             status=status.HTTP_400_BAD_REQUEST
        #         )
        #     deck.sections.set(qs)
        #     attached_section_ids = found_ids

        # # --- Create N Flashcards ---
        # created = []
        # for i in range(1, cards_count + 1):
        #     created.append(
        #         Flashcard(
        #             deck=deck,
        #             front=f"Front {i}",
        #             back=f"Back {i}",
        #             notes=""
        #         )
        #     )

        # if created:
        #     Flashcard.objects.bulk_create(created)

        # # --- Response ---
        # flashcards_count = cards_count  # ya sabes cuántas creaste
        # sections_count = len(attached_section_ids)

        # return Response(
        #     {
        #         "project_id": project_id,
        #         "deck": {
        #             "id": deck.id,
        #             "title": deck.title,
        #             "description": deck.description,
        #             "visibility": deck.visibility,
        #             "owner_id": deck.owner_id,
        #             "section_ids": attached_section_ids,
        #             "sections_count": sections_count,
        #             "flashcards_count": flashcards_count,
        #             "document_ids": document_ids,
        #         },
        #         "cards_created": flashcards_count,
        #     },
        #     status=status.HTTP_201_CREATED
        # )


    # def get_queryset(self):
    #     user = self.request.user
    #     # owner + decks compartidos conmigo
    #     return (
    #         super()
    #         .get_queryset()
    #         .filter(Q(owner=user) | Q(shares__shared_with=user) | Q(visibility="public"))
    #         .distinct()
    #         .order_by("-created_at")
    #     )

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    

class FlashcardViewSet(EncryptSelectedActionsMixin,viewsets.ModelViewSet):
    queryset = Flashcard.objects.select_related("deck").all()
    serializer_class = FlashcardSerializer
    permission_classes = [IsAuthenticated]

    encrypted_actions = {
        "list",        # GET /api/flashcards/?deck=...
        "retrieve",    # GET /api/flashcards/<id>/
        # agrega aquí si quieres cifrar acciones custom:
        "sync_from_job",
        "ws_pull_card",
        # "ws_push_feedback",
        # "shuffle_deck_cards",
    }



    @action(
    detail=False,
    methods=["post"],
    url_path="shuffle-deck-cards",
    permission_classes=[IsAuthenticated],
)
    def shuffle_deck_cards(self, request):
        deck_id = request.data.get("deck_id")
        if not deck_id:
            return Response({"detail": "deck_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck_id = int(deck_id)
        except (TypeError, ValueError):
            return Response({"detail": "deck_id must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck = Deck.objects.get(id=deck_id)
        except Deck.DoesNotExist:
            return Response({"detail": "Deck not found"}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        has_access = (
            deck.owner_id == user.id
            or deck.visibility == "public"
            or DeckShare.objects.filter(deck=deck, shared_with=user).exists()
        )
        if not has_access:
            return Response({"detail": "You do not have access to this deck."}, status=status.HTTP_403_FORBIDDEN)

        now = timezone.now()

        reset_values = {
            "kind": "new",
            "status": "learning",
            "learning_step_index": 0,
            "repetition": 0,
            "interval_days": 0,
            "ease_factor": 2.5,
            "due_at": now,
            "first_seen_at": None,
            "updated_at": now,
        }

        job_ids = list(
            Flashcard.objects.filter(deck_id=deck.id)
            .exclude(job_id__isnull=True)
            .exclude(job_id__exact="")
            .values_list("job_id", flat=True)
            .distinct()
        )

        if not job_ids:
            return Response(
                {"deck_id": deck.id, "cards_updated": 0, "detail": "No job_id found for flashcards in this deck."},
                status=status.HTTP_404_NOT_FOUND,
            )

        with transaction.atomic():
            updated_count = Flashcard.objects.filter(job_id__in=job_ids).update(**reset_values)

        # ✅ Clear progress in Redis (like the script)
        redis_deleted = {}
        redis_error = None

        clear_redis = os.getenv("FLASHCARD_CLEAR_REDIS", "1") == "1"
        if clear_redis:
            try:
                
                redis_url = os.getenv("PROGRESS_REDIS_URL", "redis://localhost:6379/2")
                client = Redis.from_url(redis_url, decode_responses=True)

                for jid in job_ids:
                    key = flashcard_redis_key(jid)
                    redis_deleted[jid] = int(client.delete(key))  # 1 if deleted, 0 if not found
            except Exception as e:
                # no rompas el endpoint si redis no está disponible
                redis_error = str(e)

        return Response(
            {
                "deck_id": deck.id,
                "job_ids": job_ids,
                "cards_updated": updated_count,
                "due_at_set_to": now,
                "redis": {
                    "enabled": clear_redis,
                    "deleted": redis_deleted,   # {job_id: 0/1}
                    "error": redis_error,
                },
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="ws-pull-card", permission_classes=[IsAuthenticated])
    def ws_pull_card(self, request):
        """
        POST /api/flashcards/ws-pull-card/
        Body:
        {
          "deck_id": 123,          (required)
          "job_id": "...",         (optional; default deck.external_job_id)
          "user_id": "...",        (optional; default request.user.id)
          "last_seq": 0,           (optional; default 0)
          "token": ""              (optional)
        }
        """
        deck_id = request.data.get("deck_id")
        if not deck_id:
            return Response({"detail": "deck_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck_id_int = int(deck_id)
        except ValueError:
            return Response({"detail": "deck_id must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck = Deck.objects.get(id=deck_id_int)
        except Deck.DoesNotExist:
            return Response({"detail": "Deck not found"}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        has_access = (
            deck.owner_id == user.id
            or deck.visibility == "public"
            or DeckShare.objects.filter(deck=deck, shared_with=user).exists()
        )
        if not has_access:
            return Response({"detail": "You do not have access to this deck."}, status=status.HTTP_403_FORBIDDEN)

        job_id = request.data.get("job_id") or deck.external_job_id
        job_id = str(job_id).strip() if job_id else None
        if not job_id:
            return Response({"detail": "job_id is required (or deck must have external_job_id)."}, status=400)

        user_id = request.data.get("user_id") or str(user.id) or str(uuid.uuid4())
        last_seq = request.data.get("last_seq", 0)
        token = request.data.get("token", "")

        try:
            last_seq = int(last_seq)
        except Exception:
            last_seq = 0

        msg = async_to_sync(ws_get_next_card)(
            job_id=str(job_id),
            user_id=str(user_id),
            last_seq=int(last_seq),
            token=str(token),
            timeout_sec=25,
        )

        mt = msg.get("message_type")
        if mt == "card":
            return Response(
                {
                    "message_type": "card",
                    "job_id": str(job_id),
                    "seq": msg.get("seq"),
                    "card": msg.get("card"),
                },
                status=status.HTTP_200_OK,
            )

        if mt == "done":
            return Response({"message_type": "done", "job_id": str(job_id)}, status=status.HTTP_200_OK)

        if mt == "error":
            return Response(
                {"message_type": "error", "job_id": str(job_id), "detail": msg},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response({"message_type": mt, "job_id": str(job_id), "detail": msg}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="ws-push-feedback", permission_classes=[IsAuthenticated])
    def ws_push_feedback(self, request):
        """
        POST /api/flashcards/ws-push-feedback/
        Body:
        {
          "deck_id": 123,          (required)
          "job_id": "...",         (optional; default deck.external_job_id)
          "user_id": "...",        (optional; default request.user.id)
          "seq": 10,               (required)
          "card_id": 999,          (required)
          "rating": 0|1|2,         (required)
          "time_to_answer_ms": 500 (optional)
          "token": ""              (optional)
        }
        """
        deck_id = request.data.get("deck_id")
        if not deck_id:
            return Response({"detail": "deck_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck_id_int = int(deck_id)
        except ValueError:
            return Response({"detail": "deck_id must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            deck = Deck.objects.get(id=deck_id_int)
        except Deck.DoesNotExist:
            return Response({"detail": "Deck not found"}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        has_access = (
            deck.owner_id == user.id
            or deck.visibility == "public"
            or DeckShare.objects.filter(deck=deck, shared_with=user).exists()
        )
        if not has_access:
            return Response({"detail": "You do not have access to this deck."}, status=status.HTTP_403_FORBIDDEN)

        job_id = request.data.get("job_id") or deck.external_job_id
        job_id = str(job_id).strip() if job_id else None
        if not job_id:
            return Response({"detail": "job_id is required (or deck must have external_job_id)."}, status=400)

        user_id = request.data.get("user_id") or str(user.id) or str(uuid.uuid4())

        seq = request.data.get("seq")
        card_id = request.data.get("card_id") or 1

        rating = request.data.get("rating")
        if seq is None or card_id is None or rating is None:
            return Response({"detail": "seq, card_id and rating are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            seq = int(seq)
            card_id = card_id
            rating = int(rating)
        except ValueError:
            return Response({"detail": "seq, card_id, rating must be integers"}, status=400)

        time_to_answer_ms = request.data.get("time_to_answer_ms", 500)
        try:
            time_to_answer_ms = int(time_to_answer_ms)
        except Exception:
            time_to_answer_ms = 500

        token = str(request.data.get("token", ""))

        msg = async_to_sync(ws_send_card_feedback)(
            job_id=str(job_id),
            user_id=str(user_id),
            seq=seq,
            card_id=card_id,
            rating=rating,
            time_to_answer_ms=time_to_answer_ms,
            token=token,
            timeout_sec=15,
        )

        mt = msg.get("message_type")
        if mt == "ok":
            return Response({"message_type": "ok", "detail": msg}, status=status.HTTP_200_OK)

        return Response({"message_type": mt, "detail": msg}, status=status.HTTP_502_BAD_GATEWAY)
    

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="add-card")
    def add_card(self, request, pk=None):
        deck = self.get_object()
        if deck.owner_id != request.user.id:
            return Response({"detail": "Only owner can add cards."}, status=status.HTTP_403_FORBIDDEN)

        front = request.data.get("front")
        back = request.data.get("back")
        notes = request.data.get("notes", "")
        if not front or not back:
            return Response({"detail": "front and back are required"}, status=status.HTTP_400_BAD_REQUEST)

        card = Flashcard.objects.create(deck=deck, front=front, back=back, notes=notes)
        return Response(FlashcardSerializer(card).data, status=status.HTTP_201_CREATED)

    def _sync_from_public_flashcards(self, *, deck, job_id: str, user_id: str, limit: int = 5000) -> int:
        """
        Copia public.flashcards (sin modelo) -> api_flashcard (modelo Flashcard)
        Mapea front/back, notes=""
        Retorna cantidad insertada
        """
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT front, back
                FROM public.flashcards
                WHERE job_id = %s
                  AND user_id = %s
                ORDER BY created_at ASC
                LIMIT %s
                """,
                [str(job_id), str(user_id), int(limit)],
            )
            rows = cursor.fetchall()

        if not rows:
            return 0

        existing = set(
            Flashcard.objects.filter(deck=deck).values_list("front", "back")
        )

        to_create = []
        for front, back in rows:
            front = "" if front is None else str(front)
            back = "" if back is None else str(back)

            key = (front, back)
            if key in existing:
                continue

            to_create.append(Flashcard(deck=deck, front=front, back=back, notes=""))
            existing.add(key)

        if to_create:
            Flashcard.objects.bulk_create(to_create)

        return len(to_create)

       # ✅ NUEVO: solo se llama cuando tú quieras (al crear deck o cuando WS termine)
    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="sync-from-job")
    @transaction.atomic
    def sync_from_job(self, request):
    

        user = request.user
        # user=User.objects.get(id=1)

        deck_id = request.query_params.get("deck")
        if not deck_id:
            return Response([], status=200)

        try:
            deck_id_int = int(deck_id)
        except ValueError:
            return Response({"detail": "deck must be an integer"}, status=400)

        # Cargar deck para permisos + sync
        try:
            deck = Deck.objects.get(id=deck_id_int)
        except Deck.DoesNotExist:
            return Response({"detail": "Deck not found"}, status=404)

        # ✅ Permisos a nivel deck (igual que tu lógica)
        # can_view = (
        #     deck.owner_id == user.id
        #     or deck.visibility == "public"
        #     or DeckShare.objects.filter(deck=deck, shared_with=user).exists()
        # )
        # if not can_view:
        #     raise PermissionDenied("You do not have access to this deck.")

        # ✅ job_id: viene del query o fallback al deck.external_job_id
        job_id = request.query_params.get("job_id") or deck.external_job_id
        job_id = str(job_id).strip() if job_id else None

        should_sync = False

        if job_id:
            # 1) El deck debe tener external_job_id y debe coincidir
            if not deck.external_job_id:
                should_sync = False
            elif str(deck.external_job_id) != job_id:
                should_sync = False
            else:
                # 2) Solo si no está ya sincronizado con ese job
                # if deck.synced_job_id == job_id:
                #     should_sync = False
                # else:
                    # 3) Solo si el deck está vacío en tu modelo
                has_any = Flashcard.objects.filter(deck=deck).exists()
                should_sync = not has_any

        if should_sync:
            
            if deck.owner_id != user.id:
                return Response({"detail": "Only owner can sync cards into this deck."}, status=403)
            updated_count = (
            Flashcard.objects
            .filter(job_id=job_id)  # si tienes user_id, agrega .filter(user_id=str(user.id))
            .exclude(deck_id=deck.id)  # evita updates innecesarios
            .update(
                deck_id=deck.id,
                updated_at=timezone.now(),  # si tu modelo tiene updated_at y lo manejas así
            )
        )
            # ✅ SOLO owner puede "escribir" al deck (recomendado)
        

        # ✅ Actualiza masivamente: todas las flashcards con ese job_id -> asignarlas al deck
        # (opcional) filtrar también por user si aplica a tu esquema
       

            # inserted = self._sync_from_public_flashcards(
            #     deck=deck,
            #     job_id=job_id,
            #     user_id=str(request.user.id),
            # )

        # ✅ Si hay job_id y todavía NO lo sincronizaste, copia una vez
        # if job_id:
        #     # recomendado: solo owner puede importar/escribir
        #     if deck.owner_id != user.id:
        #         raise PermissionDenied("Only owner can sync cards into this deck.")

        #     inserted = self._sync_from_public_flashcards(
        #         deck=deck,
        #         job_id=str(job_id),
        #         user_id=str(user.id),
        #         limit=5000,
        #     )

            # deck.synced_job_id = str(job_id)
            # deck.synced_at = timezone.now()
            # deck.save(update_fields=["synced_job_id", "synced_at"])

        # ✅ Ahora devuelve lo que ya existe en api_flashcard para ese deck
        qs = Flashcard.objects.filter(deck_id=deck_id_int).order_by("-created_at")

        page = self.paginate_queryset(qs)
        if page is not None:
            ser = self.get_serializer(page, many=True)
            return self.get_paginated_response(ser.data)

        ser = self.get_serializer(qs, many=True)
        return Response(ser.data)
    
    def get_queryset(self):
        user = self.request.user
        base_qs = super().get_queryset()

        deck_id = self.request.query_params.get("deck")
        if not deck_id:
            return base_qs.none()

        # 1) Traer el deck (para permisos y para obtener externalJobId)
        #    Ajusta "Deck" al import/modelo real.
        try:
            deck = Deck.objects.get(id=deck_id)
        except Deck.DoesNotExist:
            raise NotFound("Deck not found.")

        # 2) Check de permisos (owner OR compartido OR público)
        has_access = (
            deck.owner_id == user.id
            or deck.visibility == "public"
            or deck.shares.filter(shared_with=user).exists()
        )
        if not has_access:
            raise PermissionDenied("You do not have access to this deck.")

        # 3) Query inicial del deck
        qs = base_qs.filter(deck_id=deck_id)

        # 4) Si está vacío → sync y re-consulta
        if not qs.exists():
            job_id = getattr(deck, "external_job_id", None)  # o deck.external_job_id, según tu modelo
            if job_id:
                # Recomendado: envolver en transacción si vas a crear en DB
                # with transaction.atomic():
                #     self._sync_from_public_flashcards(
                #         deck=deck,
                #         job_id=str(job_id),
                #         user_id=str(user.id),
                #         limit=5000,
                #     )

                # Re-query después del sync
                qs = base_qs.filter(deck_id=deck_id)

        return qs.order_by("-created_at")

    # def get_queryset(self):
    #     user = self.request.user
    #     qs = super().get_queryset()

    #     deck_id = self.request.query_params.get("deck")
    #     if not deck_id:
    #         # Si NO pasas deck, por seguridad NO devuelvas todo
    #         return qs.none()

    #     # Filtra SOLO ese deck
    #     qs = qs.filter(deck_id=deck_id)

    #     # Permisos: owner OR compartido OR público
    #     allowed = qs.filter(
    #         Q(deck__owner=user) |
    #         Q(deck__shares__shared_with=user) |
    #         Q(deck__visibility="public")
    #     )

    #     if not allowed.exists():
    #         # Si el deck existe pero no tienes permiso, 403
    #         raise PermissionDenied("You do not have access to this deck.")

    #     return allowed.order_by("-created_at")


class DeckShareViewSet(viewsets.ModelViewSet):
    queryset = DeckShare.objects.select_related("deck", "shared_with").all()
    serializer_class = DeckShareSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        user = self.request.user
        return super().get_queryset().filter(Q(shared_with=user) | Q(deck__owner=user)).distinct()

    def perform_create(self, serializer):
        deck = serializer.validated_data["deck"]
        if deck.owner_id != self.request.user.id:
            raise serializers.ValidationError("Only deck owner can share this deck.")
        serializer.save()


class SavedDeckViewSet(viewsets.ModelViewSet):
    queryset = SavedDeck.objects.select_related("user", "deck").all()
    serializer_class = SavedDeckSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# ==========================================================
# Optional: exponer Tag / QaPair (managed=False)
# ==========================================================

class TagViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        document_id = self.request.query_params.get("document_id")
        if document_id:
            qs = qs.filter(document_id=str(document_id))
        return qs.order_by("created_at")


class QaPairViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = QaPair.objects.all()
    serializer_class = QaPairSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        job_id = self.request.query_params.get("job_id")
        if job_id:
            qs = qs.filter(job_id=str(job_id))
        return qs.order_by("qa_index", "created_at")


class RBACViewSet(viewsets.ViewSet):
    """
    /api/rbac/me/allowed-routes/
    Devuelve keys de rutas permitidas según roles del usuario.

    Convención:
      - Resource.key guarda keys estilo: "dashboard.home", "dashboard.projects", etc.
      - Permission.action="view" es el permiso para ver esa ruta.
    """
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"], url_path="me/allowed-routes")
    def me_allowed_routes(self, request):
        user = request.user

        # Admin override: si es staff/superuser o si tiene rol "admin"
        role_names = list(user.roles.values_list("name", flat=True))

        is_admin = bool(user.is_staff or user.is_superuser or ("admin" in role_names))

        if is_admin:
            # Admin ve todo lo que tenga permiso view (todas las routes)
            allowed = list(
                Permission.objects.filter(action="view")
                .select_related("resource")
                .values_list("resource__key", flat=True)
                .distinct()
                .order_by("resource__key")
            )
        else:
            # Usuario normal: permisos por roles
            allowed = list(
                Permission.objects.filter(
                    action="view",
                    roles__users=user,
                )
                .select_related("resource")
                .values_list("resource__key", flat=True)
                .distinct()
                .order_by("resource__key")
            )

        payload = {
            "user_id": user.id,
            "username": user.username,
            "is_admin": is_admin,
            "roles": role_names,
            "allowed_routes": allowed,
        }

        ser = AllowedRoutesSerializer(payload)
        return Response(ser.data)



class GoogleLoginView(SocialLoginView):
    permission_classes = [AllowAny]
    adapter_class = GoogleOAuth2Adapter


class FacebookLoginView(SocialLoginView):
    permission_classes = [AllowAny]
    adapter_class = FacebookOAuth2Adapter


class SupportRequestViewSet(viewsets.ModelViewSet):
    serializer_class = SupportRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # El usuario normal solo ve sus tickets
        qs = SupportRequest.objects.all().order_by("-created_at")
        # user = self.request.user
        # if user.is_staff:
        #     return qs
        return qs

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(user=user, email=user.email)

@method_decorator(csrf_exempt, name='dispatch')
class FrontendPasswordResetView(PasswordResetView):
        permission_classes = [AllowAny]
        authentication_classes = [] 
        email_template_name = "registration/password_reset_email.html"
        subject_template_name = "registration/password_reset_subject.txt"

        def form_valid(self, form):
            # Log diagnostics for password reset requests (email lookup only).
            try:
                email = form.cleaned_data.get("email")
            except Exception:
                email = None
            user_count = 0
            try:
                user_count = len(list(form.get_users(email))) if email else 0
            except Exception:
                user_count = 0
            logging.getLogger(__name__).info(
                "password_reset request email=%s matched_users=%s",
                email,
                user_count,
            )
            return super().form_valid(form)

        def get_email_options(self):
            return {
                "domain_override": "ankard.com",
                "from_email": settings.DEFAULT_FROM_EMAIL,
                "subject_template_name": self.subject_template_name,
                "email_template_name": self.email_template_name,
            }


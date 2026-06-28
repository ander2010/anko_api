"""
Email Log ViewSet — read-only list of all emails sent by the platform.
"""

from __future__ import annotations

from rest_framework import serializers, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.enterprise.services.security_service import validate_company_access
from api.enterprise_email_models import EmailLog


class EmailLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailLog
        fields = [
            "id",
            "company",
            "recipient_user",
            "recipient_email",
            "email_type",
            "subject",
            "body_preview",
            "status",
            "error_message",
            "metadata",
            "sent_at",
        ]


class EmailLogViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        company_id = request.query_params.get("company_id")
        if not company_id:
            return Response({"company_id": "This field is required."}, status=400)
        try:
            validate_company_access(request.user, company_id)
        except PermissionError as exc:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(str(exc))

        qs = EmailLog.objects.filter(company_id=company_id)

        email_type = request.query_params.get("type")
        if email_type:
            qs = qs.filter(email_type=email_type)

        status_filter = request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)

        recipient = request.query_params.get("recipient")
        if recipient:
            qs = qs.filter(recipient_email__icontains=recipient)

        qs = qs.order_by("-sent_at")[:200]
        return Response(EmailLogSerializer(qs, many=True).data)

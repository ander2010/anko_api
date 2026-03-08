from django.contrib import admin
from api.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "operation", "user", "success", "status_code", "path")
    list_filter = ("success", "operation", "method", "created_at")
    search_fields = ("operation", "path", "request_id", "user__username", "user__email")
    ordering = ("-created_at",)
    readonly_fields = [field.name for field in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

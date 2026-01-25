
from api.renders import EncryptedJSONRenderer



class EncryptSelectedActionsMixin:
    encrypted_actions = set()
    sse_actions = set()
    encrypt_response = False

    def initial(self, request, *args, **kwargs):
        action = getattr(self, "action", None)
        self.encrypt_response = action in (self.encrypted_actions or set())
        return super().initial(request, *args, **kwargs)

    def get_renderers(self):
        action = getattr(self, "action", None)
        sse_actions = getattr(self, "sse_actions", set())

        # # ✅ SSE hard override si tú quieres
        # if action in sse_actions:
        #     return [SSERenderer()]

        renderers = super().get_renderers()

        if not getattr(self, "encrypt_response", False):
            return renderers

        # ✅ NO cifrar si ya es SSE por renderer_classes o Accept
        if any(getattr(r, "media_type", None) == "text/event-stream" for r in renderers):
            return renderers

        accept = (getattr(self, "request", None).META.get("HTTP_ACCEPT", "") if getattr(self, "request", None) else "").lower()
        if "text/event-stream" in accept:
            return renderers

        return [EncryptedJSONRenderer()]

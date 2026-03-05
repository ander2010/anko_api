from rest_framework.renderers import JSONRenderer

from api.services.translate import post_translate


class TranslatingJSONRenderer(JSONRenderer):
    """
    JSONRenderer que traduce al español los valores string del dict de respuesta
    cuando el header Accept-Language del request empieza con 'es'.
    """

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if renderer_context and isinstance(data, dict):
            request = renderer_context.get("request")
            if request:
                lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
                if lang.lower().startswith("es"):
                    try:
                        data = post_translate(data)
                    except Exception as ex:
                        print(f"Error traduciendo respuesta: {ex}")
                        pass  
        return super().render(data, accepted_media_type, renderer_context)

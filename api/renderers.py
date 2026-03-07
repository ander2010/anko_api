import re
import time
import logging

from rest_framework.renderers import JSONRenderer

from api.services.translate import post_translate

logger = logging.getLogger("api.renderers")

# Cache simple en memoria: string original → traducción
# Se limpia automáticamente al superar _CACHE_MAX entradas
_translation_cache: dict[str, str] = {}
_CACHE_MAX = 10_000

# Strings que claramente NO son lenguaje natural y no deben traducirse
_SKIP_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'  # UUID
    r'|^\d+$'                                # número puro
    r'|^\d{4}-\d{2}-\d{2}'                  # fecha ISO
    r'|^[A-Za-z0-9+/=_\-]{60,}$'            # base64 / token largo
    r'|^.{0,2}$',                            # vacío o muy corto (≤2 chars)
    re.IGNORECASE,
)


def _should_translate(s: str) -> bool:
    return not _SKIP_RE.match(s)


def _collect_strings(data, strings, refs):
    """Recorre data recursivamente y acumula strings traducibles con sus referencias."""
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str):
                if _should_translate(v):
                    refs.append((data, k, len(strings)))
                    strings.append(v)
            else:
                _collect_strings(v, strings, refs)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            if isinstance(v, str):
                if _should_translate(v):
                    refs.append((data, i, len(strings)))
                    strings.append(v)
            else:
                _collect_strings(v, strings, refs)


def _apply_translations(translated, refs):
    """Aplica las traducciones en su lugar usando las referencias."""
    for container, key, idx in refs:
        if idx < len(translated):
            container[key] = translated[idx]


def translate_data_if_needed(data, request, *, caller=""):
    """
    Traduce data in-place si Accept-Language empieza con 'es'.
    - Filtra strings no traducibles (UUIDs, fechas, tokens, etc.)
    - Usa cache en memoria para no re-traducir strings ya vistos
    - Un único request al servicio con solo los strings no cacheados
    """
    tag = f"[TRANSLATE:{caller or 'default'}]"

    if not request or data is None:
        logger.warning("%s request o data es None — omitido", tag)
        return

    lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    logger.debug("%s Accept-Language: %r", tag, lang)

    if not lang.lower().startswith("es"):
        logger.info("%s idioma %r ≠ 'es' — sin traducción", tag, lang)
        return

    global _translation_cache

    # 1. Recolectar strings traducibles
    strings = []
    refs = []
    _collect_strings(data, strings, refs)
    logger.info("%s strings traducibles recolectados: %d", tag, len(strings))

    if not strings:
        logger.info("%s nada que traducir", tag)
        return

    # 2. Separar los que ya están en cache vs los que hay que pedir
    cached_map: dict[str, str] = {}
    to_fetch: list[str] = []
    to_fetch_indices: list[int] = []   # índice dentro de `strings`

    for i, s in enumerate(strings):
        if s in _translation_cache:
            cached_map[s] = _translation_cache[s]
        else:
            to_fetch.append(s)
            to_fetch_indices.append(i)

    logger.info("%s en cache: %d | a traducir: %d", tag, len(cached_map), len(to_fetch))

    # 3. Llamar al servicio solo con los no cacheados
    new_translations: list[str] = []
    if to_fetch:
        try:
            t0 = time.time()
            new_translations = post_translate(to_fetch)
            elapsed = time.time() - t0
            logger.info("%s post_translate tardó %.3fs para %d strings", tag, elapsed, len(to_fetch))

            if not isinstance(new_translations, list):
                logger.error("%s post_translate devolvió %s en vez de list — abortando", tag, type(new_translations))
                new_translations = []
        except Exception as ex:
            logger.exception("%s excepción en post_translate: %s", tag, ex)
            new_translations = []

        # Guardar en cache lo que recibimos
        for i, translated_str in enumerate(new_translations):
            if i < len(to_fetch):
                original = to_fetch[i]
                _translation_cache[original] = translated_str

        # Limpiar cache si crece demasiado
        if len(_translation_cache) > _CACHE_MAX:
            logger.info("%s cache lleno (%d) — limpiando", tag, len(_translation_cache))
            _translation_cache.clear()

    # 4. Construir lista final de traducciones alineada con `strings`
    final_translations = list(strings)  # fallback: original si no hay traducción
    for i, s in enumerate(strings):
        if s in cached_map:
            final_translations[i] = cached_map[s]
        elif s in _translation_cache:
            final_translations[i] = _translation_cache[s]
        # else: queda el original (fallback)

    _apply_translations(final_translations, refs)
    logger.info("%s traducción aplicada: %d strings (%d cache hits)", tag, len(strings), len(cached_map))


class TranslatingJSONRenderer(JSONRenderer):
    """
    JSONRenderer que traduce al español los valores string de la respuesta
    cuando el header Accept-Language empieza con 'es'.
    Soporta dict, list y estructuras anidadas. Cache + filtro de no-traducibles.
    """

    def render(self, data, accepted_media_type=None, renderer_context=None):
        logger.debug("[TranslatingJSONRenderer] render() — data type: %s", type(data).__name__)

        if renderer_context and data is not None:
            response = renderer_context.get("response")
            status = getattr(response, "status_code", None)
            is_error = response and status >= 400
            if is_error:
                logger.info("[TranslatingJSONRenderer] error %s — sin traducción", status)
            else:
                translate_data_if_needed(
                    data,
                    renderer_context.get("request"),
                    caller="TranslatingJSONRenderer",
                )

        return super().render(data, accepted_media_type, renderer_context)

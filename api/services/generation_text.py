"""
Finding 16 - text that goes into AI generation and comes back from it.

- keep_user_casing: a name the user typed keeps its exact capitalization even if the
  generation service returns it re-cased ("QA-TEST Bateria VF" -> "Qa-test Bateria VF").
- short_title: titles of generated decks/batteries/topics come from the topic (max 60
  chars) instead of concatenating three tags plus "Flashcards"/"Assessment".
- detect_language / language_for_documents: language of the source documents
  (ISO 639-1), stored on Document.language; KnowledgeSource.language overrides it.
- generation_metadata: what every generation request sends in `metadata` so the
  generation service can write ALL output in that language. anko_services ignores it
  until its prompts read it (see the PR: proposal for anko_services).
"""
from __future__ import annotations

import logging
import re
from collections import Counter

logger = logging.getLogger(__name__)

MAX_TITLE = 60

# ISO 639-1 -> the names anko_services already uses for languages (Language enum: "english", "spanish").
LANGUAGE_NAMES = {
    "es": "spanish", "en": "english", "pt": "portuguese", "fr": "french", "de": "german", "it": "italian",
    "ca": "catalan", "nl": "dutch",
}

# Fallback when langdetect is not installed: a few very common words per language.
_STOPWORDS = {
    "es": {"el", "la", "de", "que", "y", "en", "los", "las", "del", "por", "para", "con", "una", "un", "es", "se", "al"},
    "en": {"the", "of", "and", "to", "in", "is", "for", "that", "with", "on", "are", "be", "this", "by", "as"},
    "pt": {"o", "a", "de", "que", "e", "do", "da", "em", "os", "as", "para", "com", "uma", "não", "são"},
    "fr": {"le", "la", "les", "de", "des", "et", "en", "du", "un", "une", "pour", "est", "dans", "que", "qui"},
}


def keep_user_casing(current: str | None, returned: str | None) -> str | None:
    """`returned` unless it is the same text as `current` with different capitalization."""
    if not returned:
        return returned
    if current and current.strip().casefold() == str(returned).strip().casefold():
        return current
    return returned


def _clip(text: str, limit: int = MAX_TITLE) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return (cut or text[: limit - 1]) + "…"


def short_title(*, tags: list[str], kind: str, index: int) -> str:
    """Topic-based title of at most 60 characters (the first tag is the most representative)."""
    first = next((str(t).strip() for t in tags if str(t).strip()), "")
    if first:
        words = first.split()
        base = " ".join(w if any(c.isupper() for c in w) else w[:1].upper() + w[1:] for w in words)
        return _clip(base)
    return f"{'Assessment' if kind == 'battery' else 'Flashcards' if kind == 'flashcards' else 'Topic'} {index}"


def detect_language(text: str) -> str:
    """ISO 639-1 code of `text`, or "" when it cannot be told."""
    sample = re.sub(r"\s+", " ", str(text or ""))[:5000].strip()
    if len(sample) < 20:
        return ""
    try:
        from langdetect import DetectorFactory, detect

        DetectorFactory.seed = 0  # deterministic
        return detect(sample).split("-")[0]
    except ImportError:
        words = re.findall(r"[a-záéíóúñçãõâêôàèìòù]+", sample.lower())
        scores = {lang: sum(1 for w in words if w in stop) for lang, stop in _STOPWORDS.items()}
        best = max(scores, key=scores.get)
        return best if scores[best] >= 3 else ""
    except Exception:  # noqa: BLE001 - langdetect raises on text without features
        return ""


def document_language(document) -> str:
    """Document.language, detecting and saving it from the document's sections when unknown."""
    if getattr(document, "language", ""):
        return document.language
    from api.models import Section

    text = " ".join(
        Section.objects.filter(document_id=document.id).order_by("order", "id").values_list("content", flat=True)[:20]
    ) or (getattr(document, "extracted_text", "") or "")
    code = detect_language(text)
    if code:
        type(document).objects.filter(pk=document.pk).update(language=code)
        document.language = code
    return code


def language_for_documents(document_ids, knowledge_source=None) -> str:
    """Language for generating from these documents: the process setting, else the documents' majority."""
    if knowledge_source is not None and getattr(knowledge_source, "language", ""):
        return knowledge_source.language
    from api.models import Document

    codes = [document_language(doc) for doc in Document.objects.filter(id__in=list(document_ids))]
    codes = [c for c in codes if c]
    return Counter(codes).most_common(1)[0][0] if codes else ""


def generation_metadata(language_code: str) -> dict:
    """Keys added to the `metadata` of every generation request (empty when unknown)."""
    if not language_code:
        return {}
    name = LANGUAGE_NAMES.get(language_code, language_code)
    return {
        "language": name,
        "language_code": language_code,
        "output_language_instruction": f"Write ALL output (titles, questions, options, answers, explanations, flashcards) in {name}.",
    }

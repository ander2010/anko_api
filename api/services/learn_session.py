"""
Learn mode sessions (F-05).

Root cause of the old behaviour: Learn delegated every request to anko_services
over a fresh WebSocket, and anko_services keeps the session (in-flight card,
queue, schedule) in the memory of each of its uvicorn workers (--workers 5).
Consecutive requests landed on different workers, so ratings were applied in one
process and the next card was picked by another that still had card 1 due.

Here the whole session lives in the DB and every answer is processed under
``select_for_update``:

- seq must be ``last_seq + 1``; a repeated/older seq replays the stored response
  (idempotent retries); a gap returns 409 with ``expected_seq``.
- Good/Easy: the card is learned for this session. Again/Hard: it comes back after
  at least ``min(3, other pending cards)`` distinct cards. Skip: no scheduling change,
  the card goes to the end of the queue.
- Long-term scheduling is per user in FlashcardSchedule (simplified FSRS-style intervals).
"""
from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from api.models import Flashcard, FlashcardSchedule, LearnAnswer, LearnRating, LearnSession

MIN_REQUEUE_GAP = 3

# First-review stability of FSRS v4.5 default weights (w0..w3), used as interval in days.
INITIAL_INTERVAL_DAYS = {
    LearnRating.AGAIN: 0.4872,
    LearnRating.HARD: 1.4003,
    LearnRating.GOOD: 3.7145,
    LearnRating.EASY: 13.8206,
}
# Growth factors for cards already in review (simplified; not the full FSRS model).
REVIEW_GROWTH = {LearnRating.HARD: 1.2, LearnRating.GOOD: 2.5, LearnRating.EASY: 3.5}
LAPSE_FACTOR = 0.2


class SeqConflict(Exception):
    def __init__(self, expected_seq):
        super().__init__(f"expected seq {expected_seq}")
        self.expected_seq = expected_seq


class CardMismatch(Exception):
    def __init__(self, expected_card_id):
        super().__init__("card mismatch")
        self.expected_card_id = expected_card_id


@dataclass
class AnswerResult:
    payload: dict
    replayed: bool


def card_public_id(card: Flashcard) -> str:
    return str(card.card_id or card.pk)


# ─── Session state ───────────────────────────────────────────────────────────

def _deck_cards(deck):
    return list(Flashcard.objects.filter(deck=deck).order_by("created_at", "id"))


def _initial_state(cards):
    return {
        "order": [c.pk for c in cards],
        "new": [c.pk for c in cards],      # never answered, in deck order
        "learning": [],                    # [{"card": pk, "after_turn": n}]
        "learned": [],
        "answered": [],                    # answered (rated) at least once
        "turn": 0,
        "reviewed": 0,                     # rated answers (skips excluded)
        "current": None,
        "current_is_review": False,
    }


def _select_next(state, just_answered=None):
    """Pick and remove the next card from the queues; returns its pk or None."""
    turn = state["turn"]
    learning = sorted(state["learning"], key=lambda e: e["after_turn"])

    def take_learning(entry):
        state["learning"].remove(entry)
        return entry["card"]

    # 1. Learning cards whose gap has elapsed.
    for entry in learning:
        if entry["after_turn"] <= turn and entry["card"] != just_answered:
            return take_learning(entry)
    # 2. New cards in deck order.
    for pk in state["new"]:
        if pk != just_answered or len(state["new"]) == 1 and not state["learning"]:
            state["new"].remove(pk)
            return pk
    # 3. Nothing else is available: earliest learning card (may be the one just answered
    #    only when it is the last pending card).
    others = [e for e in learning if e["card"] != just_answered]
    if others:
        return take_learning(others[0])
    if learning:
        return take_learning(learning[0])
    if state["new"]:
        return state["new"].pop(0)
    return None


def _advance(state, just_answered=None):
    pk = _select_next(state, just_answered)
    state["current"] = pk
    state["current_is_review"] = bool(pk is not None and pk in state["answered"])


def _session_summary(state):
    total = len(state["order"])
    answered = set(state["answered"])
    learned = set(state["learned"])
    return {
        "total": total,
        "new_remaining": len([pk for pk in state["order"] if pk not in answered]),
        "learning_remaining": len(answered - learned),
        "reviewed": state["reviewed"],
        "learned": len(learned),
        "done": state["current"] is None,
    }


def _card_payload(card, *, is_review, request=None):
    from api.serializers import FlashcardSerializer

    data = FlashcardSerializer(card, context={"request": request}).data
    return {
        **data,
        "id": card.pk,                     # DB id (same as FlashcardSerializer)
        "card_id": card_public_id(card),   # id to send back in ws-push-feedback
        "is_review": is_review,
    }


def build_payload(session, request=None):
    state = session.state
    card = None
    if state.get("current") is not None:
        card = Flashcard.objects.filter(pk=state["current"]).first()
    return {
        "job_id": session.job_id,
        "ack_seq": session.last_seq,
        "next_card": _card_payload(card, is_review=state.get("current_is_review", False), request=request) if card else None,
        "session": _session_summary(state),
    }


# ─── Public API ──────────────────────────────────────────────────────────────

def start_or_resume(*, user, deck, job_id, request=None):
    """Create the session for ``job_id`` (first card) or resume it (current card)."""
    with transaction.atomic():
        session, created = LearnSession.objects.select_for_update().get_or_create(
            user=user, job_id=job_id, defaults={"deck": deck},
        )
        if session.deck_id != deck.id:
            raise ValueError("job_id belongs to another deck")
        if created:
            session.state = _initial_state(_deck_cards(deck))
            _advance(session.state)
            if session.state["current"] is None:
                session.finished_at = timezone.now()
            session.save()
    return build_payload(session, request=request)


def answer(*, user, job_id, seq, card_id, rating=None, skip=False, time_to_answer_ms=None, request=None):
    """Apply one answer (rating 1-4 or skip). Idempotent for repeated seq."""
    with transaction.atomic():
        session = LearnSession.objects.select_for_update().get(user=user, job_id=job_id)

        if seq <= session.last_seq:  # retry of an already processed answer
            return AnswerResult(payload=session.last_response or build_payload(session, request), replayed=True)
        if seq != session.last_seq + 1:
            raise SeqConflict(session.last_seq + 1)

        state = session.state
        current_pk = state.get("current")
        if current_pk is None:
            raise CardMismatch(None)
        card = Flashcard.objects.get(pk=current_pk)
        if str(card_id) not in (card_public_id(card), str(card.pk)):
            raise CardMismatch(card_public_id(card))

        LearnAnswer.objects.create(
            session=session, card=card, seq=seq, rating=None if skip else rating,
            skipped=skip, time_to_answer_ms=time_to_answer_ms,
        )
        state["turn"] += 1

        if skip:
            state["new"].append(current_pk)  # back of the queue, schedule untouched
        else:
            _apply_schedule(user=user, card=card, rating=rating)
            state["reviewed"] += 1
            if current_pk not in state["answered"]:
                state["answered"].append(current_pk)
            if rating in (LearnRating.GOOD, LearnRating.EASY):
                if current_pk not in state["learned"]:
                    state["learned"].append(current_pk)
            else:
                pending_others = len(state["new"]) + len(state["learning"])
                gap = min(MIN_REQUEUE_GAP, pending_others)
                state["learning"].append({"card": current_pk, "after_turn": state["turn"] + gap})

        _advance(state, just_answered=current_pk)
        session.last_seq = seq
        if state["current"] is None and session.finished_at is None:
            session.finished_at = timezone.now()
        session.state = state
        payload = build_payload(session, request=request)
        session.last_response = payload
        session.save()
    return AnswerResult(payload=payload, replayed=False)


def _apply_schedule(*, user, card, rating):
    """Per-user long-term schedule (simplified FSRS-style)."""
    now = timezone.now()
    schedule, _ = FlashcardSchedule.objects.select_for_update().get_or_create(user=user, card=card)
    rating = LearnRating(rating)
    if schedule.state in ("new", "learning") or schedule.reps == 0:
        schedule.interval_days = INITIAL_INTERVAL_DAYS[rating]
        schedule.state = "learning" if rating in (LearnRating.AGAIN, LearnRating.HARD) else "review"
    elif rating == LearnRating.AGAIN:
        schedule.lapses += 1
        schedule.interval_days = max(INITIAL_INTERVAL_DAYS[LearnRating.AGAIN], schedule.interval_days * LAPSE_FACTOR)
        schedule.state = "relearning"
    else:
        schedule.interval_days = max(1.0, schedule.interval_days * REVIEW_GROWTH[rating])
        schedule.state = "review"
    schedule.reps += 1
    schedule.last_rating = int(rating)
    schedule.last_reviewed_at = now
    schedule.due_at = now + timedelta(days=schedule.interval_days)
    schedule.save()

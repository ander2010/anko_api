import asyncio
import json
import os
import uuid

import websockets
from websockets import exceptions as ws_exceptions


BASE_WS = os.getenv("FLASHCARD_WS_BASE", "ws://localhost:8080/ws/flashcards")


def _ws_url(job_id: str) -> str:
    return BASE_WS.rstrip("/") + f"/{job_id}"


async def ws_get_next_card(*, job_id: str, user_id: str, last_seq: int = 0, token: str = "", timeout_sec: int = 25):
    """
    Abre WS, subscribe_job, espera 1 mensaje tipo "card" y retorna:
      {"message_type":"card", "seq":..., "card":{...}}
    o retorna done/error si llega eso primero.
    """
    if not job_id:
        raise ValueError("job_id is required")

    user_id = user_id or str(uuid.uuid4())
    ws_url = _ws_url(job_id)

    try:
        async with websockets.connect(ws_url, ping_interval=20, ping_timeout=100) as ws:
            await ws.send(
                json.dumps(
                    {
                        "message_type": "subscribe_job",
                        "job_id": job_id,
                        "user_id": user_id,
                        "request_id": str(uuid.uuid4()),
                        "last_seq": int(last_seq or 0),
                        "token": token or "",
                    }
                )
            )

            # Espera hasta timeout por un card/done/error
            end_at = asyncio.get_event_loop().time() + timeout_sec
            while True:
                remaining = end_at - asyncio.get_event_loop().time()
                if remaining <= 0:
                    return {"message_type": "timeout"}

                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                mt = msg.get("message_type")
                if mt in {"card", "done", "error"}:
                    return msg

    except ws_exceptions.ConnectionClosed as exc:
        return {"message_type": "ws_closed", "code": exc.code, "reason": exc.reason}
    except Exception as exc:
        return {"message_type": "ws_error", "detail": str(exc)}


async def ws_send_card_feedback(
    *,
    job_id: str,
    user_id: str,
    seq: int,
    card_id: int,
    rating: int,
    time_to_answer_ms: int = 500,
    token: str = "",
    timeout_sec: int = 15,
):
    """
    Abre WS, subscribe_job (opcional pero seguro), envía card_feedback y retorna "ok" o error.
    """
    if not job_id:
        raise ValueError("job_id is required")

    user_id = user_id or str(uuid.uuid4())
    ws_url = _ws_url(job_id)

    try:
        async with websockets.connect(ws_url, ping_interval=20, ping_timeout=100) as ws:
            await ws.send(
                json.dumps(
                    {
                        "message_type": "subscribe_job",
                        "job_id": job_id,
                        "user_id": user_id,
                        "request_id": str(uuid.uuid4()),
                        "last_seq": 0,
                        "token": token or "",
                    }
                )
            )

            await ws.send(
                json.dumps(
                    {
                        "message_type": "card_feedback",
                        "seq": seq,
                        "job_id": job_id,
                        "card_id": card_id,
                        "rating": rating,
                        "time_to_answer_ms": time_to_answer_ms,
                    }
                )
            )

            # Si tu servidor manda un ack, lo puedes leer aquí.
            # Si no manda nada, igual devolvemos ok.
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=timeout_sec)
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    msg = {"raw": raw}
                return {"message_type": "ok", "ack": msg}
            except asyncio.TimeoutError:
                return {"message_type": "ok"}

    except ws_exceptions.ConnectionClosed as exc:
        return {"message_type": "ws_closed", "code": exc.code, "reason": exc.reason}
    except Exception as exc:
        return {"message_type": "ws_error", "detail": str(exc)}

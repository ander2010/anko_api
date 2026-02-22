import asyncio
import json
import os
import uuid
from typing import Any, Dict, Optional

import websockets
from websockets import exceptions as ws_exceptions


PROGRESS_WS_BASE = os.getenv("FLASHCARD_PROGRESS_WS_BASE", "ws://localhost:8080/ws/progress")


def _progress_ws_url(job_id: str) -> str:
    return PROGRESS_WS_BASE.rstrip("/") + f"/{job_id}"


async def ws_get_latest_progress(
    *,
    job_id: str,
    user_id: Optional[str] = None,
    token: str = "",
    timeout_sec: int = 6,
    max_messages: int = 50,
    reconnects: int = 2,
    send_subscribe: bool = False,  # cámbialo a True si tu server lo requiere
) -> Dict[str, Any]:
    """
    Connects to /ws/progress/{job_id} and returns the latest progress message.
    - Reads up to max_messages or until timeout.
    - Reconnects if the WS closes.
    """
    if not job_id:
        return {"message_type": "error", "detail": "job_id is required"}

    ws_url = _progress_ws_url(str(job_id).strip())
    user_id = user_id or str(uuid.uuid4())

    last_msg: Optional[Dict[str, Any]] = None
    last_err: Optional[str] = None

    for attempt in range(reconnects + 1):
        try:
            async with websockets.connect(ws_url, ping_interval=20, ping_timeout=60, close_timeout=2) as ws:
                # Algunos servidores requieren subscribe. Otros NO.
                if send_subscribe:
                    await ws.send(
                        json.dumps(
                            {
                                "message_type": "subscribe_progress",  # <- si tu server usa otro, cámbialo
                                "job_id": str(job_id),
                                "user_id": str(user_id),
                                "request_id": str(uuid.uuid4()),
                                "token": token or "",
                            }
                        )
                    )

                end_at = asyncio.get_event_loop().time() + timeout_sec
                count = 0

                while True:
                    remaining = end_at - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        return last_msg or {"message_type": "timeout", "detail": "no progress received"}

                    raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    count += 1

                    # Parse JSON
                    try:
                        msg = json.loads(raw)
                    except Exception:
                        msg = {"message_type": "raw", "raw": raw}

                    last_msg = msg

                    # Si ya vino algo que parece final, devuelve de una vez
                    mt = (msg or {}).get("message_type")
                    if mt in {"done", "completed", "error", "failed"}:
                        return msg

                    if count >= max_messages:
                        return last_msg

        except asyncio.TimeoutError:
            if last_msg:
                return last_msg
            last_err = f"timeout after {timeout_sec}s"
        except ws_exceptions.ConnectionClosed as exc:
            # intenta reconectar
            last_err = f"ws_closed code={exc.code} reason={exc.reason}"
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"

        if last_msg:
            return last_msg

    return {"message_type": "error", "detail": last_err or "unknown ws error", "ws_url": ws_url}
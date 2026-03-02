import contextvars
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional


_CONFIGURED = False
_request_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_ctx.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
            "pathname": record.pathname,
            "lineno": record.lineno,
            "func": record.funcName,
            "process": record.process,
            "thread": record.thread,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def _configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_format = os.getenv("LOG_FORMAT", "%(asctime)s %(levelname)s %(name)s %(message)s")

    root = logging.getLogger()
    root.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(log_format))
    console_handler.addFilter(RequestIdFilter())
    root.addHandler(console_handler)

    log_file = os.getenv("LOG_FILE", "logs/app.jsonl")
    max_bytes = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
    backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    log_dir = os.path.dirname(log_file)
    try:
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(RequestIdFilter())
        root.addHandler(file_handler)
    except Exception as e:
        root.warning("File logging disabled (path=%s). error=%s", log_file, e)

    _CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    _configure_logging()
    return logging.getLogger(name or "api")


def log_exception(logger: logging.Logger, msg: str, *args, **kwargs) -> None:
    logger.exception(msg, *args, **kwargs)


def set_request_id(request_id: Optional[str]) -> None:
    _request_id_ctx.set(request_id)


def get_request_id() -> Optional[str]:
    return _request_id_ctx.get()

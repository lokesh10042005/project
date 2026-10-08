"""
Structured logging: JSON in production, coloured text in development.
"""

import logging
import sys
from typing import Any

from app.core.config import settings


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON for log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        import json, traceback
        log: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            log["exc"] = traceback.format_exception(*record.exc_info)
        if hasattr(record, "request_id"):
            log["request_id"] = record.request_id
        return json.dumps(log)


class ColourFormatter(logging.Formatter):
    COLOURS = {
        "DEBUG":    "\033[36m",
        "INFO":     "\033[32m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelname, "")
        record.levelname = f"{colour}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    # Remove default handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if settings.LOG_FORMAT == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            ColourFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s  %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "multipart", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

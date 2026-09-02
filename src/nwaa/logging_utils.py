"""Structured logging setup.

Emits one JSON object per line so scan runs can be piped into log
aggregation, while keeping a plain human-readable mode for interactive
use. The redaction filter is attached to both the root logger and the
handler itself, since a handler only re-runs filters attached directly
to it or to the logger that emitted the record.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from nwaa.redaction import install_redaction

_JSON_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in _JSON_RESERVED and not k.startswith("_")
        }
        if extras:
            payload.update(extras)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    root = logging.getLogger("nwaa")
    root.setLevel(level.upper())
    root.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stderr)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    install_redaction(handler)
    install_redaction(root)
    root.addHandler(handler)
    root.propagate = False

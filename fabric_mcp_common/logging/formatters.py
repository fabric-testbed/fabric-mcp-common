"""
Structured log formatting.
"""
from __future__ import annotations

import json
import logging
from typing import Iterable, Sequence

#: Extra fields copied onto the JSON record when present.
#:
#: Superset of what the tool decorator and ASGI middleware attach, so structured
#: output carries the same identity fields as the human-readable format —
#: notably ``user_uuid`` and ``project_name``, which an earlier field list
#: omitted, silently dropping them in JSON mode.
DEFAULT_EXTRA_FIELDS: Sequence[str] = (
    "request_id",
    "tool",
    "path",
    "method",
    "status",
    "duration_ms",
    "client",
    "client_ip",
    "user_sub",
    "user_email",
    "user_uuid",
    "project_name",
    "project_uuid",
    "auth_source",
    "result_size",
    "error",
)


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects.

    Emits ``ts``, ``level``, ``logger`` and ``msg``, plus any of
    *extra_fields* present on the record, plus ``exc_info`` when set.

    Args:
        extra_fields: Record attributes to include when present.  Defaults to
            :data:`DEFAULT_EXTRA_FIELDS`.
        datefmt: Timestamp format, ISO-8601 with offset by default.
    """

    def __init__(
        self,
        *,
        extra_fields: Iterable[str] = DEFAULT_EXTRA_FIELDS,
        datefmt: str = "%Y-%m-%dT%H:%M:%S%z",
    ) -> None:
        super().__init__(datefmt=datefmt)
        self.extra_fields = tuple(extra_fields)

    def format(self, record: logging.LogRecord) -> str:
        """Format *record* as a JSON string."""
        base = {
            "ts": self.formatTime(record, datefmt=self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in self.extra_fields:
            if hasattr(record, key):
                base[key] = getattr(record, key)
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False, default=str)


__all__ = ["DEFAULT_EXTRA_FIELDS", "JsonFormatter"]

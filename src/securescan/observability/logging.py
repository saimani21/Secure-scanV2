from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from securescan.observability.context import get_correlation_id

_ALLOWED_EXTRA_KEYS = (
    "event",
    "job_id",
    "run_id",
    "adapter_id",
    "disposition",
    "operation",
    "duration_ms",
    "affected_jobs",
    "error_type",
)
_MANAGED_HANDLER_ATTRIBUTE = "_securescan_structured_handler"


def _safe_scalar(value: object) -> str | int | float | bool | None:
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        raise TypeError
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError


class SafeJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
        correlation_value = getattr(record, "correlation_id", get_correlation_id())
        correlation_id = correlation_value if isinstance(correlation_value, str) else None

        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id,
        }
        for key in _ALLOWED_EXTRA_KEYS:
            if not hasattr(record, key):
                continue
            try:
                payload[key] = _safe_scalar(getattr(record, key))
            except TypeError:
                continue

        if record.exc_info is not None and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__

        return json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        )


def _normalize_logging_level(level: int | str) -> int:
    if isinstance(level, bool):
        raise ValueError("Logging level must be a standard level name or integer")
    if isinstance(level, str):
        normalized = logging.getLevelNamesMapping().get(level.upper())
        if normalized is None:
            raise ValueError("Logging level name is invalid")
        return normalized
    if isinstance(level, int) and 0 <= level <= 100:
        return level
    raise ValueError("Logging level must be a standard level name or integer")


def configure_structured_logging(
    *,
    level: int | str = logging.INFO,
) -> None:
    normalized_level = _normalize_logging_level(level)
    root_logger = logging.getLogger()
    managed_handlers = [
        handler
        for handler in root_logger.handlers
        if getattr(handler, _MANAGED_HANDLER_ATTRIBUTE, False)
    ]

    if managed_handlers:
        managed_handler = managed_handlers[0]
        for duplicate in managed_handlers[1:]:
            root_logger.removeHandler(duplicate)
            duplicate.close()
    else:
        managed_handler = logging.StreamHandler()
        setattr(managed_handler, _MANAGED_HANDLER_ATTRIBUTE, True)
        root_logger.addHandler(managed_handler)

    managed_handler.setLevel(logging.NOTSET)
    managed_handler.setFormatter(SafeJsonFormatter())
    root_logger.setLevel(normalized_level)

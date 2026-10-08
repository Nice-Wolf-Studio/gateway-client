"""Structured, traceable logging for gateway services.

Logging records what the code did, verbatim: arguments, results, exception
messages and tracebacks are logged exactly as the program holds them. Nothing
in this module inspects a value to decide what to do with it (no redaction,
no truncation, no pattern matching).

- `current_request_id()`: the gateway `request_id` of the call being
  handled (None outside one). Works in async and sync (worker-thread)
  handlers.
- `RequestIdFilter`: stamps `record.request_id` on every record it sees, so
  the service's own handler logs correlate with `call.start` / `call.end`.
- `JsonFormatter`: one JSON object per line, ISO-8601 UTC `timestamp`,
  `level`, `logger`, `message`, the library's event fields, `request_id`,
  and `exception` when there is one.
- `configure_logging()`: root logging for a service; JSON when
  `GATEWAY_LOG_FORMAT=json`, else human text. Either way the request-id
  filter is installed.

The library attaches its fields to a record as `gw_fields` (a dict) and its
plain message as `gw_message`; the text form of the same record is
`"<message> key=value ..."` (a string value as is, any other value as JSON).
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping

LOG_FORMAT_ENV = "GATEWAY_LOG_FORMAT"
TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "gateway_client_request_id", default=None)


# --- serialization ----------------------------------------------------------------------

def to_json(value: Any) -> str:
    """Compact JSON; anything not JSON-native is stringified."""
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))


def json_bytes(value: Any) -> int:
    """Size in bytes of `value` as compact UTF-8 JSON."""
    return len(json.dumps(value, default=str).encode())


# --- request id ---------------------------------------------------------------------------

def current_request_id() -> str | None:
    """The gateway `request_id` of the call or read being handled, else None."""
    return _request_id.get()


@contextlib.contextmanager
def request_scope(request_id: Any) -> Iterator[None]:
    """Make `request_id` the current one for the duration of the block."""
    token = _request_id.set(None if request_id is None else str(request_id))
    try:
        yield
    finally:
        _request_id.reset(token)


class RequestIdFilter(logging.Filter):
    """Stamps `record.request_id` (the current call's, or None) on every
    record that does not already carry one. Never drops a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "request_id", None) is None:
            record.request_id = current_request_id()
        return True


# --- formatting ---------------------------------------------------------------------------

def _kv_value(value: Any) -> str:
    return value if isinstance(value, str) else to_json(value)


def text_line(message: str, fields: Mapping[str, Any]) -> str:
    """`message key=value ...` for every field but `event` (the message)."""
    return " ".join([message] + [f"{key}={_kv_value(value)}"
                                 for key, value in fields.items() if key != "event"])


def emit(logger: logging.Logger, level: int, message: str, fields: dict[str, Any],
         *, exc_info: Any = None) -> None:
    """Log one structured record: text `message key=value ...`, with the
    fields kept on the record for `JsonFormatter`."""
    if not logger.isEnabledFor(level):
        return
    logger.log(level, "%s", text_line(message, fields), exc_info=exc_info,
               extra={"gw_message": message, "gw_fields": fields})


def _iso_utc(created: float) -> str:
    stamp = datetime.fromtimestamp(created, tz=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


class JsonFormatter(logging.Formatter):
    """One JSON object per record: `timestamp` (ISO-8601 UTC), `level`,
    `logger`, `message`, the library's event fields, `request_id` (from the
    record, e.g. stamped by `RequestIdFilter`), and `exception`."""

    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, "gw_fields", None)
        out: dict[str, Any] = {
            "timestamp": _iso_utc(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": getattr(record, "gw_message", None) or record.getMessage(),
        }
        if fields:
            out.update(fields)
        if "request_id" not in out and getattr(record, "request_id", None) is not None:
            out["request_id"] = record.request_id
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return to_json(out)


class _UtcTextFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return _iso_utc(record.created)


def wants_json(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get(LOG_FORMAT_ENV, "").strip().lower() == "json"


def configure_logging(level: int = logging.INFO, *, json_format: bool | None = None,
                      stream: Any = None) -> logging.Handler:
    """Replace the root handlers with one stream handler (stderr by default):
    JSON lines when `json_format` is true, or when it is None and
    `GATEWAY_LOG_FORMAT=json`; else text with ISO-8601 UTC times. The
    request-id filter is installed on the handler. Returns the handler."""
    use_json = wants_json() if json_format is None else json_format
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter() if use_json else _UtcTextFormatter(TEXT_FORMAT))
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    for old in root.handlers[:]:
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(level)
    return handler


def apply_env_format() -> None:
    """Called by `GatewayService.run()`: on the root logger's existing
    handlers, install the request-id filter (once) and, when
    `GATEWAY_LOG_FORMAT=json`, the JSON formatter. Nothing changes for a
    service that has configured no root handlers."""
    use_json = wants_json()
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, RequestIdFilter) for f in handler.filters):
            handler.addFilter(RequestIdFilter())
        if use_json and not isinstance(handler.formatter, JsonFormatter):
            handler.setFormatter(JsonFormatter())

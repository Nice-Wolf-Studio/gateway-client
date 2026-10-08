"""Structured, traceable logging for gateway services.

What it provides:

- `sanitize(value)`: the redacted, truncated copy of a value that is safe to
  log. Keys that look like secrets (`password`, `token`, `secret`, `key`,
  `credential`, `authorization`, `cookie`, in any case, at any depth) become
  `"[REDACTED]"`; a string longer than `MAX_STRING_CHARS` is cut with a
  marker; a value whose JSON is larger than `MAX_PAYLOAD_BYTES` becomes
  `{"truncated": true, "bytes": N, "preview": "<first 8 KB>"}`.
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
`"<message> key=value ..."`.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping

REDACTED = "[REDACTED]"
ENCRYPTED = "[encrypted]"
MAX_STRING_CHARS = 2000
MAX_PAYLOAD_BYTES = 8 * 1024
LOG_FORMAT_ENV = "GATEWAY_LOG_FORMAT"
TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# A key is secret-like when one of its words (split on non-alphanumerics and
# camelCase) is one of these, or ends with one of the longer ones
# ("csrftoken", "accesstoken"), or is a run-together "...key" compound.
_SECRET_WORDS = {"password", "token", "secret", "key", "credential", "credentials",
                 "authorization", "cookie"}
_SECRET_SUFFIXES = ("password", "token", "secret", "credential", "credentials",
                    "authorization", "cookie")
_KEY_COMPOUNDS = {"apikey", "privatekey", "secretkey", "accesskey", "signingkey",
                  "sessionkey"}
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "gateway_client_request_id", default=None)


# --- redaction and truncation -------------------------------------------------------------

def is_secret_key(name: Any) -> bool:
    """True when a mapping key names a secret (case-insensitive)."""
    if not isinstance(name, str):
        return False
    for word in _WORD_SPLIT.split(name):
        word = word.lower()
        if not word:
            continue
        if (word in _SECRET_WORDS or word in _KEY_COMPOUNDS
                or word.endswith(_SECRET_SUFFIXES)):
            return True
    return False


def _redact_and_cut(value: Any, state: list[bool]) -> Any:
    if isinstance(value, Mapping):
        return {str(k): (REDACTED if is_secret_key(k) else _redact_and_cut(v, state))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_and_cut(v, state) for v in value]
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            state[0] = True
            return (value[:MAX_STRING_CHARS]
                    + f"...[truncated {len(value) - MAX_STRING_CHARS} chars]")
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_and_cut(str(value), state)


def to_json(value: Any) -> str:
    """Compact JSON; anything not JSON-native is stringified."""
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))


def json_bytes(value: Any) -> int:
    """Size in bytes of `value` as compact UTF-8 JSON."""
    return len(json.dumps(value, default=str).encode())


def sanitize(value: Any) -> tuple[Any, bool]:
    """(safe copy of `value` for a log, whether anything was truncated).
    Never mutates `value`."""
    state = [False]
    out = _redact_and_cut(value, state)
    encoded = to_json(out).encode()
    if len(encoded) > MAX_PAYLOAD_BYTES:
        preview = encoded[:MAX_PAYLOAD_BYTES].decode("utf-8", errors="ignore")
        return {"truncated": True, "bytes": len(encoded), "preview": preview}, True
    return out, state[0]


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
    if isinstance(value, str):
        return value if value and not re.search(r"[\s\"=]", value) else json.dumps(value)
    return to_json(value)


def text_line(message: str, fields: Mapping[str, Any]) -> str:
    """`message key=value ...` (None values and the event itself omitted)."""
    parts = [message]
    for key, value in fields.items():
        if value is None or key == "event":
            continue
        parts.append(f"{key}={_kv_value(value)}")
    return " ".join(parts)


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

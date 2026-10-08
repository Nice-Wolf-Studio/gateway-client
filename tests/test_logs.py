"""Unit tests for `gateway_client.logs`: redaction, truncation, the JSON
formatter, the request-id filter and `configure_logging`. No I/O."""

from __future__ import annotations

import io
import json
import logging
import re

import pytest

from gateway_client import logs
from gateway_client.logs import (
    ENCRYPTED,
    MAX_PAYLOAD_BYTES,
    MAX_STRING_CHARS,
    REDACTED,
    JsonFormatter,
    RequestIdFilter,
    configure_logging,
    current_request_id,
    is_secret_key,
    sanitize,
)

# --- redaction --------------------------------------------------------------------------


@pytest.mark.parametrize("key", [
    "password", "PASSWORD", "db_password", "Password", "token", "access_token",
    "accessToken", "refresh-token", "csrftoken", "secret", "client_secret",
    "clientSecret", "key", "api_key", "apiKey", "X-Api-Key", "apikey", "private_key",
    "privateKey", "credential", "credentials", "SERVICE_CREDENTIAL", "authorization",
    "Authorization", "cookie", "Set-Cookie", "session_cookie",
])
def test_secret_like_keys_are_detected(key):
    assert is_secret_key(key)


@pytest.mark.parametrize("key", [
    "text", "recipient", "keyword", "keywords", "monkey", "max_tokens", "tokens",
    "message", "chat_id", "url", "author", "secretary_name", "keys",
])
def test_ordinary_keys_are_not_redacted(key):
    assert not is_secret_key(key)


def test_redaction_is_recursive_and_case_insensitive():
    value = {"to": "group-1", "Token": "t-1",
             "nested": {"auth": {"Authorization": "Bearer abc", "ok": 1}},
             "items": [{"password": "p"}, {"name": "n"}, ["x", {"apiKey": "k"}]]}
    out, truncated = sanitize(value)
    assert truncated is False
    assert out == {"to": "group-1", "Token": REDACTED,
                   "nested": {"auth": {"Authorization": REDACTED, "ok": 1}},
                   "items": [{"password": REDACTED}, {"name": "n"},
                             ["x", {"apiKey": REDACTED}]]}
    # The input is never mutated.
    assert value["Token"] == "t-1"


def test_a_secret_key_holding_a_container_is_redacted_whole():
    out, _ = sanitize({"credentials": {"user": "u", "pw": "p"}})
    assert out == {"credentials": REDACTED}


# --- truncation -------------------------------------------------------------------------


def test_long_string_truncated_with_marker():
    out, truncated = sanitize({"text": "a" * (MAX_STRING_CHARS + 500)})
    assert truncated is True
    assert out["text"].startswith("a" * MAX_STRING_CHARS)
    assert "truncated" in out["text"] and "500" in out["text"]
    assert len(out["text"]) < MAX_STRING_CHARS + 50


def test_string_at_the_limit_is_kept():
    out, truncated = sanitize("b" * MAX_STRING_CHARS)
    assert out == "b" * MAX_STRING_CHARS and truncated is False


def test_whole_payload_over_8kb_replaced_by_marker():
    value = [{"type": "text", "text": "c" * 1500} for _ in range(10)]   # ~15 KB
    out, truncated = sanitize(value)
    assert truncated is True
    assert isinstance(out, dict) and out["truncated"] is True
    assert out["bytes"] > MAX_PAYLOAD_BYTES
    assert len(out["preview"].encode()) <= MAX_PAYLOAD_BYTES
    assert len(json.dumps(out)) < MAX_PAYLOAD_BYTES + 200


def test_redaction_happens_before_truncation_preview():
    value = {"token": "SECRET-" + "z" * 10, "pad": ["d" * 1900] * 6}
    out, _ = sanitize(value)
    assert "SECRET-" not in json.dumps(out)


def test_non_json_values_are_stringified_not_raised():
    out, _ = sanitize({"when": object(), "b": b"\x00\x01"})
    json.dumps(out)


# --- request id -------------------------------------------------------------------------


def test_current_request_id_is_none_outside_a_call():
    assert current_request_id() is None


def test_request_id_scope_sets_and_resets():
    with logs.request_scope("r-77"):
        assert current_request_id() == "r-77"
    assert current_request_id() is None


def test_filter_stamps_request_id_on_records():
    f = RequestIdFilter()
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "hi", None, None)
    with logs.request_scope("r-9"):
        assert f.filter(rec) is True
    assert rec.request_id == "r-9"
    rec2 = logging.LogRecord("x", logging.INFO, __file__, 1, "hi", None, None)
    f.filter(rec2)
    assert rec2.request_id is None


# --- formatters -------------------------------------------------------------------------


def _record(msg="call.end", fields=None, exc_info=None, level=logging.INFO):
    rec = logging.LogRecord("gateway_client", level, __file__, 1, msg, None, exc_info)
    if fields is not None:
        rec.gw_message = fields.get("event", msg)
        rec.gw_fields = fields
    return rec


def test_json_formatter_emits_fields_and_iso_utc_timestamp():
    rec = _record(fields={"event": "call.end", "request_id": "r-1", "tool": "echo",
                          "outcome": "ok", "duration_ms": 1.5, "error_code": None})
    out = json.loads(JsonFormatter().format(rec))
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", out["timestamp"])
    assert out["level"] == "INFO" and out["logger"] == "gateway_client"
    assert out["message"] == "call.end"
    assert out["event"] == "call.end" and out["outcome"] == "ok"
    assert out["duration_ms"] == 1.5 and out["error_code"] is None


def test_json_formatter_includes_filter_request_id_for_foreign_records():
    rec = logging.LogRecord("my_backend", logging.INFO, __file__, 1, "sent %s", ("x",), None)
    with logs.request_scope("r-5"):
        RequestIdFilter().filter(rec)
    out = json.loads(JsonFormatter().format(rec))
    assert out["message"] == "sent x" and out["request_id"] == "r-5"


def test_json_formatter_includes_exception():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        rec = _record(msg="oops", exc_info=sys.exc_info(), level=logging.ERROR)
    out = json.loads(JsonFormatter().format(rec))
    assert "ValueError" in out["exception"]


def test_configure_logging_json_from_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_LOG_FORMAT", "json")
    stream = io.StringIO()
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging(stream=stream)
        with logs.request_scope("r-42"):
            logging.getLogger("my_backend").info("handler line")
        line = json.loads(stream.getvalue().strip().splitlines()[-1])
        assert line["message"] == "handler line" and line["request_id"] == "r-42"
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])


def test_configure_logging_text_is_default(monkeypatch):
    monkeypatch.delenv("GATEWAY_LOG_FORMAT", raising=False)
    stream = io.StringIO()
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging(stream=stream)
        logging.getLogger("my_backend").info("plain line")
        text = stream.getvalue()
        assert "plain line" in text and not text.lstrip().startswith("{")
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])


def test_encrypted_marker_value():
    assert ENCRYPTED == "[encrypted]" and REDACTED == "[REDACTED]"


@pytest.mark.parametrize("env_json", [True, False])
def test_apply_env_format_on_existing_root_handlers(monkeypatch, env_json):
    # A service that did its own logging.basicConfig(...): run() stamps the
    # request id on its handlers and, only with GATEWAY_LOG_FORMAT=json,
    # switches them to JSON lines.
    if env_json:
        monkeypatch.setenv("GATEWAY_LOG_FORMAT", "json")
    else:
        monkeypatch.delenv("GATEWAY_LOG_FORMAT", raising=False)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    text_fmt = logging.Formatter("%(levelname)s %(message)s")
    handler.setFormatter(text_fmt)
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    try:
        logs.apply_env_format()
        logs.apply_env_format()   # idempotent
        assert sum(isinstance(f, RequestIdFilter) for f in handler.filters) == 1
        with logs.request_scope("r-env"):
            logging.getLogger("my_backend").info("x")
        out = stream.getvalue().strip()
        if env_json:
            assert json.loads(out)["request_id"] == "r-env"
        else:
            assert handler.formatter is text_fmt and out == "INFO x"
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])

"""Unit tests for `gateway_client.logs`: formatting, request-id filter,
JSON format, configure_logging, and metadata-only invariance."""

from __future__ import annotations

import io
import json
import logging
import re

import pytest

import gateway_client
from gateway_client import logs
from gateway_client.logs import (
    JsonFormatter,
    RequestIdFilter,
    apply_env_format,
    configure_logging,
    current_request_id,
    request_scope,
    text_line,
    to_json,
)


def test_no_heuristic_redaction_api_remains():
    """Commit a4e6156 deleted heuristic redaction: assert zero heuristic
    redaction/sanitization APIs exist."""
    for name in (
        "sanitize",
        "is_secret_key",
        "redact",
        "REDACTED",
        "ENCRYPTED",
        "MAX_STRING_CHARS",
        "MAX_PAYLOAD_BYTES",
    ):
        assert not hasattr(logs, name), name
        assert not hasattr(gateway_client, name), name


def test_current_request_id_is_none_outside_handler():
    assert current_request_id() is None


def test_request_scope_sets_and_resets():
    with request_scope("req-77"):
        assert current_request_id() == "req-77"
    assert current_request_id() is None


def test_request_scope_handles_none_and_non_strings():
    with request_scope(12345):
        assert current_request_id() == "12345"
    with request_scope(None):
        assert current_request_id() is None
    assert current_request_id() is None


def test_filter_stamps_request_id_on_records():
    f = RequestIdFilter()
    rec = logging.LogRecord("app", logging.INFO, __file__, 1, "test message", None, None)
    with request_scope("r-9"):
        assert f.filter(rec) is True
    assert rec.request_id == "r-9"

    # Already set request_id is preserved
    rec2 = logging.LogRecord("app", logging.INFO, __file__, 1, "test", None, None)
    rec2.request_id = "pre-existing"
    with request_scope("r-other"):
        f.filter(rec2)
    assert rec2.request_id == "pre-existing"

    # Outside scope, stamps None if not present
    rec3 = logging.LogRecord("app", logging.INFO, __file__, 1, "test", None, None)
    f.filter(rec3)
    assert rec3.request_id is None


def _record(msg="call.end", fields=None, exc_info=None, level=logging.INFO):
    rec = logging.LogRecord("gateway_client", level, __file__, 1, msg, None, exc_info)
    if fields is not None:
        rec.gw_message = fields.get("event", msg)
        rec.gw_fields = fields
    return rec


def test_json_formatter_emits_fields_and_iso_utc_timestamp():
    rec = _record(
        fields={
            "event": "call.end",
            "request_id": "r-1",
            "tool": "echo",
            "target": "echo",
            "principal": "wrn:user/1",
            "app": "wrn:app/1",
            "encryption": "none",
            "outcome": "result",
            "duration_ms": 1.5,
        }
    )
    out = json.loads(JsonFormatter().format(rec))
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", out["timestamp"])
    assert out["level"] == "INFO"
    assert out["logger"] == "gateway_client"
    assert out["message"] == "call.end"
    assert out["event"] == "call.end"
    assert out["outcome"] == "result"
    assert out["duration_ms"] == 1.5
    assert out["principal"] == "wrn:user/1"
    assert out["app"] == "wrn:app/1"
    assert out["encryption"] == "none"
    assert out["request_id"] == "r-1"


def test_json_formatter_includes_filter_request_id_for_foreign_records():
    rec = logging.LogRecord("my_backend", logging.INFO, __file__, 1, "sent %s", ("x",), None)
    with request_scope("r-5"):
        RequestIdFilter().filter(rec)
    out = json.loads(JsonFormatter().format(rec))
    assert out["message"] == "sent x"
    assert out["request_id"] == "r-5"


def test_json_formatter_includes_exception():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        rec = _record(msg="oops", exc_info=sys.exc_info(), level=logging.ERROR)
    out = json.loads(JsonFormatter().format(rec))
    assert "ValueError" in out["exception"]
    assert "boom" in out["exception"]


def test_text_line_escapes_crlf():
    fields = {"event": "call.start", "request_id": "r\r\n1", "tool": "echo\n2"}
    line = text_line("call.start", fields)
    assert "\r" not in line
    assert "\n" not in line
    assert "request_id=r\\r\\n1" in line
    assert "tool=echo\\n2" in line


def test_to_json_handles_non_native_types():
    out = to_json({"when": object(), "raw": b"\x00\x01"})
    parsed = json.loads(out)
    assert isinstance(parsed["when"], str)
    assert isinstance(parsed["raw"], str)


def test_configure_logging_json_from_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_LOG_FORMAT", "json")
    stream = io.StringIO()
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging(stream=stream)
        with request_scope("r-42"):
            logging.getLogger("my_backend").info("handler line")
        line = json.loads(stream.getvalue().strip().splitlines()[-1])
        assert line["message"] == "handler line"
        assert line["request_id"] == "r-42"
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
        assert "plain line" in text
        assert not text.lstrip().startswith("{")
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])


@pytest.mark.parametrize("env_json", [True, False])
def test_apply_env_format_on_existing_root_handlers(monkeypatch, env_json):
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
        apply_env_format()
        apply_env_format()  # idempotent
        assert sum(isinstance(f, RequestIdFilter) for f in handler.filters) == 1
        with request_scope("r-env"):
            logging.getLogger("my_backend").info("x")
        out = stream.getvalue().strip()
        if env_json:
            assert json.loads(out)["request_id"] == "r-env"
        else:
            assert handler.formatter is text_fmt and out == "INFO x"
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])

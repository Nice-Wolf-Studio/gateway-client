"""Comprehensive tests for per-call request tracing (call.start / call.end),
request id context propagation (current_request_id), JSON formatting,
and strict metadata-only log invariance on Contract v2."""

from __future__ import annotations

import asyncio
import io
import json
import logging
from unittest.mock import AsyncMock

import pytest
from helpers import APP, PRINCIPAL, fake_gateway, make_service, recv_json, run, send_json, serve_until
from test_service import ISSUER, _call, _one_exchange, _read

from gateway_client import (
    Config,
    GatewayService,
    KeyPair,
    ServiceError,
    current_request_id,
    e2e,
)
from gateway_client.caller_token import VerifiedToken
from gateway_client.logs import JsonFormatter, RequestIdFilter, configure_logging

CONTRACT_FIELDS = ("event", "request_id", "principal", "app", "encryption")


def _events(caplog, event=None):
    """The library's structured records as the JSON formatter renders them."""
    fmt = JsonFormatter()
    out = []
    for rec in caplog.records:
        if getattr(rec, "gw_fields", None) is None:
            continue
        line = json.loads(fmt.format(rec))
        line["_levelno"] = rec.levelno
        line["_text"] = rec.getMessage()
        if event is None or line.get("event") == event:
            out.append(line)
    return out


def _exchange(caplog, frames, **service_kwargs):
    with caplog.at_level(logging.DEBUG):
        return run(_one_exchange(frames, service_kwargs=service_kwargs))


# --- call.start and call.end lifecycle & outcomes -----------------------------


def test_successful_call_emits_start_and_end(caplog):
    _, replies = _exchange(caplog, [_call(payload={"text": "hello"}, request_id="r-ok-1")])
    assert replies[0]["type"] == "result"

    starts = _events(caplog, "call.start")
    ends = _events(caplog, "call.end")
    assert len(starts) == 1
    assert len(ends) == 1

    start, end = starts[0], ends[0]
    for field in CONTRACT_FIELDS:
        assert field in start, f"Missing {field} in call.start"
        assert field in end, f"Missing {field} in call.end"

    assert start["request_id"] == "r-ok-1"
    assert start["tool"] == "echo"
    assert start["target"] == "echo"
    assert start["principal"] == PRINCIPAL
    assert start["app"] == APP
    assert start["encryption"] == "none"
    assert start["_levelno"] == logging.INFO

    assert end["request_id"] == "r-ok-1"
    assert end["tool"] == "echo"
    assert end["target"] == "echo"
    assert end["principal"] == PRINCIPAL
    assert end["app"] == APP
    assert end["encryption"] == "none"
    assert end["outcome"] == "result"
    assert isinstance(end["duration_ms"], (int, float))
    assert end["duration_ms"] >= 0
    assert end["_levelno"] == logging.INFO

    # Text message checks
    assert start["_text"].startswith("call.start ")
    assert "request_id=r-ok-1" in start["_text"]
    assert "tool=echo" in start["_text"]

    assert end["_text"].startswith("call.end ")
    assert "request_id=r-ok-1" in end["_text"]
    assert "outcome=result" in end["_text"]
    assert "duration_ms=" in end["_text"]


def test_successful_read_resource_emits_start_and_end(caplog):
    async def on_read(uri, caller):
        return "status ok"

    _, replies = _exchange(
        caplog,
        [_read(uri="svc://status", request_id="r-read-1")],
        on_read=on_read,
    )
    assert replies[0]["type"] == "result"

    starts = _events(caplog, "call.start")
    ends = _events(caplog, "call.end")
    assert len(starts) == 1
    assert len(ends) == 1

    start, end = starts[0], ends[0]
    assert start["request_id"] == "r-read-1"
    assert start["uri"] == "svc://status"
    assert start["target"] == "svc://status"
    assert start["principal"] == PRINCIPAL
    assert start["app"] == APP

    assert end["request_id"] == "r-read-1"
    assert end["uri"] == "svc://status"
    assert end["target"] == "svc://status"
    assert end["outcome"] == "result"
    assert isinstance(end["duration_ms"], (int, float))
    assert end["duration_ms"] >= 0


def test_unknown_tool_outcome_is_not_found(caplog):
    _, replies = _exchange(caplog, [_call(tool="unknown_tool", payload={}, request_id="r-nf")])
    assert replies[0]["type"] == "error"
    assert replies[0]["code"] == "not_found"

    ends = _events(caplog, "call.end")
    assert len(ends) == 1
    assert ends[0]["outcome"] == "not_found"
    assert ends[0]["request_id"] == "r-nf"
    assert ends[0]["_levelno"] == logging.WARNING


def test_bad_arguments_outcome_is_bad_arguments(caplog):
    _, replies = _exchange(caplog, [_call(payload="not-a-dict", request_id="r-badarg")])
    assert replies[0]["type"] == "error"
    assert replies[0]["code"] == "bad_arguments"

    ends = _events(caplog, "call.end")
    assert len(ends) == 1
    assert ends[0]["outcome"] == "bad_arguments"
    assert ends[0]["request_id"] == "r-badarg"
    assert ends[0]["_levelno"] == logging.WARNING


def test_service_error_outcome_reflects_code(caplog):
    async def on_call(tool, arguments, caller):
        raise ServiceError("unavailable", "temporarily down")

    _, replies = _exchange(
        caplog,
        [_call(payload={"text": "hi"}, request_id="r-unavail")],
        on_call=on_call,
    )
    assert replies[0]["type"] == "error"
    assert replies[0]["code"] == "unavailable"

    ends = _events(caplog, "call.end")
    assert len(ends) == 1
    assert ends[0]["outcome"] == "unavailable"
    assert ends[0]["_levelno"] == logging.WARNING
    assert "temporarily down" not in ends[0]["_text"]


def test_unexpected_exception_outcome_is_internal_and_error_level(caplog):
    async def on_call(tool, arguments, caller):
        raise RuntimeError("db connection failed with hunter2")

    _, replies = _exchange(
        caplog,
        [_call(payload={"text": "hi"}, request_id="r-crash")],
        on_call=on_call,
    )
    assert replies[0]["type"] == "error"
    assert replies[0]["code"] == "internal"

    ends = _events(caplog, "call.end")
    assert len(ends) == 1
    assert ends[0]["outcome"] == "internal"
    assert ends[0]["_levelno"] == logging.ERROR
    # Exception text never leaked
    assert "hunter2" not in caplog.text


def test_unverified_token_emits_no_call_start_or_end(caplog):
    bad_token = ISSUER.token(aud="unrelated-service")
    _, replies = _exchange(
        caplog,
        [_call(payload={"text": "hi"}, token=bad_token, request_id="r-forged")],
    )
    assert replies[0]["type"] == "error"
    assert replies[0]["code"] == "not_allowed"

    starts = _events(caplog, "call.start")
    ends = _events(caplog, "call.end")
    assert len(starts) == 0
    assert len(ends) == 0


def test_e2e_encryption_mode_traced(caplog):
    service_key = KeyPair.generate()
    client_key = KeyPair.generate()
    client_pub_b64 = e2e.b64url_encode(client_key.public_raw)
    kid = e2e.key_id(client_key.public_raw)

    token = ISSUER.token()
    fields = e2e.header(
        user_id=PRINCIPAL,
        client_id=APP,
        service="svc",
        encryption="end-to-end",
        tool="echo",
    )
    ciphertext = e2e.seal(
        {"text": "e2e-arg"},
        sender=client_key,
        recipient_public_raw=service_key.public_raw,
        fields=fields,
    )
    frame = {
        "type": "call",
        "request_id": "r-e2e",
        "contract_version": 2,
        "caller_token": token,
        "service": "svc",
        "tool": "echo",
        "encryption": "end-to-end",
        "client_public_key": client_pub_b64,
        "client_kid": kid,
        "payload": ciphertext,
    }

    _, replies = _exchange(caplog, [frame], key=service_key)
    assert replies[0]["type"] == "result"

    (start,) = _events(caplog, "call.start")
    (end,) = _events(caplog, "call.end")
    assert start["encryption"] == "end-to-end"
    assert end["encryption"] == "end-to-end"
    assert end["outcome"] == "result"


# --- current_request_id() context variable ------------------------------------


def test_current_request_id_outside_handlers_is_none():
    assert current_request_id() is None


@pytest.mark.parametrize("sync", [False, True])
def test_current_request_id_inside_handlers(caplog, sync):
    seen_ids = []

    def handle(tool, arguments, caller):
        seen_ids.append(current_request_id())
        return "ok"

    if sync:
        def on_call(tool, arguments, caller):
            return handle(tool, arguments, caller)
    else:
        async def on_call(tool, arguments, caller):
            return handle(tool, arguments, caller)

    _exchange(caplog, [_call(payload={"text": "x"}, request_id="r-req-42")], on_call=on_call)
    assert seen_ids == ["r-req-42"]
    assert current_request_id() is None


def test_current_request_id_across_awaits(caplog):
    seen = []

    async def on_call(tool, arguments, caller):
        seen.append(("before", current_request_id()))
        await asyncio.sleep(0.01)
        seen.append(("after", current_request_id()))
        return "ok"

    _exchange(caplog, [_call(payload={"text": "x"}, request_id="r-await")], on_call=on_call)
    assert seen == [("before", "r-await"), ("after", "r-await")]
    assert current_request_id() is None


def test_current_request_id_concurrent_calls():
    """Verify concurrent requests in the same process do not leak or collide."""
    seen_alpha = []
    seen_beta = []

    async def on_call(tool, arguments, caller):
        rid = current_request_id()
        if tool == "echo":
            seen_alpha.append(("start", rid))
            await asyncio.sleep(0.03)
            seen_alpha.append(("finish", current_request_id()))
        else:
            seen_beta.append(("start", rid))
            await asyncio.sleep(0.01)
            seen_beta.append(("finish", current_request_id()))
        return "done"

    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            # Send two concurrent calls
            await send_json(ws, _call(tool="echo", payload={"text": "a"}, request_id="r-alpha"))
            await send_json(ws, _call(tool="other", payload={}, request_id="r-beta"))
            rep1 = await recv_json(ws)
            rep2 = await recv_json(ws)
            if not done.done():
                done.set_result((rep1, rep2))
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            svc = make_service(url, on_call=on_call, issuer=ISSUER)
            await serve_until(svc, done)

    run(main())
    assert seen_alpha == [("start", "r-alpha"), ("finish", "r-alpha")]
    assert seen_beta == [("start", "r-beta"), ("finish", "r-beta")]
    assert current_request_id() is None


def test_request_id_filter_correlates_service_backend_logs(caplog):
    backend_logger = logging.getLogger("service.subsystem")

    async def on_call(tool, arguments, caller):
        backend_logger.info("processing work inside backend")
        return "ok"

    caplog.handler.addFilter(RequestIdFilter())
    _exchange(caplog, [_call(payload={"text": "x"}, request_id="r-correlated")], on_call=on_call)

    records = [r for r in caplog.records if r.name == "service.subsystem"]
    assert len(records) == 1
    assert records[0].request_id == "r-correlated"


# --- JSON formatting via GATEWAY_LOG_FORMAT=json ------------------------------


def test_json_log_format_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_LOG_FORMAT", "json")
    stream = io.StringIO()

    async def on_call(tool, arguments, caller):
        logging.getLogger("service.backend").info("inner log")
        return "ok"

    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            await send_json(ws, _call(payload={"text": "x"}, request_id="r-json-1"))
            await recv_json(ws)
            if not done.done():
                done.set_result(None)
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            svc = make_service(url, on_call=on_call, issuer=ISSUER)
            await serve_until(svc, done)

    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_logging(stream=stream)
        run(main())
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])

    output_lines = [json.loads(line) for line in stream.getvalue().strip().splitlines() if line.strip()]
    events = {line.get("event"): line for line in output_lines if "event" in line}

    assert "call.start" in events
    assert events["call.start"]["request_id"] == "r-json-1"
    assert events["call.start"]["principal"] == PRINCIPAL

    assert "call.end" in events
    assert events["call.end"]["request_id"] == "r-json-1"
    assert events["call.end"]["outcome"] == "result"
    assert isinstance(events["call.end"]["duration_ms"], (int, float))

    backend_lines = [l for l in output_lines if l.get("logger") == "service.backend"]
    assert len(backend_lines) == 1
    assert backend_lines[0]["request_id"] == "r-json-1"
    assert backend_lines[0]["message"] == "inner log"


# --- Strict metadata-only rule: zero payload, secret, or token logging --------


def test_secrets_and_tokens_never_logged_at_any_level(caplog):
    service_key = KeyPair.generate()
    credential = "CRED-s3cr3t-value"
    token = ISSUER.token()
    token_sig = token.split(".")[2]

    async def on_call(tool, arguments, caller):
        return "SUPER-SECRET-RESULT-PAYLOAD-888"

    with caplog.at_level(logging.DEBUG):
        _exchange(
            caplog,
            [_call(payload={"secret_arg": "SECRET-ARG-VALUE-777"}, token=token, request_id="r-secret-test")],
            on_call=on_call,
            key=service_key,
        )

    all_logs = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith("websockets.server"))
    all_logs += "\n".join(json.dumps(e) for e in _events(caplog))

    # Assert credentials, private keys, raw tokens, signatures, arguments, and results never leak
    for secret in (
        credential,
        service_key.private_b64(),
        token,
        token_sig,
        "SECRET-ARG-VALUE-777",
        "SUPER-SECRET-RESULT-PAYLOAD-888",
    ):
        assert secret not in all_logs, f"Found secret {secret!r} in logs!"

    # But request ID, principal, and app are preserved
    assert "r-secret-test" in all_logs
    assert PRINCIPAL in all_logs
    assert APP in all_logs

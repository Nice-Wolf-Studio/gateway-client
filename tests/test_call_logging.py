"""Every handled call is traceable: one `call.start` and one `call.end`
record per call or read, with the shared field contract (request_id,
tool|uri, user_id, client_id, service_name, encryption, event, outcome,
error_code, error_message, duration_ms, result_bytes, args, result), and
the request id visible to handler code. Plus the lifecycle fields."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from helpers import fake_gateway, make_service, recv_json, run, send_json, serve_until
from test_service import _call, _e2e_call, _legacy_gateway, _one_exchange, _read

from gateway_client import KeyPair, ServiceError, current_request_id
from gateway_client.logs import JsonFormatter, RequestIdFilter

CONTRACT = ("event", "request_id", "user_id", "client_id", "service_name", "encryption")
END = ("outcome", "error_code", "error_message", "duration_ms", "result_bytes")


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
        if event is None or line["event"] == event:
            out.append(line)
    return out


def _exchange(caplog, frames, **service_kwargs):
    with caplog.at_level(logging.DEBUG):
        return run(_one_exchange(frames, service_kwargs=service_kwargs))


# --- outcomes ---------------------------------------------------------------------------


def test_ok_call_logs_one_start_and_one_end_with_full_contract(caplog):
    _, replies = _exchange(caplog, [_call(payload={"text": "hello"})])
    assert replies[0]["type"] == "result"
    (start,) = _events(caplog, "call.start")
    (end,) = _events(caplog, "call.end")
    for line in (start, end):
        for field in CONTRACT:
            assert field in line, field
        assert line["request_id"] == "r-1" and line["tool"] == "echo"
        assert line["user_id"] == "user-1" and line["client_id"] == "client-1"
        assert line["service_name"] == "svc" and line["encryption"] == "none"
    assert start["args"] == {"text": "hello"}
    for field in END:
        assert field in end, field
    assert end["outcome"] == "ok" and end["error_code"] is None
    assert end["error_message"] is None
    assert isinstance(end["duration_ms"], (int, float)) and end["duration_ms"] >= 0
    payload = replies[0]["payload"]
    assert end["result"] == payload == [{"type": "text", "text": "echo:hello"}]
    assert end["result_bytes"] == len(json.dumps(payload).encode())
    assert start["_levelno"] == logging.INFO and end["_levelno"] == logging.INFO


def test_text_end_line_carries_outcome_and_duration(caplog):
    _exchange(caplog, [_call(payload={"text": "hello"})])
    (end,) = _events(caplog, "call.end")
    text = end["_text"]
    assert text.startswith("call.end ")
    assert "request_id=r-1" in text and "tool=echo" in text
    assert "outcome=ok" in text and "duration_ms=" in text
    (start,) = _events(caplog, "call.start")
    assert start["_text"].startswith("call.start ") and "request_id=r-1" in start["_text"]


def test_tool_error_result_is_outcome_tool_error(caplog):
    async def on_call(tool, arguments, caller):
        return {"isError": True, "content": [{"type": "text", "text": "chat not found"}]}

    _, replies = _exchange(caplog, [_call(payload={"text": "x"})], on_call=on_call)
    assert replies[0]["type"] == "result"   # the wire reply is unchanged
    (end,) = _events(caplog, "call.end")
    assert end["outcome"] == "tool_error"
    assert end["_levelno"] == logging.WARNING
    assert "chat not found" in json.dumps(end["result"])


def test_protocol_error_is_outcome_error_with_code_and_message(caplog):
    async def on_call(tool, arguments, caller):
        raise ServiceError("unavailable", "Messages is not running")

    _, replies = _exchange(caplog, [_call(payload={"text": "x"})], on_call=on_call)
    assert replies[0]["code"] == "unavailable"
    (end,) = _events(caplog, "call.end")
    assert end["outcome"] == "error"
    assert end["error_code"] == "unavailable"
    assert end["error_message"] == "Messages is not running"
    assert end["_levelno"] == logging.WARNING


def test_not_found_is_outcome_error(caplog):
    _exchange(caplog, [_call(tool="nope", payload={})])
    (end,) = _events(caplog, "call.end")
    assert end["outcome"] == "error" and end["error_code"] == "not_found"


def test_exception_logs_full_message_and_traceback_verbatim(caplog):
    async def on_call(tool, arguments, caller):
        raise RuntimeError("db password is hunter2")

    _, replies = _exchange(caplog, [_call(payload={"text": "x"})], on_call=on_call)
    # The wire reply never carries the exception text ...
    assert replies[0]["code"] == "internal" and replies[0]["payload"] == "internal error"
    (end,) = _events(caplog, "call.end")
    assert end["outcome"] == "exception"
    assert end["error_code"] == "internal"
    assert end["exception"] == "RuntimeError"
    # ... the log does, verbatim.
    assert end["error_message"] == "db password is hunter2"
    tb = end["traceback"]
    assert tb.startswith("Traceback (most recent call last):")
    assert "test_call_logging.py" in tb and "in on_call" in tb
    assert tb.rstrip().endswith("RuntimeError: db password is hunter2")
    assert end["_levelno"] == logging.ERROR
    assert "hunter2" in end["_text"]


def test_exception_traceback_is_full_not_capped(caplog):
    # Eight distinct frames under the handler (more than any cap would keep).
    def f8(): raise ValueError("deep failure in f8")
    def f7(): f8()
    def f6(): f7()
    def f5(): f6()
    def f4(): f5()
    def f3(): f4()
    def f2(): f3()
    def f1(): f2()

    async def on_call(tool, arguments, caller):
        f1()

    _exchange(caplog, [_call(payload={"text": "x"})], on_call=on_call)
    (end,) = _events(caplog, "call.end")
    for name in ("on_call", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"):
        assert f"in {name}\n" in end["traceback"], name
    assert end["error_message"] == "deep failure in f8"


# --- arguments and results ---------------------------------------------------------------


def test_secret_looking_arguments_logged_verbatim(caplog):
    args = {"text": "hi", "api_token": "TOK-1", "nested": {"Password": "PW-2"},
            "header": "Authorization: Bearer abc.def.ghi"}
    _exchange(caplog, [_call(payload=args)])
    (start,) = _events(caplog, "call.start")
    assert start["args"] == args
    assert "TOK-1" in start["_text"] and "PW-2" in start["_text"]


def test_long_argument_logged_in_full(caplog):
    _exchange(caplog, [_call(payload={"text": "q" * 50000})])
    (start,) = _events(caplog, "call.start")
    assert start["args"] == {"text": "q" * 50000}
    assert not any(k.endswith("_truncated") for k in start)


def test_large_result_logged_in_full(caplog):
    blocks = [{"type": "text", "text": "r" * 1500} for _ in range(40)]   # ~60 KB

    async def on_call(tool, arguments, caller):
        return blocks

    _exchange(caplog, [_call(payload={"text": "x"})], on_call=on_call)
    (end,) = _events(caplog, "call.end")
    assert end["result"] == blocks
    assert end["result_bytes"] == len(json.dumps(blocks).encode())
    assert not any(k.endswith("_truncated") for k in end)


def test_read_resource_logs_uri_and_no_args(caplog):
    async def on_read(uri, caller):
        return "all good"

    _exchange(caplog, [_read()], on_read=on_read)
    (start,) = _events(caplog, "call.start")
    (end,) = _events(caplog, "call.end")
    assert start["uri"] == "svc://status" and "tool" not in start
    assert "args" not in start
    assert end["outcome"] == "ok" and "all good" in json.dumps(end["result"])


def test_e2e_end_logs_decrypted_args_and_plain_result(caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    args = {"text": "plain words", "token": "E2E-TOKEN"}
    frame, _ = _e2e_call(client, service_key.public_raw, args)
    _, replies = _exchange(caplog, [frame], key=service_key)
    assert replies[0]["type"] == "result"
    (start,) = _events(caplog, "call.start")
    (end,) = _events(caplog, "call.end")
    # Plaintext is not held yet at start; the envelope is not logged since
    # the library later decrypts it.
    assert start["encryption"] == "end-to-end" and "args" not in start
    assert end["args"] == args
    assert end["outcome"] == "ok"
    assert end["result"] == [{"type": "text", "text": "echo:plain words"}]
    assert frame["payload"]["ct"] not in json.dumps(_events(caplog))


def test_e2e_never_decrypted_logs_envelope_as_is(caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    other = KeyPair.generate()
    frame, _ = _e2e_call(client, other.public_raw, {"text": "x"})   # sealed to someone else
    _exchange(caplog, [frame], key=service_key)
    (end,) = _events(caplog, "call.end")
    assert end["outcome"] == "error" and end["args"] == frame["payload"]


def test_unidentified_refusal_is_start_then_end_at_warning(caplog):
    frame = _call(payload={"text": "x"}, request_id="r-anon")
    del frame["caller"]
    _exchange(caplog, [frame])
    lines = [e for e in _events(caplog) if e.get("request_id") == "r-anon"]
    assert [e["event"] for e in lines] == ["call.start", "call.end"]
    assert lines[1]["error_code"] == "not_allowed" and lines[1]["_levelno"] == logging.WARNING


def test_legacy_call_logs_start_and_end(caplog):
    frames = []

    async def main():
        done = asyncio.get_running_loop().create_future()
        async with fake_gateway(_legacy_gateway(frames, done)) as url:
            service = make_service(url, legacy_token="LEGACY-TOKEN")
            await serve_until(service, done)

    with caplog.at_level(logging.DEBUG):
        run(main())
    ends = {e["request_id"]: e for e in _events(caplog, "call.end")}
    starts = {e["request_id"]: e for e in _events(caplog, "call.start")}
    assert starts["L-1"]["args"] == {"text": "old"} and starts["L-1"]["user_id"] is None
    assert ends["L-1"]["outcome"] == "ok" and ends["L-2"]["outcome"] == "error"
    assert ends["L-2"]["error_code"] == "not_found"


# --- request id for handler code ----------------------------------------------------------


@pytest.mark.parametrize("sync", [False, True])
def test_handler_sees_request_id_and_its_logs_are_stamped(caplog, sync):
    seen = []
    backend_log = logging.getLogger("my_backend")

    def body(caller):
        seen.append(current_request_id())
        backend_log.info("sending to chat")
        return "done"

    if sync:
        def on_call(tool, arguments, caller):
            return body(caller)
    else:
        async def on_call(tool, arguments, caller):
            return body(caller)

    caplog.handler.addFilter(RequestIdFilter())
    _exchange(caplog, [_call(payload={"text": "x"}, request_id="r-corr")], on_call=on_call)
    assert seen == ["r-corr"]
    (rec,) = [r for r in caplog.records if r.name == "my_backend"]
    assert rec.request_id == "r-corr"
    assert current_request_id() is None   # not leaked out of the call


def test_library_call_records_carry_request_id_via_filter(caplog):
    caplog.handler.addFilter(RequestIdFilter())
    _exchange(caplog, [_call(payload={"text": "x"}, request_id="r-lib")])
    ours = [r for r in caplog.records if getattr(r, "gw_fields", {}).get("event", "")
            .startswith("call.")]
    assert ours and all(r.request_id == "r-lib" for r in ours)


# --- lifecycle --------------------------------------------------------------------------


def test_lifecycle_connect_attempts_and_rejection_reason(caplog):
    attempts = []

    async def main():
        loop = asyncio.get_running_loop()
        enough = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "rejected", "reason": "key_changed"})
            await ws.close(1008)

        async def sleep(delay):
            attempts.append(delay)
            if len(attempts) >= 3 and not enough.done():
                enough.set_result(None)
            await asyncio.sleep(0)

        async with fake_gateway(handler) as url:
            await serve_until(make_service(url, sleep=sleep), enough)

    with caplog.at_level(logging.INFO, logger="gateway_client"):
        run(main())
    connects = _events(caplog, "connect")
    assert [c["attempt"] for c in connects][:3] == [1, 2, 3]
    (rejected,) = _events(caplog, "rejected")
    assert rejected["reason"] == "key_changed" and rejected["attempt"] == 1
    assert rejected["service_name"] == "svc"


def test_lifecycle_registered_resets_attempts(caplog):
    _exchange(caplog, [])
    (reg,) = _events(caplog, "register")
    assert reg["attempt"] == 1 and reg["service_name"] == "svc"
    assert reg["protocol"] == "v1"


def test_private_keys_never_logged_even_at_debug(caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    _exchange(caplog, [frame, _call(payload={"text": "y"}, request_id="r-plain")],
              key=service_key)
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if not r.name.startswith("websockets.server"))
    ours += "\n".join(json.dumps(e) for e in _events(caplog))
    # Not a redaction: these are simply never part of what is logged.
    for secret in (service_key.private_b64(), client.private_b64(), "CRED-s3cr3t-value"):
        assert secret not in ours

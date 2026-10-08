"""The connection: register, ping, calls, errors, end-to-end, fallback,
backoff and announcements, against an in-process fake gateway."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

import pytest
from helpers import (
    RESOURCES,
    ROLES,
    TOOLS,
    fake_gateway,
    make_service,
    recv_json,
    run,
    send_json,
    serve_until,
)

from gateway_client import Caller, KeyPair, ServiceError, e2e
from gateway_client.protocol import Backoff


def _call(tool="echo", payload=None, *, request_id="r-1", encryption="none", **extra):
    frame = {"type": "call", "request_id": request_id, "contract_version": 1,
             "caller": {"user_id": "user-1", "client_id": "client-1"}, "service": "svc",
             "tool": tool, "encryption": encryption, "payload": payload}
    frame.update(extra)
    return frame


def _read(uri="svc://status", *, request_id="r-2"):
    return {"type": "read_resource", "request_id": request_id, "contract_version": 1,
            "caller": {"user_id": "user-1", "client_id": "client-1"}, "service": "svc",
            "uri": uri, "encryption": "none"}


async def _one_exchange(frames, *, service_kwargs=None, after_register=None):
    """Register, send each frame in `frames`, return (register frame,
    replies)."""
    loop = asyncio.get_running_loop()
    done = loop.create_future()

    async def handler(ws):
        register = await recv_json(ws)
        await send_json(ws, {"type": "registered"})
        if after_register:
            await after_register(ws)
        replies = []
        for frame in frames:
            await send_json(ws, frame)
            replies.append(await recv_json(ws))
        if not done.done():
            done.set_result((register, replies))
        await ws.wait_closed()

    async with fake_gateway(handler) as url:
        service = make_service(url, **(service_kwargs or {}))
        return await serve_until(service, done)


# --- register -------------------------------------------------------------------

def test_v1_register_frame_contents():
    register, _ = run(_one_exchange([]))
    assert register == {
        "type": "register", "contract_version": 1, "service": "svc",
        "credential": "CRED-s3cr3t-value", "public_key": register["public_key"],
        "accepts_caller": True, "tools": TOOLS, "resources": RESOURCES, "roles": ROLES,
        "roles_version": 1,
    }
    assert len(e2e.decode_public_key(register["public_key"])) == 32


def test_declaration_validated_locally():
    from gateway_client.protocol import Declaration
    with pytest.raises(ValueError, match="undeclared"):
        Declaration.build(TOOLS, RESOURCES, [dict(ROLES[0], tools=["nope"])], 1)
    with pytest.raises(ValueError, match="requires_end_to_end"):
        Declaration.build(TOOLS, RESOURCES, [{k: v for k, v in ROLES[0].items()
                                              if k != "requires_end_to_end"}], 1)
    with pytest.raises(ValueError, match="inputSchema"):
        Declaration.build([{"name": "x", "description": ""}])
    with pytest.raises(ValueError, match="roles_version"):
        Declaration.build(TOOLS, RESOURCES, ROLES, 0)


# --- rejected + backoff ----------------------------------------------------------

def test_rejected_backs_off_exponentially_to_five_minutes_and_logs_once(caplog):
    delays = []

    async def main():
        loop = asyncio.get_running_loop()
        enough = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "rejected", "reason": "bad_credential"})
            await ws.close(1008)

        async def sleep(delay):
            delays.append(delay)
            if len(delays) >= 11 and not enough.done():
                enough.set_result(None)
            await asyncio.sleep(0)

        async with fake_gateway(handler) as url:
            service = make_service(url, sleep=sleep, rand=lambda: 1.0)
            await serve_until(service, enough)

    with caplog.at_level(logging.INFO, logger="gateway_client"):
        run(main())
    assert delays[:11] == [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]
    rejected_logs = [r for r in caplog.records if "registration rejected" in r.getMessage()]
    assert len(rejected_logs) == 1 and "bad_credential" in rejected_logs[0].getMessage()


def test_backoff_caps_and_reset():
    b = Backoff(rand=lambda: 1.0)
    assert [b.next_delay(rejected=False) for _ in range(7)] == [1, 2, 4, 8, 16, 30, 30]
    b.reset()
    assert b.next_delay(rejected=True) == 1
    jitter = Backoff(rand=lambda: 0.0)
    assert jitter.next_delay(rejected=False) == 0.5  # up to half removed at random


def test_backoff_resets_after_registration():
    delays = []

    async def main():
        loop = asyncio.get_running_loop()
        enough = loop.create_future()
        count = 0

        async def handler(ws):
            nonlocal count
            count += 1
            await recv_json(ws)
            if count in (1, 2, 3):
                await send_json(ws, {"type": "rejected", "reason": "key_changed"})
            else:
                await send_json(ws, {"type": "registered"})
            await ws.close(1008 if count <= 3 else 1000)

        async def sleep(delay):
            delays.append(delay)
            if len(delays) >= 5 and not enough.done():
                enough.set_result(None)
            await asyncio.sleep(0)

        async with fake_gateway(handler) as url:
            await serve_until(make_service(url, sleep=sleep), enough)

    run(main())
    assert delays[:5] == [1, 2, 4, 1, 1]


# --- ping / calls / errors ---------------------------------------------------------

def test_ping_answered_with_pong():
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            await send_json(ws, {"type": "ping"})
            done.set_result(await recv_json(ws))
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            return await serve_until(make_service(url), done)

    assert run(main()) == {"type": "pong"}


def test_call_dispatch_with_caller():
    seen = {}

    async def on_call(tool, arguments, caller):
        seen.update(tool=tool, arguments=arguments, caller=caller)
        return [{"type": "text", "text": "ok"}]

    _, replies = run(_one_exchange([_call(payload={"text": "hi"})],
                                   service_kwargs={"on_call": on_call}))
    assert replies == [{"type": "result", "request_id": "r-1", "encryption": "none",
                        "payload": [{"type": "text", "text": "ok"}]}]
    assert seen == {"tool": "echo", "arguments": {"text": "hi"},
                    "caller": Caller(user_id="user-1", client_id="client-1",
                                     encryption="none", request_id="r-1")}


def test_sync_handler_runs_and_string_result_becomes_text_block():
    def on_call(tool, arguments, caller):  # sync: run in a worker thread
        time.sleep(0.01)
        return {"n": 1}

    _, replies = run(_one_exchange([_call(payload={"text": "x"})],
                                   service_kwargs={"on_call": on_call}))
    assert replies[0]["payload"] == [{"type": "text", "text": '{"n": 1}'}]


def test_read_resource_dispatch():
    async def on_read(uri, caller):
        assert caller.client_id == "client-1"
        return "all good"

    _, replies = run(_one_exchange([_read()], service_kwargs={"on_read": on_read}))
    assert replies[0] == {"type": "result", "request_id": "r-2", "encryption": "none",
                          "payload": [{"uri": "svc://status", "mimeType": "text/plain",
                                       "text": "all good"}]}


@pytest.mark.parametrize("code", ["not_allowed", "not_found", "bad_arguments",
                                  "unavailable", "timed_out", "rate_limited", "internal"])
def test_service_error_code_is_sent(code):
    async def on_call(tool, arguments, caller):
        raise ServiceError(code, f"because {code}")

    _, replies = run(_one_exchange([_call(payload={"text": "x"})],
                                   service_kwargs={"on_call": on_call}))
    assert replies == [{"type": "error", "request_id": "r-1", "encryption": "none",
                        "code": code, "payload": f"because {code}"}]


def test_unknown_code_refused_at_construction():
    with pytest.raises(ValueError):
        ServiceError("teapot", "no")


def test_unexpected_exception_is_internal_and_text_not_leaked(caplog):
    async def on_call(tool, arguments, caller):
        raise RuntimeError("db password is hunter2")

    with caplog.at_level(logging.DEBUG):
        _, replies = run(_one_exchange([_call(payload={"text": "x"})],
                                       service_kwargs={"on_call": on_call}))
    assert replies[0]["code"] == "internal" and replies[0]["payload"] == "internal error"
    assert "hunter2" not in caplog.text


def test_unknown_tool_is_not_found():
    _, replies = run(_one_exchange([_call(tool="nope", payload={})]))
    assert replies[0]["type"] == "error" and replies[0]["code"] == "not_found"


def test_none_call_to_requires_end_to_end_role_refused():
    called = []

    async def on_call(tool, arguments, caller):
        called.append(tool)
        return "should not run"

    _, replies = run(_one_exchange([_call(tool="secret_op", payload={})],
                                   service_kwargs={"on_call": on_call}))
    assert replies[0]["code"] == "not_allowed" and called == []


def test_logs_carry_arguments_and_results_but_never_credentials(caplog):
    # 0.2.0: arguments and results are logged (redacted, truncated) on
    # call.start / call.end; the credential and key never are.
    async def on_call(tool, arguments, caller):
        return "RESULT-VALUE-777"

    with caplog.at_level(logging.DEBUG):
        register, replies = run(_one_exchange(
            [_call(payload={"text": "ARG-VALUE-555"})], service_kwargs={"on_call": on_call}))
    assert replies[0]["payload"][0]["text"] == "RESULT-VALUE-777"
    # Everything the service side logged (the fake gateway's own server log
    # is the test's, not the library's), at DEBUG, including the transport.
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if not r.name.startswith("websockets.server"))
    assert "ARG-VALUE-555" in ours and "RESULT-VALUE-777" in ours
    assert "CRED-s3cr3t-value" not in ours
    assert "r-1" in ours  # the request id is logged


# --- caller ids (issue #2) ---------------------------------------------------------------
#
# Spec 6.2: `caller.user_id` and `caller.client_id` are always present, as
# strings. A v1 frame unless both are non-empty, non-blank strings never
# reaches the handler: it is answered `not_allowed`.

# One value per class of bad id; "missing" deletes the key instead.
BAD_IDS = {"missing": None, "null": None, "empty": "", "blank": " \t ",
           "zero": 0, "number": 123, "false": False, "true": True,
           "empty object": {}, "object": {"id": "client-1"},
           "empty list": [], "list": ["client-1"]}


def _strip_caller(frame, variant):
    """`frame` with its caller ids missing or bad, per `variant`:
    "no caller", "caller null", "caller not an object", or
    "<user_id|client_id> <BAD_IDS key>"."""
    frame = {**frame, "caller": dict(frame["caller"])}
    if variant == "no caller":
        del frame["caller"]
    elif variant == "caller null":
        frame["caller"] = None
    elif variant == "caller not an object":
        frame["caller"] = "user-1"
    else:
        field, how = variant.split(" ", 1)
        if how == "missing":
            del frame["caller"][field]
        else:
            frame["caller"][field] = BAD_IDS[how]
    return frame


NO_CALLER_IDS = ["no caller", "caller null", "caller not an object"] + [
    f"{field} {how}" for field in ("user_id", "client_id") for how in BAD_IDS]


REFUSAL = "caller user_id and client_id must be non-empty strings"


def _assert_refused_not_allowed(reply, request_id, encryption="none"):
    assert reply["type"] == "error"
    assert reply["request_id"] == request_id
    assert reply["encryption"] == encryption
    assert reply["code"] == "not_allowed"


@pytest.mark.parametrize("variant", NO_CALLER_IDS)
def test_v1_call_without_caller_ids_refused_before_on_call(variant):
    called = []

    async def on_call(tool, arguments, caller):
        called.append(caller)
        return "should not run"

    frame = _strip_caller(_call(payload={"text": "x"}), variant)
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call}))
    _assert_refused_not_allowed(replies[0], "r-1")
    assert replies[0]["payload"] == REFUSAL
    assert called == []


@pytest.mark.parametrize("variant", NO_CALLER_IDS)
def test_v1_read_without_caller_ids_refused_before_on_read(variant):
    called = []

    async def on_read(uri, caller):
        called.append(caller)
        return "should not run"

    frame = _strip_caller(_read(), variant)
    _, replies = run(_one_exchange([frame], service_kwargs={"on_read": on_read}))
    _assert_refused_not_allowed(replies[0], "r-2")
    assert replies[0]["payload"] == REFUSAL
    assert called == []


def _e2e_read(client, *, request_id="r-e2e-read"):
    return {**_read(request_id=request_id), "encryption": "end-to-end",
            "client_public_key": client.public_b64, "client_kid": client.kid}


@pytest.mark.parametrize("kind", ["call", "read_resource"])
@pytest.mark.parametrize("variant", ["no caller", "user_id empty", "client_id list"])
def test_v1_end_to_end_refusal_is_an_envelope_the_gateway_relays(variant, kind):
    # The gateway relays an end-to-end error only when its payload is an
    # envelope under the service's key; anything else becomes `internal`
    # (mcp-gateway gateway/envelope.py `service_error`). Like every other
    # end-to-end error it is sealed to the ids as received, so a client
    # whose ids were dropped cannot open the text, but it gets the code.
    client, service_key = KeyPair.generate(), KeyPair.generate()
    called = []

    async def on_call(tool, arguments, caller):
        called.append(caller)

    async def on_read(uri, caller):
        called.append(caller)

    if kind == "call":
        frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    else:
        frame = _e2e_read(client)
    frame = _strip_caller(frame, variant)
    _, replies = run(_one_exchange([frame], service_kwargs={
        "on_call": on_call, "on_read": on_read, "key": service_key}))
    _assert_refused_not_allowed(replies[0], frame["request_id"], encryption="end-to-end")
    e2e.check_shape(replies[0]["payload"])
    assert replies[0]["payload"]["kid"] == service_key.kid  # what the gateway checks
    sent = frame.get("caller") if isinstance(frame.get("caller"), dict) else {}
    target = {"tool": "echo"} if kind == "call" else {"uri": "svc://status"}
    fields = e2e.header(user_id=sent.get("user_id"), client_id=sent.get("client_id"),
                        service="svc", **target)
    assert _open_reply(replies[0], client, service_key, fields) == REFUSAL
    assert called == []


def test_v1_end_to_end_refusal_still_pins_its_client_id():
    # An end-to-end frame with a client_id but no user_id is refused, yet it
    # still pins that client: a plaintext call from it afterwards is refused.
    client, service_key = KeyPair.generate(), KeyPair.generate()
    called = []

    async def on_call(tool, arguments, caller):
        called.append(caller)
        return "should not run"

    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    frames = [_strip_caller(frame, "user_id empty"), _call(payload={"text": "x"})]
    _, replies = run(_one_exchange(frames, service_kwargs={"on_call": on_call,
                                                           "key": service_key}))
    assert [r["code"] for r in replies] == ["not_allowed", "not_allowed"]
    assert called == []


@pytest.mark.parametrize("encryption", ["none", "end-to-end"])
@pytest.mark.parametrize("variant", ["client_id list", "client_id object"])
def test_v1_unhashable_client_id_never_reaches_the_downgrade_pin(variant, encryption,
                                                                caplog):
    # Before the fix a list or dict client_id reached the pin set (`add` or
    # `in`), raised TypeError and was answered `internal` as a handler failure.
    client, service_key = KeyPair.generate(), KeyPair.generate()
    if encryption == "none":
        frame = _call(payload={"text": "x"})
    else:
        frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    with caplog.at_level(logging.DEBUG):
        _, replies = run(_one_exchange([_strip_caller(frame, variant)],
                                       service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "not_allowed"
    assert "TypeError" not in caplog.text


def test_unknown_encryption_without_caller_ids_is_still_bad_arguments(caplog):
    # The caller check runs after the encryption-mode check, as the target
    # check did before it.
    frame = _strip_caller(_call(payload={"text": "x"}, encryption="rot13"), "no caller")
    with caplog.at_level(logging.INFO, logger="gateway_client"):
        _, replies = run(_one_exchange([frame]))
    assert replies[0]["code"] == "bad_arguments"
    assert "call.start request_id=r-1 tool=echo" in caplog.text  # the request line


@pytest.mark.parametrize("encryption", ["none", "end-to-end"])
def test_refusal_without_caller_ids_logged_once_at_warning_without_payload(encryption,
                                                                          caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    if encryption == "none":
        frame = _call(payload={"text": "ARG-SECRET-555"}, request_id="r-no-caller")
    else:
        frame, _ = _e2e_call(client, service_key.public_raw, {"text": "ARG-SECRET-555"},
                             request_id="r-no-caller")
    frame = _strip_caller(frame, "no caller")
    with caplog.at_level(logging.DEBUG):
        _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "not_allowed"
    ours = [r for r in caplog.records if r.name.startswith("gateway_client")]
    about_it = [r for r in ours if "r-no-caller" in r.getMessage()]
    # call.start, then the refusal as call.end, once, at WARNING.
    assert [r.levelno for r in about_it] == [logging.INFO, logging.WARNING]
    assert about_it[1].getMessage().startswith("call.end ")
    assert "error_code=not_allowed" in about_it[1].getMessage()
    if encryption == "end-to-end":   # never decrypted, so never logged
        assert not any("ARG-SECRET-555" in r.getMessage() for r in ours)


def test_refusal_with_unusable_client_key_is_not_blamed_on_the_handler(caplog):
    # A key that decodes but cannot be sealed to (all zero) fails while the
    # refusal is sealed; that is not a handler failure.
    zero = bytes(32)
    frame = _strip_caller(_call(payload={"text": "x"}, encryption="end-to-end",
                                client_public_key=e2e.b64url_encode(zero),
                                client_kid=e2e.key_id(zero)), "no caller")
    service = make_service("ws://127.0.0.1:9/backend")
    reply = None
    with caplog.at_level(logging.DEBUG):
        try:
            reply = run(service._reply_v1(frame))
        except ValueError:
            pass  # sealing to this key fails, as for any error reply on main
    if reply is not None:
        assert reply["code"] == "not_allowed"
    ours = [r for r in caplog.records if r.name.startswith("gateway_client")]
    assert not any("handler raised" in r.getMessage() for r in ours)
    assert [r.levelno for r in ours if r.levelno >= logging.WARNING] == [logging.WARNING]


def test_caller_contract_says_fail_closed_on_legacy_none_user_id():
    # Legacy calls reach the handler with `user_id=None` by design (see
    # test_legacy_fallback_when_closed_1008_without_reply); the documented
    # contract tells consumers to fail closed on it. (`python -OO` strips
    # docstrings, so only the README is checked there.)
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    texts = [readme] if sys.flags.optimize >= 2 else [readme, Caller.__doc__]
    for text in texts:
        assert "fail closed" in " ".join(text.split())


# --- end-to-end ------------------------------------------------------------------------

def _e2e_call(client, service_pub, args, *, request_id="r-e2e", now=None, tool="echo",
              kid=None, envelope=None):
    fields = e2e.header(user_id="user-1", client_id="client-1", service="svc", tool=tool)
    env = envelope or e2e.seal(args, sender=client, recipient_public_raw=service_pub,
                               fields=fields, now=now)
    frame = _call(tool=tool, payload=env, request_id=request_id, encryption="end-to-end",
                  client_public_key=client.public_b64, client_kid=kid or client.kid)
    return frame, fields


def _open_reply(reply, client, service_key, fields):
    assert reply["encryption"] == "end-to-end"
    assert reply["payload"]["kid"] == service_key.kid  # what the gateway checks
    return e2e.open_envelope(reply["payload"], recipient=client,
                             sender_public_raw=service_key.public_raw,
                             fields=e2e.reply_header(fields, reply["request_id"]))


def test_e2e_round_trip_handler_sees_plain_arguments():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    seen = {}

    async def on_call(tool, arguments, caller):
        seen.update(arguments=arguments, encryption=caller.encryption)
        return [{"type": "text", "text": "sealed answer"}]

    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "plain secret"})
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call,
                                                            "key": service_key}))
    assert seen == {"arguments": {"text": "plain secret"}, "encryption": "end-to-end"}
    reply = replies[0]
    assert reply["type"] == "result" and "sealed answer" not in str(reply)
    assert _open_reply(reply, client, service_key, fields) == [
        {"type": "text", "text": "sealed answer"}]


def test_e2e_error_is_sealed_with_readable_code():
    client, service_key = KeyPair.generate(), KeyPair.generate()

    async def on_call(tool, arguments, caller):
        raise ServiceError("rate_limited", "slow down")

    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "x"})
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call,
                                                            "key": service_key}))
    assert replies[0]["type"] == "error" and replies[0]["code"] == "rate_limited"
    assert _open_reply(replies[0], client, service_key, fields) == "slow down"


def test_e2e_wrong_kid_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    other = KeyPair.generate()
    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "x"}, kid=other.kid)
    _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "bad_arguments"


def test_e2e_envelope_kid_other_than_client_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    other = KeyPair.generate()
    fields = e2e.header(user_id="user-1", client_id="client-1", service="svc", tool="echo")
    env = e2e.seal({"text": "x"}, sender=other, recipient_public_raw=service_key.public_raw,
                   fields=fields)
    frame, fields = _e2e_call(client, service_key.public_raw, None, envelope=env)
    _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "bad_arguments"
    assert "kid" in _open_reply(replies[0], client, service_key, fields)


def test_e2e_reused_nonce_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "x"})
    replay = dict(frame, request_id="r-replay")
    _, replies = run(_one_exchange([frame, replay], service_kwargs={"key": service_key}))
    assert replies[0]["type"] == "result"
    assert replies[1]["type"] == "error" and replies[1]["code"] == "not_allowed"


def test_e2e_stale_sent_at_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"},
                         now=time.time() - 301)
    _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "not_allowed"


def test_e2e_arguments_checked_against_schema():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, fields = _e2e_call(client, service_key.public_raw, {"text": 5})
    _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "bad_arguments"


def test_none_call_after_e2e_from_same_client_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    plain = _call(payload={"text": "x"}, request_id="r-plain")
    _, replies = run(_one_exchange([frame, plain], service_kwargs={"key": service_key}))
    assert replies[0]["type"] == "result"
    assert replies[1]["code"] == "not_allowed"


# --- legacy fallback -----------------------------------------------------------------------

def _legacy_gateway(log_frames, done, calls_to_serve=1):
    """Behaves like the pre-contract gateway: closes 1008 on a register
    without the right backend_token; else `registered` and serves calls."""
    async def handler(ws):
        frame = await recv_json(ws)
        log_frames.append(frame)
        if frame.get("backend_token") != "LEGACY-TOKEN":
            await ws.close(1008)
            return
        await send_json(ws, {"type": "registered", "backend_id": frame["backend_id"]})
        if len([f for f in log_frames if "backend_token" in f]) == 1:
            await send_json(ws, {"type": "call", "request_id": "L-1", "tool": "echo",
                                 "arguments": {"text": "old"},
                                 "principal": {"client_id": "legacy-client"}})
            reply = await recv_json(ws)
            await send_json(ws, {"type": "read_resource", "request_id": "L-2",
                                 "uri": "svc://nope"})
            reply2 = await recv_json(ws)
            await ws.close(1000)  # force a reconnect: v1 must be tried again
            log_frames.append(("replies", reply, reply2))
            return
        if not done.done():
            done.set_result(None)
        await ws.wait_closed()
    return handler


def test_legacy_fallback_when_closed_1008_without_reply():
    frames = []
    seen = []

    async def on_call(tool, arguments, caller):
        seen.append(caller)
        return f"legacy:{arguments['text']}"

    async def main():
        done = asyncio.get_running_loop().create_future()
        async with fake_gateway(_legacy_gateway(frames, done)) as url:
            service = make_service(url, legacy_token="LEGACY-TOKEN", on_call=on_call)
            await serve_until(service, done)

    run(main())
    kinds = ["v1" if isinstance(f, dict) and "contract_version" in f else
             "legacy" if isinstance(f, dict) else "replies" for f in frames]
    assert kinds[:5] == ["v1", "legacy", "replies", "v1", "legacy"]
    legacy_register = frames[1]
    assert legacy_register == {"type": "register", "backend_token": "LEGACY-TOKEN",
                               "backend_id": "svc", "tools": TOOLS, "resources": RESOURCES}
    _, reply, reply2 = frames[2]
    assert reply == {"type": "result", "request_id": "L-1",
                     "content": [{"type": "text", "text": "legacy:old"}]}
    assert reply2["type"] == "error" and reply2["request_id"] == "L-2"
    assert seen == [Caller(user_id=None, client_id="legacy-client", encryption="none",
                           request_id="L-1")]


def test_no_fallback_without_legacy_token():
    frames = []

    async def main():
        loop = asyncio.get_running_loop()
        enough = loop.create_future()

        async def handler(ws):
            frames.append(await recv_json(ws))
            if len(frames) >= 3 and not enough.done():
                enough.set_result(None)
            await ws.close(1008)

        async with fake_gateway(handler) as url:
            await serve_until(make_service(url, legacy_token=None), enough)

    run(main())
    assert len(frames) >= 3
    assert all(f.get("contract_version") == 1 and "backend_token" not in f for f in frames)


def test_rejected_never_falls_back_even_with_legacy_token():
    frames = []

    async def main():
        loop = asyncio.get_running_loop()
        enough = loop.create_future()

        async def handler(ws):
            frames.append(await recv_json(ws))
            await send_json(ws, {"type": "rejected", "reason": "bad_role"})
            if len(frames) >= 3 and not enough.done():
                enough.set_result(None)
            await ws.close(1008)

        async with fake_gateway(handler) as url:
            await serve_until(make_service(url, legacy_token="LEGACY-TOKEN"), enough)

    run(main())
    assert all("backend_token" not in f for f in frames)


# --- re-register and announcements ------------------------------------------------------

def test_update_reregisters_then_announces_tools_changed():
    new_tools = TOOLS + [{"name": "extra", "description": "New.",
                          "inputSchema": {"type": "object"}}]

    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        registered = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            registered.set_result(None)
            again = await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            announce = await recv_json(ws)
            direct = await recv_json(ws)
            done.set_result((again, announce, direct))
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            service = make_service(url)
            runner = asyncio.create_task(service.run())
            await registered
            await service.wait_registered(5)
            await service.update(tools=new_tools)
            assert await service.send_resources_changed() is True
            result = await asyncio.wait_for(done, 5)
            await service.stop()
            await runner
            return result

    again, announce, direct = run(main())
    assert again["type"] == "register" and again["contract_version"] == 1
    assert [t["name"] for t in again["tools"]] == ["echo", "secret_op", "extra"]
    assert again["roles_version"] == 1
    assert announce == {"type": "tools_changed"}
    assert direct == {"type": "resources_changed"}


def test_update_role_change_requires_higher_roles_version():
    service = make_service("ws://127.0.0.1:1/backend")
    changed = [dict(ROLES[0], tools=["echo", "secret_op"]), ROLES[1]]
    with pytest.raises(ValueError, match="roles_version"):
        run(service.update(roles=changed))
    run(service.update(roles=changed, roles_version=2))  # not connected: stored


def test_announce_when_not_registered_returns_false():
    service = make_service("ws://127.0.0.1:1/backend")
    assert run(service.send_tools_changed()) is False

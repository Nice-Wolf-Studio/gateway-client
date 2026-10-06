"""The connection: register, ping, calls, errors, end-to-end, fallback,
backoff and announcements, against an in-process fake gateway."""

from __future__ import annotations

import asyncio
import logging
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

    frame = {"type": "read_resource", "request_id": "r-2", "contract_version": 1,
             "caller": {"user_id": "user-1", "client_id": "client-1"}, "service": "svc",
             "uri": "svc://status", "encryption": "none"}
    _, replies = run(_one_exchange([frame], service_kwargs={"on_read": on_read}))
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


def test_logs_never_contain_arguments_results_or_credentials(caplog):
    async def on_call(tool, arguments, caller):
        return "RESULT-SECRET-777"

    with caplog.at_level(logging.DEBUG):
        register, replies = run(_one_exchange(
            [_call(payload={"text": "ARG-SECRET-555"})], service_kwargs={"on_call": on_call}))
    assert replies[0]["payload"][0]["text"] == "RESULT-SECRET-777"
    # Everything the service side logged (the fake gateway's own server log
    # is the test's, not the library's), at DEBUG, including the transport.
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if not r.name.startswith("websockets.server"))
    for secret in ("ARG-SECRET-555", "RESULT-SECRET-777", "CRED-s3cr3t-value"):
        assert secret not in ours
    assert "r-1" in ours  # the request id is logged


# --- caller ids (issue #2) ---------------------------------------------------------------
#
# Spec 6.2: `caller.user_id` and `caller.client_id` are always present. A v1
# frame without both (missing, null or empty) never reaches the handler.

def _strip_caller(frame, variant):
    """`frame` with its caller ids missing, null or empty, per `variant`."""
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
            frame["caller"][field] = None if how == "null" else ""
    return frame


NO_CALLER_IDS = ["no caller", "caller null", "caller not an object",
                 "user_id missing", "user_id null", "user_id empty",
                 "client_id missing", "client_id null", "client_id empty"]


def _read(uri="svc://status", *, request_id="r-2"):
    return {"type": "read_resource", "request_id": request_id, "contract_version": 1,
            "caller": {"user_id": "user-1", "client_id": "client-1"}, "service": "svc",
            "uri": uri, "encryption": "none"}


def _assert_refused_not_allowed(reply, request_id, encryption="none"):
    assert reply["type"] == "error"
    assert reply["request_id"] == request_id
    assert reply["encryption"] == encryption
    assert reply["code"] == "not_allowed"
    assert isinstance(reply["payload"], str)


@pytest.mark.parametrize("variant", NO_CALLER_IDS)
def test_v1_call_without_caller_ids_refused_before_on_call(variant):
    called = []

    async def on_call(tool, arguments, caller):
        called.append(caller)
        return "should not run"

    frame = _strip_caller(_call(payload={"text": "x"}), variant)
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call}))
    _assert_refused_not_allowed(replies[0], "r-1")
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
    assert called == []


def test_v1_end_to_end_call_without_caller_ids_refused_before_on_call():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    called = []

    async def on_call(tool, arguments, caller):
        called.append(caller)
        return "should not run"

    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    frame = _strip_caller(frame, "no caller")
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call,
                                                            "key": service_key}))
    _assert_refused_not_allowed(replies[0], "r-e2e", encryption="end-to-end")
    assert called == []


def test_refusal_without_caller_ids_logged_once_at_warning_without_payload(caplog):
    frame = _strip_caller(_call(payload={"text": "ARG-SECRET-555"},
                                request_id="r-no-caller"), "no caller")
    with caplog.at_level(logging.DEBUG):
        _, replies = run(_one_exchange([frame]))
    assert replies[0]["code"] == "not_allowed"
    ours = [r for r in caplog.records if r.name.startswith("gateway_client")]
    about_it = [r for r in ours if "r-no-caller" in r.getMessage()]
    assert [r.levelno for r in about_it] == [logging.WARNING]
    assert not any("ARG-SECRET-555" in r.getMessage() for r in ours)


def test_caller_contract_says_fail_closed_on_legacy_none_user_id():
    # Legacy calls reach the handler with `user_id=None` by design (see
    # test_legacy_fallback_when_closed_1008_without_reply); the documented
    # contract tells consumers to fail closed on it.
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    for text in (Caller.__doc__, readme):
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

"""The connection: register, ping, calls, errors, caller-token checks,
end-to-end, backoff and announcements, against an in-process fake gateway."""

from __future__ import annotations

import asyncio
import logging
import time
import unicodedata
import uuid

import pytest
from helpers import (
    APP,
    PRINCIPAL,
    RESOURCES,
    TOOLS,
    Issuer,
    fake_gateway,
    make_service,
    recv_json,
    run,
    send_json,
    serve_until,
)

from gateway_client import Caller, KeyPair, ServiceError, e2e
from gateway_client.protocol import Backoff
from gateway_client.service import TOKEN_REFUSED

ISSUER = Issuer()   # the gateway's signing key in these tests


def _call(tool="echo", payload=None, *, request_id="r-1", encryption="none",
          token=None, **extra):
    frame = {"type": "call", "request_id": request_id, "contract_version": 2,
             "caller_token": token if token is not None else ISSUER.token(),
             "service": "svc", "tool": tool, "encryption": encryption, "payload": payload}
    frame.update(extra)
    return frame


def _read(uri="svc://status", *, request_id="r-2", token=None, **extra):
    frame = {"type": "read_resource", "request_id": request_id, "contract_version": 2,
             "caller_token": token if token is not None else ISSUER.token(),
             "service": "svc", "uri": uri, "encryption": "none"}
    frame.update(extra)
    return frame


async def _one_exchange(frames, *, service_kwargs=None, after_register=None):
    """Register, send each frame in `frames`, return (register frame,
    replies). The service checks tokens against ISSUER's key set unless
    `service_kwargs` says otherwise."""
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

    kwargs = {"issuer": ISSUER, **(service_kwargs or {})}
    async with fake_gateway(handler) as url:
        service = make_service(url, **kwargs)
        return await serve_until(service, done)


# --- register -------------------------------------------------------------------

def test_v2_register_frame_contents():
    register, _ = run(_one_exchange([]))
    assert register == {
        "type": "register", "contract_version": 2, "service": "svc",
        "credential": "CRED-s3cr3t-value", "public_key": register["public_key"],
        "accepts_caller": True, "tools": TOOLS, "resources": RESOURCES,
    }
    assert "roles" not in register and "roles_version" not in register
    assert len(e2e.decode_public_key(register["public_key"])) == 32


def test_declaration_validated_locally():
    from gateway_client.protocol import Declaration
    with pytest.raises(ValueError, match="inputSchema"):
        Declaration.build([{"name": "x", "description": ""}])
    with pytest.raises(ValueError, match="declared twice"):
        Declaration.build(TOOLS + TOOLS[:1])
    with pytest.raises(ValueError, match="mimeType"):
        Declaration.build(TOOLS, [{"uri": "a://b", "name": "b", "description": ""}])


def _tool_with(annotations):
    return {"name": "x", "description": "d", "inputSchema": {"type": "object"},
            "annotations": annotations}


@pytest.mark.parametrize("bad", ["readOnly", ["readOnlyHint"], True, 1, None])
def test_non_object_annotations_are_refused_locally(bad):
    from gateway_client.protocol import Declaration
    with pytest.raises(ValueError, match="annotations must be an object"):
        Declaration.build([_tool_with(bad)])


@pytest.mark.parametrize("hint", ["readOnlyHint", "destructiveHint",
                                  "idempotentHint", "openWorldHint"])
@pytest.mark.parametrize("bad_value", ["true", "maybe", 1, 0, None, [], {}])
def test_non_bool_annotation_hint_is_refused_locally(hint, bad_value):
    from gateway_client.protocol import Declaration
    with pytest.raises(ValueError, match=f"annotations.{hint} must be a boolean"):
        Declaration.build([_tool_with({hint: bad_value})])


def test_valid_annotations_are_kept_in_the_register_frame():
    from gateway_client.protocol import Declaration
    annotations = {"readOnlyHint": True, "destructiveHint": False,
                   "idempotentHint": True, "openWorldHint": False, "title": "X"}
    frame = Declaration.build([_tool_with(annotations)]).register("s", "c", "k")
    assert frame["tools"][0]["annotations"] == annotations


def test_roles_are_not_part_of_the_api():
    with pytest.raises(TypeError):
        make_service("ws://127.0.0.1:1/backend", roles=[])
    service = make_service("ws://127.0.0.1:1/backend")
    with pytest.raises(TypeError):
        run(service.update(roles=[]))


def test_jwks_url_derived_from_the_backend_url():
    service = make_service("wss://gw.example/backend")
    assert service.jwks_url == "https://gw.example/.well-known/jwks.json"


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

    token = ISSUER.token()
    _, replies = run(_one_exchange([_call(payload={"text": "hi"}, token=token)],
                                   service_kwargs={"on_call": on_call}))
    assert replies == [{"type": "result", "request_id": "r-1", "encryption": "none",
                        "payload": [{"type": "text", "text": "ok"}]}]
    assert seen["tool"] == "echo" and seen["arguments"] == {"text": "hi"}
    caller = seen["caller"]
    assert caller == Caller(principal=PRINCIPAL, app=APP, encryption="none",
                            request_id="r-1", token=token)
    assert caller.claims["aud"] == "svc" and caller.claims["sub"] == PRINCIPAL
    assert not hasattr(caller, "user_id") and not hasattr(caller, "client_id")
    assert token not in repr(caller)


def test_sync_handler_runs_and_string_result_becomes_text_block():
    def on_call(tool, arguments, caller):  # sync: run in a worker thread
        time.sleep(0.01)
        return {"n": 1}

    _, replies = run(_one_exchange([_call(payload={"text": "x"})],
                                   service_kwargs={"on_call": on_call}))
    assert replies[0]["payload"] == [{"type": "text", "text": '{"n": 1}'}]


def test_read_resource_dispatch():
    async def on_read(uri, caller):
        assert (caller.principal, caller.app) == (PRINCIPAL, APP)
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


def test_logs_never_contain_arguments_results_credentials_or_tokens(caplog):
    async def on_call(tool, arguments, caller):
        return "RESULT-SECRET-777"

    token = ISSUER.token()
    with caplog.at_level(logging.DEBUG):
        register, replies = run(_one_exchange(
            [_call(payload={"text": "ARG-SECRET-555"}, token=token)],
            service_kwargs={"on_call": on_call}))
    assert replies[0]["payload"][0]["text"] == "RESULT-SECRET-777"
    # Everything the service side logged (the fake gateway's own server log
    # is the test's, not the library's), at DEBUG, including the transport.
    ours = "\n".join(r.getMessage() for r in caplog.records
                     if not r.name.startswith("websockets.server"))
    for secret in ("ARG-SECRET-555", "RESULT-SECRET-777", "CRED-s3cr3t-value", token,
                   token.split(".")[2]):
        assert secret not in ours
    assert "r-1" in ours  # the request id is logged
    assert PRINCIPAL in ours and APP in ours  # and the verified caller


# --- caller tokens (INT-C3): one test per failure mode, before any handler -------------

def _refusing_handlers(called):
    async def on_call(tool, arguments, caller):
        called.append(caller)
        return "should not run"

    async def on_read(uri, caller):
        called.append(caller)
        return "should not run"
    return {"on_call": on_call, "on_read": on_read}


FORGER = Issuer()

BAD_TOKENS = {
    "bad signature": lambda: FORGER.token(kid=ISSUER.kid),
    "wrong aud": lambda: ISSUER.token(aud="other-service"),
    "expired": lambda: ISSUER.token(now=time.time() - 300),
    "lifetime over 60 s": lambda: ISSUER.token(ttl=3600),
    "missing sub": lambda: ISSUER.token(drop=("sub",)),
    "missing act": lambda: ISSUER.token(drop=("act",)),
    "missing aud": lambda: ISSUER.token(drop=("aud",)),
    "missing exp": lambda: ISSUER.token(drop=("exp",)),
    "missing jti": lambda: ISSUER.token(drop=("jti",)),
    "blank sub": lambda: ISSUER.token(sub=" "),
    "no kid": lambda: ISSUER.token(kid=None),
    "unknown kid": lambda: FORGER.token(),
    "HS256": lambda: ISSUER.hs256_token(),
    "not a JWT": lambda: "not-a-jwt",
    "empty": lambda: "",
}


@pytest.mark.parametrize("kind", ["call", "read_resource"])
@pytest.mark.parametrize("bad", list(BAD_TOKENS))
def test_bad_caller_token_refused_before_the_handler(bad, kind):
    called = []
    token = BAD_TOKENS[bad]()
    frame = _call(payload={"text": "x"}, token=token) if kind == "call" else \
        _read(token=token)
    _, replies = run(_one_exchange([frame], service_kwargs=_refusing_handlers(called)))
    assert replies == [{"type": "error", "request_id": frame["request_id"],
                        "encryption": "none", "code": "not_allowed",
                        "payload": "caller token refused"}]
    assert called == []


@pytest.mark.parametrize("variant", ["missing", "null", "number"])
def test_frame_without_a_caller_token_refused(variant):
    called = []
    frame = _call(payload={"text": "x"})
    if variant == "missing":
        del frame["caller_token"]
    else:
        frame["caller_token"] = None if variant == "null" else 42
    _, replies = run(_one_exchange([frame], service_kwargs=_refusing_handlers(called)))
    assert replies[0]["code"] == "not_allowed" and called == []


def test_replayed_jti_refused_before_the_handler():
    seen = []

    async def on_call(tool, arguments, caller):
        seen.append(caller.request_id)
        return "ok"

    token = ISSUER.token()
    frames = [_call(payload={"text": "x"}, token=token, request_id="r-a"),
              _call(payload={"text": "x"}, token=token, request_id="r-b")]
    _, replies = run(_one_exchange(frames, service_kwargs={"on_call": on_call}))
    assert replies[0]["type"] == "result"
    assert replies[1]["code"] == "not_allowed" and seen == ["r-a"]


def test_unknown_kid_refetches_the_key_set_then_serves():
    # The gateway rotated its key: the first token under the new kid makes
    # the library refetch the key set once, then it verifies.
    old, new = Issuer(), Issuer()
    published = [old]
    fetches = []

    def fetch(url):
        fetches.append(url)
        return {"keys": [k for i in published for k in i.jwks()["keys"]]}

    async def rotate(ws):
        published[:] = [new]

    frames = [_call(payload={"text": "a"}, token=old.token(), request_id="r-old"),
              _call(payload={"text": "b"}, token=new.token(), request_id="r-new")]
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            replies = []
            await send_json(ws, frames[0])
            replies.append(await recv_json(ws))
            await rotate(ws)
            await send_json(ws, frames[1])
            replies.append(await recv_json(ws))
            done.set_result(replies)
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            service = make_service(url, jwks_fetch=fetch, jwks_min_refetch_interval=0)
            return await serve_until(service, done)

    replies = run(main())
    assert [r["type"] for r in replies] == ["result", "result"]
    assert len(fetches) == 2


def test_key_set_unreachable_answers_unavailable():
    called = []

    def fetch(url):
        raise OSError("connection refused")

    _, replies = run(_one_exchange([_call(payload={"text": "x"})], service_kwargs={
        "jwks_fetch": fetch, **_refusing_handlers(called)}))
    assert replies[0]["code"] == "unavailable" and called == []


def test_token_refusal_logged_once_at_warning_without_token(caplog):
    token = ISSUER.token(aud="other-service")
    with caplog.at_level(logging.DEBUG):
        run(_one_exchange([_call(payload={"text": "ARG-SECRET-555"}, token=token,
                                 request_id="r-bad")]))
    ours = [r for r in caplog.records if r.name.startswith("gateway_client")]
    about_it = [r for r in ours if "r-bad" in r.getMessage()]
    warnings = [r for r in about_it if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "audience" in warnings[0].getMessage()
    assert not any(token in r.getMessage() or "ARG-SECRET-555" in r.getMessage()
                   for r in ours)


def test_identity_comes_only_from_the_token_not_frame_fields():
    # A v1-style `caller` object (or any other field) cannot change who calls.
    seen = []

    async def on_call(tool, arguments, caller):
        seen.append((caller.principal, caller.app))
        return "ok"

    frame = _call(payload={"text": "x"}, caller={"user_id": "mallory", "client_id": "evil"},
                  principal={"client_id": "evil"}, user_id="mallory", sub="mallory")
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call}))
    assert replies[0]["type"] == "result" and seen == [(PRINCIPAL, APP)]


def test_unknown_encryption_with_valid_token_is_bad_arguments():
    _, replies = run(_one_exchange([_call(payload={"text": "x"}, encryption="rot13")]))
    assert replies[0]["code"] == "bad_arguments"


# --- end-to-end ------------------------------------------------------------------------

def _fields(tool="echo", *, user_id=PRINCIPAL, client_id=APP, service="svc"):
    """The v2 request associated data: the verified token's sub / act / aud."""
    return e2e.header(user_id=user_id, client_id=client_id, service=service, tool=tool)


def _e2e_call(client, service_pub, args, *, request_id="r-e2e", now=None, tool="echo",
              kid=None, envelope=None, fields=None, token=None):
    fields = fields or _fields(tool)
    env = envelope or e2e.seal(args, sender=client, recipient_public_raw=service_pub,
                               fields=fields, now=now)
    frame = _call(tool=tool, payload=env, request_id=request_id, encryption="end-to-end",
                  client_public_key=client.public_b64, client_kid=kid or client.kid,
                  token=token)
    return frame, fields


def _open_reply(reply, client, service_key, fields):
    assert reply["encryption"] == "end-to-end"
    assert reply["payload"]["kid"] == service_key.kid  # what the gateway checks
    return e2e.open_envelope(reply["payload"], recipient=client,
                             sender_public_raw=service_key.public_raw,
                             fields=e2e.reply_header(fields, reply["request_id"]))


def test_v2_associated_data_is_bound_to_the_verified_token():
    aad = e2e.associated_data(_fields(), "Tk9OQ0U", 5)
    assert aad == (b'{"client_id":"' + APP.encode() + b'","contract_version":2,'
                   b'"encryption":"end-to-end","nonce":"Tk9OQ0U","sent_at":5,'
                   b'"service":"svc","tool":"echo","user_id":"' + PRINCIPAL.encode() + b'"}')


def test_e2e_round_trip_handler_sees_plain_arguments():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    seen = {}

    async def on_call(tool, arguments, caller):
        seen.update(arguments=arguments, encryption=caller.encryption, app=caller.app)
        return [{"type": "text", "text": "sealed answer"}]

    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "plain secret"})
    _, replies = run(_one_exchange([frame], service_kwargs={"on_call": on_call,
                                                            "key": service_key}))
    assert seen == {"arguments": {"text": "plain secret"}, "encryption": "end-to-end",
                    "app": APP}
    reply = replies[0]
    assert reply["type"] == "result" and "sealed answer" not in str(reply)
    assert _open_reply(reply, client, service_key, fields) == [
        {"type": "text", "text": "sealed answer"}]


@pytest.mark.parametrize("wrong", [{"user_id": "wrn:wolf-access:user/u-other"},
                                   {"client_id": "wrn:gateway:client/other"},
                                   {"service": "other-svc"}])
def test_e2e_envelope_bound_to_other_ids_than_the_token_refused(wrong):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    called = []
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"},
                         fields=_fields(**wrong))
    _, replies = run(_one_exchange([frame], service_kwargs={
        "key": service_key, **_refusing_handlers(called)}))
    assert replies[0]["code"] == "bad_arguments" and called == []
    # The refusal is sealed to the token's ids, which the real client holds.
    assert "decrypt" in _open_reply(replies[0], client, service_key, _fields())


def test_e2e_token_refusal_is_plain_not_allowed():
    # No verified identity, so no associated data to seal to: the gateway
    # turns this plain reply into `internal` for the client.
    client, service_key = KeyPair.generate(), KeyPair.generate()
    called = []
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"},
                         token=ISSUER.token(aud="other-service"))
    _, replies = run(_one_exchange([frame], service_kwargs={
        "key": service_key, **_refusing_handlers(called)}))
    assert replies[0] == {"type": "error", "request_id": "r-e2e", "encryption": "end-to-end",
                          "code": "not_allowed", "payload": "caller token refused"}
    assert called == []


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
    env = e2e.seal({"text": "x"}, sender=other, recipient_public_raw=service_key.public_raw,
                   fields=_fields())
    frame, fields = _e2e_call(client, service_key.public_raw, None, envelope=env)
    _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))
    assert replies[0]["code"] == "bad_arguments"
    assert "kid" in _open_reply(replies[0], client, service_key, fields)


def test_e2e_reused_nonce_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "x"})
    replay = dict(frame, request_id="r-replay", caller_token=ISSUER.token())
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


def test_none_call_after_e2e_from_same_app_refused():
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, _ = _e2e_call(client, service_key.public_raw, {"text": "x"})
    plain = _call(payload={"text": "x"}, request_id="r-plain")
    other_app = _call(payload={"text": "x"}, request_id="r-other",
                      token=ISSUER.token(act="wrn:gateway:client/another-app"))
    _, replies = run(_one_exchange([frame, plain, other_app],
                                   service_kwargs={"key": service_key}))
    assert replies[0]["type"] == "result"
    assert replies[1]["code"] == "not_allowed"
    assert replies[2]["type"] == "result"


# --- unusable client key and seal fallback (Issue #9) -----------------------------------

@pytest.mark.parametrize("path,frame_factory", [
    ("unknown_tool", lambda pub, kid: {
        "type": "call", "request_id": "r-zero-a", "contract_version": 2,
        "caller_token": ISSUER.token(act=APP), "service": "svc",
        "tool": "nonexistent_tool", "encryption": "end-to-end",
        "client_public_key": pub, "client_kid": kid, "payload": {},
    }),
    ("declared_tool", lambda pub, kid: {
        "type": "call", "request_id": "r-zero-b", "contract_version": 2,
        "caller_token": ISSUER.token(act=APP), "service": "svc",
        "tool": "echo", "encryption": "end-to-end",
        "client_public_key": pub, "client_kid": kid, "payload": {},
    }),
    ("read_resource", lambda pub, kid: {
        "type": "read_resource", "request_id": "r-zero-c", "contract_version": 2,
        "caller_token": ISSUER.token(act=APP), "service": "svc",
        "uri": "svc://status", "encryption": "end-to-end",
        "client_public_key": pub, "client_kid": kid,
    }),
])
@pytest.mark.parametrize("bad_key", [
    b"\x00" * 32,             # all zeros
    b"\x01" + b"\x00" * 31,   # order 2 point
])
def test_unusable_client_key_refused_plain_bad_arguments_and_app_not_pinned(
        path, frame_factory, bad_key, caplog):
    service_key = KeyPair.generate()
    pub_b64 = e2e.b64url_encode(bad_key)
    kid = e2e.key_id(bad_key)
    frame = frame_factory(pub_b64, kid)
    req_id = frame["request_id"]

    calls_invoked, reads_invoked = [], []
    async def on_call(tool, arguments, caller):
        calls_invoked.append(tool)
        return [{"type": "text", "text": "ok"}]

    async def on_read(uri, caller):
        reads_invoked.append(uri)
        return "status ok"

    followup = _call(tool="echo", payload={"text": "plain-allowed"},
                     request_id=f"{req_id}-followup", encryption="none",
                     token=ISSUER.token(act=APP))

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame, followup],
                                       service_kwargs={"key": service_key,
                                                       "on_call": on_call,
                                                       "on_read": on_read}))

    assert len(replies) == 2
    reply, followup_reply = replies[0], replies[1]

    # Plain unsealed error bad_arguments
    assert reply == {
        "type": "error", "request_id": req_id, "encryption": "end-to-end",
        "code": "bad_arguments",
        "payload": "client_public_key cannot be used for end-to-end encryption",
    }
    # Handlers were never invoked for the bad frame
    assert reads_invoked == []
    assert calls_invoked == (["echo"] if followup_reply["type"] == "result" else [])

    # App was not pinned: follow-up plaintext call from the same app succeeds
    assert followup_reply["type"] == "result"
    assert followup_reply["payload"] == [{"type": "text", "text": "ok"}]

    # Log assertions:
    # 1. No "handler raised" logged
    assert "handler raised" not in caplog.text
    # 2. No unhandled exception
    assert "Task exception was never retrieved" not in caplog.text
    # 3. Logged error code matches the code actually sent
    client_logs = [r for r in caplog.records if r.name.startswith("gateway_client")]
    for record in client_logs:
        msg = record.getMessage()
        if f"request_id={req_id}" in msg and "error" in msg:
            assert "bad_arguments" in msg
            assert "internal" not in msg


@pytest.mark.parametrize("bad_token", [None, "invalid.caller.token"])
def test_unusable_client_key_with_missing_or_invalid_token_is_not_allowed(bad_token, caplog):
    service_key = KeyPair.generate()
    zero_key = b"\x00" * 32
    pub_b64 = e2e.b64url_encode(zero_key)
    kid = e2e.key_id(zero_key)
    frame = {
        "type": "call", "request_id": "r-zero-d", "contract_version": 2,
        "caller_token": bad_token, "service": "svc",
        "tool": "echo", "encryption": "end-to-end",
        "client_public_key": pub_b64, "client_kid": kid, "payload": {},
    }
    followup = _call(tool="echo", payload={"text": "plain-allowed"},
                     request_id="r-zero-d-followup", encryption="none",
                     token=ISSUER.token(act=APP))

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame, followup],
                                       service_kwargs={"key": service_key}))

    assert len(replies) == 2
    assert replies[0] == {
        "type": "error", "request_id": "r-zero-d", "encryption": "end-to-end",
        "code": "not_allowed", "payload": TOKEN_REFUSED,
    }
    assert replies[1]["type"] == "result"
    assert "handler raised" not in caplog.text
    assert "Task exception was never retrieved" not in caplog.text


def test_seal_failure_fallback_on_result_answers_plain_internal(monkeypatch, caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "hello"},
                             request_id="r-seal-fail")

    def broken_seal(*args, **kwargs):
        raise ValueError("broken crypto hardware")

    monkeypatch.setattr(e2e, "seal", broken_seal)

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key}))

    assert len(replies) == 1
    assert replies[0] == {
        "type": "error", "request_id": "r-seal-fail", "encryption": "end-to-end",
        "code": "internal", "payload": "internal error",
    }
    assert "handler raised" not in caplog.text
    assert any("could not seal the reply (ValueError); answering plain error internal" in r.getMessage()
               for r in caplog.records)


def test_seal_failure_fallback_on_error_preserves_error_code(monkeypatch, caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()

    async def on_call(tool, arguments, caller):
        raise ServiceError("not_found", "unknown tool: undeclared_tool")

    frame, fields = _e2e_call(client, service_key.public_raw, {"text": "hello"},
                             tool="echo", request_id="r-seal-err")

    def broken_seal(*args, **kwargs):
        raise ValueError("broken crypto hardware")

    monkeypatch.setattr(e2e, "seal", broken_seal)

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key,
                                                                "on_call": on_call}))

    assert len(replies) == 1
    assert replies[0] == {
        "type": "error", "request_id": "r-seal-err", "encryption": "end-to-end",
        "code": "not_found", "payload": "unknown tool: undeclared_tool",
    }
    assert "handler raised" not in caplog.text
    assert any("could not seal the reply (ValueError); answering plain error not_found" in r.getMessage()
               for r in caplog.records)


def test_answer_catches_unexpected_reply_failure_and_sends_plain_internal(caplog):
    sent = []
    class FakeWS:
        async def send(self, data):
            import json
            sent.append(json.loads(data))

    service = make_service("ws://localhost:9999", issuer=ISSUER)

    async def broken_reply(frame):
        raise RuntimeError("unexpected fatal flaw")

    service._reply = broken_reply
    frame = {"type": "call", "request_id": "r-fatal", "encryption": "end-to-end"}

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        run(service._answer(FakeWS(), frame))

    assert sent == [{
        "type": "error", "request_id": "r-fatal", "encryption": "end-to-end",
        "code": "internal", "payload": "internal error",
    }]
    assert any("could not build the reply (RuntimeError); answering plain error internal" in r.getMessage()
               for r in caplog.records)


def test_answer_catches_send_failure_without_raising(caplog):
    class ExplodingWS:
        async def send(self, data):
            raise ConnectionResetError("socket dropped")

    service = make_service("ws://localhost:9999", issuer=ISSUER)
    frame = {"type": "call", "request_id": "r-send-drop", "encryption": "none"}

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        # Must not raise
        run(service._answer(ExplodingWS(), frame))

    assert any("reply not sent (ConnectionResetError)" in r.getMessage()
               for r in caplog.records)


# --- missing target in end-to-end mode (Issue #10) -------------------------------

@pytest.mark.parametrize("kind,bad_target_kwargs", [
    ("call", {}),                           # omitted tool
    ("call", {"tool": None}),               # null tool
    ("call", {"tool": 123}),                # non-string tool
    ("read_resource", {}),                  # omitted uri
    ("read_resource", {"uri": None}),       # null uri
    ("read_resource", {"uri": 123}),        # non-string uri
])
def test_e2e_missing_or_non_string_target_answered_not_found(kind, bad_target_kwargs, caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    calls_invoked, reads_invoked = [], []

    async def on_call(tool, arguments, caller):
        calls_invoked.append(tool)
        return [{"type": "text", "text": "ok"}]

    async def on_read(uri, caller):
        reads_invoked.append(uri)
        return "status ok"

    req_id = f"r-{kind}-missing"
    frame: dict[str, Any] = {
        "type": kind,
        "request_id": req_id,
        "contract_version": 2,
        "caller_token": ISSUER.token(act=APP),
        "service": "svc",
        "encryption": "end-to-end",
        "client_public_key": client.public_b64,
        "client_kid": client.kid,
    }
    if kind == "call":
        frame["payload"] = {}
    frame.update(bad_target_kwargs)

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key,
                                                                "on_call": on_call,
                                                                "on_read": on_read}))

    assert len(replies) == 1
    reply = replies[0]
    assert reply["type"] == "error"
    assert reply["request_id"] == req_id
    assert reply["encryption"] == "end-to-end"
    assert reply["code"] == "not_found"
    assert calls_invoked == []
    assert reads_invoked == []
    assert "handler raised" not in caplog.text


@pytest.mark.parametrize("kind,bad_target_kwargs", [
    ("call", {"tool": "undeclared_tool"}),
    ("call", {}),
    ("call", {"tool": None}),
    ("call", {"tool": 123}),
    ("read_resource", {"uri": "svc://undeclared"}),
    ("read_resource", {}),
    ("read_resource", {"uri": None}),
    ("read_resource", {"uri": 123}),
])
def test_e2e_mismatched_client_kid_precedes_missing_or_undeclared_target(
        kind, bad_target_kwargs, caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    other = KeyPair.generate()
    calls_invoked, reads_invoked = [], []

    async def on_call(tool, arguments, caller):
        calls_invoked.append(tool)
        return [{"type": "text", "text": "ok"}]

    async def on_read(uri, caller):
        reads_invoked.append(uri)
        return "status ok"

    req_id = f"r-{kind}-kid-mismatch"
    frame: dict[str, Any] = {
        "type": kind,
        "request_id": req_id,
        "contract_version": 2,
        "caller_token": ISSUER.token(act=APP),
        "service": "svc",
        "encryption": "end-to-end",
        "client_public_key": client.public_b64,
        "client_kid": other.kid,  # mismatched kid
    }
    if kind == "call":
        frame["payload"] = {}
    frame.update(bad_target_kwargs)

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame], service_kwargs={"key": service_key,
                                                                "on_call": on_call,
                                                                "on_read": on_read}))

    assert len(replies) == 1
    reply = replies[0]
    assert reply["type"] == "error"
    assert reply["request_id"] == req_id
    assert reply["encryption"] == "end-to-end"
    assert reply["code"] == "bad_arguments"
    assert reply["payload"] == "client_kid does not match client_public_key"
    assert calls_invoked == []
    assert reads_invoked == []
    assert "handler raised" not in caplog.text


def test_e2e_missing_target_unit_reply_direct(caplog):
    service_key = KeyPair.generate()
    client = KeyPair.generate()
    calls_invoked, reads_invoked = [], []

    async def on_call(tool, arguments, caller):
        calls_invoked.append(tool)
        return "ok"

    async def on_read(uri, caller):
        reads_invoked.append(uri)
        return "ok"

    service = make_service("ws://localhost:9999", issuer=ISSUER, key=service_key,
                           on_call=on_call, on_read=on_read)

    call_frame = {
        "type": "call", "request_id": "r-direct-call", "contract_version": 2,
        "caller_token": ISSUER.token(act=APP), "service": "svc",
        "encryption": "end-to-end", "client_public_key": client.public_b64,
        "client_kid": client.kid,
    }
    read_frame = {
        "type": "read_resource", "request_id": "r-direct-read", "contract_version": 2,
        "caller_token": ISSUER.token(act=APP), "service": "svc",
        "encryption": "end-to-end", "client_public_key": client.public_b64,
        "client_kid": client.kid,
    }

    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        rep_call = run(service._reply(call_frame))
        rep_read = run(service._reply(read_frame))

    assert rep_call["type"] == "error" and rep_call["code"] == "not_found"
    assert rep_call["encryption"] == "end-to-end"
    assert rep_read["type"] == "error" and rep_read["code"] == "not_found"
    assert rep_read["encryption"] == "end-to-end"
    assert calls_invoked == [] and reads_invoked == []
    assert "handler raised" not in caplog.text


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
    assert again["type"] == "register" and again["contract_version"] == 2
    assert [t["name"] for t in again["tools"]] == ["echo", "other", "extra"]
    assert "roles" not in again and "roles_version" not in again
    assert announce == {"type": "tools_changed"}
    assert direct == {"type": "resources_changed"}


def test_announce_when_not_registered_returns_false():
    service = make_service("ws://127.0.0.1:1/backend")
    assert run(service.send_tools_changed()) is False


# --- caller identity string validation (#7) ---------------------------------------------

BAD_CALLER_IDENTITY_VALUES = (
    # Unicode category Cc (control)
    "\x00", "u\x1fu", "u\x7f", "\x85u", "u\ru",
    # Unicode category Cf (format)
    "\u200b", "u\u200du", "\ufeffu", "u\u202eu",
    # Leading / trailing str.isspace()
    " u", "u ", "\tu", "u\n", "\u00a0u", "u\u3000",
    # Blank / empty
    "", " \t ",
)

VALID_CALLER_IDENTITY_VALUES = (
    "wrn:access:user/user-1",
    str(uuid.UUID("7f9a0b1c-0000-4000-8000-000000000001")),
    "u s",
    "use\u0301r",
    "用户",
)


@pytest.mark.parametrize("kind", ["call", "read_resource"])
@pytest.mark.parametrize("field", ["sub", "act", "jti", "kid"])
@pytest.mark.parametrize("bad_value", BAD_CALLER_IDENTITY_VALUES)
def test_control_format_or_edge_whitespace_claim_or_kid_refused_and_logged_once(
    kind, field, bad_value, caplog
):
    called = []
    issuer = Issuer()
    if field == "kid":
        issuer.kid = bad_value
    token = issuer.token(**{field: bad_value})
    req_id = "r-bad-id"
    frame = (_call(payload={"text": "x"}, request_id=req_id, token=token) if kind == "call"
             else _read(request_id=req_id, token=token))
    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([frame], service_kwargs={
            "issuer": issuer, **_refusing_handlers(called)}))
    assert replies == [{"type": "error", "request_id": req_id,
                        "encryption": "none", "code": "not_allowed",
                        "payload": TOKEN_REFUSED}]
    assert called == []
    ours = [r for r in caplog.records if r.name.startswith("gateway_client")]
    warnings = [r for r in ours if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert req_id in warnings[0].getMessage()
    assert "non-empty" not in warnings[0].getMessage()


@pytest.mark.parametrize("valid_id", VALID_CALLER_IDENTITY_VALUES)
def test_valid_identity_claims_reach_handlers_byte_identical(valid_id):
    seen_call = []
    seen_read = []

    async def on_call(tool, arguments, caller):
        seen_call.append(caller)
        return "ok"

    async def on_read(uri, caller):
        seen_read.append(caller)
        return "status-ok"

    tok_call = ISSUER.token(sub=valid_id, act=valid_id, jti=valid_id)
    tok_read = ISSUER.token(sub=valid_id, act=valid_id)
    _, replies = run(_one_exchange(
        [_call(payload={"text": "hi"}, request_id="r-c", token=tok_call),
         _read(request_id="r-r", token=tok_read)],
        service_kwargs={"on_call": on_call, "on_read": on_read}))
    assert [r["type"] for r in replies] == ["result", "result"]
    assert len(seen_call) == 1 and len(seen_read) == 1
    for caller in (seen_call[0], seen_read[0]):
        assert caller.principal == valid_id
        assert caller.app == valid_id
        assert caller.principal.encode("utf-8") == valid_id.encode("utf-8")
        assert caller.app.encode("utf-8") == valid_id.encode("utf-8")
        if valid_id == "use\u0301r":
            assert unicodedata.is_normalized("NFD", caller.principal)
            assert not unicodedata.is_normalized("NFC", caller.principal)
    assert seen_call[0].claims["jti"] == valid_id
    assert seen_call[0].claims["jti"].encode("utf-8") == valid_id.encode("utf-8")


def test_padded_or_format_char_act_cannot_bypass_e2e_pin(caplog):
    client, service_key = KeyPair.generate(), KeyPair.generate()
    pinned_app = "wrn:gateway:client/c1"
    invoked = []

    async def on_call(tool, arguments, caller):
        invoked.append(caller.app)
        return "sealed"

    e2e_frame, _ = _e2e_call(
        client, service_key.public_raw, {"text": "x"},
        request_id="r-pin",
        fields=_fields(client_id=pinned_app),
        token=ISSUER.token(act=pinned_app))
    bypass_variants = [
        ("r-trail-space", "wrn:gateway:client/c1 "),
        ("r-lead-space", " wrn:gateway:client/c1"),
        ("r-zwsp", "wrn:gateway:client/c1\u200b"),
        ("r-nul", "wrn:gateway:client/c1\x00"),
    ]
    plain_frames = [
        _call(payload={"text": "x"}, request_id=req_id, token=ISSUER.token(act=bad_act))
        for req_id, bad_act in bypass_variants
    ]
    with caplog.at_level(logging.DEBUG, logger="gateway_client"):
        _, replies = run(_one_exchange([e2e_frame, *plain_frames],
                                       service_kwargs={"on_call": on_call,
                                                       "key": service_key}))
    assert replies[0]["type"] == "result"
    assert invoked == [pinned_app]
    for (req_id, _), reply in zip(bypass_variants, replies[1:]):
        assert reply == {"type": "error", "request_id": req_id,
                         "encryption": "none", "code": "not_allowed",
                         "payload": TOKEN_REFUSED}
    warnings = [r for r in caplog.records
                if r.name.startswith("gateway_client") and r.levelno == logging.WARNING]
    assert len(warnings) == len(bypass_variants)

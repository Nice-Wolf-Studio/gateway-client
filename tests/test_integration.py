"""End to end over a real (loopback) WebSocket: the example service against a
tiny server that behaves like the contract v1 gateway for `register` and one
`call` (the gateway repo's `mock_backend` flow, from the gateway's side)."""

from __future__ import annotations

import asyncio
import pathlib
import sys
import uuid

from helpers import fake_gateway, make_config, recv_json, run, send_json

from gateway_client import e2e

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "examples"))
import selftest_service  # noqa: E402

REQUIRED = ("service", "credential", "public_key", "accepts_caller", "tools",
            "resources", "roles", "roles_version")


def _gateway_validate(frame: dict) -> str | None:
    """The gateway's section 6.1 checks that need no database; the reason
    it would reject with, or None."""
    if frame.get("contract_version") != 1:
        return "unsupported_contract"
    if any(f not in frame for f in REQUIRED) or frame["accepts_caller"] is not True:
        return "missing_field"
    try:
        e2e.decode_public_key(frame["public_key"])
    except ValueError:
        return "missing_field"
    for tool in frame["tools"]:
        if not {"name", "description", "inputSchema"} <= set(tool):
            return "malformed_tool"
    names = {t["name"] for t in frame["tools"]}
    for role in frame["roles"]:
        if not set(role["tools"]) <= names or not isinstance(
                role.get("requires_end_to_end"), bool):
            return "bad_role"
    return None


def test_example_service_registers_and_answers_one_call():
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        request_id = str(uuid.uuid4())

        async def gateway(ws):
            register = await recv_json(ws)
            reason = _gateway_validate(register)
            if reason:
                await send_json(ws, {"type": "rejected", "reason": reason})
                await ws.close(1008)
                done.set_exception(AssertionError(reason))
                return
            await send_json(ws, {"type": "registered"})
            await send_json(ws, {"type": "ping"})
            pong = await recv_json(ws)
            await send_json(ws, {
                "type": "call", "request_id": request_id, "contract_version": 1,
                "caller": {"user_id": "u-42", "client_id": "c-7"},
                "service": register["service"], "tool": "lib_selftest",
                "encryption": "none", "payload": {"text": "hello"}})
            result = await recv_json(ws)
            done.set_result((register, pong, result))
            await ws.wait_closed()

        async with fake_gateway(gateway) as url:
            service = selftest_service.build(config=make_config(url))
            runner = asyncio.create_task(service.run())
            try:
                register, pong, result = await asyncio.wait_for(done, 10)
                assert service.mode == "v1"
            finally:
                await service.stop()
                await runner
        return request_id, register, pong, result

    request_id, register, pong, result = run(main())
    assert register["roles"][0]["name"] == "selftest-user"
    assert register["tools"][0]["name"] == "lib_selftest"
    assert pong == {"type": "pong"}
    assert result == {
        "type": "result", "request_id": request_id, "encryption": "none",
        "payload": [{"type": "text", "text": "gateway-client selftest ok: user_id=u-42 "
                     "client_id=c-7 encryption=none echo=hello"}]}

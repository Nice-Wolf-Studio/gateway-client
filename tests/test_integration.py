"""End to end over a real (loopback) WebSocket: the example service against a
tiny server that behaves like the contract v2 gateway for `register` and one
`call` with a GW-3 caller token (the gateway repo's `mock_backend` flow, from
the gateway's side). `test_gateway_e2e.py` runs the real gateway."""

from __future__ import annotations

import asyncio
import pathlib
import sys
import uuid

from helpers import (APP, PRINCIPAL, Issuer, fake_gateway, make_config, recv_json, run,
                     send_json)

from gateway_client import e2e

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "examples"))
import selftest_service  # noqa: E402

REQUIRED = ("service", "credential", "public_key", "accepts_caller", "tools",
            "resources")


def _gateway_validate(frame: dict) -> str | None:
    """mcp-gateway `development` `gateway/contract.py` `validate_register`
    (the checks that need no database); the reason it would reject with, or
    None."""
    version = frame.get("contract_version")
    if isinstance(version, bool) or version != 2:
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
    return None


def test_example_service_registers_and_answers_one_call():
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        request_id = str(uuid.uuid4())
        issuer = Issuer()

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
                "type": "call", "request_id": request_id, "contract_version": 2,
                "caller_token": issuer.token(aud=register["service"]),
                "service": register["service"], "tool": "lib_selftest",
                "encryption": "none", "payload": {"text": "hello"}})
            result = await recv_json(ws)
            done.set_result((register, pong, result))
            await ws.wait_closed()

        async with fake_gateway(gateway) as url:
            service = selftest_service.build(config=make_config(url),
                                             jwks_fetch=lambda u: issuer.jwks())
            runner = asyncio.create_task(service.run())
            try:
                register, pong, result = await asyncio.wait_for(done, 10)
                assert service.mode == "v2"
            finally:
                await service.stop()
                await runner
        return request_id, register, pong, result

    request_id, register, pong, result = run(main())
    assert "roles" not in register
    assert register["tools"][0]["name"] == "lib_selftest"
    assert pong == {"type": "pong"}
    assert result == {
        "type": "result", "request_id": request_id, "encryption": "none",
        "payload": [{"type": "text", "text": f"gateway-client selftest ok: "
                     f"principal={PRINCIPAL} app={APP} encryption=none echo=hello"}]}

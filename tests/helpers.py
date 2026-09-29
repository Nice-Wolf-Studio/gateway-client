"""Test helpers: an in-process fake gateway on 127.0.0.1 (no network) and a
service factory."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any, Awaitable, Callable

from websockets.asyncio.server import ServerConnection, serve

from gateway_client import Config, GatewayService, KeyPair

TOOLS = [
    {"name": "echo", "description": "Echo text.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"]}},
    {"name": "secret_op", "description": "Needs end-to-end.",
     "inputSchema": {"type": "object"}},
]
RESOURCES = [{"uri": "svc://status", "name": "status", "mimeType": "text/plain",
              "description": "Status."}]
ROLES = [
    {"name": "echo-user", "description": "May echo.", "tools": ["echo"],
     "resources": ["svc://status"], "requires_end_to_end": False},
    {"name": "secret-user", "description": "Secret ops.", "tools": ["secret_op"],
     "resources": [], "requires_end_to_end": True},
]

Handler = Callable[[ServerConnection], Awaitable[None]]


def run(coro: Awaitable[Any], timeout: float = 20.0) -> Any:
    async def bounded() -> Any:
        return await asyncio.wait_for(coro, timeout)
    return asyncio.run(bounded())


@contextlib.asynccontextmanager
async def fake_gateway(handler: Handler):
    """Yield the ws:// URL of a loopback server running `handler` per
    connection."""
    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}/backend"


async def recv_json(ws: Any) -> dict[str, Any]:
    return json.loads(await ws.recv())


async def send_json(ws: Any, frame: dict[str, Any]) -> None:
    await ws.send(json.dumps(frame))


def make_config(url: str, *, legacy_token: str | None = None,
                key: KeyPair | None = None) -> Config:
    return Config(url=url, service_name="svc", credential="CRED-s3cr3t-value",
                  key=key or KeyPair.generate(), legacy_token=legacy_token)


async def default_on_call(tool: str, arguments: dict, caller: Any) -> Any:
    return f"echo:{arguments.get('text')}"


def make_service(url: str, *, legacy_token: str | None = None,
                 on_call: Callable | None = None, on_read: Callable | None = None,
                 sleep: Callable | None = None, rand: Callable[[], float] = lambda: 1.0,
                 key: KeyPair | None = None) -> GatewayService:
    async def fast_sleep(_delay: float) -> None:
        await asyncio.sleep(0.01)
    return GatewayService(
        tools=TOOLS, resources=RESOURCES, roles=ROLES, roles_version=1,
        on_call=on_call or default_on_call, on_read=on_read,
        config=make_config(url, legacy_token=legacy_token, key=key),
        sleep=sleep or fast_sleep, rand=rand, reply_timeout=5.0)


async def serve_until(service: GatewayService, done: asyncio.Future,
                      timeout: float = 10.0) -> Any:
    """Run `service` until `done` resolves; return its result."""
    runner = asyncio.create_task(service.run())
    try:
        return await asyncio.wait_for(done, timeout)
    finally:
        await service.stop()
        await asyncio.wait_for(runner, 5)

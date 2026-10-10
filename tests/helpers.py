"""Test helpers: an in-process fake gateway on 127.0.0.1 (no network), a
GW-3 caller-token issuer standing in for the gateway's signing key, and a
service factory."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import time
import uuid
from typing import Any, Awaitable, Callable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from websockets.asyncio.server import ServerConnection, serve

from gateway_client import Config, GatewayService, KeyPair

PRINCIPAL = "wrn:wolf-access:user/u-1a2b3c4d5e6f"
APP = "wrn:gateway:client/7f9a0b1c-0000-4000-8000-000000000001"
_KEEP = object()


class Issuer:
    """The gateway's GW-3 token issuer (mcp-gateway `gateway/caller_token.py`)
    with its own Ed25519 key, and that key's JWKS document
    (`gateway/signing_key.py` `jwks()`)."""

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.public_raw = self._key.public_key().public_bytes(Encoding.Raw,
                                                               PublicFormat.Raw)
        self.kid = hashlib.sha256(self.public_raw).digest()[:16].hex()

    def jwks(self) -> dict:
        x = base64.urlsafe_b64encode(self.public_raw).rstrip(b"=").decode()
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": self.kid,
                          "alg": "EdDSA", "use": "sig"}]}

    def claims(self, *, now: float | None = None, ttl: int = 60, sub: Any = PRINCIPAL,
               act: Any = APP, aud: Any = "svc", jti: Any = None,
               drop: tuple[str, ...] = ()) -> dict:
        now = int(time.time() if now is None else now)
        claims = {"sub": sub, "act": act, "aud": aud, "iat": now, "exp": now + ttl,
                  "jti": jti if jti is not None else str(uuid.uuid4())}
        return {k: v for k, v in claims.items() if k not in drop}

    def token(self, *, kid: Any = _KEEP, **claims: Any) -> str:
        headers = {} if kid is None else {"kid": self.kid if kid is _KEEP else kid}
        return jwt.encode(self.claims(**claims), self._key, algorithm="EdDSA",
                          headers=headers)

    def hs256_token(self, **claims: Any) -> str:
        return jwt.encode(self.claims(**claims), "x" * 32, algorithm="HS256",
                          headers={"kid": self.kid})


TOOLS = [
    {"name": "echo", "description": "Echo text.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"]}},
    {"name": "other", "description": "Another tool.",
     "inputSchema": {"type": "object"}},
]
RESOURCES = [{"uri": "svc://status", "name": "status", "mimeType": "text/plain",
              "description": "Status."}]

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


def make_config(url: str, *, key: KeyPair | None = None,
                jwks_url: str | None = None) -> Config:
    return Config(url=url, service_name="svc", credential="CRED-s3cr3t-value",
                  key=key or KeyPair.generate(), jwks_url=jwks_url)


async def default_on_call(tool: str, arguments: dict, caller: Any) -> Any:
    return f"echo:{arguments.get('text')}"


def make_service(url: str, *, issuer: Issuer | None = None,
                 on_call: Callable | None = None, on_read: Callable | None = None,
                 sleep: Callable | None = None, rand: Callable[[], float] = lambda: 1.0,
                 key: KeyPair | None = None, jwks_fetch: Callable | None = None,
                 **kwargs: Any) -> GatewayService:
    """A service whose key set is `issuer`'s (no HTTP)."""
    async def fast_sleep(_delay: float) -> None:
        await asyncio.sleep(0.01)
    if jwks_fetch is None:
        source = issuer or Issuer()
        jwks_fetch = lambda url: source.jwks()  # noqa: E731
    return GatewayService(
        tools=TOOLS, resources=RESOURCES,
        on_call=on_call or default_on_call, on_read=on_read,
        config=make_config(url, key=key), jwks_fetch=jwks_fetch,
        sleep=sleep or fast_sleep, rand=rand, reply_timeout=5.0, **kwargs)


async def serve_until(service: GatewayService, done: asyncio.Future,
                      timeout: float = 10.0) -> Any:
    """Run `service` until `done` resolves; return its result."""
    runner = asyncio.create_task(service.run())
    try:
        return await asyncio.wait_for(done, timeout)
    finally:
        await service.stop()
        await asyncio.wait_for(runner, 5)

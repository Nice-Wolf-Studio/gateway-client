#!/usr/bin/env python3
"""Drive this library against the REAL mcp-gateway (contract v2), end to end.

Run by `test_gateway_e2e.py` (or by hand) inside a checkout of
Nice-Wolf-Studio/mcp-gateway `development`, with that repository's
requirements installed alongside this library:

    cd <mcp-gateway checkout>
    TEST_DATABASE_URL=postgresql://... python <this file>

It migrates and empties the test database, seeds a service and two connected
apps of one user (one `none`, one `end-to-end`) with the gateway's own test
kit (`gateway_testkit`), starts the gateway's wolf-access stub and the
gateway as subprocesses, then runs a `GatewayService` from this library
in-process. The service registers with contract v2, fetches the gateway's
real `/.well-known/jwks.json` over HTTP, and verifies the GW-3 token of every
call. An MCP client calls its `whoami` tool through the gateway's `/mcp`:

1. `none` app: the handler sees `principal` = the user's WRN and `app` = the
   connected app's WRN, from the verified token.
2. `end-to-end` app: the client seals its arguments with the v2 associated
   data (`user_id` = principal, `client_id` = app, `contract_version` 2),
   the gateway relays the envelope untouched, the library opens it, and the
   client opens the sealed reply.

Prints one JSON object of named checks; exits 0 only when all pass.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import time

GATEWAY_DIR = os.path.abspath(os.environ.get("MCP_GATEWAY_DIR") or os.getcwd())
sys.path.insert(0, GATEWAY_DIR)
os.chdir(GATEWAY_DIR)
os.environ.setdefault("WN_WOLF_ACCESS_URL", "http://wolf-access.test")
TEST_DATABASE_URL = os.environ["TEST_DATABASE_URL"]
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

SERVICE = "gwc-e2e"
TOOL = {"name": "whoami", "description": "gateway-client e2e: who is calling.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                        "additionalProperties": False}}

checks: dict[str, tuple[bool, str]] = {}


def check(name: str, ok: bool, detail: str = "") -> None:
    checks[name] = (bool(ok), detail)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _seed():
    """Migrate, empty and seed the test database. Returns the service row,
    the user's WRN, the two apps, their access tokens and the client key."""
    proc = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                          cwd=GATEWAY_DIR, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise SystemExit(f"alembic upgrade failed:\n{proc.stderr}")
    from conftest import reset_db
    from gateway import signing_key
    from gateway_testkit import access_token, make_client, make_service, user_wrn

    from gateway_client import KeyPair
    reset_db()
    asyncio.run(signing_key.load())
    service = make_service(SERVICE, tools=("whoami",), public_key=None)
    owner = user_wrn()
    plain = make_client(owner, name="gwc-plain")
    client_key = KeyPair.generate()
    sealed = make_client(owner, name="gwc-e2e-app", encryption="end-to-end",
                         public_key=client_key.public_b64)
    return service, owner, plain, sealed, access_token(plain), access_token(sealed), \
        client_key


async def _spawn(*args: str, env: dict) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable, *args, env={**os.environ, **env}, cwd=GATEWAY_DIR,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)


async def _kill(proc) -> None:
    if proc is None or proc.returncode is not None:
        return
    proc.terminate()
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(proc.wait(), 5)
    if proc.returncode is None:
        proc.kill()


async def _wait_http(url: str, timeout: float = 45.0) -> bool:
    import urllib.request
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)  # noqa: S310 (loopback)
            return True
        except Exception:
            await asyncio.sleep(0.3)
    return False


@contextlib.asynccontextmanager
async def _mcp(mcp_url: str, token: str):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    async with streamablehttp_client(mcp_url, headers={"Authorization": f"Bearer {token}"}
                                     ) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            yield session


async def _call(mcp_url: str, token: str, args: dict):
    async with _mcp(mcp_url, token) as session:
        return await session.call_tool("whoami", args)


async def _tools(mcp_url: str, token: str) -> list[str]:
    async with _mcp(mcp_url, token) as session:
        return [t.name for t in (await session.list_tools()).tools]


async def main() -> int:
    import logging

    from gateway_client import GatewayService, KeyPair, e2e
    logging.basicConfig(level=logging.WARNING)
    (service_row, owner, plain, sealed, plain_token, sealed_token,
     client_key) = await asyncio.to_thread(_seed)
    from gateway.wrn import PLATFORM_WRN
    port, stub_port = _free_port(), _free_port()
    base = f"http://127.0.0.1:{port}"
    stub = await _spawn("wolf_access_stub.py", "--port", str(stub_port), env={
        "STUB_PRINCIPALS": json.dumps({owner: "active"}),
        "STUB_GRANTS": json.dumps([[owner, f"{SERVICE}.use", PLATFORM_WRN]]),
        "STUB_GATEWAY_JWKS_URL": f"{base}/.well-known/jwks.json"})
    gateway = await _spawn("-m", "gateway", env={
        "PORT": str(port), "HOST": "127.0.0.1", "DATABASE_URL": TEST_DATABASE_URL,
        "WN_WOLF_ACCESS_URL": f"http://127.0.0.1:{stub_port}"})
    seen: list = []

    async def on_call(tool, arguments, caller):
        seen.append(caller)
        return {"principal": caller.principal, "app": caller.app,
                "encryption": caller.encryption, "aud": caller.claims["aud"],
                "text": arguments.get("text")}

    service_key = KeyPair.generate()
    service = GatewayService(tools=[TOOL], on_call=on_call,
                             url=f"ws://127.0.0.1:{port}/backend", service_name=SERVICE,
                             credential=service_row.credential, private_key=service_key,
                             env={})
    runner = None
    try:
        up = await _wait_http(f"{base}/health")
        check("gateway boots", up)
        if not up:
            return 1
        runner = asyncio.create_task(service.run())
        try:
            await service.wait_registered(30)
            registered = True
        except asyncio.TimeoutError:
            registered = False
        check("library registers with contract v2", registered and service.mode == "v2",
              f"mode={service.mode}")
        check("key set URL derived from the backend URL",
              service.jwks_url == f"{base}/.well-known/jwks.json", service.jwks_url)
        if not registered:
            return 1
        mcp_url = f"{base}/mcp"
        names: list[str] = []
        for _ in range(40):
            with contextlib.suppress(Exception):
                names = await _tools(mcp_url, plain_token)
            if "whoami" in names:
                break
            await asyncio.sleep(0.5)
        check("tool listed through the gateway", "whoami" in names, f"tools={names}")

        # 1. `none` app.
        res = await _call(mcp_url, plain_token, {"text": "hello"})
        body = json.loads(res.content[0].text) if res.content and not res.isError else {}
        check("none: call answered", not res.isError,
              res.content[0].text if res.content else "")
        check("none: principal is the user's WRN from the verified token",
              body.get("principal") == owner, str(body.get("principal")))
        check("none: app is the connected app's WRN from the verified token",
              body.get("app") == plain.wrn, str(body.get("app")))
        check("none: token audience is this service", body.get("aud") == SERVICE)
        check("none: arguments reached the handler", body.get("text") == "hello")
        check("none: Caller.token is a forwardable compact JWT",
              bool(seen) and seen[-1].token.count(".") == 2)

        # 2. `end-to-end` app, v2 associated data.
        fields = e2e.header(user_id=owner, client_id=sealed.wrn, service=SERVICE,
                            tool="whoami")
        envelope = e2e.seal({"text": "sealed hello"}, sender=client_key,
                            recipient_public_raw=service_key.public_raw, fields=fields)
        before = len(seen)
        res = await _call(mcp_url, sealed_token, {"e2e": envelope})
        ok = not res.isError and len(seen) == before + 1
        check("e2e: call answered", ok, res.content[0].text[:120] if res.content else "")
        if ok:
            reply = json.loads(res.content[0].text)
            check("e2e: reply sealed under the service's kid",
                  reply.get("kid") == service_key.kid)
            # The gateway does not give the client the call's request_id on
            # a successful end-to-end reply; the handler's Caller has it.
            request_id = seen[-1].request_id
            opened = e2e.open_envelope(reply, recipient=client_key,
                                       sender_public_raw=service_key.public_raw,
                                       fields=e2e.reply_header(fields, request_id))
            inner = json.loads(opened[0]["text"])
            check("e2e: handler saw the plain arguments", inner.get("text") == "sealed hello")
            check("e2e: principal and app from the verified token",
                  (inner.get("principal"), inner.get("app")) == (owner, sealed.wrn),
                  str(inner))
            check("e2e: encryption is end-to-end", inner.get("encryption") == "end-to-end")
    finally:
        await service.stop()
        if runner is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(runner, 10)
        await _kill(gateway)
        await _kill(stub)
    return 0 if checks and all(ok for ok, _ in checks.values()) else 1


if __name__ == "__main__":
    code = asyncio.run(main())
    print(json.dumps({name: {"ok": ok, "detail": detail}
                      for name, (ok, detail) in checks.items()}, indent=2))
    raise SystemExit(code)

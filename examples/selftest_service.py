#!/usr/bin/env python3
"""Smallest real service: one tool, `lib_selftest`, that answers with the
verified caller it was given.

    SERVICE_NAME=... SERVICE_CREDENTIAL=... SERVICE_PRIVATE_KEY_FILE=... \
        GATEWAY_BACKEND_URL=wss://<gateway>/backend python examples/selftest_service.py

`--once` exits 0 as soon as the gateway accepts the registration (exit 1 if
it does not within 60 s): a registration smoke test.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from gateway_client import Caller, GatewayService

TOOLS = [{
    "name": "lib_selftest",
    "description": "gateway-client self test: answers with the caller it was given.",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                    "additionalProperties": False},
}]


async def on_call(tool: str, arguments: dict, caller: Caller) -> str:
    return (f"gateway-client selftest ok: principal={caller.principal} "
            f"app={caller.app} encryption={caller.encryption} "
            f"echo={arguments.get('text', '')}")


def build(**config) -> GatewayService:
    return GatewayService(tools=TOOLS, on_call=on_call, **config)


async def _once(service: GatewayService, timeout: float) -> int:
    runner = asyncio.create_task(service.run())
    try:
        await service.wait_registered(timeout)
        print(f"registered: mode={service.mode} kid={service.kid}")
        return 0
    except asyncio.TimeoutError:
        print(f"not registered within {timeout:g} s", file=sys.stderr)
        return 1
    finally:
        await service.stop()
        await runner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true",
                        help="exit after the first accepted registration")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    service = build()
    if args.once:
        raise SystemExit(asyncio.run(_once(service, args.timeout)))
    service.run_forever()


if __name__ == "__main__":
    main()

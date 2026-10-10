"""Pure (no I/O) half of the client: what the service declares, the frames
it sends, reply shaping and reconnect backoff.

Service contract version 2 (mcp-gateway `development`, `gateway/contract.py`
and `gateway/protocol.py`; docs/spec.md Interface): the `register` frame is
`{type, contract_version: 2, service, credential, public_key,
accepts_caller: true, tools, resources}`. Version 2 has no `roles` or
`roles_version`; the gateway refuses a version 1 registration with
`unsupported_contract`. There is no legacy (pre-contract) protocol.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any, Callable, Iterable

CONTRACT_VERSION = 2

RETRY_CAP_SECONDS = 30.0      # backoff cap after a dropped connection
REJECTED_CAP_SECONDS = 300.0  # backoff cap after `rejected`
BASE_DELAY_SECONDS = 1.0


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


@dataclass(frozen=True)
class Declaration:
    """What a service declares: its tools and resources. Validated on
    construction with the gateway's own section 6.1 rules
    (`gateway/contract.py` `_validate_tools` / `_validate_resources`), so a
    mistake fails at start instead of as a `rejected` loop."""

    tools: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]

    @classmethod
    def build(cls, tools: Iterable[dict], resources: Iterable[dict] = ()) -> "Declaration":
        tools, resources = list(tools), list(resources)
        tool_names: set[str] = set()
        for i, tool in enumerate(tools):
            if not (isinstance(tool, dict) and _nonempty_str(tool.get("name"))
                    and isinstance(tool.get("description"), str)
                    and isinstance(tool.get("inputSchema"), dict)):
                raise ValueError(f"tools[{i}] needs name, description and inputSchema")
            if tool["name"] in tool_names:
                raise ValueError(f"tool {tool['name']!r} declared twice")
            tool_names.add(tool["name"])
        uris: set[str] = set()
        for i, res in enumerate(resources):
            if not (isinstance(res, dict) and _nonempty_str(res.get("uri"))
                    and isinstance(res.get("name"), str)
                    and isinstance(res.get("mimeType"), str)
                    and isinstance(res.get("description"), str)):
                raise ValueError(f"resources[{i}] needs uri, name, mimeType and description")
            if res["uri"] in uris:
                raise ValueError(f"resource {res['uri']!r} declared twice")
            uris.add(res["uri"])
        return cls(tuple(tools), tuple(resources))

    # --- lookups -----------------------------------------------------------------

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(t["name"] for t in self.tools)

    def tool(self, name: str) -> dict[str, Any] | None:
        return next((t for t in self.tools if t["name"] == name), None)

    def resource(self, uri: str) -> dict[str, Any] | None:
        return next((r for r in self.resources if r["uri"] == uri), None)

    # --- frames ------------------------------------------------------------------

    def register(self, service: str, credential: str, public_key: str) -> dict[str, Any]:
        """The contract v2 `register` frame."""
        return {
            "type": "register",
            "contract_version": CONTRACT_VERSION,
            "service": service,
            "credential": credential,
            "public_key": public_key,
            "accepts_caller": True,
            "tools": list(self.tools),
            "resources": list(self.resources),
        }


# --- reply shaping ----------------------------------------------------------------

def content_blocks(value: Any) -> list[Any]:
    """A handler's tool result as MCP content blocks: a list is kept, a
    string becomes one text block, anything else one text block of its JSON."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    return [{"type": "text", "text": json.dumps(value, default=str)}]


def resource_contents(value: Any, uri: str, mime_type: str) -> list[Any]:
    """A handler's resource read as MCP contents: a list is kept, a string
    becomes one text content, anything else one text content of its JSON."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [{"uri": uri, "mimeType": mime_type, "text": value}]
    return [{"uri": uri, "mimeType": "application/json",
             "text": json.dumps(value, default=str)}]


# --- backoff ----------------------------------------------------------------------

class Backoff:
    """Exponential backoff with jitter: the wait doubles per failed attempt,
    capped at 30 s after a dropped connection and 5 minutes after `rejected`,
    and resets after a successful registration. The wait is the current step
    less up to half of it at random, so services refused together do not
    retry in step."""

    def __init__(self, rand: Callable[[], float] = random.random) -> None:
        self._rand = rand
        self._step = BASE_DELAY_SECONDS

    def reset(self) -> None:
        self._step = BASE_DELAY_SECONDS

    def next_delay(self, *, rejected: bool) -> float:
        cap = REJECTED_CAP_SECONDS if rejected else RETRY_CAP_SECONDS
        step = min(self._step, cap)
        self._step = min(step * 2, cap)
        return step * (0.5 + self._rand() / 2)

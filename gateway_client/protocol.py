"""Pure (no I/O) half of the client: what the service declares, the frames
it sends, reply shaping and reconnect backoff.

Contract version 1 is gateway spec section 6; the legacy protocol is the
pre-contract `/backend` protocol (`register {backend_token, backend_id,
tools, resources}`, `call {request_id, tool, arguments[, principal]}`,
`read_resource {request_id, uri}`, replies `result {content}` /
`resource_result {contents}` / `error {message}`).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any, Callable, Iterable

CONTRACT_VERSION = 1

RETRY_CAP_SECONDS = 30.0      # backoff cap after a dropped connection
REJECTED_CAP_SECONDS = 300.0  # backoff cap after `rejected`
BASE_DELAY_SECONDS = 1.0


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


@dataclass(frozen=True)
class Declaration:
    """What a service declares: tools, resources, roles and `roles_version`.
    Validated on construction with the gateway's own section 6.1 rules, so a
    mistake fails at start instead of as a `rejected` loop."""

    tools: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    roles: tuple[dict[str, Any], ...]
    roles_version: int

    @classmethod
    def build(cls, tools: Iterable[dict], resources: Iterable[dict] = (),
              roles: Iterable[dict] = (), roles_version: int = 1) -> "Declaration":
        tools, resources, roles = list(tools), list(resources), list(roles)
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
        role_names: set[str] = set()
        for i, role in enumerate(roles):
            if not (isinstance(role, dict) and _nonempty_str(role.get("name"))
                    and isinstance(role.get("description"), str)
                    and isinstance(role.get("tools"), list)
                    and all(_nonempty_str(t) for t in role["tools"])
                    and isinstance(role.get("resources"), list)
                    and all(_nonempty_str(r) for r in role["resources"])
                    and isinstance(role.get("requires_end_to_end"), bool)):
                raise ValueError(f"roles[{i}] needs name, description, tools, resources "
                                 "and requires_end_to_end (boolean)")
            if role["name"] in role_names:
                raise ValueError(f"role {role['name']!r} declared twice")
            role_names.add(role["name"])
            unknown = sorted(set(role["tools"]) - tool_names) + sorted(
                set(role["resources"]) - uris)
            if unknown:
                raise ValueError(f"role {role['name']!r} names undeclared {unknown}")
        if (not isinstance(roles_version, int) or isinstance(roles_version, bool)
                or roles_version < 1):
            raise ValueError("roles_version must be a positive integer")
        return cls(tuple(tools), tuple(resources), tuple(roles), roles_version)

    # --- lookups -----------------------------------------------------------------

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(t["name"] for t in self.tools)

    def tool(self, name: str) -> dict[str, Any] | None:
        return next((t for t in self.tools if t["name"] == name), None)

    def resource(self, uri: str) -> dict[str, Any] | None:
        return next((r for r in self.resources if r["uri"] == uri), None)

    def e2e_only(self) -> frozenset[str]:
        """Tool names and resource addresses in any role declared
        `requires_end_to_end`: a `none` call to them is refused."""
        out: set[str] = set()
        for role in self.roles:
            if role["requires_end_to_end"]:
                out.update(role["tools"])
                out.update(role["resources"])
        return frozenset(out)

    def role_set(self) -> frozenset:
        """The role list in the gateway's comparison form (order-free)."""
        return frozenset(
            (r["name"], r["description"], frozenset(r["tools"]),
             frozenset(r["resources"]), r["requires_end_to_end"]) for r in self.roles)

    def check_successor(self, new: "Declaration") -> None:
        """Raise ValueError when `new` would be refused `bad_role` for its
        `roles_version` (lower, or equal with a different role list)."""
        if new.roles_version < self.roles_version:
            raise ValueError(f"roles_version {new.roles_version} is lower than "
                             f"{self.roles_version}")
        if new.roles_version == self.roles_version and new.role_set() != self.role_set():
            raise ValueError("the role list changed: raise roles_version")

    # --- frames ------------------------------------------------------------------

    def v1_register(self, service: str, credential: str, public_key: str) -> dict[str, Any]:
        return {
            "type": "register",
            "contract_version": CONTRACT_VERSION,
            "service": service,
            "credential": credential,
            "public_key": public_key,
            "accepts_caller": True,
            "tools": list(self.tools),
            "resources": list(self.resources),
            "roles": list(self.roles),
            "roles_version": self.roles_version,
        }

    def legacy_register(self, token: str, backend_id: str) -> dict[str, Any]:
        return {"type": "register", "backend_token": token, "backend_id": backend_id,
                "tools": list(self.tools), "resources": list(self.resources)}


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

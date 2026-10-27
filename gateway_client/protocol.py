"""Pure (no I/O) half of the client: what the service declares, the frames
it sends, reply shaping and reconnect backoff.

Service contract version 2 (mcp-gateway `development`, `gateway/contract.py`
and `gateway/protocol.py`; docs/spec.md Interface): the `register` frame is
`{type, contract_version: 2, service, credential, public_key,
accepts_caller: true, tools, resources}`, plus the optional `instructions`
and `prompts` (additive; sent only when the service gives them, so a frame
without them is unchanged). Version 2 has no `roles` or
`roles_version`; the gateway refuses a version 1 registration with
`unsupported_contract`. There is no legacy (pre-contract) protocol.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

CONTRACT_VERSION = 2

RETRY_CAP_SECONDS = 30.0      # backoff cap after a dropped connection
REJECTED_CAP_SECONDS = 300.0  # backoff cap after `rejected`
BASE_DELAY_SECONDS = 1.0


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


ANNOTATION_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _check_annotations(i: int, annotations: Any) -> None:
    """A tool's optional MCP `annotations`, checked like the gateway does: an
    object whose hints, when present, are booleans."""
    if not isinstance(annotations, dict):
        raise ValueError(f"tools[{i}] annotations must be an object")
    for hint in ANNOTATION_HINTS:
        if hint in annotations and not isinstance(annotations[hint], bool):
            raise ValueError(f"tools[{i}] annotations.{hint} must be a boolean")


# Server instructions: at most this many characters (the gateway's own cap,
# `gateway/contract.py` MAX_INSTRUCTIONS_CHARS).
MAX_INSTRUCTIONS_CHARS = 8192

PROMPT_ROLES = ("user", "assistant")
# A prompt argument name, and a `{{name}}` placeholder in a message text.
ARGUMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def prompt_prefix(service: str) -> str:
    """Every prompt name of `service` starts with `<service>_`."""
    return f"{service}_"


def _check_instructions(instructions: Any) -> str | None:
    """Optional server instructions: a string of at most
    MAX_INSTRUCTIONS_CHARS characters; blank counts as none."""
    if instructions is None:
        return None
    if not isinstance(instructions, str):
        raise ValueError("instructions must be a string")
    if len(instructions) > MAX_INSTRUCTIONS_CHARS:
        raise ValueError(f"instructions must be at most {MAX_INSTRUCTIONS_CHARS} "
                         f"characters (got {len(instructions)})")
    return instructions if instructions.strip() else None


def _check_prompt(i: int, prompt: Any, prefix: str) -> None:
    """One MCP prompt, checked like the gateway does: `{name, description,
    arguments?, messages}`. The name starts with the service prefix; each
    argument is `{name, description?, required?}`; each message is
    `{role: user|assistant, content: {type: "text", text}}`, whose `{{arg}}`
    placeholders name declared arguments."""
    if not (isinstance(prompt, dict) and _nonempty_str(prompt.get("name"))
            and isinstance(prompt.get("description"), str)
            and isinstance(prompt.get("messages"), list) and prompt["messages"]):
        raise ValueError(f"prompts[{i}] needs name, description and messages")
    name = prompt["name"]
    if not (name.startswith(prefix) and len(name) > len(prefix)):
        raise ValueError(f"prompts[{i}] name {name!r} must start with {prefix!r}")
    arguments = prompt.get("arguments", [])
    if not isinstance(arguments, list):
        raise ValueError(f"prompts[{i}] arguments must be a list")
    declared: set[str] = set()
    for j, arg in enumerate(arguments):
        where = f"prompts[{i}] arguments[{j}]"
        if not (isinstance(arg, dict) and isinstance(arg.get("name"), str)
                and ARGUMENT_NAME.fullmatch(arg["name"])):
            raise ValueError(f"{where} needs a name of letters, digits and _")
        if "description" in arg and not isinstance(arg["description"], str):
            raise ValueError(f"{where} description must be a string")
        if "required" in arg and not isinstance(arg["required"], bool):
            raise ValueError(f"{where} required must be a boolean")
        if arg["name"] in declared:
            raise ValueError(f"prompts[{i}] argument {arg['name']!r} declared twice")
        declared.add(arg["name"])
    for j, msg in enumerate(prompt["messages"]):
        content = msg.get("content") if isinstance(msg, dict) else None
        if not (isinstance(msg, dict) and msg.get("role") in PROMPT_ROLES
                and isinstance(content, dict) and content.get("type") == "text"
                and isinstance(content.get("text"), str)):
            raise ValueError(f"prompts[{i}] messages[{j}] needs role user or assistant "
                             "and text content {type: text, text}")
        for placeholder in PLACEHOLDER.findall(content["text"]):
            if placeholder not in declared:
                raise ValueError(f"prompts[{i}] messages[{j}] placeholder "
                                 f"{placeholder!r} is not a declared argument")


@dataclass(frozen=True)
class Declaration:
    """What a service declares: its tools, resources, prompts and server
    instructions. Validated on construction with the gateway's own section
    6.1 rules (`gateway/contract.py` `_validate_tools` /
    `_validate_resources` / `_validate_prompts` / `_validate_instructions`),
    so a mistake fails at start instead of as a `rejected` loop."""

    tools: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    prompts: tuple[dict[str, Any], ...] = ()
    instructions: str | None = None

    @classmethod
    def build(cls, tools: Iterable[dict], resources: Iterable[dict] = (), *,
              prompts: Iterable[dict] = (), instructions: str | None = None,
              service: str | None = None) -> "Declaration":
        """`service` is the service's name; it is needed (to check the
        `<service>_` prefix) only when there are prompts."""
        tools, resources, prompts = list(tools), list(resources), list(prompts)
        tool_names: set[str] = set()
        for i, tool in enumerate(tools):
            if not (isinstance(tool, dict) and _nonempty_str(tool.get("name"))
                    and isinstance(tool.get("description"), str)
                    and isinstance(tool.get("inputSchema"), dict)):
                raise ValueError(f"tools[{i}] needs name, description and inputSchema")
            if "annotations" in tool:
                _check_annotations(i, tool["annotations"])
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
        if prompts and not _nonempty_str(service):
            raise ValueError("prompts need the service name, to check their prefix")
        prompt_names: set[str] = set()
        for i, prompt in enumerate(prompts):
            _check_prompt(i, prompt, prompt_prefix(service or ""))
            if prompt["name"] in prompt_names:
                raise ValueError(f"prompt {prompt['name']!r} declared twice")
            prompt_names.add(prompt["name"])
        return cls(tuple(tools), tuple(resources), tuple(prompts),
                   _check_instructions(instructions))

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
        """The contract v2 `register` frame. `instructions` and `prompts` are
        included only when declared."""
        frame = {
            "type": "register",
            "contract_version": CONTRACT_VERSION,
            "service": service,
            "credential": credential,
            "public_key": public_key,
            "accepts_caller": True,
            "tools": list(self.tools),
            "resources": list(self.resources),
        }
        if self.instructions is not None:
            frame["instructions"] = self.instructions
        if self.prompts:
            frame["prompts"] = list(self.prompts)
        return frame


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

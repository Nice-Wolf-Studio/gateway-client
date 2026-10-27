# Release Notes: `gateway-client` v0.3.0 (`v0.2.1` → `v0.3.0`)

`gateway-client` `0.3.0` (`v0.3.0:pyproject.toml:7`, `v0.3.0:gateway_client/__init__.py:24`) lets a service teach the model through the gateway: optional server **instructions** and optional MCP **prompts** in its declaration. It is **additive** to service contract version 2 (`CONTRACT_VERSION = 2` is unchanged): a service that passes neither sends exactly the `register` frame of `0.2.x` (`v0.3.0:gateway_client/protocol.py:195-198`, `v0.3.0:tests/test_prompts.py:36-38`), and a gateway that predates the fields ignores them. It also ships the tool `annotations` support merged after `v0.2.1`. No new dependencies.

---

## 1. Server instructions

- **API**: `GatewayService(..., instructions="...")` (`v0.3.0:gateway_client/service.py:171`, `:186-188`) and `await service.update(instructions="...")`; `update(instructions=None)` removes them, leaving the argument out keeps them (`_KEEP`, `v0.3.0:gateway_client/service.py:64`, `:284-307`).
- **Rule (local `ValueError`, same rule as the gateway)**: a `str` of at most `MAX_INSTRUCTIONS_CHARS = 8192` characters (`v0.3.0:gateway_client/protocol.py:48`, `:61-71`); a non-string raises `ValueError("instructions must be a string")`, a longer one `ValueError("instructions must be at most 8192 characters ...")`. Blank text counts as none and is not sent.
- **Wire**: `register` carries `"instructions": "<text>"` only when set (`v0.3.0:gateway_client/protocol.py:195-196`).
- **What the model sees**: at MCP `initialize` the gateway returns the instructions of every service the calling app may use (`<service>.use`), each under a `## <service>` header. MCP has no change notice for instructions; an app sees a change at its next `initialize`. `update(instructions=...)` therefore re-registers but announces nothing (`v0.3.0:tests/test_prompts.py:171-203`).

## 2. Prompts

- **API**: `GatewayService(..., prompts=[...])` (`v0.3.0:gateway_client/service.py:171`), `await service.update(prompts=[...])`, `await service.send_prompts_changed()` (`v0.3.0:gateway_client/service.py:350`).
- **Shape** (MCP prompt, text messages only), checked by `_check_prompt` (`v0.3.0:gateway_client/protocol.py:74-113`):
  - `name`: non-empty `str` that starts with `<SERVICE_NAME>_` and is longer than the prefix (`prompt_prefix`, `v0.3.0:gateway_client/protocol.py:56-58`); unique within the service (`v0.3.0:gateway_client/protocol.py:159-164`). The gateway also keeps it unique across services (reserved names, `name_reserved`).
  - `description`: `str` (may be empty).
  - `arguments` (optional list): each `{name, description?, required?}`; `name` matches `[A-Za-z_][A-Za-z0-9_]*` (`ARGUMENT_NAME`, `v0.3.0:gateway_client/protocol.py:52`), no duplicates, `required` a boolean.
  - `messages`: non-empty list of `{role: "user" | "assistant", content: {type: "text", text}}`; every `{{argument}}` placeholder (`PLACEHOLDER`, `v0.3.0:gateway_client/protocol.py:53`) names a declared argument.
- **No handler**: prompts are static templates. The gateway serves `prompts/list` from the declaration and renders `prompts/get` itself, replacing each `{{argument}}` with the caller's value (a missing optional argument becomes empty text; a missing required one is refused with JSON-RPC invalid params). No `caller_token` round trip happens for a prompt.
- **Wire**: `register` carries `"prompts": [...]` only when non-empty (`v0.3.0:gateway_client/protocol.py:197-198`). After an accepted `update` that changed the prompts the library sends `{"type": "prompts_changed"}` (`v0.3.0:gateway_client/service.py:311`, `:339-340`); the gateway relays it as `notifications/prompts/list_changed` to the sessions allowed to use the service.
- **Constructing with prompts needs the service name** (to check the prefix): `Declaration.build(..., prompts=[...])` without `service=` raises `ValueError` (`v0.3.0:gateway_client/protocol.py:157-158`); `GatewayService` always passes `SERVICE_NAME` (`v0.3.0:gateway_client/service.py:186-188`).

## 3. Tool annotations (since `v0.2.1`)

- A tool may carry MCP `annotations`; `Declaration.build` refuses a non-object value and a non-boolean `readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint` with `ValueError`, matching the gateway's `malformed_tool` (`v0.3.0:gateway_client/protocol.py:33-43`). Other keys pass through unchanged.

## 4. Gateway compatibility

| Gateway | Service passes neither | Service passes `instructions` / `prompts` |
|---|---|---|
| mcp-gateway before prompt support | Unchanged | Fields ignored; `prompts_changed` logged as an unknown type and ignored |
| mcp-gateway with prompt support | Unchanged | Instructions composed at `initialize`; prompts listed and rendered; bad shape → `rejected: malformed_tool`; a name another service holds → `rejected: name_reserved` |

## 5. Pinning

```
gateway-client @ https://github.com/Nice-Wolf-Studio/gateway-client/archive/refs/tags/v0.3.0.tar.gz
```

Tests: `v0.3.0:tests/test_prompts.py` (local rules, register frame, `prompts_changed` after `update`).

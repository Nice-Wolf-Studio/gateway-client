# Changelog

The version follows semantic versioning; before 1.0.0 a breaking change
raises the minor version.

## [0.4.2] - 2026-10-28

Persistent downgrade pin store and owner decision on Q2/D2 (#3).

### Added

- `FilePinStore` in `gateway_client.pins` and exported from `gateway_client`: persistent `MutableSet[str]` storing pinned connected app WRNs with atomic writes and 0600 permissions.
- `pin_store` parameter on `GatewayService`: accepts any `MutableSet[str]` (or store protocol supporting `in`, `add`, `discard`/`remove`, `clear`).
- `SERVICE_PIN_STORE_FILE` environment variable and `pin_store_file` parameter in `Config` / `Config.load()`.
- Recorded owner decision for docs/spec.md Q2 and docs/acceptance.md D2: in-memory per-process pinning is the default, maintaining the zero-disk-dependency stateless invariant and avoiding permanent breakage of legitimate user-initiated encryption mode switches in `mcp-gateway`; cross-restart persistence is opt-in via `pin_store` or `SERVICE_PIN_STORE_FILE`.

## [0.4.1] - 2026-10-28

Application-level MCP tool errors (`isError=true`) on Contract v2 (#14).

### Added

- `ToolResult(content=..., is_error=False)` helper class in `gateway_client` and `gateway_client.protocol`.
- Support for returning `ToolResult(..., is_error=True)` or mappings containing `{"isError": True, "content": ...}` (or `"is_error": True`) from `on_call` handlers without stringifying the dictionary.
- When `is_error` is True:
  - In `none` mode: the `result` frame carries `is_error: True` and unnested `payload`.
  - In `end-to-end` mode: `is_error: True` is included in the frame and cryptographically authenticated within the HPKE envelope associated data (`reply_header`), ensuring the error status cannot be flipped in transit without failing AEAD authentication.
  - The gateway emits `CallToolResult(isError=True)` without attaching a gateway error code (`_meta.gateway.code`).
  - Request tracing emits `call.end` with `outcome="tool_error"`.
- Existing backends that never set `isError` see zero wire or behavioral changes.

## [0.4.0] - 2026-10-28

Additive request tracing and structured logging on service contract version 2 (#20).

### Added

- Every routed `call` and `read_resource` emits structured `call.start` and `call.end`
  log records once the caller is verified:
  - `call.start`: `request_id`, `target` (`tool` or `uri`), `principal` (`caller.principal`),
    `app` (`caller.app`), and `encryption`.
  - `call.end`: `request_id`, `target` (`tool` or `uri`), `principal`, `app`, `encryption`,
    `duration_ms`, and `outcome` (`"result"` or error code e.g. `"not_found"`, `"bad_arguments"`,
    `"internal"`).
- `current_request_id()`: context variable helper (`contextvars.ContextVar`) that returns
  the active gateway `request_id` inside `on_call` and `on_read` handlers (across `await`
  boundaries, threads, and concurrent tasks) and `None` outside handlers.
- `RequestIdFilter`: stamps `record.request_id` on every log record, correlating a service's
  internal logs with the gateway request lifecycle.
- Structured JSON log formatting:
  - `GATEWAY_LOG_FORMAT=json` switches log formatting to single-line JSON with ISO-8601 UTC timestamps.
  - `JsonFormatter`, `configure_logging()`, and `apply_env_format()` in `gateway_client.logs`
    and exported from `gateway_client`.
- Metadata-only logging invariant: arguments, results, error text, `SERVICE_CREDENTIAL`,
  `SERVICE_PRIVATE_KEY`, and `Caller.token` are strictly never logged (zero heuristic redaction).

## 0.3.0

Additive to service contract version 2: nothing changes for a service
that passes neither new argument, and a gateway that predates them ignores
them.

### Added

- `GatewayService(instructions=...)`: optional server instructions, a
  string of at most 8192 characters (`protocol.MAX_INSTRUCTIONS_CHARS`),
  sent as `instructions` in `register`. The gateway returns the
  instructions of the services an MCP app may use at `initialize`, each
  under a header naming the service.
- `GatewayService(prompts=[...])`: optional MCP prompts, sent as `prompts`
  in `register` and served by the gateway itself (`prompts/list`,
  `prompts/get`; `{{argument}}` placeholders filled by the gateway). Each
  name starts with `<SERVICE_NAME>_`.
- `update(prompts=..., instructions=...)`, and `prompts_changed` announced
  after an accepted update that changed the prompts;
  `send_prompts_changed()`.
- Tools may carry MCP `annotations` (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`); a non-object value or a non-boolean
  hint is refused locally, as the gateway refuses it (`malformed_tool`).

## 0.2.0

Service contract version 2 (issue #15). **Breaking.** mcp-gateway
`development` refuses a version 1 registration with `unsupported_contract`,
so 0.1.x cannot connect to it, and 0.2.0 cannot connect to a gateway that
speaks only version 1.

### Added

- Every `call` and `read_resource` carries a GW-3 `caller_token`, verified
  before anything else: EdDSA signature by `kid` against the gateway's key
  set, `aud` equal to `SERVICE_NAME`, `exp` (10 s skew, at most 60 s
  lifetime), required `sub` / `act` / `aud` / `exp` / `jti`, and `jti` not
  replayed. A failure is answered `not_allowed` (`unavailable` when the key
  set cannot be fetched) and no handler runs.
- The key set (`/.well-known/jwks.json`) is fetched over HTTP, cached,
  refetched on an unknown `kid` at most once per 10 s, and refreshed hourly.
  `GATEWAY_JWKS_URL` / `jwks_url=` overrides the URL derived from the
  backend URL.
- `Caller.principal` (token `sub`), `Caller.app` (token `act`),
  `Caller.token` (the raw verified JWT) and `Caller.claims`.
- `gateway_client.caller_token` (`CallerTokenVerifier`, `KeySet`,
  `TokenRefused`, `VerifiedToken`), exported from the package.
- A test that runs the library against the real gateway
  (`tests/test_gateway_e2e.py`, opt-in; see the README).

### Changed

- `register` sends `contract_version: 2` and no `roles` / `roles_version`.
- End-to-end associated data: `contract_version` is 2, and `user_id`,
  `client_id` and `service` are the verified token's `sub`, `act` and
  `aud` (README, "End-to-end wire details").
- The end-to-end nonce replay window and the plaintext-downgrade pin are
  kept per connected app (`act`) instead of per v1 `client_id`.
- `GatewayService.mode` is `"v2"` while registered.
- `GatewayService(config=..., <configuration keyword>=...)` raises
  `TypeError` instead of silently ignoring the keyword.

### Removed

- `Caller.user_id` and `Caller.client_id`. Use `caller.principal` and
  `caller.app`; they come from the verified token, the only source of
  caller identity (INT-C3).
- `roles`, `roles_version` and `update(roles=..., roles_version=...)`.
  Contract v2 has no roles; which tools need end-to-end encryption is
  decided by wolf-access and enforced by the gateway. The local refusal of
  a `none` call to a `requires_end_to_end` role went with them.
- The legacy (pre-contract) protocol fallback, with `WN_BACKEND_TOKEN`,
  `BACKEND_ID`, `Config.legacy_token`, `Config.backend_id` and
  `Config.legacy_backend_id`. A legacy call carries no caller token, so it
  could never be served.

### Migrating from 0.1.x

1. Pin `gateway-client@v0.2.0` and deploy against a gateway that speaks
   contract v2.
2. Drop `roles=` / `roles_version=` from `GatewayService(...)`; move each
   role's permissions (and `requires_end_to_end`) to wolf-access.
3. Replace `caller.user_id` with `caller.principal` and `caller.client_id`
   with `caller.app` (both WRNs now, not ids).
4. Remove `WN_BACKEND_TOKEN` and `BACKEND_ID` from the environment.
5. Make sure the service can reach the gateway's `/.well-known/jwks.json`
   (or set `GATEWAY_JWKS_URL`).

## 0.1.1

- Refuse a v1 call or read without caller ids before the handler (#5).

## 0.1.0

- Service contract version 1 client library.

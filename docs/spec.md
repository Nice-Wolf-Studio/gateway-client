# gateway-client: spec

Status markers used on every rule below:

- **[as-built]**: true of the code at the commit named below, with a `file:line` anchor.
- **[decided]**: a ruling recorded in the access/notification
  [decision record](https://github.com/Nice-Wolf-Studio/wolf-access/blob/main/docs/decisions.md) (2026-10-01).
- **[proposed]**: a recommendation nobody has ruled on. Not a commitment.

Anchors are against **`main` at `c075232`** (tag `v0.1.0`). `main` is this repo's only long-lived
branch and its GitHub default branch, so it is the integration branch PRs target. Line numbers move;
treat the file and named symbol as the anchor and the range as a hint.

Gateway-side anchors (marked `mcp-gateway:`) are against `Nice-Wolf-Studio/mcp-gateway`
`development` at `6e4bbcc`. "Gateway spec N" means section N of
`mcp-gateway:specs/2026-09-28-users-clients-rbac.md`.

## 1. Purpose and boundaries

gateway-client is a **Python library, not a service**. A service imports it, declares its tools,
resources and roles, and supplies two callbacks; the library dials out to the Wolf MCP Gateway,
registers under service contract version 1, and turns gateway frames into plain callback calls
with a `Caller` [as-built] (`README.md:3-7`, `gateway_client/service.py:1-20`).

| Party | Owns |
|---|---|
| gateway-client (this repo) | The service end of the `/backend` WebSocket: register frame, credential and X25519 key presentation, ping/pong, call/read dispatch, the `Caller` object, end-to-end envelope open/seal, downgrade refusal, schema check in end-to-end mode, reconnect/backoff, legacy fallback, safe logging [as-built]. |
| The service that embeds it | Its tools, resources, role declarations, the handler logic, and every data-level decision about what the caller may see or change [as-built: the library makes no data-level decision; `service.py:528-581` only dispatches]. |
| MCP gateway | Identity: OAuth 2.1 sign-in, users, clients, coarse tool roles; sends each backend call with caller `{user_id, client_id}` [decided] (`mcp-gateway:gateway/app.py:237-245`). Service credentials (stored as SHA-256 hashes) and pinning of each service's public key [as-built] (`mcp-gateway:gateway/service_store.py:14-22`). |
| wolf-access | Authorization ("access governance"): principals, orgs and memberships (org management is folded in here), ownership, roles, role assignments/grants, requests, delegations, escalation, admin review cases, audit. Service plus a client library in one repo [decided]. |
| wolf-notify | Notification delivery; each user configures how they want to be notified [decided]. |

The gateway does NOT move onto wolf-access now [decided]. So the tool roles a service declares
through this library stay gateway roles, checked by the gateway before a call reaches the service
[as-built] (`mcp-gateway:gateway/app.py:206-210`).

## 2. As built

### 2.1 Components

| Module | What it does | Anchor |
|---|---|---|
| `gateway_client/__init__.py` | Public surface: `GatewayService`, `Caller`, `ServiceError`, `RegistrationRejected`, `ConfigError`, `Config`, `KeyPair`, the seven error codes; `__version__ = "0.1.0"`. | `__init__.py:4-28` |
| `gateway_client/config.py` | `Config.load`: keyword arguments win over env; requires service name and credential; URL must be `ws://`/`wss://`; loads or creates the X25519 key. | `config.py:45-67` |
| `gateway_client/protocol.py` | Pure half: `Declaration` (validated with the gateway's 6.1 rules at construction), v1 and legacy register frames, reply shaping, `Backoff`. | `protocol.py:29-141`, `169-187` |
| `gateway_client/service.py` | `GatewayService`: connect, register, serve, reconnect, `update()`, announce; `Caller` dataclass. | `service.py:61-70`, `114-624` |
| `gateway_client/e2e.py` | HPKE Auth-mode envelopes (X25519 / HKDF-SHA256 / ChaCha20-Poly1305, empty `info`) via `pyhpke`; `ReplayGuard`; `KeyPair`. | `e2e.py:1-29`, `72-73`, `204-300` |
| `gateway_client/errors.py` | Section 6.3 codes; `ServiceError(code, message)` refuses an unknown code at construction. | `errors.py:6-32` |
| `examples/selftest_service.py` | One tool `lib_selftest`, role `selftest-user`; `--once` exits 0 on accepted registration, 1 after the timeout. | `selftest_service.py:21-58` |

Dependencies: `websockets>=13,<17`, `pyhpke>=0.6.5,<0.7`, `cryptography>=42`,
`jsonschema>=4.18,<5`; Python 3.10+ [as-built] (`pyproject.toml:10-16`).

### 2.2 How a service embeds it

1. Build `GatewayService(tools=..., roles=..., roles_version=..., on_call=..., resources=..., on_read=...)`.
   The declaration is validated locally first: every tool needs `name`, `description`,
   `inputSchema`; every resource `uri`, `name`, `mimeType`, `description`; every role `name`,
   `description`, `tools`, `resources`, boolean `requires_end_to_end`; a role may only name declared
   tools/resources; no duplicates; `roles_version` a positive integer. A mistake raises at start, not
   as a `rejected` loop [as-built] (`protocol.py:40-84`, `service.py:143-144`).
2. `service.run_forever()` or `await service.run()` [as-built] (`service.py:184-219`).
3. Callbacks may be sync (run in a worker thread) or async [as-built] (`service.py:91-99`).
   A tool result may be content blocks, a string, or any JSON value [as-built] (`protocol.py:146-153`).

### 2.3 Registration handshake (contract v1, auth)

| Step | Rule | Anchor |
|---|---|---|
| Connect | Dial **out** to `GATEWAY_BACKEND_URL` (default `ws://127.0.0.1:8000/backend`); no inbound port on the service. Frame limit 5 MB; open/reply timeout 30 s. | `config.py:29`, `service.py:57-58`, `316-319` |
| Register frame | `{type: register, contract_version: 1, service, credential, public_key, accepts_caller: true, tools, resources, roles, roles_version}`. | `protocol.py:125-137` |
| Credential | `SERVICE_CREDENTIAL`, issued on the gateway's Services page; required. The gateway compares its SHA-256 against stored hashes in constant time; a mismatch is `rejected: bad_credential`. | `config.py:56-59`; `mcp-gateway:gateway/service_store.py:14-16` |
| Key | `SERVICE_PRIVATE_KEY` (base64url raw X25519), or `SERVICE_PRIVATE_KEY_FILE` (read, or created with mode 0600 via `O_EXCL`), or else a fresh key printed **once** to stderr. The gateway pins the public key at first accepted registration; a different key is `rejected: key_changed` until an admin approves it. | `config.py:70-112`; `mcp-gateway:gateway/service_store.py:17-22` |
| Reply | Waits for `registered` or `rejected {reason}`, answering any `ping` meanwhile. | `service.py:349-374` |
| Rejected | Logged once per change of reason; retried with exponential backoff and jitter capped at 300 s. A `rejected` reply **never** falls back to legacy. | `service.py:206-218`, `protocol.py:20-22`, `183-187` |
| Legacy fallback | Only when the gateway closes **without** answering the v1 register (old gateway closes 1008) **and** `WN_BACKEND_TOKEN` is set: reconnect with `{backend_token, backend_id, tools, resources}`; the next reconnect tries v1 again. | `service.py:197-203`, `protocol.py:139-141` |
| Dropped connection | Backoff capped at 30 s; reset after a successful registration. | `protocol.py:20`, `service.py:376-378` |
| Changes | `update()` re-registers on the same connection; a changed role list needs a higher `roles_version` (checked locally); accepted → `tools_changed` / `resources_changed`; rejected → previous declaration restored and `RegistrationRejected` raised. | `service.py:236-291`, `protocol.py:114-121` |

### 2.4 Call handshake (contract v1, auth)

Before a call reaches the library, the gateway has accepted the bearer token only if it is
signed and belongs to an active client of an active user; anything else is not a bearer, so the
request fails sign-in and never becomes a tool call [as-built, gateway]
(`mcp-gateway:gateway/oauth.py:416-452`). For a signed-in caller, a tool or resource the client
holds no role for is refused `not_found`, the same as a name that does not exist, and audited
[as-built, gateway] (`mcp-gateway:gateway/app.py:206-210`). It then sends the call frame with
`caller {user_id, client_id}` [decided] (`mcp-gateway:gateway/app.py:237-245`).

| Step | Rule | Anchor |
|---|---|---|
| Caller | `Caller(user_id, client_id, encryption, request_id)` built from the frame's `caller` object. | `service.py:61-70`, `535-539` |
| Logging | Logs request id, tool/uri, user_id, client_id, encryption. Never arguments, results, error text, credentials or keys; the WebSocket frame dump is held at INFO. | `service.py:49-53`, `540-542` |
| Target | Undeclared tool or resource, or a read with no `on_read`: `not_found`. | `service.py:465-472` |
| `none` mode | Refused `not_allowed` if the target is in a `requires_end_to_end` role, or the client_id was seen in end-to-end mode by **this process**. | `service.py:474-482`, `556-557`, `567-569` |
| `end-to-end` mode | Check `client_kid` matches `client_public_key`; open the envelope (kid must name the client's key; tampered/undecryptable → `bad_arguments`; `sent_at` > 5 min off or nonce reused for that client within 10 min → `not_allowed`); validate arguments against `inputSchema`; seal the reply (or error text) to the client key. | `service.py:514-526`, `548-566`, `583-597`; `e2e.py:269-300` |
| Handler error | `ServiceError(code, msg)` sends that code; any other exception sends `internal` with text `internal error`, exception text never sent or logged. | `service.py:573-581` |
| Legacy calls | `Caller.user_id` is `None`; `client_id` comes from the legacy `principal`. | `service.py:599-624` |

**Known gap** [as-built]: a v1 frame with no `caller` (or a non-object one) still runs the
handler, with `user_id=None, client_id=None` (`service.py:535-539`). Gateway spec 6.2 says both
are always present. Tracked in
[#2](https://github.com/Nice-Wolf-Studio/gateway-client/issues/2); see open question Q1.

### 2.5 Data

The library stores nothing on disk except an optionally created private-key file
(`config.py:98-112`). In memory: the replay nonces per client for 10 minutes
(`e2e.py:246-266`) and the set of client ids seen in end-to-end mode (`service.py:152`). Both are
lost on restart; the replay loss is bounded by the 5-minute `sent_at` limit (`e2e.py:248-249`), the
downgrade pin loss is not bounded. Tracked in
[#3](https://github.com/Nice-Wolf-Studio/gateway-client/issues/3); see open question Q2.

### 2.6 Distribution and CI

- Installed from git by tag: `gateway-client @ git+https://github.com/Nice-Wolf-Studio/gateway-client@v0.1.0` [as-built] (`README.md:9-11`). Nothing deploys; each service pins a tag.
- CI: one `pytest` job in a Python 3.10 / 3.12 matrix on every push and PR, so the checks report as `pytest (3.10)` and `pytest (3.12)` [as-built] (`.github/workflows/ci.yml:1-17`). No workflow creates or gates a tag. The tests run against an in-process WebSocket server on 127.0.0.1 (`README.md:104-105`).
- `main` has no branch protection (GitHub API `branches/main/protection` answers 404 at time of writing). Tracked in [#4](https://github.com/Nice-Wolf-Studio/gateway-client/issues/4).

## 3. Access integration [proposed unless marked]

This section is a proposal. Nothing here is built. Rulings that already exist are marked [decided].

### 3.1 What is decided and touches this library

- Identity stays in the MCP gateway: OAuth 2.1 sign-in, users, clients, coarse tool roles. It sends each backend call with caller `{user_id, client_id}` [decided]. The library already surfaces both on `Caller` [as-built] (`service.py:61-70`, `535-539`).
- Services (WolfNotes, finOps, later others) embed the wolf-access client library and keep their own resource types and service-specific rules [decided].
- The gateway does NOT move onto wolf-access now [decided]; it keeps the coarse tool roles, so the `roles` a service declares through this library are unchanged.
- No role = no visibility, not even existence [decided]. A caller with no role on a resource gets the same `not_found` answer as for a resource that does not exist.

Not decided, and marked so:

- That data-level checks are required and tool roles are only the outer gate is [proposed] (listed among the finOps items in the decision record, all proposed). If adopted, those checks happen in the service, using the ids the gateway sent [proposed].

### 3.2 Resource types

gateway-client owns **no resource types** and holds no resources [proposed: stays that way]. It is
transport. The resource types (notes, bank accounts, envelopes, receipts...) belong to each service.

### 3.3 How it relates to the wolf-access client library [proposed, open]

```
gateway  --call{caller:{user_id, client_id}}-->  gateway-client  --on_call(tool, args, Caller)-->  service
                                                                                                    |
                                                         wolf-access client: check(subject=Caller.user_id,
                                                           acting client=Caller.client_id, action, resource)
                                                                                                    |
                                       allowed -> handler result | no role on it -> not_found [decided]
                                                                 | role lacks the action -> open (Q9)
```

Options nobody has ruled on (listed so the choice is visible, not chosen):

- (a) gateway-client stays authorization-agnostic; each service passes `Caller.user_id` / `Caller.client_id` into the wolf-access client itself.
- (b) gateway-client gains an optional hook (e.g. an `authorize(tool, arguments, caller)` callback run before `on_call`) that a service wires to the wolf-access client.
- (c) A thin adapter in the wolf-access repo that accepts a gateway-client `Caller` directly.

The decision record also proposes an acting agent with a human sponsor (RFC 8693 `act`) and
consistency tokens returned on wolf-access writes. Whether either needs a field in the call frame
is not established; if one did, it might be a gateway contract change rather than a library-only
change (Q4).

### 3.4 What would change from today [proposed]

| Today [as-built] | Proposed |
|---|---|
| Missing `caller` runs the handler with `None` ids (`service.py:535-539`, #2). | Whether to refuse such a call before the handler is open (Q1). |
| `Caller` carries user_id, client_id, encryption, request_id only. | Possibly an actor/sponsor field, if the gateway contract adds one (Q4). |
| Error codes are the gateway's 6.3 set; the service picks `not_found` vs `not_allowed`. | The `not_found` answer for a resource the caller has no role on is [decided]. Whether this library documents or enforces it is [proposed] and open (Q5). |

## 4. Notifications via wolf-notify [proposed]

gateway-client emits and consumes **no notifications** today [as-built: no notification code in
`gateway_client/`]. Proposed: it stays that way.

- Approval requests, timeouts and decisions are wolf-access events: the proposed wolf-notify spec
  lists wolf-access as their producer (Nice-Wolf-Studio/wolf-notify#2, sections 3 and 4) [proposed].
  Neither this library nor the services that embed it emit them.
- A `key_changed` rejection is recorded by the gateway in its audit log [as-built, gateway]
  (`mcp-gateway:gateway/service_store.py:49-56`); if anyone notifies an admin about it, the gateway
  would be the producer (Q7).
- The same wolf-notify spec lists "gateway backend frame" as one candidate event transport
  (section 3, transport open). If chosen, it would touch this library (Q7).

This spec names no event types, so the wolf-access / wolf-notify event-name difference does not
arise here.

## 5. Open questions

- **Q1.** Should a v1 call or read with no `caller` (or no `user_id`/`client_id`) be refused before the handler runs, and if so with which error code (`bad_arguments` or `internal`)? Tracked in #2.
- **Q2.** Should the end-to-end downgrade pin (client ids seen in end-to-end mode) survive a restart, and if so where is it stored, given the library stores nothing today? Tracked in #3.
- **Q3.** Which of options (a), (b), (c) in 3.3 links this library to the wolf-access client, or something else?
- **Q4.** Does the caller frame need an acting-agent / sponsor field or a consistency token for wolf-access, and if so is that a contract v2?
- **Q5.** Should the library enforce the decided not-found rule for resources the caller has no role on, or only document it?
- **Q6.** Should `main` get branch protection requiring the CI checks `pytest (3.10)` and `pytest (3.12)` (there is no check named plain `pytest`), and should this repo adopt a `development` integration branch like mcp-gateway? Tracked in #4.
- **Q7.** Should anything about service registration (e.g. `key_changed`) be sent to admins through wolf-notify, and is that the gateway's job? Should wolf-notify events travel over the gateway backend frame (one of wolf-notify#2's candidate transports), which would touch this library?
- **Q8.** Every running gateway already speaks only contract v1 (`mcp-gateway` `development` `6e4bbcc` and `main` `c3448d4`: `gateway/protocol.py:1-10`, `gateway/contract.py:8-11`), so the legacy fallback (`WN_BACKEND_TOKEN`, `service.py:197-203`) only fires against a pre-contract gateway. Should it be removed, and when?
- **Q9.** When a caller holds a role on a resource but the role lacks the requested action, should the service answer `not_allowed` or `not_found`? The decided rule covers only "no role".

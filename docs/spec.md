# gateway-client: spec

Status markers used on every rule below:

- **[as-built]**: true of the code at the commit named below, with a `file:line` anchor.
- **[decided]**: a ruling recorded in the access/notification
  [decision record](https://github.com/Nice-Wolf-Studio/wolf-access/blob/main/docs/decisions.md) (2026-10-01).
  Where service contract v2 contradicts one, the ruling's text is kept and a note
  "superseded by the v2 cutover" cites the code or gateway rule that differs.
- **[proposed]**: a recommendation nobody has ruled on. Not a commitment.

Anchors are against **`development` at `23e25d0`** (tags `v0.2.0` and `v0.2.1`; service contract
version 2). `development` was created from `main` at that commit; `main` is the GitHub default
branch. Which of the two PRs target is not stated in this repo's files (Q6). The library code at
`23e25d0` is the code of `197f3b8`; `RELEASE.md` describes the `v0.1.1` -> `197f3b8` changes. Line
numbers move; treat the file and named symbol as the anchor and the range as a hint.

Gateway-side anchors (marked `mcp-gateway:`) are against `Nice-Wolf-Studio/mcp-gateway`
`development` at `e2e46d7`. Code anchors there are marked [as-built, gateway]; anchors to its
`docs/spec.md` rules (GW-n) are marked [gateway spec]. "Gateway spec N" means section N of
`mcp-gateway:specs/2026-09-28-users-clients-rbac.md`.

## 1. Purpose and boundaries

gateway-client is a **Python library, not a service**. A service imports it, declares its tools
and resources, and supplies two callbacks; the library dials out to the Wolf MCP Gateway,
registers under service contract version 2, verifies each call's GW-3 caller token, and turns
gateway frames into plain callback calls with a `Caller` [as-built] (`README.md:3-8`,
`gateway_client/service.py:1-22`).

| Party | Owns |
|---|---|
| gateway-client (this repo) | The service end of the `/backend` WebSocket: register frame, credential and X25519 key presentation, ping/pong, GW-3 caller-token verification against the gateway's key set, call/read dispatch, the `Caller` object, end-to-end envelope open/seal, downgrade refusal, schema check in end-to-end mode, reconnect/backoff, safe logging [as-built]. There is no legacy fallback since v0.2.0 (`protocol.py:9`, `CHANGELOG.md:53-56`). |
| The service that embeds it | Its tools, resources, the handler logic, and every data-level decision about what the caller may see or change [as-built: the library makes no data-level decision; `service.py:550-607` only verifies the token, checks the target and envelope, and dispatches]. |
| MCP gateway | Identity: OAuth 2.1 sign-in, users, clients, coarse tool roles; sends each backend call with caller `{user_id, client_id}` [decided] (`mcp-gateway:gateway/app.py:237-245` at `6e4bbcc`). **Superseded by the v2 cutover:** accounts and roles left the gateway (`mcp-gateway:docs/spec.md:37`, `:39`), and each call carries a GW-3 `caller_token` (`sub` principal WRN, `act` connected app WRN, `aud` the backend) instead of a `caller` object [as-built, gateway] (`mcp-gateway:gateway/protocol.py:10-18`, `:471-485`; `mcp-gateway:gateway/caller_token.py:23-31`). Service credentials stored as SHA-256 hashes and compared in constant time [as-built, gateway] (`mcp-gateway:gateway/contract.py:151-168`); each service's public key stored, a different one refused `key_changed` and kept as the pending key until an admin approves it [as-built, gateway] (`mcp-gateway:gateway/contract.py:48`) [gateway spec] (`mcp-gateway:docs/spec.md:27`, `:68`). |
| wolf-access | Authorization ("access governance"): principals, orgs and memberships (org management is folded in here), ownership, roles, role assignments/grants, requests, delegations, escalation, admin review cases, audit. Service plus a client library in one repo [decided]. |
| wolf-notify | Notification delivery; each user configures how they want to be notified [decided]. |

The gateway does NOT move onto wolf-access now [decided]. So the tool roles a service declares
through this library stay gateway roles, checked by the gateway before a call reaches the service.
**Superseded by the v2 cutover:** a service declares no roles (the register frame has no `roles` or
`roles_version`) [as-built] (`protocol.py:4-9`, `78-89`); the gateway lists a backend's tools, and
sends its change notices, only to callers wolf-access allows `<service>.use`, and every
authorization request carries the connected app's WRN and encryption mode [gateway spec]
(`mcp-gateway:docs/spec.md:39`, `:66`, `:69`).

## 2. As built

### 2.1 Components

| Module | What it does | Anchor |
|---|---|---|
| `gateway_client/__init__.py` | Public surface: `GatewayService`, `Caller`, `ServiceError`, `RegistrationRejected`, `ConfigError`, `Config`, `KeyPair`, `CallerTokenVerifier`, `KeySet`, `TokenRefused`, `VerifiedToken`, `CONTRACT_VERSION`, the seven error codes; `__version__ = "0.2.0"`. | `__init__.py:5-31` |
| `gateway_client/config.py` | `Config.load`: keyword arguments win over env; requires service name and credential; URL must be `ws://`/`wss://`; optional `GATEWAY_JWKS_URL` must be `https://`/`http://`; loads or creates the X25519 key. `key_set_url` is `jwks_url`, else derived from the backend URL. | `config.py:40-68` |
| `gateway_client/protocol.py` | Pure half: `Declaration` (tools and resources, validated with the gateway's 6.1 rules at construction), the v2 register frame, reply shaping, `Backoff`. | `protocol.py:30-89`, `94-135` |
| `gateway_client/caller_token.py` | GW-3 caller-token checks: `CallerTokenVerifier` (EdDSA signature by `kid`, `aud`, `exp`, required claims, `jti` replay), `KeySet` (cached JWKS fetch, rate-limited refetch), `TokenRefused`, `VerifiedToken`, `jwks_url_for`. | `caller_token.py:1-41`, `74-297` |
| `gateway_client/service.py` | `GatewayService`: connect, register, serve, verify each frame's token, reconnect, `update()`, announce; `Caller` dataclass. | `service.py:66-93`, `137-624` |
| `gateway_client/e2e.py` | HPKE Auth-mode envelopes (X25519 / HKDF-SHA256 / ChaCha20-Poly1305, empty `info`) via `pyhpke`; contract v2 associated data; `ReplayGuard`; `KeyPair`. | `e2e.py:1-43`, `79-84`, `191-316` |
| `gateway_client/errors.py` | Section 6.3 codes; `ServiceError(code, message)` refuses an unknown code at construction. | `errors.py:6-45` |
| `examples/selftest_service.py` | One tool `lib_selftest`, no roles; answers with the verified `principal` and `app`; `--once` exits 0 on accepted registration, 1 after the timeout. | `selftest_service.py:21-50` |

Dependencies: `websockets>=13,<17`, `pyhpke>=0.6.5,<0.7`, `cryptography>=42`,
`jsonschema>=4.18,<5`, `PyJWT[crypto]>=2.8,<3`; Python 3.10+ [as-built] (`pyproject.toml:10-17`).

### 2.2 How a service embeds it

1. Build `GatewayService(tools=..., on_call=..., resources=..., on_read=...)` [as-built]
   (`service.py:161-177`). The declaration is validated locally first: every tool needs a
   non-empty `name`, a string `description` and an object `inputSchema`; every resource a
   non-empty `uri` and string `name`, `mimeType`, `description`; no duplicate tool names or
   resource URIs. A mistake raises `ValueError` at start, not as a `rejected` loop [as-built]
   (`protocol.py:40-62`, `service.py:177`). `roles=` / `roles_version=` no longer exist and raise
   `TypeError` [as-built] (`tests/test_service.py:97-102`). Passing both `config=` and
   configuration keyword arguments raises `TypeError` [as-built] (`service.py:173-175`).
2. `service.run_forever()` or `await service.run()` [as-built] (`service.py:227-256`).
3. Callbacks may be sync (run in a worker thread) or async [as-built] (`service.py:114-122`).
   A tool result may be content blocks, a string, or any JSON value [as-built] (`protocol.py:94-101`).

### 2.3 Registration handshake (contract v2, auth)

| Step | Rule | Anchor |
|---|---|---|
| Connect | Dial **out** to `GATEWAY_BACKEND_URL` (default `ws://127.0.0.1:8000/backend`); no inbound port on the service. Frame limit 5 MB; open/reply timeout 30 s. | `config.py:29`, `service.py:60-61`, `336-338` |
| Register frame | `{type: register, contract_version: 2, service, credential, public_key, accepts_caller: true, tools, resources}`. The gateway refuses any other `contract_version` with `unsupported_contract` and requires exactly these fields. | `protocol.py:78-89`; `mcp-gateway:gateway/contract.py:63-66`, `245-257` |
| Credential | `SERVICE_CREDENTIAL`, issued on the gateway's Services page; required. The gateway compares its SHA-256 against stored hashes in constant time; a mismatch is `rejected: bad_credential`. Expired or retired credentials are refused (GW-6). | `config.py:55-59`; `mcp-gateway:gateway/contract.py:43`, `151-168`; `mcp-gateway:docs/spec.md:28`, `:65` |
| Key | `SERVICE_PRIVATE_KEY` (base64url raw X25519), or `SERVICE_PRIVATE_KEY_FILE` (read, or created with mode 0600 via `O_EXCL`), or else a fresh key printed **once** to stderr. The gateway stores the service's public key; a different key is `rejected: key_changed` and kept as the pending key until an admin approves it. | `config.py:71-113`; `mcp-gateway:gateway/contract.py:48`; `mcp-gateway:docs/spec.md:27`, `:68` |
| Reply | Waits for `registered` or `rejected {reason}`, answering any `ping` meanwhile. Gateway reasons: `bad_credential`, `unsupported_contract`, `missing_field`, `malformed_tool`, `name_reserved`, `key_changed`. | `service.py:365-390`; `mcp-gateway:gateway/contract.py:42-52` |
| Rejected | Logged once per change of reason; retried with exponential backoff and jitter capped at 300 s. | `service.py:246-255`, `protocol.py:21-22`, `131-135` |
| Legacy fallback | Removed in v0.2.0: there is no legacy (pre-contract) protocol, `WN_BACKEND_TOKEN` and `BACKEND_ID` are gone. A gateway that closes **without** answering the register (or no reply within 30 s) is retried with contract v2 and backoff capped at 30 s. | `protocol.py:9`, `service.py:343-348`, `251-255`; `CHANGELOG.md:53-56`; `tests/test_config.py:44-51` |
| Dropped connection | Backoff capped at 30 s; reset after a successful registration. | `protocol.py:21`, `service.py:392-394` |
| Changes | `update(tools=..., resources=...)` re-registers on the same connection; accepted → `tools_changed` if the tools changed, `resources_changed` if the resources changed (with `announce=True`); rejected → previous declaration restored, `RegistrationRejected` raised, and the 300 s cap applies after the disconnect. | `service.py:273-316`, `356-358` |

### 2.4 Call handshake (contract v2, auth)

The gateway lists a backend's tools only to callers wolf-access allows `<service>.use`, and a
token check refuses a disabled user or agent [gateway spec] (`mcp-gateway:docs/spec.md:66`,
`:71`). For every routed call it issues a fresh GW-3 token for that one backend, `sub` the
principal, `act` the connected app's WRN, `aud` the backend's name, `exp` at most 60 s after
`iat`, a `jti`, signed EdDSA under its own key with the `kid` in the header, and sends it as the
frame's `caller_token` [as-built, gateway] (`mcp-gateway:gateway/caller_token.py:23-31`,
`mcp-gateway:gateway/protocol.py:471-485`). The key set is published at
`/.well-known/jwks.json` [gateway spec] (`mcp-gateway:docs/spec.md:72`, `:82`). The caller's
identity reaches a backend no other way [as-built, gateway] (`mcp-gateway:gateway/protocol.py:16-18`).

| Step | Rule | Anchor |
|---|---|---|
| Caller token | Verified **first** on every `call` and `read_resource`: a non-empty string; compact JWS with header `alg: EdDSA` and a non-empty `kid`; `kid` in the key set; signature verifies; `sub`, `act`, `aud`, `exp`, `jti` present; `sub`, `act`, `jti` non-blank strings; `aud` a string equal to `SERVICE_NAME` (a list is refused); `exp` not passed (10 s leeway) and at most 60 s + leeway ahead; `jti` not accepted before while the token could be valid. A failure answers `not_allowed` with payload `caller token refused`; a key set that cannot be fetched answers `unavailable` with `caller token could not be checked; retry`. No handler runs. | `service.py:62-63`, `537-548`, `568`; `caller_token.py:243-297` |
| Key set | Derived from the backend URL (`wss://` → `https://`, `ws://` → `http://`, `/backend` → `/.well-known/jwks.json`) unless `GATEWAY_JWKS_URL` / `jwks_url=` is set. Fetched on first use (5 s timeout, 64 KiB cap), kept 1 h; an unknown `kid` triggers a refetch; fetches at least 10 s apart; concurrent checks share one fetch; a failed refresh keeps the cached keys. Only `kty OKP`, `crv Ed25519` keys with a `kid` are used. | `caller_token.py:95-132`, `155-214`; `config.py:40-43`, `64-66` |
| Caller | `Caller(principal, app, encryption, request_id, token, claims)` built from the verified token only: `principal` = `sub`, `app` = `act`, `token` the raw JWT (`repr=False`), `claims` read-only. Frame fields such as a v1 `caller` object are ignored. | `service.py:66-93`, `569-570`; `caller_token.py:265-266`; `tests/test_service.py:437-448` |
| Logging | Logs request id, tool/uri, encryption, and the verified `principal` and `app`; a token refusal is logged once at WARNING with the failed check. Never arguments, results, error text, credentials, keys or tokens; the WebSocket frame dump is held at INFO. | `service.py:21`, `54-57`, `545-546`, `563-564`, `571-572`; `tests/test_service.py:276-294`, `424-434` |
| Target | Undeclared tool or resource, or a read with no `on_read`: `not_found`. | `service.py:475-482`, `584` |
| `none` mode | Refused `not_allowed` if the connected app (`act`) was seen in end-to-end mode by **this process**. The local refusal of a `none` call to a `requires_end_to_end` role was removed in v0.2.0; which tools need end-to-end is wolf-access's decision, enforced by the gateway. | `service.py:484-491`, `583`, `594`; `CHANGELOG.md:49-52`; `README.md:95` |
| `end-to-end` mode | Check `client_kid` matches `client_public_key`; build the associated data from the verified token (`user_id` = `sub`, `client_id` = `act`, `service` = `aud`, `contract_version: 2`); open the envelope (kid must name the client's key; tampered/undecryptable or bound to other ids → `bad_arguments`; `sent_at` > 5 min off or nonce reused by that app within 10 min → `not_allowed`); validate arguments against `inputSchema`; seal the reply (or error text) to the client key. A token refusal is sent unsealed. | `service.py:523-535`, `575-592`, `609-624`; `e2e.py:191-211`, `285-316` |
| Handler error | `ServiceError(code, msg)` sends that code; any other exception sends `internal` with text `internal error`, exception text never sent or logged. | `service.py:599-607` |
| Legacy calls | Removed in v0.2.0: a legacy call carries no caller token, so it could never be served. | `CHANGELOG.md:53-56` |

**Known gap: resolved in v0.1.1, superseded in v0.2.0** [as-built, `development` `23e25d0`]. At
`c075232`, a v1 frame with no `caller` (or a non-object one) still ran the handler with
`user_id=None, client_id=None` (`service.py:535-539` at `c075232`). v0.1.1 (`b4b05a2`, PR
[#5](https://github.com/Nice-Wolf-Studio/gateway-client/pull/5), issue
[#2](https://github.com/Nice-Wolf-Studio/gateway-client/issues/2)) refused a v1 call or read
whose `caller.user_id` and `caller.client_id` were not both non-empty, non-blank strings with
`not_allowed`, logged once at WARNING (anchors at `b4b05a2`: `service.py:115-117`, `566-570`,
`594-596`). v0.2.0 removed the `caller` object as an identity source: a call or read reaches the
handler only when its `caller_token` verifies; anything else, including a missing, `null` or
non-string token, is answered `not_allowed` (or `unavailable` when the key set cannot be fetched)
and logged once at WARNING with its request id and the failed check, never the token or payload
(`service.py:537-548`, `568`; `tests/test_service.py:331-354`, `413-434`). Q1 is resolved.

### 2.5 Data

The library stores nothing on disk except an optionally created private-key file
(`config.py:99-113`). In memory: the end-to-end replay nonces per connected app for 10 minutes
(`e2e.py:84`, `262-283`; `service.py:591`), the set of connected app WRNs seen in end-to-end mode
(`service.py:190`), the accepted caller-token `jti`s until each token's `exp` plus leeway
(`caller_token.py:227`, `264`), and the cached gateway key set (`caller_token.py:147-148`). All are
lost on restart. The nonce loss is bounded by the 5-minute `sent_at` limit (`e2e.py:83`,
`299-300`); the `jti` loss by the token lifetime of at most 60 s plus leeway
(`caller_token.py:61-62`, `294-297`); the downgrade pin loss is not bounded. Tracked in
[#3](https://github.com/Nice-Wolf-Studio/gateway-client/issues/3); see open question Q2.

### 2.6 Distribution and CI

- Installed from git by tag: `gateway-client @ git+https://github.com/Nice-Wolf-Studio/gateway-client@v0.2.0` [as-built] (`README.md:11`). Nothing deploys; each service pins a tag. Tags `v0.2.0` and `v0.2.1` both point at `23e25d0`, whose package version is `0.2.0` (`pyproject.toml:7`, `__init__.py:24`).
- CI: one `pytest` job in a Python 3.10 / 3.12 matrix on every push and PR, so the checks report as `pytest (3.10)` and `pytest (3.12)` [as-built] (`.github/workflows/ci.yml:1-17`). No workflow creates or gates a tag. The tests run against an in-process WebSocket server on 127.0.0.1 with an in-process token issuer (`README.md:140-142`). `tests/test_gateway_e2e.py` runs the library against the real gateway and is skipped unless `MCP_GATEWAY_DIR` and `TEST_DATABASE_URL` are set, so CI does not run it (`README.md:144-156`).
- Classic branch protection is still absent on `main` and `development` (GitHub API `branches/<branch>/protection` answers 404 at time of writing). Repository rulesets `platform-main` and `platform-development` (created 2026-10-24, active) cover them: no deletion, no force-push, changes through a PR with no approving review required, and required checks `pytest (3.10)` and `pytest (3.12)` on an up-to-date branch (GitHub API `rulesets/25791452`, `rulesets/25794050`). Issue [#4](https://github.com/Nice-Wolf-Studio/gateway-client/issues/4) is still open.

## 3. Access integration [proposed unless marked]

This section is a proposal. Nothing here is built. Rulings that already exist are marked [decided].

### 3.1 What is decided and touches this library

- Identity stays in the MCP gateway: OAuth 2.1 sign-in, users, clients, coarse tool roles. It sends each backend call with caller `{user_id, client_id}` [decided]. **Superseded by the v2 cutover:** users and roles left the gateway, and each call carries a GW-3 `caller_token` instead (`mcp-gateway:docs/spec.md:37`, `:39`, `:62`; `mcp-gateway:gateway/protocol.py:10-18`). The library surfaces the verified token's `sub` and `act` as `Caller.principal` and `Caller.app` [as-built] (`service.py:81-93`).
- Services (WolfNotes, finOps, later others) embed the wolf-access client library and keep their own resource types and service-specific rules [decided].
- The gateway does NOT move onto wolf-access now [decided]; it keeps the coarse tool roles, so the `roles` a service declares through this library are unchanged. **Superseded by the v2 cutover:** the library declares no roles (`protocol.py:78-89`) and the gateway asks wolf-access whether a caller may use a backend (`mcp-gateway:docs/spec.md:39`, `:66`, `:69`).
- No role = no visibility, not even existence [decided]. A caller with no role on a resource gets the same `not_found` answer as for a resource that does not exist.

Not decided, and marked so:

- That data-level checks are required and tool roles are only the outer gate is [proposed] (listed among the finOps items in the decision record, all proposed). If adopted, those checks happen in the service, using the ids the gateway sent (under v2: `Caller.principal` / `Caller.app`) [proposed]. The gateway's own spec states that each backend decides access to its own records (GW-7, `mcp-gateway:docs/spec.md:66`).

### 3.2 Resource types

gateway-client owns **no resource types** and holds no resources [proposed: stays that way]. It is
transport. The resource types (notes, bank accounts, envelopes, receipts...) belong to each service.

### 3.3 How it relates to the wolf-access client library [proposed, open]

```
gateway  --call{caller_token: sub, act, aud}-->  gateway-client  --on_call(tool, args, Caller)-->  service
                                                                                                    |
                                                         wolf-access client: check(subject=Caller.principal,
                                                           acting app=Caller.app, action, resource)
                                                                                                    |
                                       allowed -> handler result | no role on it -> not_found [decided]
                                                                 | role lacks the action -> open (Q9)
```

Options nobody has ruled on (listed so the choice is visible, not chosen):

- (a) gateway-client stays authorization-agnostic; each service passes `Caller.principal` / `Caller.app` (named `Caller.user_id` / `Caller.client_id` before v0.2.0) into the wolf-access client itself.
- (b) gateway-client gains an optional hook (e.g. an `authorize(tool, arguments, caller)` callback run before `on_call`) that a service wires to the wolf-access client.
- (c) A thin adapter in the wolf-access repo that accepts a gateway-client `Caller` directly.

The decision record also proposes an acting agent with a human sponsor (RFC 8693 `act`) and
consistency tokens returned on wolf-access writes. Whether either needs a field in the call frame
is not established; if one did, it might be a gateway contract change rather than a library-only
change (Q4).

### 3.4 What would change from today [proposed]

| Today [as-built] | Proposed |
|---|---|
| A call or read without a verifying `caller_token` is refused `not_allowed` (or `unavailable`) before the handler (`service.py:537-548`, `568`). At `c075232` a missing `caller` ran the handler with `None` ids (#2). | Resolved in v0.1.1 (`b4b05a2`), superseded by the v0.2.0 caller-token check (Q1, AC 24). |
| `Caller` carries `principal`, `app`, `encryption`, `request_id`, `token`, `claims` (`service.py:81-86`). | Possibly an actor/sponsor field, if the gateway contract adds one (Q4). |
| Error codes are the gateway's 6.3 set (`errors.py:6-15`; `mcp-gateway:gateway/contract.py:55-58`); the service picks `not_found` vs `not_allowed`. | The `not_found` answer for a resource the caller has no role on is [decided]. Whether this library documents or enforces it is [proposed] and open (Q5). |

## 4. Notifications via wolf-notify [proposed]

gateway-client emits and consumes **no notifications** today [as-built: no notification code in
`gateway_client/`; the only change announcements are the contract's `tools_changed` /
`resources_changed`, `service.py:318-324`]. Proposed: it stays that way.

- Approval requests, timeouts and decisions are wolf-access events: the proposed wolf-notify spec
  lists wolf-access as their producer (Nice-Wolf-Studio/wolf-notify#2, sections 3 and 4) [proposed].
  Neither this library nor the services that embed it emit them.
- A `key_changed` rejection is logged and audited by the gateway [as-built, gateway]
  (`mcp-gateway:gateway/protocol.py:247-251`, `267-269`); if anyone notifies an admin about it,
  the gateway would be the producer (Q7).
- The same wolf-notify spec lists "gateway backend frame" as one candidate event transport
  (section 3, transport open). If chosen, it would touch this library (Q7).

This spec names no event types, so the wolf-access / wolf-notify event-name difference does not
arise here.

## 5. Open questions

- **Q1. Resolved by v0.1.1** (`b4b05a2`, #2 closed): a v1 call or read without valid caller ids is refused before the handler runs, with `not_allowed`. Superseded in v0.2.0 by the caller-token check: no frame reaches a handler without a verified `caller_token` (`service.py:537-548`, `568`). Question was: should a v1 call or read with no `caller` (or no `user_id`/`client_id`) be refused before the handler runs, and if so with which error code (`bad_arguments` or `internal`)?
- **Q2.** Should the end-to-end downgrade pin (connected app WRNs seen in end-to-end mode, `service.py:190`) survive a restart, and if so where is it stored, given the library stores nothing today? Tracked in #3.
- **Q3.** Which of options (a), (b), (c) in 3.3 links this library to the wolf-access client, or something else?
- **Q4.** Does the caller frame need an acting-agent / sponsor field or a consistency token for wolf-access, and if so is that a contract v2? Contract v2 shipped with a GW-3 token carrying `sub` (the principal: a user, or the agent the app acts for), `act` (the connected app WRN), `aud`, `iat`, `exp`, `jti`, and no sponsor or consistency-token field (`mcp-gateway:gateway/caller_token.py:23-31`; `service.py:73-75`). Whether one is needed is still open.
- **Q5.** Should the library enforce the decided not-found rule for resources the caller has no role on, or only document it? Under v2 the library holds no roles at all (`protocol.py:30-38`).
- **Q6.** Should `main` get branch protection requiring the CI checks `pytest (3.10)` and `pytest (3.12)` (there is no check named plain `pytest`), and should this repo adopt a `development` integration branch like mcp-gateway? Tracked in #4. At time of writing a `development` branch exists and rulesets on `main` and `development` require those two checks (2.6); #4 is still open.
- **Q7.** Should anything about service registration (e.g. `key_changed`) be sent to admins through wolf-notify, and is that the gateway's job? Should wolf-notify events travel over the gateway backend frame (one of wolf-notify#2's candidate transports), which would touch this library?
- **Q8. Resolved by v0.2.0:** the legacy fallback, `WN_BACKEND_TOKEN` and `BACKEND_ID` were removed (`protocol.py:9`; `CHANGELOG.md:53-56`; `tests/test_config.py:44-51`), and the gateway refuses any `contract_version` other than 2 (`mcp-gateway:gateway/contract.py:245-247`). Question was: every running gateway already speaks only contract v1 (`mcp-gateway` `development` `6e4bbcc` and `main` `c3448d4`: `gateway/protocol.py:1-10`, `gateway/contract.py:8-11`), so the legacy fallback (`WN_BACKEND_TOKEN`, `service.py:197-203` at `c075232`) only fires against a pre-contract gateway. Should it be removed, and when?
- **Q9.** When a caller holds a role on a resource but the role lacks the requested action, should the service answer `not_allowed` or `not_found`? The decided rule covers only "no role".

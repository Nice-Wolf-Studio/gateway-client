# gateway-client: acceptance criteria

Each criterion can fail. "Fake gateway" means the in-process WebSocket server the tests use
(`tests/helpers.py`). Anchors are against `main` at `c075232`, except AC 24, which is anchored
at `b4b05a2` (v0.1.1). AC 1-20 and AC 24 are as-built behavior; AC 21-23 check decided rules that
apply to this library. The last section is not acceptance criteria yet: it lists the tracked
defect whose required behavior depends on an open question (D1 became AC 24).

## Configuration and keys

1. `Config.load` with no service name or no credential raises `ConfigError` (`config.py:57-59`).
2. A `GATEWAY_BACKEND_URL` not starting with `ws://` or `wss://` raises `ConfigError` (`config.py:60-61`).
3. With no key configured, a key is generated and its private key is written to stderr exactly once; a second `Config.load` with the printed value yields the same `kid` (`config.py:84-95`).
4. `SERVICE_PRIVATE_KEY_FILE` pointing at a missing file creates it with mode `0600`; a second load reuses the same key (`config.py:98-112`).
5. `repr(KeyPair)` and `repr(Config)` contain neither the private key, the credential, nor the legacy token (`e2e.py:163-164`, `config.py:36-38`).

## Registration

6. The first frame sent is `register` with `contract_version: 1`, `service`, `credential`, `public_key`, `accepts_caller: true`, `tools`, `resources`, `roles`, `roles_version` (`protocol.py:125-137`).
7. A declaration with a role naming an undeclared tool, a duplicate tool, or `roles_version < 1` raises `ValueError` at construction and sends nothing (`protocol.py:40-84`).
8. After `rejected`, retries back off exponentially to a 300 s cap, the reason is logged once per change, and no legacy register is ever sent, even with `WN_BACKEND_TOKEN` set (`service.py:206-218`).
9. When the fake gateway closes 1008 without a reply and `WN_BACKEND_TOKEN` is set, the next frame is the legacy register; without the token, no legacy frame is sent (`service.py:197-203`).
10. `update()` with a changed role list and the same `roles_version` raises `ValueError`; with `announce=True`, an accepted update that changes tools or roles sends `tools_changed`, and one that changes resources or roles sends `resources_changed`; a rejected update raises `RegistrationRejected` and restores the previous declaration (`service.py:236-291`).
11. Every `ping` is answered with `pong`, including before `registered` arrives (`service.py:369-370`, `407-408`).

## Calls and the caller

12. A v1 call with `caller {user_id: U, client_id: C}` invokes `on_call` with `Caller.user_id == U` and `Caller.client_id == C` (`service.py:535-539`).
13. A call to an undeclared tool answers `error` code `not_found` without invoking `on_call` (`service.py:465-472`).
14. A handler raising `ServiceError("not_allowed", m)` answers code `not_allowed` with payload `m` (`service.py:573-574`).
15. A handler raising any other exception answers code `internal` with payload `internal error`, and the exception text appears in no log record (`service.py:575-578`).
16. No log record from a call contains the arguments, the result, the error text or the credential (`service.py:49-53`, `540-542`).

## End-to-end and downgrade

17. An end-to-end call whose envelope opens is handed to `on_call` as plain arguments, and the reply payload is an envelope whose `kid` is the service's kid (`service.py:548-566`, `583-597`).
18. An envelope that is tampered, or whose `kid` is not the client's, answers `bad_arguments`; one with `sent_at` more than 300 s off, or a nonce reused by the same client within 600 s, answers `not_allowed` (`e2e.py:269-300`).
19. End-to-end arguments that do not match the tool's `inputSchema` answer `bad_arguments` without invoking `on_call` (`service.py:497-512`).
20. A `none` call to a tool in a `requires_end_to_end` role, and a `none` call from a client_id this process has seen in end-to-end mode, both answer `not_allowed` (`service.py:474-482`).

## Decided rules that apply here

21. **Identity stays in the MCP gateway; it sends each backend call with caller `{user_id, client_id}` [decided].** The library sends no user or client identity of its own and never derives `Caller` ids from tool arguments: a call whose `payload` contains `user_id`/`client_id` keys still yields `Caller` ids equal to the frame's `caller` object.
22. **The gateway does NOT move onto wolf-access now; it keeps the coarse tool roles [decided].** The `roles` passed to `GatewayService` appear unchanged in the register frame, and the library sends no wolf-access-specific field in it (the register frame's key set equals the nine fields in AC 6 plus `type`).
23. **No role = no visibility, not even existence [decided].** With a declared tool `D` whose handler raises `ServiceError("not_found", "unknown tool: X")`, and an undeclared tool named `X`: in `none` mode, the reply to a call of `D` equals the library's reply to a call of `X` in every key except `request_id`. In `end-to-end` mode the two replies have the same keys and the same `code`, and their payloads decrypt to the same plaintext (each sealed envelope differs, so the envelopes themselves are not compared).

## Caller ids (v0.1.1)

24. **(v0.1.1, `b4b05a2`; resolves #2 and Q1.)** Consider a v1 `call` or `read_resource` that names a `tool` or `uri`, with `encryption` `none`, or `end-to-end` with a valid `client_public_key` and matching `client_kid`. Two cases are tracked elsewhere: a key that cannot be sealed to is [#9](https://github.com/Nice-Wolf-Studio/gateway-client/issues/9), and an `end-to-end` frame without a `tool`/`uri` is [#10](https://github.com/Nice-Wolf-Studio/gateway-client/issues/10). If its `caller` is absent or not an object, or its `caller.user_id` or `caller.client_id` is absent, `null`, or not a non-empty, non-blank string, then:
    - it is answered with an `error` frame with code `not_allowed`;
    - neither `on_call` nor `on_read` is invoked;
    - exactly one `gateway_client` log record names its `request_id` at WARNING level or above, and no record contains its payload.

    It fails if any such frame reaches a handler, gets another code, or is logged at WARNING more than once. Anchors at `b4b05a2`: `service.py:115-117`, `566-570`, `594-596`. Tests: `test_v1_call_without_caller_ids_refused_before_on_call`, `test_v1_read_without_caller_ids_refused_before_on_read`, `test_refusal_without_caller_ids_logged_once_at_warning_without_payload`.

## Tracked defects pending open questions (not acceptance criteria yet)

These are defects against gateway spec 6.2 and 7 (`mcp-gateway:specs/2026-09-28-users-clients-rbac.md`).
Whether and how the library must change is an open question, so neither item is a pass/fail
criterion until that question is answered. Each states the criterion it would become if the
answer is yes [proposed].

- **D1: resolved.** Issue [#2](https://github.com/Nice-Wolf-Studio/gateway-client/issues/2) and Q1 were resolved by v0.1.1 (`b4b05a2`) with code `not_allowed`. The criterion is now AC 24.
- **D2** (issue [#3](https://github.com/Nice-Wolf-Studio/gateway-client/issues/3), open question Q2 in `docs/spec.md`). Today the set of client ids seen in end-to-end mode is in memory only (`service.py:152`, `480`, `557`), so after a restart a `none` call from such a client is accepted. If Q2 is answered yes, the criterion would be: after a `GatewayService` restart, a `none` call from a `client_id` that sent an end-to-end call before the restart answers `not_allowed`.

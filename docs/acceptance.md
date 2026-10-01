# gateway-client: acceptance criteria

Each criterion can fail. "Fake gateway" means the in-process WebSocket server the tests use
(`tests/helpers.py`). Anchors are against `main` at `c075232`. AC 1-20 are as-built behavior;
AC 21-23 check decided rules that apply to this library; AC 24-25 cover known gaps and fail today.

## Configuration and keys

1. `Config.load` with no service name or no credential raises `ConfigError` (`config.py:57-59`).
2. A `GATEWAY_BACKEND_URL` not starting with `ws://` or `wss://` raises `ConfigError` (`config.py:60-61`).
3. With no key configured, a key is generated and its private key is written to stderr exactly once; a second `Config.load` with the printed value yields the same `kid` (`config.py:84-95`).
4. `SERVICE_PRIVATE_KEY_FILE` pointing at a missing file creates it with mode `0600`; a second load reuses the same key (`config.py:98-112`).
5. `repr(KeyPair)` and `repr(Config)` contain neither the private key nor the credential (`e2e.py:163-164`, `config.py:36-38`).

## Registration

6. The first frame sent is `register` with `contract_version: 1`, `service`, `credential`, `public_key`, `accepts_caller: true`, `tools`, `resources`, `roles`, `roles_version` (`protocol.py:125-137`).
7. A declaration with a role naming an undeclared tool, a duplicate tool, or `roles_version < 1` raises `ValueError` at construction and sends nothing (`protocol.py:40-84`).
8. After `rejected`, retries back off exponentially to a 300 s cap, the reason is logged once per change, and no legacy register is ever sent, even with `WN_BACKEND_TOKEN` set (`service.py:206-218`).
9. When the fake gateway closes 1008 without a reply and `WN_BACKEND_TOKEN` is set, the next frame is the legacy register; without the token, no legacy frame is sent (`service.py:197-203`).
10. `update()` with a changed role list and the same `roles_version` raises `ValueError`; an accepted update sends `tools_changed`; a rejected update raises `RegistrationRejected` and restores the previous declaration (`service.py:236-291`).
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

21. **Identity stays in the gateway [decided].** The library sends no user or client identity of its own and never derives `Caller` ids from tool arguments: a call whose `payload` contains `user_id`/`client_id` keys still yields `Caller` ids equal to the frame's `caller` object.
22. **Gateway tool roles stay the outer gate [decided].** The `roles` passed to `GatewayService` appear unchanged in the register frame, and the library sends no wolf-access-specific field in it (the register frame's key set equals the nine fields in AC 6 plus `type`).
23. **No role = no visibility, not even existence [decided].** A handler raising `ServiceError("not_found", "unknown tool: T")` produces a reply frame with the same keys, the same `code`, and the same payload as the library's own reply to an undeclared tool `T`.

## Known gaps (fail today)

24. A v1 call frame with no `caller` object, or with `user_id` or `client_id` missing, is answered with an `error` frame and `on_call` is **not** invoked. Fails today: `on_call` runs with `user_id=None` (`service.py:535-539`). Error code pending open question Q1 in `docs/spec.md`.
25. After a `GatewayService` restart, a `none` call from a client_id that sent an end-to-end call before the restart answers `not_allowed`. Fails today: the pin set is in memory only (`service.py:152`, `480`, `557`). Pending open question Q2.

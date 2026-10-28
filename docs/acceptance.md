# gateway-client: acceptance criteria

Each criterion can fail. "Fake gateway" means the in-process WebSocket server the tests use
(`tests/helpers.py`). Anchors are against `development` at `23e25d0` (tag `v0.2.0`;
service contract version 2). AC 24 keeps its v0.1.1 history (anchored at `b4b05a2`) and states
the v0.2.0 criterion. AC 1-20 and AC 24 are as-built behavior; AC 21-23 check decided rules that
apply to this library, and AC 21-22 carry a "superseded by the v2 cutover" note where contract v2
contradicts them. The last section is not acceptance criteria yet: it lists the tracked defect
whose required behavior depends on an open question (D1 became AC 24).

## Configuration and keys

1. `Config.load` with no service name or no credential raises `ConfigError` (`config.py:57-59`).
2. A `GATEWAY_BACKEND_URL` not starting with `ws://` or `wss://` raises `ConfigError` (`config.py:60-61`).
3. With no key configured, a key is generated and its private key is written to stderr exactly once; a second `Config.load` with the printed value yields the same `kid` (`config.py:85-96`).
4. `SERVICE_PRIVATE_KEY_FILE` pointing at a missing file creates it with mode `0600`; a second load reuses the same key (`config.py:99-113`).
5. `repr(KeyPair)` and `repr(Config)` contain neither the private key nor the credential (`e2e.py:177-178`, `config.py:36`). The legacy token no longer exists: `Config` has no `legacy_token` field and `Config.load(legacy_token=...)` raises `TypeError` (`config.py:32-38`, `46-51`; `tests/test_config.py:44-51`).

## Registration

6. The first frame sent is `register` with `contract_version: 2`, `service`, `credential`, `public_key`, `accepts_caller: true`, `tools`, `resources`, and no `roles` or `roles_version` (`protocol.py:78-89`; `tests/test_service.py:76-84`).
7. A declaration with a tool missing `name`, `description` or `inputSchema`, a duplicate tool name, a resource missing `uri`, `name`, `mimeType` or `description`, or a duplicate resource URI raises `ValueError` at construction and sends nothing (`protocol.py:40-62`, `service.py:177`). Passing `roles=` or `roles_version=` to `GatewayService` or `update()` raises `TypeError` (`tests/test_service.py:97-102`).
8. After `rejected`, retries back off exponentially to a 300 s cap, the reason is logged once per change, and the retry is again a contract v2 register (there is no legacy register frame) (`service.py:246-255`, `protocol.py:9`, `21-22`; `tests/test_service.py:112-138`).
9. When the fake gateway closes without a reply to `register` (or sends none within the reply timeout), the next frame after the reconnect is a contract v2 register again, with backoff capped at 30 s; no legacy frame is sent, with or without `WN_BACKEND_TOKEN` in the environment (`service.py:343-348`, `251-255`; `protocol.py:9`, `21`).
10. `update()` with `announce=True`: an accepted update that changes the tools sends `tools_changed`, and one that changes the resources sends `resources_changed`; a rejected update raises `RegistrationRejected` and restores the previous declaration (`service.py:273-316`; `tests/test_service.py:608-645`).
11. Every `ping` is answered with `pong`, including before `registered` arrives (`service.py:385-386`, `418-419`).

## Calls and the caller

12. A v2 call whose `caller_token` verifies with `sub` P and `act` A invokes `on_call` with `Caller.principal == P`, `Caller.app == A` and `Caller.token` equal to that token, and the token does not appear in `repr(Caller)` (`service.py:66-93`, `568-570`; `tests/test_service.py:201-219`).
13. A call to an undeclared tool answers `error` code `not_found` without invoking `on_call` (`service.py:475-482`, `584`).
14. A handler raising `ServiceError("not_allowed", m)` answers code `not_allowed` with payload `m` (`service.py:599-600`).
15. A handler raising any other exception answers code `internal` with payload `internal error`, and the exception text appears in no log record (`service.py:601-604`).
16. No log record from a call contains the arguments, the result, the error text, the credential or the caller token (`service.py:21`, `54-57`, `545-546`, `563-564`, `571-572`; `tests/test_service.py:276-294`).

## End-to-end and downgrade

17. An end-to-end call whose envelope opens is handed to `on_call` as plain arguments, and the reply payload is an envelope whose `kid` is the service's kid (`service.py:575-598`, `609-618`; `e2e.py:220-230`).
18. An envelope that is tampered, whose `kid` is not the client's, or whose associated data names other ids than the verified token's `sub` / `act` / `aud`, answers `bad_arguments`; one with `sent_at` more than 300 s off, or a nonce reused by the same connected app (`act`) within 600 s, answers `not_allowed` (`e2e.py:285-316`; `service.py:579-591`; `tests/test_service.py:508-520`).
19. End-to-end arguments that do not match the tool's `inputSchema` answer `bad_arguments` without invoking `on_call` (`service.py:505-521`, `592`).
20. A `none` call from a connected app (`act`) this process has seen in end-to-end mode answers `not_allowed`; a `none` call from another app is served (`service.py:484-491`, `583`, `594`; `tests/test_service.py:593-603`). The v0.1.x refusal of a `none` call to a tool in a `requires_end_to_end` role was removed in v0.2.0 with the roles (`CHANGELOG.md:49-52`).

## Decided rules that apply here

21. **Identity stays in the MCP gateway; it sends each backend call with caller `{user_id, client_id}` [decided].** The library sends no user or client identity of its own and never derives `Caller` ids from tool arguments: a call whose `payload` contains `user_id`/`client_id` keys still yields `Caller` ids equal to the frame's `caller` object.
    - **Superseded by the v2 cutover:** the gateway sends a GW-3 `caller_token` and no `caller` object (`mcp-gateway:gateway/protocol.py:10-18`, `471-485`). `Caller.principal` / `Caller.app` come from the verified token only; a frame `caller` object, `principal`, `user_id` or `sub` field never changes them (`service.py:568-570`; `tests/test_service.py:437-448`).
22. **The gateway does NOT move onto wolf-access now; it keeps the coarse tool roles [decided].** The `roles` passed to `GatewayService` appear unchanged in the register frame, and the library sends no wolf-access-specific field in it (the register frame's key set equals the nine fields in AC 6 plus `type`).
    - **Superseded by the v2 cutover:** contract v2 has no roles; the register frame's key set is exactly the seven fields in AC 6 plus `type`, with no wolf-access-specific field (`protocol.py:78-89`; `tests/test_service.py:76-84`), and the gateway asks wolf-access whether a caller may use a backend (`mcp-gateway:docs/spec.md:39`, `:66`).
23. **No role = no visibility, not even existence [decided].** With a declared tool `D` whose handler raises `ServiceError("not_found", "unknown tool: X")`, and an undeclared tool named `X`: in `none` mode, the reply to a call of `D` equals the library's reply to a call of `X` in every key except `request_id`. In `end-to-end` mode the two replies have the same keys and the same `code`, and their payloads decrypt to the same plaintext (each sealed envelope differs, so the envelopes themselves are not compared).

## Caller ids (v0.1.1; superseded by the caller token in v0.2.0)

24. **(v0.1.1, `b4b05a2`; resolves #2 and Q1.)** Consider a v1 `call` or `read_resource` that names a `tool` or `uri`, with `encryption` `none`, or `end-to-end` with a valid `client_public_key` and matching `client_kid`. Two cases are tracked elsewhere: a key that cannot be sealed to is [#9](https://github.com/Nice-Wolf-Studio/gateway-client/issues/9), and an `end-to-end` frame without a `tool`/`uri` is [#10](https://github.com/Nice-Wolf-Studio/gateway-client/issues/10). If its `caller` is absent or not an object, or its `caller.user_id` or `caller.client_id` is absent, `null`, or not a non-empty, non-blank string, then:
    - it is answered with an `error` frame with code `not_allowed`;
    - neither `on_call` nor `on_read` is invoked;
    - exactly one `gateway_client` log record names its `request_id` at WARNING level or above, and no record contains its payload.

    It fails if any such frame reaches a handler, gets another code, or is logged at WARNING more than once. Anchors at `b4b05a2`: `service.py:115-117`, `566-570`, `594-596`. Tests at `b4b05a2`: `test_v1_call_without_caller_ids_refused_before_on_call`, `test_v1_read_without_caller_ids_refused_before_on_read`, `test_refusal_without_caller_ids_logged_once_at_warning_without_payload`.

    **v0.2.0 criterion** (the v1 `caller` check and its tests are gone; identity comes only from the token). A `call` or `read_resource` whose `caller_token` is absent, `null`, not a string, or fails any check of `CallerTokenVerifier.verify` (signature by `kid`, `aud`, `exp`, required claims, `jti` replay) is answered with an `error` frame with code `not_allowed` and payload `caller token refused`, or code `unavailable` and payload `caller token could not be checked; retry` when the key set cannot be fetched; neither `on_call` nor `on_read` is invoked; exactly one `gateway_client` record naming its `request_id` is at WARNING and names the failed check, and no record contains the token or the payload. In `end-to-end` mode the refusal is sent unsealed. #9 and #10 are still open. Anchors: `service.py:537-548`, `568`, `609-618`; `caller_token.py:243-297`, `197-214`. Tests: `test_bad_caller_token_refused_before_the_handler`, `test_frame_without_a_caller_token_refused`, `test_replayed_jti_refused_before_the_handler`, `test_key_set_unreachable_answers_unavailable`, `test_token_refusal_logged_once_at_warning_without_token`, `test_e2e_token_refusal_is_plain_not_allowed` (`tests/test_service.py:331-434`, `523-534`).

## Tracked defects pending open questions (not acceptance criteria yet)

These are defects against gateway spec 6.2 and 7 (`mcp-gateway:specs/2026-09-28-users-clients-rbac.md`).
Whether and how the library must change is an open question, so neither item is a pass/fail
criterion until that question is answered. Each states the criterion it would become if the
answer is yes [proposed].

- **D1: resolved.** Issue [#2](https://github.com/Nice-Wolf-Studio/gateway-client/issues/2) and Q1 were resolved by v0.1.1 (`b4b05a2`) with code `not_allowed`. The criterion is now AC 24.
- **D2: resolved** (issue [#3](https://github.com/Nice-Wolf-Studio/gateway-client/issues/3), open question Q2 in `docs/spec.md`). In-memory per-process pinning is the default, maintaining the zero-disk-dependency stateless invariant and avoiding permanent breakage of legitimate user-initiated encryption mode switches in `mcp-gateway`. For deployments that opt in to persistence via `pin_store` (or `SERVICE_PIN_STORE_FILE`), after a `GatewayService` restart, a `none` call whose connected app WRN (`caller.app`, verified `act` claim) was seen in `end-to-end` mode before the restart answers `not_allowed`. Connected apps never seen in `end-to-end` mode continue to be allowed.

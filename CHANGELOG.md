# Changelog

The version follows semantic versioning; before 1.0.0 a breaking change
raises the minor version.

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

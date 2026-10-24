# gateway-client

The shared Python library every service uses to connect to the Wolf MCP
Gateway under **service contract version 2** (mcp-gateway `development`:
`gateway/contract.py`, `gateway/protocol.py`, `gateway/caller_token.py`;
docs/spec.md GW-3, GW-13; integration spec INT-C3). It replaces each
service's hand-written `/backend` client and the gateway's `mock_backend.py`
as the reference for real services.

```bash
pip install "gateway-client @ git+https://github.com/Nice-Wolf-Studio/gateway-client@v0.2.0"
```

Python 3.10+. Depends on `websockets`, `pyhpke` (HPKE, RFC 9180),
`cryptography`, `jsonschema` and `PyJWT`.

0.2.0 is a breaking release; see [CHANGELOG.md](CHANGELOG.md) for what
changed from 0.1.x and how to migrate.

## Adopting it

```python
from gateway_client import Caller, GatewayService, ServiceError

TOOLS = [{"name": "add", "description": "Add two numbers.",
          "inputSchema": {"type": "object", "required": ["a", "b"],
                          "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}}]

async def on_call(tool: str, arguments: dict, caller: Caller):
    # caller.principal  the principal WRN the call acts as (verified token `sub`)
    # caller.app        the connected app's WRN (verified token `act`)
    # caller.token      the verified GW-3 token, to forward if you must
    # caller.claims     the verified claims; caller.encryption; caller.request_id
    if tool == "add":
        return str(arguments["a"] + arguments["b"])     # str, content blocks, or any JSON
    raise ServiceError("not_found", f"unknown tool: {tool}")

async def on_read(uri: str, caller: Caller):
    raise ServiceError("not_found", uri)

service = GatewayService(tools=TOOLS, on_call=on_call, resources=[], on_read=on_read)
service.run_forever()          # or: await service.run() inside your own loop
```

The service code sees plain arguments and returns plain results in both
encryption modes. Callbacks may be sync (run in a worker thread) or async.

### Who is calling

`Caller` is built from the call's **verified** GW-3 caller token and from
nothing else (INT-C3): `principal` (the token's `sub`) and `app` (its `act`)
are always non-blank strings, because a call whose token fails any check
never reaches the handler. Authorize on `caller.principal` (and, where it
matters, `caller.app`). `caller.token` is the raw verified JWT, short-lived
(at most 60 s) and valid for this service only; forward it only where
something downstream must check it itself, and never log it.

## Configuration

Keyword arguments to `GatewayService(...)` (`url`, `service_name`,
`credential`, `private_key`, `private_key_file`, `jwks_url`) win over the
environment. Passing both `config=` and any of them is a `TypeError`.

| Variable | Meaning |
|---|---|
| `GATEWAY_BACKEND_URL` | `wss://<gateway>/backend` (default `ws://127.0.0.1:8000/backend`). |
| `SERVICE_NAME` | The service's reserved name. Required. It is also the audience every caller token must name. |
| `SERVICE_CREDENTIAL` | The service's own credential (issued on the gateway's Services page). Required. |
| `SERVICE_PRIVATE_KEY` | base64url raw X25519 private key. |
| `SERVICE_PRIVATE_KEY_FILE` | File holding that key; created with mode 0600 if it does not exist. |
| `GATEWAY_JWKS_URL` | The gateway's key set. Default: derived from `GATEWAY_BACKEND_URL` (`wss://host/backend` -> `https://host/.well-known/jwks.json`, `ws://` -> `http://`). |

With neither key variable set, a key pair is generated and the private key is
printed **once** to stderr with instructions. The gateway pins the public key
at the first accepted registration; a different key later is `rejected` with
`key_changed` until an admin approves it, so keep the key.

Token-check settings (keyword arguments to `GatewayService`):
`token_leeway` (clock skew allowed on `exp`, default 10 s),
`jwks_min_refetch_interval` (default 10 s), `jwks_max_age` (default 1 h),
and `jwks_fetch(url) -> dict` to replace the HTTP fetch (tests).

## What it does

| Contract part | Behaviour |
|---|---|
| Register | Sends `{type: register, contract_version: 2, service, credential, public_key, accepts_caller: true, tools, resources}`, exactly the fields `gateway/contract.py` requires (v2 has no `roles` / `roles_version`). The declaration is validated locally with the gateway's rules first, so a mistake fails at start. `registered` / `rejected {reason}` handled. |
| Ping | Every `ping` is answered `pong`. |
| Caller token (GW-3, INT-C3) | Checked on every `call` and `read_resource` **before anything else**: compact JWS with header `alg: EdDSA` and a `kid`; the `kid` is in the gateway key set; the Ed25519 signature verifies; `sub`, `act`, `aud`, `exp`, `jti` present, with `sub`, `act`, `jti` non-blank strings; `aud` is a string equal to `SERVICE_NAME` (a list is refused); `exp` not passed (10 s skew) and no more than 60 s (+ skew) ahead; `jti` not already accepted while the token could be valid (in-memory). Any failure is answered `not_allowed` with the text `caller token refused` and logged once at WARNING with the failed check (never the token); the handler never runs. When the key set cannot be fetched at all the answer is `unavailable` (the token was not checked; a retry may succeed). |
| Key set | `GET` of the JWKS on first use, cached; an unknown `kid` triggers one refetch (the gateway rotated its key), at most one fetch per 10 s however many tokens arrive, and concurrent checks share one fetch. Refreshed after 1 h; a failed refresh keeps the cached keys. Only Ed25519 (`kty OKP`, `crv Ed25519`) keys are used. |
| Call / read | `on_call(tool, arguments, caller)` / `on_read(uri, caller)`; the reply is `result` or `error` with `request_id`, `encryption`, `payload`. The request id and the verified `principal` / `app` are logged. Frame fields other than the token (a v1 `caller` object, say) never affect who is calling. |
| Errors (6.3) | `ServiceError(code, message)` sends that code. Unknown tool or resource: `not_found`. Any other exception: `internal` with the text `internal error` (the exception text is never sent or logged). |
| Changes | `await service.update(tools=..., resources=...)` re-registers on the same connection and, when accepted, sends `tools_changed` / `resources_changed`. A rejected update restores the previous declaration and raises `RegistrationRejected`. `send_tools_changed()` / `send_resources_changed()` announce on their own. |
| End-to-end (7, 7.1) | Opens the client's envelope (HPKE Auth mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305, empty `info`), checks the arguments against the tool's `inputSchema`, and seals the result or error text to `client_public_key`. Refused: a `kid` that is not the client's (`bad_arguments`), a tampered or undecryptable envelope, including one bound to other ids than the token's (`bad_arguments`), a `sent_at` more than 5 minutes off (`not_allowed`), a nonce already used by that app in the last 10 minutes (`not_allowed`). A token refusal in `end-to-end` is sent in plaintext (there is no verified identity to bind it to), which the gateway relays to the client as `internal`. |
| Downgrade (7) | A `none` call from a connected app (`act`) this process has seen in `end-to-end` is refused `not_allowed`. Which tools require end-to-end is decided by wolf-access (permissions carry `requires_end_to_end`) and enforced by the gateway before routing. |
| Reconnect | Exponential backoff with jitter, capped at 5 minutes after `rejected` and 30 seconds after a dropped connection, reset after a successful registration. The rejection reason is logged once per change. There is no legacy-protocol fallback. |
| Logging | Logger `gateway_client`. Never logs arguments, results, error text, credentials, keys or tokens; the WebSocket library's frame dump is kept off (its logger, `gateway_client.transport`, stays at INFO). |

### End-to-end wire details (contract v2)

Plaintext is the UTF-8 JSON of the value: the arguments object for a request;
for a reply, what the `payload` would be in `none` mode (content blocks,
resource contents, or the error message string).

Associated data is the UTF-8 JSON, keys sorted, no spaces, of

```
{contract_version: 2, user_id, client_id, service, tool | uri,
 encryption: "end-to-end", nonce, sent_at}
```

plus `request_id` and `"direction": "reply"` for a reply, where `user_id` is
the caller token's `sub` (principal WRN), `client_id` its `act` (connected
app WRN) and `service` its `aud`, taken from the **verified** token, never
from frame fields; `nonce` and `sent_at` are the envelope's own. The key
names are contract v1's (spec section 7.1); only the version and the values
changed. A request example:

```
{"client_id":"wrn:gateway:client/<uuid>","contract_version":2,"encryption":"end-to-end","nonce":"<b64url>","sent_at":1800000000,"service":"<service>","tool":"<tool>","user_id":"wrn:wolf-access:user/<id>"}
```

The envelope `kid` names the sender's key, which is what the gateway checks
(the client's key on a request, the service's on a reply).
`gateway_client.e2e` exposes `seal`, `open_envelope`, `header`
(`header(user_id=<sub>, client_id=<act>, service=<aud>, tool=...)`),
`reply_header` and `KeyPair` for a client-side program.

## Example and tests

`examples/selftest_service.py` is a one-tool service (`lib_selftest`) that
answers with the verified caller; `--once` exits 0 after the gateway accepts
the registration.

```bash
pip install -e ".[test]"
python -m pytest -q
```

The tests need no network: they run against an in-process WebSocket server
on 127.0.0.1, with an in-process token issuer standing in for the gateway's
signing key.

`tests/test_gateway_e2e.py` runs the library against the **real** gateway
(mcp-gateway `development`: the gateway and its wolf-access stub as
subprocesses, a Postgres test database, an MCP client through `/mcp`, in
`none` and `end-to-end` mode). It is skipped unless both `MCP_GATEWAY_DIR`
(a checkout of the private mcp-gateway repository, with its requirements
installed) and `TEST_DATABASE_URL` are set, so this repository's CI does not
run it:

```bash
pip install -r ../mcp-gateway/requirements.txt
MCP_GATEWAY_DIR=../mcp-gateway TEST_DATABASE_URL=postgresql://... \
    python -m pytest tests/test_gateway_e2e.py
```

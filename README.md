# gateway-client

The shared Python library every service uses to connect to the Wolf MCP
Gateway under **service contract version 1** (gateway repo
`specs/2026-09-28-users-clients-rbac.md`, sections 6, 6.1, 6.2, 6.3, 7, 7.1).
It replaces each service's hand-written `/backend` client and the gateway's
`mock_backend.py` as the reference for real services.

```bash
pip install "gateway-client @ git+https://github.com/Nice-Wolf-Studio/gateway-client@v0.2.0"
```

Python 3.10+. Depends on `websockets`, `pyhpke` (HPKE, RFC 9180),
`cryptography` and `jsonschema`.

## Adopting it

```python
from gateway_client import Caller, GatewayService, ServiceError

TOOLS = [{"name": "add", "description": "Add two numbers.",
          "inputSchema": {"type": "object", "required": ["a", "b"],
                          "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}}]
ROLES = [{"name": "math-user", "description": "May add.", "tools": ["add"],
          "resources": [], "requires_end_to_end": False}]

async def on_call(tool: str, arguments: dict, caller: Caller):
    # caller.user_id, caller.client_id, caller.encryption, caller.request_id
    if tool == "add":
        return str(arguments["a"] + arguments["b"])     # str, content blocks, or any JSON
    raise ServiceError("not_found", f"unknown tool: {tool}")

async def on_read(uri: str, caller: Caller):
    raise ServiceError("not_found", uri)

service = GatewayService(tools=TOOLS, roles=ROLES, roles_version=1,
                         on_call=on_call, resources=[], on_read=on_read)
service.run_forever()          # or: await service.run() inside your own loop
```

The service code sees plain arguments and returns plain results in both
encryption modes. Callbacks may be sync (run in a worker thread) or async.

## Configuration

Keyword arguments to `GatewayService(...)` (`url`, `service_name`,
`credential`, `private_key`, `private_key_file`, `legacy_token`,
`backend_id`) win over the environment:

| Variable | Meaning |
|---|---|
| `GATEWAY_BACKEND_URL` | `wss://<gateway>/backend` (default `ws://127.0.0.1:8000/backend`). |
| `SERVICE_NAME` | The service's reserved name. Required. |
| `SERVICE_CREDENTIAL` | The service's own credential (issued on the gateway's Services page). Required. |
| `SERVICE_PRIVATE_KEY` | base64url raw X25519 private key. |
| `SERVICE_PRIVATE_KEY_FILE` | File holding that key; created with mode 0600 if it does not exist. |
| `WN_BACKEND_TOKEN` | Legacy shared token. Only enables the old-protocol fallback. |
| `BACKEND_ID` | Legacy registry id (default `SERVICE_NAME`). |
| `GATEWAY_LOG_FORMAT` | `json` for one JSON object per log line (ISO-8601 UTC `timestamp`). Unset or anything else: human text (the default; unchanged). |

With neither key variable set, a key pair is generated and the private key is
printed **once** to stderr with instructions. The gateway pins the public key
at the first accepted registration; a different key later is `rejected` with
`key_changed` until an admin approves it, so keep the key.

## What it does

| Contract part | Behaviour |
|---|---|
| Register (6.1) | Sends every required field; the declaration is validated locally with the gateway's rules first, so a mistake fails at start. `registered` / `rejected {reason}` handled. |
| Ping | Every `ping` is answered `pong`. |
| Call / read (6.2) | `on_call(tool, arguments, caller)` / `on_read(uri, caller)`; the reply is `result` or `error` with `request_id`, `encryption`, `payload`. Each one is logged as `call.start` and `call.end` (see Logging below). Unless `caller.user_id` and `caller.client_id` are both non-empty, non-blank strings, a call or read never reaches the handler. Once its encryption mode and end-to-end client key check out (a failure there keeps its own code), it is answered `not_allowed`, and its `call.end` is at WARNING with `error_code=not_allowed`. In `end-to-end` the refusal is sealed like any other error, to the ids as received, so the gateway relays the code. |
| Errors (6.3) | `ServiceError(code, message)` sends that code. Unknown tool or resource: `not_found`. Any other exception: `internal` with the text `internal error` on the wire (the exception text is never sent to the client); the log has its full message and traceback. |
| Changes (6) | `await service.update(tools=..., resources=..., roles=..., roles_version=...)` re-registers on the same connection and, when accepted, sends `tools_changed` / `resources_changed`. A changed role list needs a higher `roles_version`. A rejected update restores the previous declaration and raises `RegistrationRejected`. `send_tools_changed()` / `send_resources_changed()` announce on their own. |
| End-to-end (7, 7.1) | Opens the client's envelope (HPKE Auth mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305, empty `info`), checks the arguments against the tool's `inputSchema`, and seals the result or error text to `client_public_key`. Refused: a `kid` that is not the client's (`bad_arguments`), a tampered or undecryptable envelope (`bad_arguments`), a `sent_at` more than 5 minutes off (`not_allowed`), a nonce already used by that client in the last 10 minutes (`not_allowed`). |
| Downgrade (7) | A `none` call to anything in a role declared `requires_end_to_end`, and a `none` call from a client this process has seen in `end-to-end`, are refused `not_allowed`. |
| Legacy fallback | If the gateway closes the connection without answering the v1 `register` (the old gateway closes 1008) **and** `WN_BACKEND_TOKEN` is set, it reconnects at once with the old register frame and serves old-style calls; the next reconnect tries v1 again. Without the token it never falls back. A `rejected` reply never falls back. A legacy call reaches the handler with `caller.user_id` None: it carries no usable identity, so a service must fail closed (refuse) whenever `user_id` is None. |
| Reconnect | Exponential backoff with jitter, capped at 5 minutes after `rejected` and 30 seconds after a dropped connection, reset after a successful registration. The rejection reason is logged once per change. |
| Logging | Logger `gateway_client`. Every call or read: one `call.start` and one `call.end` (below), verbatim. The register frame (credential) and keys are not part of any log record; the WebSocket library's frame dump is kept off (its logger, `gateway_client.transport`, stays at INFO). |

## Logging

Logging records what the code did, verbatim. Arguments, results, exception
messages and tracebacks are logged exactly as the program holds them:
nothing is redacted, truncated or pattern-matched, and no logging code reads
a value to decide what to do with it. **Logs therefore contain everything a
caller sent and a tool returned, secrets included; treat log files and log
shipping accordingly.**

Every call or read produces exactly two records on the `gateway_client`
logger, with one shared field contract (other Wolf services log the same
names):

| Field | On | Meaning |
|---|---|---|
| `event` | both | `call.start` or `call.end` |
| `request_id` | both | the gateway's request id |
| `tool` / `uri` | both | the tool (call) or resource uri (read) |
| `user_id`, `client_id` | both | the caller ids as received (`user_id` null under the legacy protocol) |
| `service_name` | both | `SERVICE_NAME` |
| `encryption` | both | `none` or `end-to-end` |
| `args` | start (`none`); end (`end-to-end`) | the arguments as received. `end-to-end`: not on `call.start` (no plaintext yet); on `call.end` the decrypted arguments, or the envelope as received when it was never opened. Not on a read. |
| `outcome` | end | `ok`; `tool_error` (the handler returned a mapping with `isError: true`; the reply itself is unchanged); `error` (answered with a section 6.3 code); `exception` (the handler raised; answered `internal`) |
| `error_code` | end | the code sent, else null |
| `error_message` | end | the message sent for `error`; for `exception`, `str(exception)` (the client still gets only `internal error`); else null |
| `exception`, `traceback` | end (`exception`) | the exception's type and its full traceback as Python prints it |
| `duration_ms` | end | receipt of the frame to the reply being ready |
| `result_bytes` | end | size of the reply payload as JSON, before any sealing |
| `result` | end (`ok`, `tool_error`) | the reply payload (content blocks or resource contents), before any sealing |

Levels: `call.start` INFO; `call.end` INFO for `ok`, WARNING for `tool_error`
and `error`, ERROR for `exception`.

Text (the default) is `<message> key=value ...` for every field, a string
value as is and any other value as JSON (so a traceback spans lines):

```
2026-10-08T13:57:23.357Z INFO gateway_client call.start request_id=r-7f3a tool=echo user_id=u-42 client_id=c-claude service_name=svc encryption=none args={"text":"https://img.example/x.png","token":"abc"}
2026-10-08T13:57:23.357Z INFO gateway_client call.end request_id=r-7f3a tool=echo user_id=u-42 client_id=c-claude service_name=svc encryption=none outcome=ok error_code=null error_message=null duration_ms=0.1 result_bytes=60 result=[{"type":"text","text":"echo:https://img.example/x.png"}]
```

`GATEWAY_LOG_FORMAT=json`, one object per line:

```
{"timestamp":"2026-10-08T13:57:23.519Z","level":"INFO","logger":"gateway_client","message":"call.start","event":"call.start","request_id":"r-7f3a","tool":"echo","user_id":"u-42","client_id":"c-claude","service_name":"svc","encryption":"none","args":{"text":"https://img.example/x.png","token":"abc"}}
{"timestamp":"2026-10-08T13:57:23.520Z","level":"ERROR","logger":"gateway_client","message":"call.end","event":"call.end","request_id":"r-9c1e","tool":"echo","user_id":"u-42","client_id":"c-claude","service_name":"svc","encryption":"none","outcome":"exception","error_code":"internal","error_message":"Messages.app refused chat 'Family' (AppleScript error -1743)","duration_ms":0.1,"result_bytes":62,"exception":"RuntimeError","traceback":"Traceback (most recent call last):\n  File \"/srv/svc/handler.py\", line 9, in on_call\n    raise RuntimeError(\"Messages.app refused chat 'Family' (AppleScript error -1743)\")\nRuntimeError: Messages.app refused chat 'Family' (AppleScript error -1743)\n"}
```

Lifecycle records carry `event` and `service_name` too: `connect`
(`attempt`, `protocol`, `url`), `register` (`attempt`, `protocol`, counts,
`kid`), `rejected` (`reason`, `attempt`), `reconnect` (`reason` and
`attempt` after a problem), `fallback` (`close_code`). `attempt` counts
connection attempts since the last accepted registration, starting at 1.

Correlating the service's own logs:

```python
from gateway_client import configure_logging, current_request_id

configure_logging()        # root handler; JSON when GATEWAY_LOG_FORMAT=json

async def on_call(tool, arguments, caller):
    log.info("sending")    # stamped with request_id by the filter
    current_request_id()   # == caller.request_id, in async and sync handlers
```

`configure_logging(level=INFO, json_format=None, stream=None)` replaces the
root handlers with one stream handler, installs `RequestIdFilter` on it and
picks JSON or text (ISO-8601 UTC times) from `GATEWAY_LOG_FORMAT`. A service
that keeps its own `logging.basicConfig(...)` needs no change: `run()`
installs `RequestIdFilter` on the root handlers and, only when
`GATEWAY_LOG_FORMAT=json`, switches them to `JsonFormatter`. Both classes are
exported for custom setups.

### End-to-end wire details

Plaintext is the UTF-8 JSON of the value: the arguments object for a request;
for a reply, what the `payload` would be in `none` mode (content blocks,
resource contents, or the error message string). Associated data is the
UTF-8 JSON, keys sorted, no spaces, of `{contract_version, user_id,
client_id, service, tool|uri, encryption, nonce, sent_at}` (the envelope's own
`nonce` and `sent_at`), plus `request_id` and `"direction":"reply"` for a
reply. The envelope `kid` names the sender's key, which is what the gateway
checks (the client's key on a request, the service's on a reply).
`gateway_client.e2e` exposes `seal`, `open_envelope`, `header`,
`reply_header` and `KeyPair` for a client-side program.

## Example and tests

`examples/selftest_service.py` is a one-tool service (`lib_selftest`, role
`selftest-user`); `--once` exits 0 after the gateway accepts the
registration.

```bash
pip install -e ".[test]"
python -m pytest -q
```

The tests need no network: they run against an in-process WebSocket server
on 127.0.0.1.

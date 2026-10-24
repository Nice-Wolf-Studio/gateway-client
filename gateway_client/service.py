"""`GatewayService`: connect a service to the Wolf MCP Gateway.

The service dials OUT to the gateway's `/backend` WebSocket, registers under
service contract version 2, answers `ping`, and serves `call` /
`read_resource` frames by invoking the service's two callbacks with plain
arguments and a `Caller`.

Every frame's `caller_token` (GW-3) is verified before anything else
(`caller_token.CallerTokenVerifier`): signature by `kid` against the
gateway's key set, `aud` = this service, `exp`, the required claims, and
`jti` not replayed. A frame whose token fails is answered `not_allowed`
(`unavailable` when the key set could not be fetched) and no handler runs.
The verified token is the only source of the `Caller`'s identity (INT-C3).

In `end-to-end` mode the library opens the client's envelope and seals the
reply (see `e2e`), so the service code sees plain data in both modes; the
associated data is built from the verified token.

Reconnects back off exponentially with jitter (`protocol.Backoff`).

Never logged: arguments, results, error text, credentials, keys, tokens.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable

import jsonschema
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from . import caller_token, e2e
from .caller_token import CallerTokenVerifier, KeySet, TokenRefused, VerifiedToken
from .config import Config
from .errors import (
    BAD_ARGUMENTS,
    INTERNAL,
    NOT_ALLOWED,
    NOT_FOUND,
    UNAVAILABLE,
    RegistrationRejected,
    ServiceError,
)
from .protocol import Backoff, Declaration, content_blocks, resource_contents

log = logging.getLogger("gateway_client")
# The WebSocket library logs every frame at DEBUG, and frames carry the
# credential, arguments and results. Its logger here never goes below INFO.
_transport_log = logging.getLogger("gateway_client.transport")
_transport_log.setLevel(logging.INFO)

MODE_V2 = "v2"
DEFAULT_MAX_FRAME_BYTES = 5 * 1024 * 1024  # the gateway's own frame limit
DEFAULT_REPLY_TIMEOUT = 30.0               # wait for `registered` / `rejected`
TOKEN_REFUSED = "caller token refused"
TOKEN_UNCHECKED = "caller token could not be checked; retry"


@dataclass(frozen=True)
class Caller:
    """Who is calling, from the call's verified GW-3 caller token and
    nothing else. A call or read reaches the handler only after its token
    passed every check (signature, audience, expiry, required claims, no
    replay), so `principal` and `app` are always non-blank strings.

    - `principal`: the principal WRN the call acts as (the token's `sub`):
      a user, or the agent the app acts for.
    - `app`: the connected app's WRN (the token's `act`).
    - `token`: the verified compact JWT, for a backend that must forward it
      (it is short-lived and for this service only; never log it).
    - `claims`: the verified claims (read-only).
    """

    principal: str
    app: str
    encryption: str  # "none" or "end-to-end"
    request_id: str | None
    token: str = field(repr=False)
    claims: Any = field(repr=False, compare=False, default=None)

    @classmethod
    def from_token(cls, verified: VerifiedToken, *, encryption: str,
                   request_id: str | None) -> "Caller":
        return cls(principal=verified.principal, app=verified.app,
                   encryption=encryption, request_id=request_id,
                   token=verified.token, claims=verified.claims)


OnCall = Callable[[str, dict, Caller], Any]
OnRead = Callable[[str, Caller], Any]


class _Outcome(Enum):
    REGISTERED = "registered"  # served until the connection ended
    REJECTED = "rejected"      # the gateway refused the registration
    NO_REPLY = "no_reply"      # closed without `registered` / `rejected`
    FAILED = "failed"          # could not connect, or a protocol problem


@dataclass(frozen=True)
class _Attempt:
    outcome: _Outcome
    reason: str | None = None
    close_code: int | None = None


async def _invoke(fn: Callable[..., Any], *args: Any) -> Any:
    """Await an async callback; run a sync one in a worker thread so it
    cannot block the connection."""
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    result = await asyncio.to_thread(fn, *args)
    if inspect.isawaitable(result):
        result = await result
    return result


def _parse(raw: Any) -> dict[str, Any] | None:
    try:
        frame = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return frame if isinstance(frame, dict) else None


def _close_code(exc: ConnectionClosed) -> int | None:
    return exc.rcvd.code if exc.rcvd is not None else None


class GatewayService:
    """One service's connection to the gateway.

    Required: `tools` (each `{name, description, inputSchema}`) and
    `on_call(tool, arguments, caller) -> content`. Optional: `resources`
    (each `{uri, name, mimeType, description}`), `on_read(uri, caller) ->
    contents`.

    Configuration comes from `config`, else from keyword arguments
    (`url`, `service_name`, `credential`, `private_key`, `private_key_file`,
    `jwks_url`) over the environment (see `Config`).

    Caller-token checks: `token_leeway` (seconds of clock skew allowed on
    `exp`, default 10), `jwks_min_refetch_interval` (default 10 s) and
    `jwks_max_age` (default 1 h); `jwks_fetch(url) -> dict` (sync or async)
    replaces the HTTP fetch of the key set (for tests).

    Callbacks may be async or sync (sync ones run in a worker thread). A
    tool result may be a list of MCP content blocks, a string, or any JSON
    value; a read may return a list of MCP resource contents, a string, or
    any JSON value. Raise `ServiceError(code, message)` to answer with a
    section 6.3 error; any other exception answers `internal`.
    """

    def __init__(self, *, tools: Iterable[dict], on_call: OnCall,
                 resources: Iterable[dict] = (), on_read: OnRead | None = None,
                 config: Config | None = None,
                 max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
                 reply_timeout: float = DEFAULT_REPLY_TIMEOUT,
                 sleep: Callable[[float], Awaitable[Any]] | None = None,
                 rand: Callable[[], float] = random.random,
                 jwks_fetch: caller_token.Fetch | None = None,
                 token_leeway: float = caller_token.DEFAULT_LEEWAY_SECONDS,
                 jwks_min_refetch_interval: float = caller_token.DEFAULT_MIN_REFETCH_SECONDS,
                 jwks_max_age: float = caller_token.DEFAULT_MAX_AGE_SECONDS,
                 **config_kwargs: Any) -> None:
        if config is not None and config_kwargs:
            raise TypeError("pass either config or configuration keyword arguments, "
                            f"not both (got {', '.join(sorted(config_kwargs))})")
        self.config = config if config is not None else Config.load(**config_kwargs)
        self._decl = Declaration.build(tools, resources)
        self._verifier = CallerTokenVerifier(
            self.config.service_name,
            KeySet(self.config.key_set_url, fetch=jwks_fetch,
                   min_refetch_interval=jwks_min_refetch_interval, max_age=jwks_max_age),
            leeway=token_leeway)
        self._on_call = on_call
        self._on_read = on_read
        self._max_frame_bytes = max_frame_bytes
        self._reply_timeout = reply_timeout
        self._sleep_fn = sleep
        self._backoff = Backoff(rand)
        self._replay = e2e.ReplayGuard()
        self._pinned: set[str] = set()   # app WRNs seen in end-to-end mode
        self._ws: ClientConnection | None = None     # the registered connection
        self._conn: ClientConnection | None = None   # any open connection
        self._mode: str | None = None
        self._send_lock = asyncio.Lock()
        self._update_lock = asyncio.Lock()
        self._pending_register: asyncio.Future | None = None
        self._rejected_on_update: str | None = None
        self._registered_event: asyncio.Event | None = None
        self._stop_event: asyncio.Event | None = None
        self._tasks: set[asyncio.Task] = set()

    # --- public surface ------------------------------------------------------------

    @property
    def public_key(self) -> str:
        """The service's base64url X25519 public key (sent at register)."""
        return self.config.key.public_b64

    @property
    def kid(self) -> str:
        return self.config.key.kid

    @property
    def mode(self) -> str | None:
        """`"v2"` while registered, else None."""
        return self._mode

    @property
    def jwks_url(self) -> str:
        """The key set caller tokens are checked against."""
        return self._verifier.key_set.url

    @property
    def registered(self) -> bool:
        return self._mode is not None

    def run_forever(self) -> None:
        """Blocking entry point: `asyncio.run(self.run())`, quiet on Ctrl-C."""
        try:
            asyncio.run(self.run())
        except KeyboardInterrupt:
            log.info("shutting down")

    async def run(self) -> None:
        """Connect, register and serve, reconnecting until `stop()`."""
        self._stop_event = asyncio.Event()
        self._registered_event = self._registered_event or asyncio.Event()
        last_problem: str | None = None
        while not self._stop_event.is_set():
            attempt = await self._attempt()
            if self._stop_event.is_set():
                break
            if attempt.outcome is _Outcome.REGISTERED:
                last_problem = None
                log.info("connection to the gateway ended; reconnecting")
            elif attempt.reason != last_problem:
                last_problem = attempt.reason
                if attempt.outcome is _Outcome.REJECTED:
                    log.error("registration rejected: %s; retrying with backoff up to "
                              "300 s", attempt.reason)
                else:
                    log.warning("gateway connection problem: %s; retrying with backoff "
                                "up to 30 s", attempt.reason)
            delay = self._backoff.next_delay(rejected=attempt.outcome is _Outcome.REJECTED)
            await self._sleep(delay)
        await self._drain()

    async def stop(self) -> None:
        """End `run()`: close the connection and stop reconnecting."""
        if self._stop_event is not None:
            self._stop_event.set()
        conn = self._conn
        if conn is not None:
            await conn.close()

    async def wait_registered(self, timeout: float | None = None) -> None:
        """Wait until a registration is accepted (asyncio.TimeoutError after
        `timeout` seconds)."""
        if self._registered_event is None:
            self._registered_event = asyncio.Event()
        await asyncio.wait_for(self._registered_event.wait(), timeout)

    async def update(self, *, tools: Iterable[dict] | None = None,
                     resources: Iterable[dict] | None = None,
                     announce: bool = True) -> None:
        """Change what the service declares and re-register on the same
        connection. When accepted and `announce` is true, send
        `tools_changed` if the tools changed and `resources_changed` if the
        resources changed.

        If the gateway rejects the new declaration the previous one is
        restored (used on the next reconnect) and RegistrationRejected is
        raised. When not connected, the new declaration is used at the next
        registration and nothing is announced."""
        async with self._update_lock:
            old = self._decl
            new = Declaration.build(old.tools if tools is None else tools,
                                    old.resources if resources is None else resources)
            tools_changed = list(new.tools) != list(old.tools)
            resources_changed = list(new.resources) != list(old.resources)
            self._decl = new
            ws = self._ws
            if ws is None:
                return
            future = asyncio.get_running_loop().create_future()
            self._pending_register = future
            try:
                await self._send(ws, self._register_frame())
                reply = await asyncio.wait_for(future, self._reply_timeout)
            except (ConnectionClosed, ConnectionError, asyncio.TimeoutError) as exc:
                log.warning("re-registration not confirmed (%s); the new declaration "
                            "is used at the next registration", type(exc).__name__)
                return
            finally:
                self._pending_register = None
            if reply.get("type") != "registered":
                reason = str(reply.get("reason"))
                self._decl = old
                self._rejected_on_update = reason
                raise RegistrationRejected(reason)
            log.info("re-registered: %d tool(s), %d resource(s)", len(new.tools),
                     len(new.resources))
            if announce and tools_changed:
                await self.send_tools_changed()
            if announce and resources_changed:
                await self.send_resources_changed()

    async def send_tools_changed(self) -> bool:
        """Announce `tools_changed`. False when not registered."""
        return await self._announce("tools_changed")

    async def send_resources_changed(self) -> bool:
        """Announce `resources_changed`. False when not registered."""
        return await self._announce("resources_changed")

    # --- connection ------------------------------------------------------------------

    def _register_frame(self) -> dict[str, Any]:
        cfg = self.config
        return self._decl.register(cfg.service_name, cfg.credential, cfg.key.public_b64)

    async def _attempt(self) -> _Attempt:
        """One connection: register, then serve until it ends."""
        log.info("connecting to %s (contract v2)", self.config.url)
        try:
            async with connect(self.config.url, max_size=self._max_frame_bytes,
                               open_timeout=self._reply_timeout,
                               logger=_transport_log) as ws:
                self._conn = ws
                if self._stop_event is not None and self._stop_event.is_set():
                    return _Attempt(_Outcome.FAILED, "stopping")
                reply, code = await self._first_reply(ws, self._register_frame())
                if reply is None:
                    if code == -1:
                        return _Attempt(_Outcome.FAILED, "no reply to register within "
                                        f"{self._reply_timeout:g} s")
                    return _Attempt(_Outcome.NO_REPLY, "connection closed without a reply "
                                    f"to register (code {code})", code)
                if reply["type"] == "rejected":
                    return _Attempt(_Outcome.REJECTED, str(reply.get("reason")))
                self._on_registered(ws)
                try:
                    await self._serve(ws)
                finally:
                    self._on_disconnected()
                if self._rejected_on_update is not None:
                    reason, self._rejected_on_update = self._rejected_on_update, None
                    return _Attempt(_Outcome.REJECTED, reason)
                return _Attempt(_Outcome.REGISTERED)
        except (OSError, asyncio.TimeoutError, WebSocketException) as exc:
            return _Attempt(_Outcome.FAILED, f"cannot connect ({type(exc).__name__})")
        finally:
            self._conn = None

    async def _first_reply(self, ws: ClientConnection,
                           frame: dict[str, Any]) -> tuple[dict | None, int | None]:
        """Send the register frame and wait for `registered` / `rejected`.
        Returns (reply, None), or (None, close code) when the gateway closed
        without one, or (None, -1) on timeout."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._reply_timeout
        try:
            await self._send(ws, frame)
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return None, -1
                try:
                    raw = await asyncio.wait_for(ws.recv(), remaining)
                except asyncio.TimeoutError:
                    return None, -1
                msg = _parse(raw)
                if msg is None:
                    continue
                if msg.get("type") == "ping":
                    await self._send(ws, {"type": "pong"})
                elif msg.get("type") in ("registered", "rejected"):
                    return msg, None
        except ConnectionClosed as exc:
            return None, _close_code(exc)

    def _on_registered(self, ws: ClientConnection) -> None:
        self._ws, self._mode = ws, MODE_V2
        self._backoff.reset()
        if self._registered_event is None:
            self._registered_event = asyncio.Event()
        self._registered_event.set()
        d = self._decl
        log.info("registered as service %r (contract v2): %d tool(s), %d resource(s), "
                 "kid %s; caller tokens checked against %s", self.config.service_name,
                 len(d.tools), len(d.resources), self.kid, self.jwks_url)

    def _on_disconnected(self) -> None:
        self._ws, self._mode = None, None
        if self._registered_event is not None:
            self._registered_event.clear()
        pending = self._pending_register
        if pending is not None and not pending.done():
            pending.set_exception(ConnectionError("connection closed"))

    async def _serve(self, ws: ClientConnection) -> None:
        try:
            async for raw in ws:
                frame = _parse(raw)
                if frame is None:
                    continue
                ftype = frame.get("type")
                if ftype == "ping":
                    await self._send(ws, {"type": "pong"})
                elif ftype in ("call", "read_resource"):
                    task = asyncio.create_task(self._answer(ws, frame))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
                elif ftype in ("registered", "rejected"):
                    pending = self._pending_register
                    if pending is not None and not pending.done():
                        pending.set_result(frame)
                # `pong` and unknown types are ignored (forward-compatible).
        except ConnectionClosed:
            pass

    async def _send(self, ws: ClientConnection, frame: dict[str, Any]) -> None:
        async with self._send_lock:
            await ws.send(json.dumps(frame))

    async def _announce(self, ftype: str) -> bool:
        ws = self._ws
        if ws is None:
            return False
        await self._send(ws, {"type": ftype})
        log.info("announced %s", ftype)
        return True

    async def _sleep(self, delay: float) -> None:
        if self._sleep_fn is not None:
            await self._sleep_fn(delay)
            return
        assert self._stop_event is not None
        try:
            await asyncio.wait_for(self._stop_event.wait(), delay)
        except asyncio.TimeoutError:
            pass

    async def _drain(self, grace: float = 5.0) -> None:
        """On stop: let in-flight handlers finish for `grace` seconds, then
        cancel the rest."""
        tasks = list(self._tasks)
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=grace)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    # --- requests --------------------------------------------------------------------

    async def _answer(self, ws: ClientConnection, frame: dict[str, Any]) -> None:
        reply = await self._reply(frame)
        try:
            await self._send(ws, reply)
        except ConnectionClosed:
            log.warning("request_id=%s: reply not sent, the connection closed",
                        frame.get("request_id"))

    def _check_target(self, is_call: bool, target: Any) -> dict[str, Any]:
        """The declared tool or resource, else ServiceError(not_found)."""
        declared = (self._decl.tool(target) if is_call else self._decl.resource(target)
                    ) if isinstance(target, str) else None
        if declared is None or (not is_call and self._on_read is None):
            noun = "tool" if is_call else "resource"
            raise ServiceError(NOT_FOUND, f"unknown {noun}: {target}")
        return declared

    def _check_plaintext_allowed(self, app: str) -> None:
        """Downgrade protection (spec section 7): refuse a `none` call from a
        connected app this process has seen in `end-to-end` mode. (Which
        tools require end-to-end is wolf-access's decision under contract
        v2; the gateway enforces it before routing.)"""
        if app in self._pinned:
            raise ServiceError(NOT_ALLOWED, "this client uses end-to-end encryption; a "
                                            "plaintext call is refused")

    async def _run_handler(self, is_call: bool, target: str, declared: dict[str, Any],
                           arguments: Any, caller: Caller) -> list[Any]:
        if is_call:
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                raise ServiceError(BAD_ARGUMENTS, "arguments must be a JSON object")
            return content_blocks(await _invoke(self._on_call, target, arguments, caller))
        assert self._on_read is not None
        value = await _invoke(self._on_read, target, caller)
        return resource_contents(value, target, declared.get("mimeType") or "text/plain")

    @staticmethod
    def _check_schema(declared: dict[str, Any], arguments: Any) -> None:
        """End-to-end mode: the gateway cannot see the arguments, so the
        service checks them against the tool's inputSchema (spec section 7)."""
        if not isinstance(arguments, dict):
            raise ServiceError(BAD_ARGUMENTS, "arguments must be a JSON object")
        schema = declared["inputSchema"]
        try:
            validator = jsonschema.validators.validator_for(schema)
            validator(schema).validate(arguments)
        except jsonschema.ValidationError as exc:
            where = "/".join(str(p) for p in exc.absolute_path) or "(root)"
            raise ServiceError(BAD_ARGUMENTS, f"arguments do not match the tool's "
                                              f"inputSchema at {where}: {exc.message}"
                               ) from None
        except jsonschema.SchemaError:
            raise ServiceError(INTERNAL, "the tool's inputSchema is invalid") from None

    @staticmethod
    def _client_key(frame: dict[str, Any]) -> bytes:
        """The client's raw public key from an `end-to-end` frame, checked
        against `client_kid`."""
        try:
            raw = e2e.decode_public_key(frame.get("client_public_key"), "client_public_key")
        except ValueError:
            raise ServiceError(BAD_ARGUMENTS, "end-to-end frame has no valid "
                                              "client_public_key") from None
        if frame.get("client_kid") != e2e.key_id(raw):
            raise ServiceError(BAD_ARGUMENTS, "client_kid does not match "
                                              "client_public_key")
        return raw

    async def _verify_caller(self, frame: dict[str, Any]) -> VerifiedToken:
        """The frame's verified caller token, else ServiceError: `not_allowed`
        for a refused token, `unavailable` when the gateway key set could
        not be fetched. Logged once at WARNING with the reason, never the
        token."""
        try:
            return await self._verifier.verify(frame.get("caller_token"))
        except TokenRefused as exc:
            log.warning("%s request_id=%s refused: %s; answering %s", frame.get("type"),
                        frame.get("request_id"), exc.reason, exc.code)
            raise ServiceError(exc.code, TOKEN_UNCHECKED if exc.code == UNAVAILABLE
                               else TOKEN_REFUSED) from None

    async def _reply(self, frame: dict[str, Any]) -> dict[str, Any]:
        """The `result` / `error` reply to a `call` or `read_resource`.

        Order: the caller token (nothing runs for a frame whose token fails),
        the encryption mode, the client key (end-to-end), the target, then
        the payload. In `end-to-end` every error after the token check is
        sealed to the client; a token refusal is not (there is no verified
        identity to bind the associated data to), so the gateway relays it
        to the client as `internal`."""
        request_id = frame.get("request_id")
        encryption = frame.get("encryption")
        is_call = frame.get("type") == "call"
        target = frame.get("tool") if is_call else frame.get("uri")
        log.info("%s request_id=%s %s=%s encryption=%s", frame.get("type"), request_id,
                 "tool" if is_call else "uri", target, encryption)
        client_key: bytes | None = None
        fields: dict[str, Any] | None = None
        try:
            verified = await self._verify_caller(frame)
            caller = Caller.from_token(verified, encryption=encryption,
                                       request_id=request_id)
            log.info("request_id=%s caller principal=%s app=%s", request_id,
                     caller.principal, caller.app)
            if encryption not in (e2e.ENCRYPTION_NONE, e2e.ENCRYPTION_E2E):
                raise ServiceError(BAD_ARGUMENTS, "unknown encryption mode")
            if encryption == e2e.ENCRYPTION_E2E:
                # Key and associated data first, so even a refusal is sealed.
                # The associated data comes from the verified token only.
                client_key = self._client_key(frame)
                fields = e2e.header(
                    user_id=caller.principal, client_id=caller.app,
                    service=verified.claims["aud"], encryption=encryption,
                    **({"tool": target} if is_call else {"uri": target}))
                self._pinned.add(caller.app)
            declared = self._check_target(is_call, target)
            if encryption == e2e.ENCRYPTION_E2E:
                arguments = None
                if is_call:
                    arguments = e2e.open_envelope(
                        frame.get("payload"), recipient=self.config.key,
                        sender_public_raw=client_key, fields=fields, replay=self._replay,
                        replay_client_id=caller.app)
                    self._check_schema(declared, arguments)
            else:
                self._check_plaintext_allowed(caller.app)
                arguments = frame.get("payload")
            payload = await self._run_handler(is_call, target, declared, arguments, caller)
            return self._reply_frame("result", request_id, encryption, payload,
                                     client_key, fields)
        except (ServiceError, e2e.E2EError) as exc:
            code, message = exc.code, str(exc)
        except Exception as exc:  # the service's own failure: never leak its text
            log.warning("request_id=%s: handler raised %s; answering internal",
                        request_id, type(exc).__name__)
            code, message = INTERNAL, "internal error"
        log.info("request_id=%s answered error %s", request_id, code)
        return self._reply_frame("error", request_id, encryption, message, client_key,
                                 fields, code=code)

    def _reply_frame(self, ftype: str, request_id: Any, encryption: Any, payload: Any,
                     client_key: bytes | None, fields: dict[str, Any] | None,
                     code: str | None = None) -> dict[str, Any]:
        """`{type, request_id, encryption, [code,] payload}`; in `end-to-end`
        the payload is sealed to the client when the client's key and the
        verified caller are known (else plain, which the gateway turns into
        `internal`)."""
        if encryption == e2e.ENCRYPTION_E2E and client_key is not None and fields is not None:
            payload = e2e.seal(payload, sender=self.config.key, recipient_public_raw=client_key,
                               fields=e2e.reply_header(fields, str(request_id)))
        reply: dict[str, Any] = {"type": ftype, "request_id": request_id,
                                 "encryption": encryption}
        if code is not None:
            reply["code"] = code
        reply["payload"] = payload
        return reply

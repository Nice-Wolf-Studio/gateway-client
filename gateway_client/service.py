"""`GatewayService`: connect a service to the Wolf MCP Gateway.

The service dials OUT to the gateway's `/backend` WebSocket, registers under
service contract version 1 (gateway spec section 6), answers `ping`, and
serves `call` / `read_resource` frames by invoking the service's two
callbacks with plain arguments and a `Caller`. In `end-to-end` mode the
library opens the client's envelope and seals the reply (see `e2e`), so the
service code sees plain data in both modes.

Fallback: when the gateway closes the connection without answering the
version 1 `register` (the pre-contract gateway closes with 1008 on a frame
without `backend_token`) and `WN_BACKEND_TOKEN` is configured, the library
reconnects at once with the legacy register frame and serves legacy calls;
the next reconnect tries version 1 again. Without a legacy token it never
falls back.

Reconnects back off exponentially with jitter (`protocol.Backoff`).

Logging (see `logs`): every call or read is one `call.start` and one
`call.end` record with the shared field contract. Arguments, results,
exception messages and tracebacks are logged verbatim; end-to-end arguments
are logged decrypted on `call.end` (the envelope as received only when it
was never opened). The register frame (credential) and keys are not logged.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import random
import time
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable

import jsonschema
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from . import e2e, logs
from .config import Config
from .errors import (
    BAD_ARGUMENTS,
    INTERNAL,
    NOT_ALLOWED,
    NOT_FOUND,
    RegistrationRejected,
    ServiceError,
)
from .protocol import Backoff, Declaration, content_blocks, resource_contents

log = logging.getLogger("gateway_client")
# The WebSocket library logs every frame at DEBUG, and frames carry the
# credential, arguments and results. Its logger here never goes below INFO.
_transport_log = logging.getLogger("gateway_client.transport")
_transport_log.setLevel(logging.INFO)

MODE_V1 = "v1"
MODE_LEGACY = "legacy"
DEFAULT_MAX_FRAME_BYTES = 5 * 1024 * 1024  # the gateway's own frame limit
DEFAULT_REPLY_TIMEOUT = 30.0               # wait for `registered` / `rejected`
UNIDENTIFIED = "caller user_id and client_id must be non-empty strings"

OK, TOOL_ERROR, ERROR, EXCEPTION = "ok", "tool_error", "error", "exception"
_END_LEVEL = {OK: logging.INFO, TOOL_ERROR: logging.WARNING, ERROR: logging.WARNING,
              EXCEPTION: logging.ERROR}


@dataclass(frozen=True)
class Caller:
    """Who is calling. In contract version 1 `user_id` and `client_id` are
    always present, as strings: a v1 call or read never reaches the handler
    unless both are non-empty, non-blank strings (it is answered
    `not_allowed`, or with the code of an earlier frame check such as an
    unknown encryption mode). Under the legacy protocol `user_id` is None and `client_id` is
    the legacy `principal.client_id` (or None): there is no usable identity,
    so a consumer must fail closed (refuse) whenever `user_id` is None."""

    user_id: str | None
    client_id: str | None
    encryption: str  # "none" or "end-to-end"
    request_id: str | None


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


def _is_id(value: Any) -> bool:
    """A usable caller id: a string that is not empty or blank (spec 6.2)."""
    return isinstance(value, str) and bool(value.strip())


def _close_code(exc: ConnectionClosed) -> int | None:
    return exc.rcvd.code if exc.rcvd is not None else None


def _is_tool_error(value: Any) -> bool:
    """A handler result shaped like an MCP CallToolResult with `isError: true`."""
    return isinstance(value, dict) and value.get("isError") is True


def _traceback_text(exc: BaseException) -> str:
    """The full traceback of `exc`, as Python prints it."""
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


class _CallLog:
    """The `call.start` / `call.end` pair for one call or read."""

    def __init__(self, *, request_id: Any, is_call: bool, target: Any, user_id: Any,
                 client_id: Any, service_name: str, encryption: Any) -> None:
        self._started = time.monotonic()
        self._is_call = is_call
        self._encrypted = encryption != e2e.ENCRYPTION_NONE
        self._base: dict[str, Any] = {
            "request_id": request_id, ("tool" if is_call else "uri"): target,
            "user_id": user_id, "client_id": client_id, "service_name": service_name,
            "encryption": encryption}
        self.envelope: Any = None
        self.plain_args: Any = None
        self.have_plain_args = False

    def start(self, arguments: Any) -> None:
        fields: dict[str, Any] = {"event": "call.start", **self._base}
        if self._is_call:
            if self._encrypted:
                # Plaintext is not held yet; logged on call.end.
                self.envelope = arguments
            else:
                fields["args"] = arguments
        logs.emit(log, logging.INFO, "call.start", fields)

    def end(self, outcome: str, *, payload: Any = None, error_code: str | None = None,
            error_message: str | None = None, exc: BaseException | None = None) -> None:
        fields: dict[str, Any] = {
            "event": "call.end", **self._base, "outcome": outcome,
            "error_code": error_code, "error_message": error_message,
            "duration_ms": round((time.monotonic() - self._started) * 1000, 1),
            "result_bytes": logs.json_bytes(payload if outcome in (OK, TOOL_ERROR)
                                            else error_message)}
        if outcome in (OK, TOOL_ERROR):
            fields["result"] = payload
        if self._is_call and self._encrypted:
            fields["args"] = self.plain_args if self.have_plain_args else self.envelope
        if exc is not None:
            fields["exception"] = type(exc).__name__
            fields["traceback"] = _traceback_text(exc)
        logs.emit(log, _END_LEVEL[outcome], "call.end", fields)


class GatewayService:
    """One service's connection to the gateway.

    Required: `tools` (each `{name, description, inputSchema}`) and
    `on_call(tool, arguments, caller) -> content`. Optional: `resources`
    (each `{uri, name, mimeType, description}`), `on_read(uri, caller) ->
    contents`, `roles` (each `{name, description, tools, resources,
    requires_end_to_end}`), `roles_version` (positive, only increases).

    Configuration comes from `config`, else from keyword arguments
    (`url`, `service_name`, `credential`, `private_key`, `private_key_file`,
    `legacy_token`, `backend_id`) over the environment (see `Config`).

    Callbacks may be async or sync (sync ones run in a worker thread). A
    tool result may be a list of MCP content blocks, a string, or any JSON
    value; a read may return a list of MCP resource contents, a string, or
    any JSON value. A tool result that is a mapping with `isError: true` is
    logged with outcome `tool_error` (the reply is unchanged). Raise `ServiceError(code, message)` to answer with a
    section 6.3 error; any other exception answers `internal`.
    """

    def __init__(self, *, tools: Iterable[dict], on_call: OnCall,
                 resources: Iterable[dict] = (), on_read: OnRead | None = None,
                 roles: Iterable[dict] = (), roles_version: int = 1,
                 config: Config | None = None,
                 max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
                 reply_timeout: float = DEFAULT_REPLY_TIMEOUT,
                 sleep: Callable[[float], Awaitable[Any]] | None = None,
                 rand: Callable[[], float] = random.random,
                 **config_kwargs: Any) -> None:
        self.config = config if config is not None else Config.load(**config_kwargs)
        self._decl = Declaration.build(tools, resources, roles, roles_version)
        self._on_call = on_call
        self._on_read = on_read
        self._max_frame_bytes = max_frame_bytes
        self._reply_timeout = reply_timeout
        self._sleep_fn = sleep
        self._backoff = Backoff(rand)
        self._replay = e2e.ReplayGuard()
        self._pinned: set[str] = set()   # client ids seen in end-to-end mode
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
        self._attempts = 0   # connection attempts since the last registration

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
        """`"v1"` or `"legacy"` while registered, else None."""
        return self._mode

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
        logs.apply_env_format()
        self._stop_event = asyncio.Event()
        self._registered_event = self._registered_event or asyncio.Event()
        last_problem: str | None = None
        while not self._stop_event.is_set():
            attempt = await self._attempt(MODE_V1)
            if (attempt.outcome is _Outcome.NO_REPLY and self.config.legacy_token
                    and not self._stop_event.is_set()):
                self._event(logging.WARNING, "fallback",
                            "gateway closed the connection without answering the contract "
                            "v1 register; falling back to the legacy protocol for this "
                            "connection", close_code=attempt.close_code)
                attempt = await self._attempt(MODE_LEGACY)
            if self._stop_event.is_set():
                break
            if attempt.outcome is _Outcome.REGISTERED:
                last_problem = None
                self._event(logging.INFO, "reconnect",
                            "connection to the gateway ended; reconnecting")
            elif attempt.reason != last_problem:
                last_problem = attempt.reason
                if attempt.outcome is _Outcome.REJECTED:
                    self._event(logging.ERROR, "rejected",
                                "registration rejected; retrying with backoff up to 300 s",
                                reason=attempt.reason,
                                attempt=self._attempts)
                else:
                    self._event(logging.WARNING, "reconnect",
                                "gateway connection problem; retrying with backoff up to "
                                "30 s", reason=attempt.reason,
                                attempt=self._attempts)
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
                     roles: Iterable[dict] | None = None,
                     roles_version: int | None = None, announce: bool = True) -> None:
        """Change what the service declares and re-register on the same
        connection (spec section 6). When accepted and `announce` is true,
        send `tools_changed` if the tools or roles changed and
        `resources_changed` if the resources or roles changed.

        A changed role list needs a higher `roles_version` (ValueError
        otherwise). If the gateway rejects the new declaration the previous
        one is restored (used on the next reconnect) and RegistrationRejected
        is raised. When not connected, the new declaration is used at the
        next registration and nothing is announced. Under the legacy protocol
        the connection is closed so the reconnect registers the new lists."""
        async with self._update_lock:
            old = self._decl
            new = Declaration.build(
                old.tools if tools is None else tools,
                old.resources if resources is None else resources,
                old.roles if roles is None else roles,
                old.roles_version if roles_version is None else roles_version)
            old.check_successor(new)
            roles_changed = new.role_set() != old.role_set()
            tools_changed = roles_changed or list(new.tools) != list(old.tools)
            resources_changed = roles_changed or list(new.resources) != list(old.resources)
            self._decl = new
            ws, mode = self._ws, self._mode
            if ws is None:
                return
            if mode == MODE_LEGACY:
                await ws.close()
                return
            future = asyncio.get_running_loop().create_future()
            self._pending_register = future
            try:
                await self._send(ws, self._register_frame(MODE_V1))
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
            log.info("re-registered: %d tool(s), %d resource(s), %d role(s), "
                     "roles_version %d", len(new.tools), len(new.resources),
                     len(new.roles), new.roles_version)
            if announce and tools_changed:
                await self.send_tools_changed()
            if announce and resources_changed:
                await self.send_resources_changed()

    async def send_tools_changed(self) -> bool:
        """Announce `tools_changed` (contract v1 only). False when not
        registered under contract v1."""
        return await self._announce("tools_changed")

    async def send_resources_changed(self) -> bool:
        """Announce `resources_changed` (contract v1 only). False when not
        registered under contract v1."""
        return await self._announce("resources_changed")

    # --- connection ------------------------------------------------------------------

    def _register_frame(self, mode: str) -> dict[str, Any]:
        cfg = self.config
        if mode == MODE_V1:
            return self._decl.v1_register(cfg.service_name, cfg.credential,
                                          cfg.key.public_b64)
        return self._decl.legacy_register(cfg.legacy_token or "", cfg.legacy_backend_id)

    async def _attempt(self, mode: str) -> _Attempt:
        """One connection: register in `mode`, then serve until it ends."""
        self._attempts += 1
        self._event(logging.INFO, "connect",
                    "connecting to the gateway",
                    attempt=self._attempts, protocol=mode, url=self.config.url)
        try:
            async with connect(self.config.url, max_size=self._max_frame_bytes,
                               open_timeout=self._reply_timeout,
                               logger=_transport_log) as ws:
                self._conn = ws
                if self._stop_event is not None and self._stop_event.is_set():
                    return _Attempt(_Outcome.FAILED, "stopping")
                reply, code = await self._first_reply(ws, self._register_frame(mode))
                if reply is None:
                    if code == -1:
                        return _Attempt(_Outcome.FAILED, "no reply to register within "
                                        f"{self._reply_timeout:g} s")
                    if mode == MODE_LEGACY:
                        return _Attempt(_Outcome.REJECTED, "legacy registration refused "
                                        f"(connection closed, code {code})", code)
                    return _Attempt(_Outcome.NO_REPLY, "connection closed without a reply "
                                    f"to register (code {code})", code)
                if reply["type"] == "rejected":
                    return _Attempt(_Outcome.REJECTED, str(reply.get("reason")))
                self._on_registered(ws, mode)
                try:
                    await self._serve(ws, mode)
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

    def _event(self, level: int, event: str, message: str, **fields: Any) -> None:
        """A lifecycle record: `message key=value ...`, fields for JSON."""
        logs.emit(log, level, message, {"event": event,
                                        "service_name": self.config.service_name,
                                        **fields})

    def _on_registered(self, ws: ClientConnection, mode: str) -> None:
        self._ws, self._mode = ws, mode
        self._backoff.reset()
        if self._registered_event is None:
            self._registered_event = asyncio.Event()
        self._registered_event.set()
        d = self._decl
        counts = {"attempt": self._attempts, "protocol": mode, "tools": len(d.tools),
                  "resources": len(d.resources)}
        self._attempts = 0
        if mode == MODE_V1:
            self._event(logging.INFO, "register",
                        "registered (contract v1)", **counts, roles=len(d.roles),
                        roles_version=d.roles_version, kid=self.kid)
        else:
            self._event(logging.WARNING, "register",
                        "registered with the LEGACY protocol; contract v1 is retried on "
                        "the next reconnect", **counts, backend_id=self.config.legacy_backend_id)

    def _on_disconnected(self) -> None:
        self._ws, self._mode = None, None
        if self._registered_event is not None:
            self._registered_event.clear()
        pending = self._pending_register
        if pending is not None and not pending.done():
            pending.set_exception(ConnectionError("connection closed"))

    async def _serve(self, ws: ClientConnection, mode: str) -> None:
        try:
            async for raw in ws:
                frame = _parse(raw)
                if frame is None:
                    continue
                ftype = frame.get("type")
                if ftype == "ping":
                    await self._send(ws, {"type": "pong"})
                elif ftype in ("call", "read_resource"):
                    task = asyncio.create_task(self._answer(ws, frame, mode))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
                elif ftype in ("registered", "rejected") and mode == MODE_V1:
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
        if ws is None or self._mode != MODE_V1:
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

    async def _answer(self, ws: ClientConnection, frame: dict[str, Any], mode: str) -> None:
        reply = (await self._reply_v1(frame) if mode == MODE_V1
                 else await self._reply_legacy(frame))
        try:
            await self._send(ws, reply)
        except ConnectionClosed:
            logs.emit(log, logging.WARNING, "call.reply_not_sent",
                      {"event": "call.reply_not_sent", "request_id": frame.get("request_id"),
                       "service_name": self.config.service_name,
                       "reason": "the connection closed"})

    def _check_target(self, is_call: bool, target: Any) -> dict[str, Any]:
        """The declared tool or resource, else ServiceError(not_found)."""
        declared = (self._decl.tool(target) if is_call else self._decl.resource(target)
                    ) if isinstance(target, str) else None
        if declared is None or (not is_call and self._on_read is None):
            noun = "tool" if is_call else "resource"
            raise ServiceError(NOT_FOUND, f"unknown {noun}: {target}")
        return declared

    def _check_plaintext_allowed(self, target: str, client_id: str | None) -> None:
        """Downgrade protection (spec section 7): refuse a `none` call to
        anything in a `requires_end_to_end` role, and any `none` call from a
        client this process has seen in `end-to-end` mode."""
        if target in self._decl.e2e_only():
            raise ServiceError(NOT_ALLOWED, "this requires end-to-end encryption")
        if client_id is not None and client_id in self._pinned:
            raise ServiceError(NOT_ALLOWED, "this client uses end-to-end encryption; a "
                                            "plaintext call is refused")

    async def _run_handler(self, is_call: bool, target: str, declared: dict[str, Any],
                           arguments: Any, caller: Caller) -> tuple[list[Any], bool]:
        """(reply payload, whether the tool result is an `isError` one)."""
        if is_call:
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                raise ServiceError(BAD_ARGUMENTS, "arguments must be a JSON object")
            value = await _invoke(self._on_call, target, arguments, caller)
            return content_blocks(value), _is_tool_error(value)
        assert self._on_read is not None
        value = await _invoke(self._on_read, target, caller)
        return resource_contents(value, target, declared.get("mimeType") or "text/plain"), False

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

    async def _reply_v1(self, frame: dict[str, Any]) -> dict[str, Any]:
        """The `result` / `error` reply to a contract v1 `call` or
        `read_resource` (spec section 6.2), logged as `call.start` /
        `call.end` with the request id current throughout."""
        with logs.request_scope(frame.get("request_id")):
            return await self._reply_v1_logged(frame)

    async def _reply_v1_logged(self, frame: dict[str, Any]) -> dict[str, Any]:
        request_id = frame.get("request_id")
        encryption = frame.get("encryption")
        is_call = frame.get("type") == "call"
        target = frame.get("tool") if is_call else frame.get("uri")
        raw_caller = frame.get("caller") if isinstance(frame.get("caller"), dict) else {}
        user_id, client_id = raw_caller.get("user_id"), raw_caller.get("client_id")
        call_log = _CallLog(request_id=request_id, is_call=is_call, target=target,
                            user_id=user_id, client_id=client_id,
                            service_name=self.config.service_name, encryption=encryption)
        call_log.start(frame.get("payload"))
        client_key: bytes | None = None
        fields: dict[str, Any] | None = None
        failure: BaseException | None = None
        try:
            if encryption not in (e2e.ENCRYPTION_NONE, e2e.ENCRYPTION_E2E):
                raise ServiceError(BAD_ARGUMENTS, "unknown encryption mode")
            if encryption == e2e.ENCRYPTION_E2E:
                # Key and associated data first, so even a refusal is sealed.
                client_key = self._client_key(frame)
                service = frame.get("service")
                fields = e2e.header(
                    user_id=user_id, client_id=client_id,
                    service=service if isinstance(service, str) else self.config.service_name,
                    encryption=encryption, **({"tool": target} if is_call else {"uri": target}))
                if _is_id(client_id):
                    self._pinned.add(client_id)
            if not (_is_id(user_id) and _is_id(client_id)):
                # Spec 6.2: both ids are always present, as strings. Without
                # them there is no one to act for, so the handler never runs.
                raise ServiceError(NOT_ALLOWED, UNIDENTIFIED)
            caller = Caller(user_id=user_id, client_id=client_id, encryption=encryption,
                            request_id=request_id)
            declared = self._check_target(is_call, target)
            if encryption == e2e.ENCRYPTION_E2E:
                arguments = None
                if is_call:
                    arguments = e2e.open_envelope(
                        frame.get("payload"), recipient=self.config.key,
                        sender_public_raw=client_key, fields=fields, replay=self._replay,
                        replay_client_id=caller.client_id)
                    call_log.plain_args, call_log.have_plain_args = arguments, True
                    self._check_schema(declared, arguments)
            else:
                self._check_plaintext_allowed(target, caller.client_id)
                arguments = frame.get("payload")
            payload, tool_error = await self._run_handler(is_call, target, declared,
                                                          arguments, caller)
            reply = self._reply_frame("result", request_id, encryption, payload,
                                      client_key, fields)
            call_log.end(TOOL_ERROR if tool_error else OK, payload=payload)
            return reply
        except (ServiceError, e2e.E2EError) as exc:
            code, message = exc.code, str(exc)
        except Exception as exc:  # the service's own failure: never sent to the client
            code, message, failure = INTERNAL, "internal error", exc
        if failure is not None:
            call_log.end(EXCEPTION, error_code=code, error_message=str(failure), exc=failure)
        else:
            call_log.end(ERROR, error_code=code, error_message=message)
        return self._reply_frame("error", request_id, encryption, message, client_key,
                                 fields, code=code)

    def _reply_frame(self, ftype: str, request_id: Any, encryption: Any, payload: Any,
                     client_key: bytes | None, fields: dict[str, Any] | None,
                     code: str | None = None) -> dict[str, Any]:
        """`{type, request_id, encryption, [code,] payload}`; in `end-to-end`
        the payload is sealed to the client (plain only when the client's key
        is unusable, which the gateway turns into `internal`)."""
        if encryption == e2e.ENCRYPTION_E2E and client_key is not None and fields is not None:
            payload = e2e.seal(payload, sender=self.config.key, recipient_public_raw=client_key,
                               fields=e2e.reply_header(fields, str(request_id)))
        reply: dict[str, Any] = {"type": ftype, "request_id": request_id,
                                 "encryption": encryption}
        if code is not None:
            reply["code"] = code
        reply["payload"] = payload
        return reply

    async def _reply_legacy(self, frame: dict[str, Any]) -> dict[str, Any]:
        """The reply to a legacy `call` / `read_resource`: `result {content}`,
        `resource_result {contents}` or `error {message}`."""
        with logs.request_scope(frame.get("request_id")):
            return await self._reply_legacy_logged(frame)

    async def _reply_legacy_logged(self, frame: dict[str, Any]) -> dict[str, Any]:
        request_id = frame.get("request_id")
        is_call = frame.get("type") == "call"
        target = frame.get("tool") if is_call else frame.get("uri")
        principal = frame.get("principal") if isinstance(frame.get("principal"), dict) else {}
        caller = Caller(user_id=None, client_id=principal.get("client_id"),
                        encryption=e2e.ENCRYPTION_NONE, request_id=request_id)
        call_log = _CallLog(request_id=request_id, is_call=is_call, target=target,
                            user_id=None, client_id=caller.client_id,
                            service_name=self.config.service_name,
                            encryption=e2e.ENCRYPTION_NONE)
        call_log.start(frame.get("arguments"))
        try:
            declared = self._check_target(is_call, target)
            self._check_plaintext_allowed(target, caller.client_id)
            payload, tool_error = await self._run_handler(is_call, target, declared,
                                                          frame.get("arguments"), caller)
            call_log.end(TOOL_ERROR if tool_error else OK, payload=payload)
            if is_call:
                return {"type": "result", "request_id": request_id, "content": payload}
            return {"type": "resource_result", "request_id": request_id, "contents": payload}
        except ServiceError as exc:
            message = str(exc)
            call_log.end(ERROR, error_code=exc.code, error_message=message)
        except Exception as exc:
            message = "internal error"
            call_log.end(EXCEPTION, error_code=INTERNAL, error_message=str(exc), exc=exc)
        return {"type": "error", "request_id": request_id, "message": message}

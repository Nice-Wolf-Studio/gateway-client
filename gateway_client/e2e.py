"""End-to-end payloads (gateway spec sections 7 and 7.1).

HPKE (RFC 9180) Auth mode with X25519, HKDF-SHA256 and ChaCha20-Poly1305, via
the maintained `pyhpke` implementation; nothing here implements crypto itself.

Envelope (exactly these seven fields):

    {"alg": "X25519-HKDF-SHA256-ChaCha20Poly1305", "mode": "auth",
     "kid": <hex>, "enc": <b64url>, "ct": <b64url>,
     "nonce": <b64url 16 bytes>, "sent_at": <unix seconds>}

- `kid` names the SENDER's public key: a request carries the client's kid
  (the gateway checks it equals `client_kid`), a reply the service's kid (the
  gateway checks it equals the service's registered key id).
- Associated data is the UTF-8 JSON, keys sorted, no spaces, of
  `{contract_version, user_id, client_id, service, tool|uri, encryption,
  nonce, sent_at}` for a request, plus `request_id` and
  `"direction": "reply"` for a reply. `nonce` and `sent_at` are the
  envelope's own.
- The plaintext is the UTF-8 JSON of the value: the arguments object for a
  request; for a reply, the `payload` the service would send in `none` mode
  (content blocks, resource contents, or the error message string).
- HPKE `info` is empty.
- The receiver refuses a `sent_at` more than 5 minutes from its clock (either
  direction) and a `nonce` already accepted for that client in the last 10
  minutes. A nonce is recorded only after the envelope authenticates.

This module never logs anything.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from pyhpke.exceptions import PyHPKEError

from .errors import BAD_ARGUMENTS, NOT_ALLOWED

ENCRYPTION_E2E = "end-to-end"
ENCRYPTION_NONE = "none"
ALG = "X25519-HKDF-SHA256-ChaCha20Poly1305"
MODE = "auth"
FIELDS = frozenset({"alg", "mode", "kid", "enc", "ct", "nonce", "sent_at"})
MIME_TYPE = "application/vnd.gateway.e2e+json"
CONTRACT_VERSION = 1
HPKE_INFO = b""
KEY_BYTES = 32
NONCE_BYTES = 16
MAX_AGE_SECONDS = 300        # sent_at more than 5 minutes off is refused
REPLAY_WINDOW_SECONDS = 600  # a nonce is remembered per client for 10 minutes

_SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
_KID = re.compile(r"[0-9a-f]{32}")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class E2EError(Exception):
    """An envelope was refused. `code` is the section 6.3 code to answer with;
    the message names what is wrong, never a value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# --- encoding helpers ------------------------------------------------------------

def b64url_encode(raw: bytes) -> str:
    """Unpadded base64url."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: Any, field: str = "value") -> bytes:
    """Bytes of unpadded (or padded) base64url text; ValueError otherwise."""
    if not isinstance(text, str):
        raise ValueError(f"{field} is not base64url text")
    stripped = text.rstrip("=")
    if not _B64URL.fullmatch(stripped) or len(stripped) % 4 == 1:
        raise ValueError(f"{field} is not base64url text")
    try:
        return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(f"{field} is not base64url text") from None


def canonical_json(value: Any) -> bytes:
    """UTF-8 JSON, keys sorted, no spaces (the associated-data form)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def key_id(public_key_raw: bytes) -> str:
    """Section 7.1 `kid`: first 16 bytes of SHA-256 over the raw 32-byte
    public key, as hex."""
    return hashlib.sha256(public_key_raw).digest()[:16].hex()


def decode_public_key(text: Any, field: str = "public_key") -> bytes:
    raw = b64url_decode(text, field)
    if len(raw) != KEY_BYTES:
        raise ValueError(f"{field} must decode to {KEY_BYTES} bytes")
    return raw


# --- keys ------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyPair:
    """An X25519 key pair. `repr` never shows the private key."""

    _private: X25519PrivateKey

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_b64(cls, text: str) -> "KeyPair":
        """From the base64url raw 32-byte private key."""
        raw = b64url_decode(text.strip(), "private key")
        if len(raw) != KEY_BYTES:
            raise ValueError(f"private key must decode to {KEY_BYTES} bytes")
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def private_b64(self) -> str:
        """The raw private key as base64url. Only for storing it once."""
        return b64url_encode(self._private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    @property
    def public_raw(self) -> bytes:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_b64(self) -> str:
        return b64url_encode(self.public_raw)

    @property
    def kid(self) -> str:
        return key_id(self.public_raw)

    def __repr__(self) -> str:
        return f"KeyPair(kid={self.kid})"


def _kem_private(pair: KeyPair) -> Any:
    return KEMKey.from_pyca_cryptography_key(pair._private)


def _kem_public(raw: bytes) -> Any:
    return KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(raw))


# --- associated data -------------------------------------------------------------

def header(*, user_id: str, client_id: str, service: str, tool: str | None = None,
           uri: str | None = None, encryption: str = ENCRYPTION_E2E,
           contract_version: int = CONTRACT_VERSION) -> dict[str, Any]:
    """The request's associated-data fields, without `nonce` and `sent_at`
    (those come from the envelope). Exactly one of `tool` / `uri`."""
    if (tool is None) == (uri is None):
        raise ValueError("exactly one of tool / uri")
    fields: dict[str, Any] = {
        "contract_version": contract_version, "user_id": user_id,
        "client_id": client_id, "service": service, "encryption": encryption,
    }
    fields["tool" if tool is not None else "uri"] = tool if tool is not None else uri
    return fields


def reply_header(request_header: dict[str, Any], request_id: str) -> dict[str, Any]:
    """A reply's associated-data fields: the request's plus `request_id` and
    `direction: "reply"`."""
    return {**request_header, "request_id": request_id, "direction": "reply"}


def associated_data(fields: dict[str, Any], nonce: str, sent_at: int) -> bytes:
    return canonical_json({**fields, "nonce": nonce, "sent_at": sent_at})


# --- seal / open -----------------------------------------------------------------

def seal(value: Any, *, sender: KeyPair, recipient_public_raw: bytes,
         fields: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """Encrypt `value` (as UTF-8 JSON) from `sender` to the recipient's key.
    `fields` is `header(...)` or `reply_header(...)`. Returns the envelope."""
    nonce = b64url_encode(secrets.token_bytes(NONCE_BYTES))
    sent_at = int(time.time() if now is None else now)
    enc, context = _SUITE.create_sender_context(
        _kem_public(recipient_public_raw), info=HPKE_INFO, sks=_kem_private(sender))
    ct = context.seal(canonical_json(value), aad=associated_data(fields, nonce, sent_at))
    return {"alg": ALG, "mode": MODE, "kid": sender.kid, "enc": b64url_encode(enc),
            "ct": b64url_encode(ct), "nonce": nonce, "sent_at": sent_at}


def check_shape(envelope: Any) -> None:
    """Raise E2EError(bad_arguments) unless `envelope` has the 7.1 shape."""
    def bad(message: str) -> E2EError:
        return E2EError(BAD_ARGUMENTS, f"invalid end-to-end envelope: {message}")

    if not isinstance(envelope, dict):
        raise bad("not a JSON object")
    if set(envelope) != FIELDS:
        raise bad(f"fields must be exactly {', '.join(sorted(FIELDS))}")
    if envelope["alg"] != ALG:
        raise bad(f"alg must be {ALG}")
    if envelope["mode"] != MODE:
        raise bad(f"mode must be {MODE}")
    if not isinstance(envelope["kid"], str) or not _KID.fullmatch(envelope["kid"]):
        raise bad("kid must be 32 lowercase hex characters")
    try:
        if len(b64url_decode(envelope["enc"], "enc")) != KEY_BYTES:
            raise bad("enc must decode to 32 bytes")
        if not b64url_decode(envelope["ct"], "ct"):
            raise bad("ct is empty")
        if len(b64url_decode(envelope["nonce"], "nonce")) != NONCE_BYTES:
            raise bad("nonce must decode to 16 bytes")
    except ValueError as exc:
        raise bad(str(exc)) from None
    sent_at = envelope["sent_at"]
    if not isinstance(sent_at, int) or isinstance(sent_at, bool) or sent_at < 0:
        raise bad("sent_at must be integer unix seconds")


class ReplayGuard:
    """Remembers each accepted nonce per client for REPLAY_WINDOW_SECONDS.
    Thread-safe; in memory (a restart forgets, which the 5-minute `sent_at`
    limit bounds)."""

    def __init__(self, window: float = REPLAY_WINDOW_SECONDS) -> None:
        self._window = window
        self._seen: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def claim(self, client_id: str, nonce: str, now: float) -> bool:
        """Record `nonce` for `client_id`; False when it was already recorded
        within the window (a replay). Check and record are one atomic step."""
        with self._lock:
            nonces = self._seen.setdefault(client_id, {})
            for old in [n for n, exp in nonces.items() if exp <= now]:
                del nonces[old]
            if nonce in nonces:
                return False
            nonces[nonce] = now + self._window
            return True


def open_envelope(envelope: Any, *, recipient: KeyPair, sender_public_raw: bytes,
                  fields: dict[str, Any], replay: ReplayGuard | None = None,
                  replay_client_id: str | None = None,
                  now: float | None = None) -> Any:
    """Check, authenticate and decrypt `envelope` sent by the holder of
    `sender_public_raw`; return the decoded JSON value.

    Refusals (E2EError): shape, `kid` not the sender's key, undecryptable or
    tampered (`bad_arguments`); `sent_at` more than 5 minutes off, or a nonce
    already accepted for `replay_client_id` (`not_allowed`)."""
    check_shape(envelope)
    clock = time.time() if now is None else now
    if envelope["kid"] != key_id(sender_public_raw):
        raise E2EError(BAD_ARGUMENTS, "envelope kid does not name the sender's key")
    if abs(clock - envelope["sent_at"]) > MAX_AGE_SECONDS:
        raise E2EError(NOT_ALLOWED, "envelope sent_at is more than 5 minutes off")
    try:
        context = _SUITE.create_recipient_context(
            b64url_decode(envelope["enc"]), _kem_private(recipient), info=HPKE_INFO,
            pks=_kem_public(sender_public_raw))
        plaintext = context.open(
            b64url_decode(envelope["ct"]),
            aad=associated_data(fields, envelope["nonce"], envelope["sent_at"]))
    except (PyHPKEError, ValueError):
        raise E2EError(BAD_ARGUMENTS, "envelope did not decrypt (wrong key or "
                                      "tampered data)") from None
    if replay is not None and not replay.claim(replay_client_id or "", envelope["nonce"], clock):
        raise E2EError(NOT_ALLOWED, "envelope nonce was already used")
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise E2EError(BAD_ARGUMENTS, "envelope plaintext is not UTF-8 JSON") from None

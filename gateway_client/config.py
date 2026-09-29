"""Service configuration from arguments or the environment.

| Variable | Meaning |
|---|---|
| `GATEWAY_BACKEND_URL` | The gateway's `/backend` WebSocket URL (default `ws://127.0.0.1:8000/backend`). |
| `SERVICE_NAME` | The service's reserved name. Required. |
| `SERVICE_CREDENTIAL` | The service's own credential. Required. |
| `SERVICE_PRIVATE_KEY` | base64url raw X25519 private key. |
| `SERVICE_PRIVATE_KEY_FILE` | A file holding it (read if present, created 0600 if not). |
| `WN_BACKEND_TOKEN` | Legacy shared token; enables the old-protocol fallback. |
| `BACKEND_ID` | Legacy registry id (default: `SERVICE_NAME`). |

When neither key variable is set, a key pair is generated and the private
key printed ONCE to stderr with instructions; the gateway pins the public key
at the first accepted registration, so it must be kept.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, TextIO

from .e2e import KeyPair
from .errors import ConfigError

DEFAULT_URL = "ws://127.0.0.1:8000/backend"


@dataclass(frozen=True)
class Config:
    url: str
    service_name: str
    credential: str = field(repr=False)
    key: KeyPair
    legacy_token: str | None = field(default=None, repr=False)
    backend_id: str | None = None

    @property
    def legacy_backend_id(self) -> str:
        return self.backend_id or self.service_name

    @classmethod
    def load(cls, *, url: str | None = None, service_name: str | None = None,
             credential: str | None = None, private_key: str | KeyPair | None = None,
             private_key_file: str | os.PathLike | None = None,
             legacy_token: str | None = None, backend_id: str | None = None,
             env: Mapping[str, str] | None = None,
             stderr: TextIO | None = None) -> "Config":
        """Arguments win over the environment. Raises ConfigError."""
        env = os.environ if env is None else env
        url = (url or env.get("GATEWAY_BACKEND_URL") or DEFAULT_URL).strip()
        service_name = (service_name or env.get("SERVICE_NAME") or "").strip()
        credential = (credential or env.get("SERVICE_CREDENTIAL") or "").strip()
        if not service_name or not credential:
            raise ConfigError("SERVICE_NAME and SERVICE_CREDENTIAL are required "
                              "(gateway service contract version 1).")
        if not url.startswith(("ws://", "wss://")):
            raise ConfigError("GATEWAY_BACKEND_URL must be a ws:// or wss:// URL")
        key = _load_key(private_key, private_key_file, env, service_name,
                        stderr or sys.stderr)
        legacy_token = legacy_token or env.get("WN_BACKEND_TOKEN") or None
        backend_id = backend_id or env.get("BACKEND_ID") or None
        return cls(url=url, service_name=service_name, credential=credential, key=key,
                   legacy_token=legacy_token, backend_id=backend_id)


def _load_key(private_key: str | KeyPair | None, key_file: str | os.PathLike | None,
              env: Mapping[str, str], service_name: str, stderr: TextIO) -> KeyPair:
    if isinstance(private_key, KeyPair):
        return private_key
    text = private_key or env.get("SERVICE_PRIVATE_KEY")
    if text:
        try:
            return KeyPair.from_private_b64(text)
        except ValueError:
            raise ConfigError("SERVICE_PRIVATE_KEY is not a base64url 32-byte "
                              "X25519 private key") from None
    path = key_file or env.get("SERVICE_PRIVATE_KEY_FILE")
    if path:
        return _key_from_file(Path(path))
    key = KeyPair.generate()
    stderr.write(
        "\n=== gateway-client: no SERVICE_PRIVATE_KEY set; generated a new key pair ===\n"
        f"Service {service_name!r}, public key {key.public_b64} (kid {key.kid}).\n"
        "The gateway pins this public key at the first accepted registration.\n"
        "Store the private key below as SERVICE_PRIVATE_KEY (or in a file named by\n"
        "SERVICE_PRIVATE_KEY_FILE) in a secret store now. It is shown only this once;\n"
        "restarting without it registers a different key and is rejected\n"
        "with key_changed until an admin approves the new fingerprint.\n\n"
        f"SERVICE_PRIVATE_KEY={key.private_b64()}\n\n")
    stderr.flush()
    return key


def _key_from_file(path: Path) -> KeyPair:
    if path.exists():
        try:
            return KeyPair.from_private_b64(path.read_text(encoding="ascii"))
        except (ValueError, UnicodeDecodeError):
            raise ConfigError(f"{path} does not hold a base64url 32-byte X25519 "
                              "private key") from None
    key = KeyPair.generate()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ConfigError(f"cannot create key file {path}: {exc.strerror}") from None
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key.private_b64() + "\n")
    return key

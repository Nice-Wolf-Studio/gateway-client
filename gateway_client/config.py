"""Service configuration from arguments or the environment.

| Variable | Meaning |
|---|---|
| `GATEWAY_BACKEND_URL` | The gateway's `/backend` WebSocket URL (default `ws://127.0.0.1:8000/backend`). |
| `SERVICE_NAME` | The service's reserved name. Required. |
| `SERVICE_CREDENTIAL` | The service's own credential. Required. |
| `SERVICE_PRIVATE_KEY` | base64url raw X25519 private key. |
| `SERVICE_PRIVATE_KEY_FILE` | A file holding it (read if present, created 0600 if not). |
| `GATEWAY_JWKS_URL` | The gateway's key set for GW-3 caller tokens (default: derived from `GATEWAY_BACKEND_URL`, `wss://host/backend` -> `https://host/.well-known/jwks.json`). |
| `SERVICE_PIN_STORE_FILE` | Optional file path for persisting end-to-end downgrade pins across restarts. |

When neither key variable is set, a key pair is generated and the private
key printed ONCE to stderr with instructions; the gateway pins the public key
at the first accepted registration, so it must be kept.
"""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, TextIO
from urllib.parse import urlsplit

from .caller_token import jwks_url_for
from .e2e import KeyPair
from .errors import ConfigError

DEFAULT_URL = "ws://127.0.0.1:8000/backend"


@dataclass(frozen=True)
class Config:
    url: str
    service_name: str
    credential: str = field(repr=False)
    key: KeyPair
    jwks_url: str | None = None
    pin_store_file: Path | None = None

    @property
    def key_set_url(self) -> str:
        """`jwks_url`, else the key-set URL derived from `url`."""
        return self.jwks_url or jwks_url_for(self.url)

    @classmethod
    def load(cls, *, url: str | None = None, service_name: str | None = None,
             credential: str | None = None, private_key: str | KeyPair | None = None,
             private_key_file: str | os.PathLike | None = None,
             jwks_url: str | None = None,
             pin_store_file: str | os.PathLike | None = None,
             env: Mapping[str, str] | None = None,
             stderr: TextIO | None = None) -> "Config":
        """Arguments win over the environment. Raises ConfigError."""
        env = os.environ if env is None else env
        raw_url = url if url is not None else (env.get("GATEWAY_BACKEND_URL") or DEFAULT_URL)
        url = raw_url.strip()
        service_name = (service_name if service_name is not None
                        else (env.get("SERVICE_NAME") or "")).strip()
        credential = (credential if credential is not None
                      else (env.get("SERVICE_CREDENTIAL") or "")).strip()
        if not service_name or not credential:
            raise ConfigError("SERVICE_NAME and SERVICE_CREDENTIAL are required "
                              "(gateway service contract version 2).")
        url_parts = urlsplit(url)
        if url_parts.scheme not in ("ws", "wss") or not url_parts.hostname:
            raise ConfigError("GATEWAY_BACKEND_URL must be a ws:// or wss:// URL with a host")
        key = _load_key(private_key, private_key_file, env, service_name,
                        stderr or sys.stderr)
        if jwks_url is not None:
            jwks_url = jwks_url.strip()
            if not jwks_url:
                raise ConfigError("GATEWAY_JWKS_URL must be an https:// or http:// URL")
        else:
            jwks_url = (env.get("GATEWAY_JWKS_URL") or "").strip() or None
        if jwks_url is not None:
            jwks_parts = urlsplit(jwks_url)
            if jwks_parts.scheme not in ("http", "https") or not jwks_parts.hostname:
                raise ConfigError("GATEWAY_JWKS_URL must be an https:// or http:// URL with a host")
        if pin_store_file is not None:
            pin_str = pin_store_file.strip() if isinstance(pin_store_file, str) else os.fspath(pin_store_file)
            if isinstance(pin_str, str) and not pin_str.strip():
                raise ConfigError("SERVICE_PIN_STORE_FILE cannot be empty")
            pin_path: Path | None = Path(pin_str)
        else:
            raw_pin = (env.get("SERVICE_PIN_STORE_FILE") or "").strip()
            pin_path = Path(raw_pin) if raw_pin else None
        if pin_path is not None and pin_path.is_dir():
            raise ConfigError(f"SERVICE_PIN_STORE_FILE {pin_path} is a directory")
        return cls(url=url, service_name=service_name, credential=credential, key=key,
                   jwks_url=jwks_url, pin_store_file=pin_path)


def _load_key(private_key: str | KeyPair | None, key_file: str | os.PathLike | None,
              env: Mapping[str, str], service_name: str, stderr: TextIO) -> KeyPair:
    if isinstance(private_key, KeyPair):
        return private_key
    if private_key is not None:
        text = private_key.strip()
        if not text:
            raise ConfigError("SERVICE_PRIVATE_KEY is not a base64url 32-byte "
                              "X25519 private key")
        try:
            return KeyPair.from_private_b64(text)
        except ValueError:
            raise ConfigError("SERVICE_PRIVATE_KEY is not a base64url 32-byte "
                              "X25519 private key") from None
    if key_file is not None:
        path_val = key_file.strip() if isinstance(key_file, str) else os.fspath(key_file)
        if isinstance(path_val, str) and not path_val.strip():
            raise ConfigError("SERVICE_PRIVATE_KEY_FILE cannot be empty")
        return _key_from_file(Path(path_val))
    text = (env.get("SERVICE_PRIVATE_KEY") or "").strip()
    if text:
        try:
            return KeyPair.from_private_b64(text)
        except ValueError:
            raise ConfigError("SERVICE_PRIVATE_KEY is not a base64url 32-byte "
                              "X25519 private key") from None
    raw_path = (env.get("SERVICE_PRIVATE_KEY_FILE") or "").strip()
    if raw_path:
        return _key_from_file(Path(raw_path))
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


def _read_key_file(path: Path) -> KeyPair:
    try:
        text = path.read_text(encoding="ascii")
    except UnicodeDecodeError:
        raise ConfigError(f"{path} does not hold a base64url 32-byte X25519 "
                          "private key") from None
    except OSError as exc:
        raise ConfigError(f"cannot read key file {path}: {exc.strerror or exc}") from None
    try:
        return KeyPair.from_private_b64(text)
    except ValueError:
        raise ConfigError(f"{path} does not hold a base64url 32-byte X25519 "
                          "private key") from None


def _key_from_file(path: Path) -> KeyPair:
    if path.exists() or path.is_symlink():
        return _read_key_file(path)
    key = KeyPair.generate()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd: int | None
        tmp_fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp")
    except OSError as exc:
        raise ConfigError(f"cannot create key file {path}: {exc.strerror or exc}") from None
    try:
        os.chmod(tmp_name, 0o600)
        payload = (key.private_b64() + "\n").encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(tmp_fd, view)
            if written <= 0:
                raise OSError("short write to key file")
            view = view[written:]
        os.fsync(tmp_fd)
        fd_to_close = tmp_fd
        tmp_fd = None
        os.close(fd_to_close)
        try:
            os.link(tmp_name, path)
        except FileExistsError:
            return _read_key_file(path)
    except OSError as exc:
        raise ConfigError(f"cannot create key file {path}: {exc.strerror or exc}") from None
    finally:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
    return key

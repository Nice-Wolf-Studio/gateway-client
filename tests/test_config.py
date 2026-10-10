"""Configuration from arguments and the environment."""

from __future__ import annotations

import io
import os
import stat

import pytest

from gateway_client import Config, ConfigError, KeyPair

BASE = {"SERVICE_NAME": "svc", "SERVICE_CREDENTIAL": "cred",
        "GATEWAY_BACKEND_URL": "wss://gw.example/backend"}


def test_from_env():
    key = KeyPair.generate()
    cfg = Config.load(env={**BASE, "SERVICE_PRIVATE_KEY": key.private_b64()})
    assert (cfg.url, cfg.service_name, cfg.credential) == (
        "wss://gw.example/backend", "svc", "cred")
    assert cfg.key.public_raw == key.public_raw
    assert cfg.key_set_url == "https://gw.example/.well-known/jwks.json"
    assert "cred" not in repr(cfg)
    assert key.private_b64() not in repr(cfg)


def test_arguments_override_env_and_defaults():
    cfg = Config.load(service_name="other", env={**BASE, "SERVICE_PRIVATE_KEY":
                                                  KeyPair.generate().private_b64()})
    assert cfg.service_name == "other" and cfg.jwks_url is None


def test_jwks_url_from_env_or_argument():
    env = {**BASE, "SERVICE_PRIVATE_KEY": KeyPair.generate().private_b64(),
           "GATEWAY_JWKS_URL": "https://keys.example/jwks.json"}
    assert Config.load(env=env).key_set_url == "https://keys.example/jwks.json"
    cfg = Config.load(env=env, jwks_url="https://other.example/jwks.json")
    assert cfg.key_set_url == "https://other.example/jwks.json"
    with pytest.raises(ConfigError, match="GATEWAY_JWKS_URL"):
        Config.load(env={**env, "GATEWAY_JWKS_URL": "ftp://x/jwks.json"})


def test_legacy_settings_are_gone():
    env = {**BASE, "SERVICE_PRIVATE_KEY": KeyPair.generate().private_b64(),
           "WN_BACKEND_TOKEN": "tok", "BACKEND_ID": "svc-1"}
    cfg = Config.load(env=env)
    assert not hasattr(cfg, "legacy_token") and not hasattr(cfg, "backend_id")
    with pytest.raises(TypeError):
        Config.load(env=env, legacy_token="tok")


@pytest.mark.parametrize("missing", ["SERVICE_NAME", "SERVICE_CREDENTIAL"])
def test_required(missing):
    env = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(ConfigError):
        Config.load(env=env, stderr=io.StringIO())


def test_bad_private_key():
    with pytest.raises(ConfigError, match="SERVICE_PRIVATE_KEY"):
        Config.load(env={**BASE, "SERVICE_PRIVATE_KEY": "not-a-key"})


def test_generated_key_printed_once_to_stderr():
    err = io.StringIO()
    cfg = Config.load(env=BASE, stderr=err)
    text = err.getvalue()
    assert f"SERVICE_PRIVATE_KEY={cfg.key.private_b64()}" in text
    assert text.count(cfg.key.private_b64()) == 1
    assert cfg.key.public_b64 in text


def test_key_file_created_0600_then_reused(tmp_path):
    path = tmp_path / "service.key"
    err = io.StringIO()
    first = Config.load(env={**BASE, "SERVICE_PRIVATE_KEY_FILE": str(path)}, stderr=err)
    assert path.exists() and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert err.getvalue() == ""  # never printed when a file is used
    second = Config.load(env={**BASE, "SERVICE_PRIVATE_KEY_FILE": str(path)})
    assert second.key.public_raw == first.key.public_raw

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


def test_pin_store_file_from_env_and_argument(tmp_path):
    key = KeyPair.generate()
    env = {**BASE, "SERVICE_PRIVATE_KEY": key.private_b64()}
    assert Config.load(env=env).pin_store_file is None

    pin_path = tmp_path / "pins.txt"
    cfg_env = Config.load(env={**env, "SERVICE_PIN_STORE_FILE": str(pin_path)})
    assert cfg_env.pin_store_file == pin_path

    other_path = tmp_path / "other.txt"
    cfg_arg = Config.load(env={**env, "SERVICE_PIN_STORE_FILE": str(pin_path)},
                          pin_store_file=str(other_path))
    assert cfg_arg.pin_store_file == other_path


def test_pin_store_file_rejects_empty_or_directory(tmp_path):
    key = KeyPair.generate()
    env = {**BASE, "SERVICE_PRIVATE_KEY": key.private_b64()}
    d = tmp_path / "pindir"
    d.mkdir()
    os.chmod(d, 0o755)
    for bad in ("", "   ", d):
        with pytest.raises(ConfigError):
            Config.load(env=env, pin_store_file=bad)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o755


def test_key_from_file_unreadable_or_directory_raises_config_error(tmp_path, monkeypatch):
    from pathlib import Path
    d = tmp_path / "keydir"
    d.mkdir()
    with pytest.raises(ConfigError):
        Config.load(env=BASE, private_key_file=d)

    f = tmp_path / "unreadable.key"
    f.write_text("dummy", encoding="ascii")
    orig_read_text = Path.read_text

    def fail_read(self, *args, **kwargs):
        if self == f:
            raise PermissionError(13, "Permission denied", str(f))
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_read)
    with pytest.raises(ConfigError):
        Config.load(env=BASE, private_key_file=f)


def test_private_key_file_strips_whitespace(tmp_path):
    key_path = tmp_path / "my.key"
    c1 = Config.load(env={**BASE, "SERVICE_PRIVATE_KEY_FILE": f"  {key_path}\n"})
    assert key_path.exists()
    c2 = Config.load(env=BASE, private_key_file=f" {key_path}\t")
    assert c2.key.public_raw == c1.key.public_raw


def test_explicit_empty_kwargs_do_not_fall_back_to_env(tmp_path):
    key = KeyPair.generate()
    env = {**BASE, "SERVICE_PRIVATE_KEY": key.private_b64()}
    with pytest.raises(ConfigError):
        Config.load(service_name="", credential="c", env=env)
    with pytest.raises(ConfigError):
        Config.load(service_name="s", credential="", env=env)
    with pytest.raises(ConfigError):
        Config.load(url="", env=env)
    with pytest.raises(ConfigError):
        Config.load(jwks_url="", env=env)
    with pytest.raises(ConfigError):
        Config.load(private_key="", env=env)
    with pytest.raises(ConfigError):
        Config.load(private_key_file="", env=env)


@pytest.mark.parametrize("bad_url", ["ws://", "wss:///backend", "ws://:8000/backend"])
def test_hostless_backend_url_raises_config_error(bad_url):
    key = KeyPair.generate()
    with pytest.raises(ConfigError):
        Config.load(url=bad_url, service_name="s", credential="c", private_key=key)


@pytest.mark.parametrize("bad_jwks", ["https://", "http:///jwks.json", "https://:8443/jwks"])
def test_hostless_jwks_url_raises_config_error(bad_jwks):
    key = KeyPair.generate()
    with pytest.raises(ConfigError):
        Config.load(jwks_url=bad_jwks, service_name="s", credential="c", private_key=key)


def test_concurrent_key_from_file_creation_converges_without_zero_byte_file(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from gateway_client.config import _key_from_file

    key_path = tmp_path / "nested" / "concurrent.key"
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _key_from_file(key_path), range(8)))
    assert key_path.stat().st_size > 0
    assert len({k.public_raw for k in results}) == 1


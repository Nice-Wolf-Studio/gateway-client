"""Unit tests for FilePinStore and pin persistence."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from gateway_client.pins import FilePinStore


def test_file_pin_store_creates_file_0600(tmp_path: Path):
    path = tmp_path / "pins.txt"
    assert not path.exists()
    store = FilePinStore(path)
    assert path.exists()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert len(store) == 0
    assert list(store) == []


def test_file_pin_store_add_and_persistence(tmp_path: Path):
    path = tmp_path / "pins.txt"
    store1 = FilePinStore(path)
    store1.add("wrn:access:client/app-1")
    store1.add("wrn:access:client/app-2")
    assert "wrn:access:client/app-1" in store1
    assert "wrn:access:client/app-2" in store1
    assert "wrn:access:client/app-3" not in store1
    assert len(store1) == 2
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    # Second store instance loads persisted pins
    store2 = FilePinStore(path)
    assert len(store2) == 2
    assert "wrn:access:client/app-1" in store2
    assert "wrn:access:client/app-2" in store2
    assert "wrn:access:client/app-3" not in store2


def test_file_pin_store_discard_remove_clear(tmp_path: Path):
    path = tmp_path / "pins.txt"
    store = FilePinStore(path)
    store.add("wrn:access:client/app-1")
    store.add("wrn:access:client/app-2")

    store.discard("wrn:access:client/non-existent")
    assert len(store) == 2

    store.remove("wrn:access:client/app-1")
    assert "wrn:access:client/app-1" not in store
    assert len(store) == 1

    with pytest.raises(KeyError):
        store.remove("wrn:access:client/app-1")

    store.clear()
    assert len(store) == 0
    assert not list(store)

    # Persisted empty
    store_reloaded = FilePinStore(path)
    assert len(store_reloaded) == 0


def test_file_pin_store_validation(tmp_path: Path):
    path = tmp_path / "pins.txt"
    store = FilePinStore(path)
    with pytest.raises(TypeError):
        store.add(123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="newlines"):
        store.add("wrn:app\ninvalid")
    with pytest.raises(ValueError, match="empty"):
        store.add("   ")


def test_file_pin_store_reloads_on_external_change(tmp_path: Path):
    path = tmp_path / "pins.txt"
    store = FilePinStore(path)
    assert "wrn:access:client/ext" not in store

    # External append
    path.write_text("wrn:access:client/ext\n# comment\n\n", encoding="utf-8")
    assert "wrn:access:client/ext" in store
    assert len(store) == 1

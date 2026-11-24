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


@pytest.mark.parametrize("bad_pin", [
    "wrn:app1\u2028wrn:app2",
    "wrn:app1\u2029wrn:app2",
    "wrn:app1\x85wrn:app2",
    "wrn:app1\vwrn:app2",
    "wrn:app1\fwrn:app2",
    "wrn:app1\x1cwrn:app2",
    " wrn:app1",
    "wrn:app1 ",
    "#wrn:app1",
    "wrn:app1\u200b",
])
def test_file_pin_store_rejects_line_separators_whitespace_and_hash_prefix(tmp_path: Path, bad_pin: str):
    path = tmp_path / "pins.txt"
    store = FilePinStore(path)
    with pytest.raises(ValueError):
        store.add(bad_pin)
    assert bad_pin not in store
    assert len(FilePinStore(path)) == 0


def test_file_pin_store_round_trip_and_discard_exact(tmp_path: Path):
    path = tmp_path / "pins.txt"
    store = FilePinStore(path)
    val = "wrn:access:client/app with space"
    store.add(val)
    assert val in store
    assert val in FilePinStore(path)
    store.discard(f" {val} ")
    assert val in store

"""Persistent and pluggable stores for end-to-end downgrade pins."""

from __future__ import annotations

import collections.abc
import os
import tempfile
from collections.abc import Iterator, MutableSet
from pathlib import Path


class FilePinStore(MutableSet[str]):
    """Persistent store for pinned connected app WRNs on disk.

    Pinned app WRNs are stored one per line with atomic writes (via mkstemp +
    fsync + os.replace) and 0600 permissions matching SERVICE_PRIVATE_KEY_FILE safety.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._apps: set[str] = set()
        self._mtime_ns: int | None = None
        if self.path.exists():
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._load()
        else:
            self._save()

    def _load(self) -> None:
        if not self.path.exists():
            self._apps.clear()
            self._mtime_ns = None
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return
        self._apps = {
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        try:
            self._mtime_ns = self.path.stat().st_mtime_ns
        except OSError:
            self._mtime_ns = None

    def _reload_if_changed(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._apps.clear()
            self._mtime_ns = None
            return
        if self._mtime_ns != st.st_mtime_ns:
            self._load()

    def _save(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{self.path.name}.tmp",
        )
        try:
            os.chmod(tmp_name, 0o600)
            lines = [line + "\n" for line in sorted(self._apps)]
            content = "".join(lines).encode("utf-8")
            os.write(tmp_fd, content)
            os.fsync(tmp_fd)
            os.close(tmp_fd)
            os.replace(tmp_name, self.path)
            self._mtime_ns = self.path.stat().st_mtime_ns
        except BaseException:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
            if os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise

    def add(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"expected str, got {type(value).__name__}")
        if "\n" in value or "\r" in value:
            raise ValueError("pin value cannot contain newlines")
        value = value.strip()
        if not value:
            raise ValueError("pin value cannot be empty")
        self._reload_if_changed()
        if value not in self._apps:
            self._apps.add(value)
            self._save()

    def discard(self, value: str) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        self._reload_if_changed()
        if value in self._apps:
            self._apps.discard(value)
            self._save()

    def clear(self) -> None:
        self._reload_if_changed()
        if self._apps:
            self._apps.clear()
            self._save()

    def __contains__(self, x: object) -> bool:
        self._reload_if_changed()
        return x in self._apps

    def __iter__(self) -> Iterator[str]:
        self._reload_if_changed()
        return iter(set(self._apps))

    def __len__(self) -> int:
        self._reload_if_changed()
        return len(self._apps)

    def __repr__(self) -> str:
        return f"FilePinStore({str(self.path)!r})"

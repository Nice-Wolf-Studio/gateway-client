"""Persistent and pluggable stores for end-to-end downgrade pins."""

from __future__ import annotations

import collections.abc
import errno
import os
import tempfile
import threading
import unicodedata
from collections.abc import Iterator, MutableSet
from pathlib import Path

_FORBIDDEN_PIN_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))


class FilePinStore(MutableSet[str]):
    """Persistent store for pinned connected app WRNs on disk.

    Pinned app WRNs are stored one per line with atomic writes (via mkstemp +
    fsync + os.replace) and 0600 permissions matching SERVICE_PRIVATE_KEY_FILE safety.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if isinstance(path, str) and not path.strip():
            raise ValueError("pin store path cannot be empty")
        self.path = Path(path)
        self._apps: set[str] = set()
        self._file_stat: tuple[int, int, int] | None = None
        self._lock = threading.RLock()
        if self.path.is_dir():
            raise IsADirectoryError(errno.EISDIR, "pin store path is a directory", str(self.path))
        if self.path.exists():
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._load()
        else:
            self._save()

    @staticmethod
    def _stat_key(st: os.stat_result) -> tuple[int, int, int]:
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _load(self) -> None:
        if not self.path.exists():
            self._apps.clear()
            self._file_stat = None
            return
        if self.path.is_dir():
            raise IsADirectoryError(errno.EISDIR, "pin store path is a directory", str(self.path))
        text = self.path.read_text(encoding="utf-8")
        self._apps = {
            line.strip()
            for line in text.split("\n")
            if line.strip() and not line.strip().startswith("#")
        }
        self._file_stat = self._stat_key(self.path.stat())

    def _reload_if_changed(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._apps.clear()
            self._file_stat = None
            return
        if self._file_stat != self._stat_key(st):
            self._load()

    def _save(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        tmp_fd: int | None
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{self.path.name}.tmp",
        )
        try:
            os.chmod(tmp_name, 0o600)
            lines = [line + "\n" for line in sorted(self._apps)]
            content = "".join(lines).encode("utf-8")
            view = memoryview(content)
            while view:
                written = os.write(tmp_fd, view)
                if written <= 0:
                    raise OSError("short write to pin store")
                view = view[written:]
            os.fsync(tmp_fd)
            fd_to_close = tmp_fd
            tmp_fd = None
            os.close(fd_to_close)
            os.replace(tmp_name, self.path)
            self._file_stat = self._stat_key(self.path.stat())
        except BaseException:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def add(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"expected str, got {type(value).__name__}")
        if not value or not value.strip():
            raise ValueError("pin value cannot be empty")
        if value[0].isspace() or value[-1].isspace():
            raise ValueError("pin value cannot have leading or trailing whitespace")
        if value.startswith("#"):
            raise ValueError("pin value cannot start with '#'")
        if any(unicodedata.category(ch) in _FORBIDDEN_PIN_CATEGORIES for ch in value):
            raise ValueError("pin value cannot contain newlines or control characters")
        with self._lock:
            self._reload_if_changed()
            if value not in self._apps:
                self._apps.add(value)
                self._save()

    def discard(self, value: str) -> None:
        if not isinstance(value, str):
            return
        with self._lock:
            self._reload_if_changed()
            if value in self._apps:
                self._apps.discard(value)
                self._save()

    def clear(self) -> None:
        with self._lock:
            self._reload_if_changed()
            if self._apps:
                self._apps.clear()
                self._save()

    def __contains__(self, x: object) -> bool:
        with self._lock:
            self._reload_if_changed()
            return x in self._apps

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            self._reload_if_changed()
            return iter(set(self._apps))

    def __len__(self) -> int:
        with self._lock:
            self._reload_if_changed()
            return len(self._apps)

    def __repr__(self) -> str:
        return f"FilePinStore({str(self.path)!r})"

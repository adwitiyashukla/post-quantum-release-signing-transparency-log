import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

MAX_RESPONSE = 1 << 25


class NotFound(FileNotFoundError):
    pass


def sync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(src: Path, dst: Path, attempts: int = 40) -> None:
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if os.name != "nt" or attempt == attempts - 1:
                raise
            time.sleep(0.05)


def atomic_write(path, data: bytes, private: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    sync_dir(path.parent)


class DirStore:
    def __init__(self, root):
        self.root = Path(root)

    def read(self, path: str) -> bytes:
        try:
            return (self.root / path).read_bytes()
        except FileNotFoundError:
            raise NotFound(path) from None

    def write(self, path: str, data: bytes) -> None:
        atomic_write(self.root / path, data)

    __call__ = read


class HttpFetcher:
    def __init__(self, base: str, timeout: float = 10.0):
        self.base = base.rstrip("/") + "/"
        self.timeout = timeout

    def __call__(self, path: str) -> bytes:
        try:
            with urllib.request.urlopen(self.base + path, timeout=self.timeout) as resp:
                data = resp.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(path) from None
            raise
        if len(data) > MAX_RESPONSE:
            raise ValueError(f"response too large: {path}")
        return data


def fetcher(location: str, timeout: float = 10.0):
    if location.startswith(("http://", "https://")):
        return HttpFetcher(location, timeout)
    return DirStore(location)

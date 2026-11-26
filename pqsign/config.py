import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import note


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    name: str
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"


@dataclass(frozen=True)
class Config:
    base: Path
    log: Node
    batch_ms: int
    max_batch: int
    max_pending: int
    max_entry_bytes: int
    submit_timeout_s: float
    witnesses: tuple[Node, ...]
    quorum: int
    witness_timeout_s: float
    grace_ms: int
    max_future_s: int
    max_connections: int
    request_timeout_s: float
    signer: str
    scrypt_log_n: int
    expected: Path
    state: Path

    @property
    def keys(self) -> Path:
        return self.state / "keys"

    @property
    def policy(self) -> Path:
        return self.state / "policy.txt"

    @property
    def log_dir(self) -> Path:
        return self.state / "log"

    def witness_key(self, i: int) -> Path:
        return self.keys / f"witness-{i + 1}.key"

    def witness_state(self, i: int) -> Path:
        return self.state / f"witness-{i + 1}.json"


def _table(data: dict, key: str, fields: set[str]) -> dict:
    t = data.get(key)
    if not isinstance(t, dict):
        raise ConfigError(f"missing [{key}] table")
    extra = set(t) - fields
    if extra:
        raise ConfigError(f"unknown keys in [{key}]: {', '.join(sorted(extra))}")
    missing = fields - set(t)
    if missing:
        raise ConfigError(f"missing keys in [{key}]: {', '.join(sorted(missing))}")
    return t


def _int(t: dict, key: str, lo: int, hi: int, where: str) -> int:
    v = t[key]
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ConfigError(f"{where}.{key} must be an integer from {lo} to {hi}")
    return v


def _num(t: dict, key: str, lo: float, hi: float, where: str) -> float:
    v = t[key]
    if isinstance(v, bool) or not isinstance(v, int | float) or not lo <= v <= hi:
        raise ConfigError(f"{where}.{key} must be a number from {lo} to {hi}")
    return float(v)


def _name(v, where: str) -> str:
    if not isinstance(v, str) or not v.isascii():
        raise ConfigError(f"{where} must be an ASCII string")
    try:
        return note.check_name(v)
    except note.NoteError as e:
        raise ConfigError(f"{where}: {e}") from None


def _node(name, listen, where: str) -> Node:
    name = _name(name, f"{where}.name")
    if not isinstance(listen, str) or listen.count(":") != 1:
        raise ConfigError(f"{where}.listen must look like 127.0.0.1:7380")
    host, port = listen.split(":")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            raise ConfigError(f"{where}.listen needs an IP address or localhost") from None
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ConfigError(f"{where}.listen has a bad port")
    return Node(name, host, int(port))


def _path(base: Path, v, where: str) -> Path:
    if not isinstance(v, str) or not v:
        raise ConfigError(f"{where} must be a path")
    return (base / v).resolve()


def load(path) -> Config:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from None
    extra = set(data) - {"log", "witnesses", "http", "signer", "monitor", "paths"}
    if extra:
        raise ConfigError(f"unknown tables: {', '.join(sorted(extra))}")
    base = path.resolve().parent
    lg = _table(data, "log", {"origin", "listen", "batch_ms", "max_batch", "max_pending", "max_entry_bytes",
                              "submit_timeout_s"})
    wt = _table(data, "witnesses", {"quorum", "timeout_s", "grace_ms", "max_future_s", "nodes"})
    hp = _table(data, "http", {"max_connections", "request_timeout_s"})
    sg = _table(data, "signer", {"name", "scrypt_log_n"})
    mn = _table(data, "monitor", {"expected"})
    ps = _table(data, "paths", {"state"})
    nodes = wt["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 16:
        raise ConfigError("witnesses.nodes must list 1 to 16 witnesses")
    witnesses = []
    for i, n in enumerate(nodes):
        if not isinstance(n, dict) or set(n) != {"name", "listen"}:
            raise ConfigError(f"witnesses.nodes[{i}] needs exactly name and listen")
        witnesses.append(_node(n["name"], n["listen"], f"witnesses.nodes[{i}]"))
    log = _node(lg["origin"], lg["listen"], "log")
    names = [log.name] + [w.name for w in witnesses]
    ports = [(log.host, log.port)] + [(w.host, w.port) for w in witnesses]
    if len(set(names)) != len(names):
        raise ConfigError("log origin and witness names must all be different")
    if len(set(ports)) != len(ports):
        raise ConfigError("every server needs its own listen address")
    return Config(
        base=base,
        log=log,
        batch_ms=_int(lg, "batch_ms", 1, 60000, "log"),
        max_batch=_int(lg, "max_batch", 1, 65536, "log"),
        max_pending=_int(lg, "max_pending", 1, 1_000_000, "log"),
        max_entry_bytes=_int(lg, "max_entry_bytes", 4096, 65535, "log"),
        submit_timeout_s=_num(lg, "submit_timeout_s", 1, 3600, "log"),
        witnesses=tuple(witnesses),
        quorum=_int(wt, "quorum", 1, len(witnesses), "witnesses"),
        witness_timeout_s=_num(wt, "timeout_s", 0.1, 600, "witnesses"),
        grace_ms=_int(wt, "grace_ms", 0, 10000, "witnesses"),
        max_future_s=_int(wt, "max_future_s", 0, 86400, "witnesses"),
        max_connections=_int(hp, "max_connections", 1, 10000, "http"),
        request_timeout_s=_num(hp, "request_timeout_s", 0.1, 600, "http"),
        signer=_name(sg["name"], "signer.name"),
        scrypt_log_n=_int(sg, "scrypt_log_n", 14, 20, "signer"),
        expected=_path(base, mn["expected"], "monitor.expected"),
        state=_path(base, ps["state"], "paths.state"),
    )

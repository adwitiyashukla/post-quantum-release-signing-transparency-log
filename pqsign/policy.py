import re
import time
from dataclasses import dataclass, field

from . import note

FIELDS = re.compile(r"[ \t]+")
ALLOWED = set(range(0x20, 0x7F)) | set(range(0x80, 0x100)) | {0x09, 0x0A}


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    logs: list[note.PublicKey] = field(default_factory=list)
    witnesses: dict[str, note.PublicKey] = field(default_factory=dict)
    groups: dict[str, tuple[int, list[str]]] = field(default_factory=dict)
    quorum: str = "none"
    urls: dict[str, str] = field(default_factory=dict)

    def satisfied(self, cosigned: set[str]) -> bool:
        def ok(name: str) -> bool:
            if name == "none":
                return True
            if name in self.witnesses:
                return name in cosigned
            k, members = self.groups[name]
            return sum(ok(m) for m in members) >= k
        return ok(self.quorum)


def _key(text: str, algs: tuple[int, ...], what: str) -> note.PublicKey:
    try:
        key = note.parse_vkey(text)
    except note.NoteError as e:
        raise PolicyError(f"bad {what} vkey: {e}") from None
    if key.alg not in algs:
        raise PolicyError(f"unsupported {what} key type")
    return key


def parse_policy(data: bytes) -> Policy:
    data = data.replace(b"\r\n", b"\n")
    if any(b not in ALLOWED for b in data):
        raise PolicyError("policy contains control characters")
    p = Policy()
    keys, used, quorum = set(), set(), None
    for number, raw in enumerate(data.decode("utf-8", "surrogateescape").split("\n"), 1):
        line = raw.strip(" \t")
        if not line or line.startswith("#"):
            continue
        f = FIELDS.split(line)
        try:
            if f[0] == "log" and len(f) in (2, 3):
                key = _key(f[1], (note.ED25519, note.MLDSA44), "log")
                if key.key in keys:
                    raise PolicyError("duplicate key")
                keys.add(key.key)
                p.logs.append(key)
                if len(f) == 3:
                    p.urls[key.vkey()] = f[2]
            elif f[0] == "witness" and len(f) in (3, 4):
                name, key = f[1], _key(f[2], (note.MLDSA44,), "witness")
                if name == "none" or name in p.witnesses or name in p.groups:
                    raise PolicyError(f"duplicate name {name}")
                if key.key in keys:
                    raise PolicyError("duplicate key")
                keys.add(key.key)
                p.witnesses[name] = key
                if len(f) == 4:
                    p.urls[name] = f[3]
            elif f[0] == "group" and len(f) >= 4:
                name, members = f[1], f[3:]
                if name == "none" or name in p.witnesses or name in p.groups:
                    raise PolicyError(f"duplicate name {name}")
                for m in members:
                    if m not in p.witnesses and m not in p.groups:
                        raise PolicyError(f"unknown member {m}")
                    if m in used:
                        raise PolicyError(f"{m} is already a member of a group")
                    used.add(m)
                if f[2] == "all":
                    k = len(members)
                elif f[2] == "any":
                    k = 1
                elif re.fullmatch(r"[1-9][0-9]*", f[2]) and int(f[2]) <= len(members):
                    k = int(f[2])
                else:
                    raise PolicyError(f"bad threshold {f[2]}")
                p.groups[name] = (k, members)
            elif f[0] == "quorum" and len(f) == 2:
                if quorum is not None:
                    raise PolicyError("more than one quorum line")
                if f[1] != "none" and f[1] not in p.witnesses and f[1] not in p.groups:
                    raise PolicyError(f"unknown quorum {f[1]}")
                quorum = f[1]
            else:
                raise PolicyError(f"unknown line {f[0]!r}")
        except PolicyError as e:
            raise PolicyError(f"policy line {number}: {e}") from None
    if quorum is None:
        raise PolicyError("policy has no quorum line")
    p.quorum = quorum
    return p


def format_policy(logs, witnesses, threshold: int) -> bytes:
    lines = [f"log {key.vkey()} {url}" for key, url in logs]
    lines += [f"witness {name} {key.vkey()} {url}" for name, key, url in witnesses]
    names = " ".join(name for name, _, _ in witnesses)
    lines += [f"group witnesses {threshold} {names}", "quorum witnesses"]
    return ("\n".join(lines) + "\n").encode()


def verify_checkpoint(data: bytes, policy: Policy, now: float | None = None,
                      max_future: int = 600) -> tuple[note.Checkpoint, set[str]]:
    text, _ = note.split_note(data)
    cp = note.parse_checkpoint(text)
    log_keys = [k for k in policy.logs if k.name == cp.origin]
    if not log_keys:
        raise PolicyError(f"unknown log origin {cp.origin}")
    _, verified = note.verify_note(data, log_keys + list(policy.witnesses.values()))
    now = time.time() if now is None else now
    signed = {key for key, ts in verified if ts is None or ts <= now + max_future}
    if not any(key in log_keys for key in signed):
        if any(key in log_keys for key, _ in verified):
            raise PolicyError("the log signature is dated in the future")
        raise PolicyError("checkpoint is not signed by the log")
    cosigned = {name for name, key in policy.witnesses.items() if key in signed}
    if not policy.satisfied(cosigned):
        raise PolicyError(f"witness quorum not met, {len(cosigned)} valid cosignature(s)")
    return cp, cosigned

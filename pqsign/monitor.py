import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import merkle, note, policy, release, tiles
from .storage import HttpFetcher, atomic_write

SUM_LINE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")


def read_sums(path) -> set[tuple[str, str]]:
    sums = set()
    for line in Path(path).read_text("utf-8-sig").splitlines():
        if not line.strip():
            continue
        m = SUM_LINE.fullmatch(line.strip())
        if not m:
            raise ValueError(f"bad line in {path}: {line!r}")
        sums.add((m.group(2), m.group(1).lower()))
    return sums


@dataclass
class Report:
    old_size: int = 0
    size: int = 0
    checked: int = 0
    watched: int = 0
    alerts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Monitor:
    def __init__(self, fetch, trust: policy.Policy, watched: dict[str, release.ReleaseKey],
                 expected: set[tuple[str, str]], state_path, witness_timeout: float = 5.0):
        self.fetch = fetch
        self.trust = trust
        self.watched = watched
        self.expected = expected
        self.state_path = Path(state_path)
        self.witness_timeout = witness_timeout

    def _state(self) -> dict:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text())
        return {"size": 0, "root": note.b64(merkle.EMPTY), "frontier": []}

    def _inspect(self, index: int, data: bytes, report: Report) -> None:
        try:
            entry = release.parse_entry(data)
        except release.VerifyError as e:
            report.alerts.append(f"malformed entry at index {index}: {e}")
            return
        if entry.statement.signer not in self.watched:
            return
        report.watched += 1
        st = entry.statement
        try:
            key = release.check_entry(entry, self.watched)
        except release.VerifyError as e:
            report.alerts.append(f"entry at index {index} claims a watched key but {e}")
            return
        if (st.file, st.sha256) not in self.expected:
            report.alerts.append(f"unexpected release {st.file} (sha256 {st.sha256[:16]}) at index {index}, "
                                 f"signed by {key.name}")

    def run(self) -> Report:
        report = Report()
        state = self._state()
        report.old_size = state["size"]
        try:
            data = self.fetch("checkpoint")
        except OSError as e:
            report.alerts.append(f"could not fetch the checkpoint: {e}")
            return report
        try:
            cp, _ = policy.verify_checkpoint(data, self.trust)
        except ValueError as e:
            report.alerts.append(f"checkpoint does not verify: {e}")
            return report
        report.size = cp.size
        if cp.size < state["size"]:
            report.alerts.append(f"log went backwards from size {state['size']} to {cp.size}")
            return report
        if cp.size == state["size"]:
            if cp.root != note.unb64(state["root"]):
                report.alerts.append(f"log shows a different tree at size {cp.size}")
            else:
                self._check_witnesses(cp, report)
            return report
        frontier = merkle.Frontier(state["size"], [note.unb64(h) for h in state["frontier"]])
        reader = tiles.TileReader(self.fetch, cp.size)
        try:
            for t in range(state["size"] // tiles.WIDTH, (cp.size + tiles.WIDTH - 1) // tiles.WIDTH):
                for i, entry in enumerate(reader.entries(t), t * tiles.WIDTH):
                    if i < state["size"]:
                        continue
                    frontier.append(merkle.leaf_hash(entry))
                    report.checked += 1
                    self._inspect(i, entry, report)
        except (OSError, ValueError) as e:
            report.alerts.append(f"could not read the log entries: {e}")
            return report
        if frontier.root() != cp.root:
            report.alerts.append("log entries do not hash to the checkpoint root")
            return report
        self._check_witnesses(cp, report)
        state = {"origin": cp.origin, "size": cp.size, "root": note.b64(cp.root),
                 "frontier": [note.b64(h) for h in frontier.hashes], "checkpoint": data.decode()}
        atomic_write(self.state_path, json.dumps(state, indent=1).encode())
        return report

    def _check_witnesses(self, cp: note.Checkpoint, report: Report) -> None:
        origin_hash = hashlib.sha256(cp.origin.encode()).hexdigest()
        logs = [k for k in self.trust.logs if k.name == cp.origin]
        for name, key in self.trust.witnesses.items():
            url = self.trust.urls.get(name)
            if not url:
                continue
            try:
                data = HttpFetcher(url, self.witness_timeout)(f"{origin_hash}/checkpoint")
                text, verified = note.verify_note(data, logs + [key])
                if key not in {k for k, _ in verified}:
                    raise ValueError("no cosignature from the witness")
                seen = note.parse_checkpoint(text)
            except (OSError, ValueError) as e:
                report.notes.append(f"{name}: could not read its view ({e})")
                continue
            small, big = (seen, cp) if seen.size <= cp.size else (cp, seen)
            try:
                proof = merkle.consistency_proof(tiles.TileReader(self.fetch, big.size).node, small.size, big.size)
            except (OSError, ValueError) as e:
                report.alerts.append(f"{name} cosigned size {seen.size} but the log cannot prove it matches ({e})")
                continue
            if not merkle.verify_consistency(small.size, big.size, small.root, big.root, proof):
                report.alerts.append(f"split view: {name} saw a different tree at size {seen.size}")
            elif seen.size > cp.size:
                report.notes.append(f"{name} has already seen size {seen.size}, consistent")
            else:
                report.notes.append(f"{name} saw size {seen.size}, consistent")

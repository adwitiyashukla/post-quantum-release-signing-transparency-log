import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from . import merkle, note, policy, release, tiles, web
from .storage import DirStore, HttpFetcher, NotFound
from .witness import WitnessClient

IMMUTABLE = "public, max-age=31536000, immutable"


class LogError(Exception):
    pass


def _usable(future) -> bool:
    return not future.done() or (future.exception() is None and future.result() is not None)


class Log:
    def __init__(self, root, origin: str, keys: list[note.SecretKey], witnesses: list[WitnessClient], quorum: int,
                 deadline: float = 5.0, grace: float = 0.25):
        self.store = DirStore(root)
        self.origin = origin
        self.keys = keys
        self.witnesses = witnesses
        self.quorum = quorum
        self.deadline = deadline
        self.grace = grace
        self.pool = ThreadPoolExecutor(max_workers=max(1, len(witnesses)))
        self.inflight = {}
        self._load()

    def _load(self) -> None:
        verifiers = [k.public for k in self.keys]
        try:
            staged = self.store.read("staged")
        except NotFound:
            staged = None
        if staged is None:
            self.writer, self.frontier = tiles.TileWriter(), merkle.Frontier()
            self.staged = self._stage(self.writer, self.frontier)
        else:
            text, _ = note.verify_note(staged, verifiers)
            cp = note.parse_checkpoint(text)
            if cp.origin != self.origin:
                raise LogError(f"log directory belongs to {cp.origin}")
            reader = tiles.TileReader(self.store, cp.size)
            self.writer = tiles.TileWriter.load(self.store, cp.size)
            self.frontier = merkle.Frontier.from_tree(reader.node, cp.size)
            if self.frontier.root() != cp.root:
                raise LogError("stored tiles do not match the staged checkpoint")
            self.staged = (cp, staged)
        try:
            self.checkpoint = self.store.read("checkpoint")
            text, _ = note.verify_note(self.checkpoint, verifiers)
            self.published = note.parse_checkpoint(text).size
        except NotFound:
            self.checkpoint, self.published = None, -1

    @property
    def size(self) -> int:
        return self.writer.size

    def _stage(self, writer: tiles.TileWriter, frontier: merkle.Frontier) -> tuple[note.Checkpoint, bytes]:
        cp = note.Checkpoint(self.origin, writer.size, frontier.root())
        text = cp.text()
        signed = note.format_note(text, [k.sign(text) for k in self.keys])
        self.store.write("staged", signed)
        return cp, signed

    def append(self, entries: list[bytes]) -> int:
        writer, frontier = self.writer.copy(), self.frontier.copy()
        first = writer.size
        for path, data in writer.extend(entries).items():
            self.store.write(path, data)
        for e in entries:
            frontier.append(merkle.leaf_hash(e))
        self.staged = self._stage(writer, frontier)
        self.writer, self.frontier = writer, frontier
        return first

    def consistency(self, old: int, new: int) -> list[bytes]:
        return merkle.consistency_proof(tiles.TileReader(self.store, new).node, old, new)

    def publish(self) -> bool:
        cp, signed = self.staged
        if self.published == cp.size:
            return True
        text = cp.text()
        asked = {}
        for w in self.witnesses:
            prev = self.inflight.get(w.name)
            if prev and prev[0] == text and _usable(prev[1]):
                asked[prev[1]] = w
                continue
            if prev and not prev[1].done():
                continue
            future = self.pool.submit(w.cosign, text, signed, self.consistency)
            self.inflight[w.name] = (text, future)
            asked[future] = w
        got, pending = {}, set(asked)
        end = time.monotonic() + self.deadline
        while pending and len(got) < self.quorum:
            done, pending = wait(pending, timeout=max(0.0, end - time.monotonic()), return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                sig = future.result()
                if sig is not None:
                    got[asked[future].name] = sig
        if len(got) < self.quorum:
            return False
        if pending:
            done, _ = wait(pending, timeout=min(self.grace, max(0.0, end - time.monotonic())))
            for future in done:
                sig = future.result()
                if sig is not None:
                    got[asked[future].name] = sig
        sigs = [got[w.name] for w in self.witnesses if w.name in got]
        checkpoint = signed + b"".join(s.line() for s in sigs)
        self.store.write("checkpoint", checkpoint)
        self.checkpoint, self.published = checkpoint, cp.size
        return True

    def close(self) -> None:
        self.pool.shutdown(wait=False)

    def problems(self) -> list[str]:
        return [f"{w.name}: {w.error}" for w in self.witnesses if w.error]


class _Slot:
    def __init__(self, entry: bytes):
        self.entry = entry
        self.index = -1
        self.error = None
        self.sequenced = threading.Event()
        self.done = threading.Event()


class Sequencer:
    def __init__(self, log: Log, batch_ms: int, max_batch: int, max_pending: int, retry_ms: int = 1000,
                 on_event=None):
        self.log = log
        self.on_event = on_event or (lambda message: None)
        self.last_problem = ""
        self.batch = batch_ms / 1000
        self.max_batch = max_batch
        self.max_pending = max_pending
        self.retry = retry_ms / 1000
        self.pending: list[_Slot] = []
        self.waiting: list[_Slot] = []
        self.cond = threading.Condition()
        self.stopped = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "Sequencer":
        self.thread.start()
        return self

    def stop(self) -> None:
        with self.cond:
            self.stopped = True
            self.cond.notify()
        if self.thread.is_alive():
            self.thread.join()

    def submit(self, entry: bytes, timeout: float) -> tuple[int, bool]:
        slot = _Slot(entry)
        with self.cond:
            if len(self.pending) + len(self.waiting) >= self.max_pending:
                raise LogError("log is busy")
            self.pending.append(slot)
            self.cond.notify()
        if not slot.done.wait(timeout):
            with self.cond:
                if slot in self.pending:
                    self.pending.remove(slot)
                    raise LogError("timed out before the entry was sequenced, nothing was logged")
            if not slot.sequenced.wait(timeout):
                raise LogError("log is not making progress")
        if slot.error:
            raise LogError(slot.error)
        return slot.index, slot.done.is_set()

    def _append(self, batch: list[_Slot]) -> None:
        try:
            first = self.log.append([s.entry for s in batch])
        except Exception as e:
            for s in batch:
                s.error = f"log write failed: {e}"
                s.sequenced.set()
                s.done.set()
            self.on_event(f"log write failed: {e}")
            return
        with self.cond:
            for i, s in enumerate(batch):
                s.index = first + i
                s.sequenced.set()
            self.waiting += batch

    def _publish(self) -> None:
        try:
            published = self.log.publish()
        except Exception as e:
            published = False
            self.on_event(f"publishing failed: {e}")
        if published:
            with self.cond:
                done, self.waiting = self.waiting, []
            if done or self.last_problem:
                self.on_event(f"published tree size {self.log.published}, new entries: {len(done)}")
            for s in done:
                s.done.set()
            self.last_problem = ""
            return
        problem = "; ".join(self.log.problems()) or "not enough cosignatures"
        if problem != self.last_problem:
            self.on_event(f"waiting for witnesses: {problem}")
            self.last_problem = problem
        time.sleep(self.retry)

    def _run(self) -> None:
        while True:
            with self.cond:
                while not self.stopped and not self.pending and self.log.published == self.log.size:
                    self.cond.wait()
                if self.stopped:
                    return
            time.sleep(self.batch)
            with self.cond:
                batch, self.pending = self.pending[:self.max_batch], self.pending[self.max_batch:]
            if batch:
                self._append(batch)
            self._publish()


class _Handler(web.Handler):
    server_version = "pqsign-log"

    def do_GET(self):
        path = self.path.lstrip("/")
        lg = self.server.log
        try:
            if path == "checkpoint" and lg.checkpoint:
                return self.send(200, lg.checkpoint)
            if tiles.parse_path(path):
                return self.send(200, lg.store.read(path), "application/octet-stream", IMMUTABLE)
        except NotFound:
            pass
        self.send(404, b"not found\n")

    def do_POST(self):
        if self.path != "/add":
            return self.refuse(404, b"not found\n")
        data = self.body(self.server.max_entry)
        if data is None:
            return
        try:
            release.check_entry(release.parse_entry(data), self.server.signers)
        except release.VerifyError as e:
            return self.send(403, f"rejected: {e}\n".encode())
        try:
            index, published = self.server.sequencer.submit(data, self.server.submit_timeout)
        except LogError as e:
            return self.send(503, f"{e}\n".encode())
        self.send(200 if published else 202, f"{index}\n".encode())


def serve(log: Log, sequencer: Sequencer, signers: dict, host: str, port: int, max_entry: int, timeout: float,
          max_connections: int = 64, request_timeout: float = 10.0) -> web.Server:
    httpd = web.Server((host, port), _Handler, max_connections, request_timeout)
    httpd.log, httpd.sequencer, httpd.signers = log, sequencer, signers
    httpd.max_entry, httpd.submit_timeout = max_entry, timeout
    return httpd


def submit(url: str, entry: bytes, timeout: float) -> int:
    req = urllib.request.Request(url.rstrip("/") + "/add", data=entry, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return note.parse_decimal(resp.read(64).decode("ascii").strip())
    except urllib.error.HTTPError as e:
        raise LogError(f"log refused the entry: {e.read(1024).decode('utf-8', 'replace').strip()}") from None


def prove(url: str, entry: bytes, index: int, trust: policy.Policy, timeout: float, wait_s: float = 10.0) -> bytes:
    fetch = HttpFetcher(url, timeout)
    end = time.monotonic() + wait_s
    while True:
        try:
            data = fetch("checkpoint")
            cp, _ = policy.verify_checkpoint(data, trust)
            if cp.size > index:
                break
        except NotFound:
            pass
        if time.monotonic() > end:
            raise LogError(f"the entry is in the log at index {index}, but no witnessed checkpoint covers it yet")
        time.sleep(0.2)
    reader = tiles.TileReader(fetch, cp.size)
    if reader.entries(index // tiles.WIDTH)[index % tiles.WIDTH] != entry:
        raise LogError(f"log has a different entry at index {index}")
    hashes = merkle.inclusion_proof(reader.node, index, cp.size)
    if not merkle.verify_inclusion(merkle.leaf_hash(entry), index, cp.size, hashes, cp.root):
        raise LogError("log tiles do not match its checkpoint")
    return release.format_proof(entry, index, hashes, data)

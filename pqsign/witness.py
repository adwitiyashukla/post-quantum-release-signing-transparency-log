import hashlib
import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import merkle, note, web
from .storage import atomic_write

MAX_BODY = 1 << 18
MAX_PROOF = 63
CHECKPOINT_PATH = re.compile(r"/([0-9a-f]{64})/checkpoint")


def parse_request(body: bytes) -> tuple[int, list[bytes], bytes]:
    cut = body.find(b"\n\n")
    if cut < 0:
        raise note.NoteError("missing empty line")
    try:
        lines = body[:cut].decode("ascii").split("\n")
    except UnicodeDecodeError:
        raise note.NoteError("request header is not ASCII") from None
    if not lines[0].startswith("old ") or len(lines) - 1 > MAX_PROOF:
        raise note.NoteError("malformed request")
    return note.parse_decimal(lines[0][4:]), [note.unb64(x, 32) for x in lines[1:]], body[cut + 2:]


def format_request(old: int, proof: list[bytes], checkpoint: bytes) -> bytes:
    return "".join([f"old {old}\n"] + [note.b64(h) + "\n" for h in proof] + ["\n"]).encode() + checkpoint


class Witness:
    def __init__(self, key: note.SecretKey, logs: dict[str, list[note.PublicKey]], state_path):
        if key.alg != note.MLDSA44:
            raise ValueError("witness keys must be ML-DSA-44")
        self.key = key
        self.logs = logs
        self.state_path = Path(state_path)
        self.lock = threading.Lock()
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}

    def latest(self, origin_hash: str) -> bytes | None:
        with self.lock:
            for origin, st in self.state.items():
                if hashlib.sha256(origin.encode()).hexdigest() == origin_hash:
                    return st["checkpoint"].encode()
        return None

    def add_checkpoint(self, body: bytes) -> tuple[int, str, bytes]:
        try:
            old, proof, data = parse_request(body)
            text, sigs = note.split_note(data)
            cp = note.parse_checkpoint(text)
        except note.NoteError as e:
            return 400, "text/plain", f"bad request: {e}\n".encode()
        keys = self.logs.get(cp.origin)
        if keys is None:
            return 404, "text/plain", b"unknown log\n"
        try:
            _, verified = note.verify_note(data, keys)
        except note.NoteError as e:
            return 403, "text/plain", f"{e}\n".encode()
        if old > cp.size:
            return 400, "text/plain", b"old size is larger than the checkpoint\n"
        with self.lock:
            st = self.state.get(cp.origin)
            size = st["size"] if st else 0
            root = note.unb64(st["root"]) if st else merkle.EMPTY
            if old != size:
                return 409, "text/x.tlog.size", f"{size}\n".encode()
            if cp.size == 0 and cp.root != merkle.EMPTY:
                return 422, "text/plain", b"empty tree with a non-empty root\n"
            if old == 0 and proof:
                return 422, "text/plain", b"proof from the empty tree must be empty\n"
            if old == cp.size and cp.root != root:
                return 422, "text/plain", b"same size, different root\n"
            if 0 < old < cp.size and not merkle.verify_consistency(old, cp.size, root, cp.root, proof):
                return 422, "text/plain", b"consistency proof does not verify\n"
            sig = self.key.sign(text, int(time.time()))
            known = {(k.name, k.id) for k, _ in verified}
            kept = [s for s in sigs if (s.name, s.key_id) in known] + [sig]
            state = dict(self.state)
            state[cp.origin] = {"size": cp.size, "root": note.b64(cp.root),
                                "checkpoint": note.format_note(text, kept).decode()}
            atomic_write(self.state_path, json.dumps(state, indent=1, sort_keys=True).encode())
            self.state = state
        return 200, "text/plain; charset=utf-8", sig.line()


class _Handler(web.Handler):
    server_version = "pqsign-witness"

    def do_POST(self):
        if self.path != "/add-checkpoint":
            return self.send(404, b"not found\n")
        body = self.body(MAX_BODY)
        if body is not None:
            status, ctype, payload = self.server.witness.add_checkpoint(body)
            self.send(status, payload, ctype)

    def do_GET(self):
        m = CHECKPOINT_PATH.fullmatch(self.path)
        data = self.server.witness.latest(m.group(1)) if m else None
        if data is None:
            return self.send(404, b"not found\n")
        self.send(200, data)


def serve(witness: Witness, host: str, port: int, max_connections: int = 64,
          request_timeout: float = 10.0) -> web.Server:
    httpd = web.Server((host, port), _Handler, max_connections, request_timeout)
    httpd.witness = witness
    return httpd


class WitnessClient:
    def __init__(self, name: str, url: str, key: note.PublicKey, timeout: float):
        self.name = name
        self.url = url.rstrip("/") + "/add-checkpoint"
        self.key = key
        self.timeout = timeout
        self.size = 0
        self.error = ""

    def _post(self, body: bytes) -> tuple[int, bytes]:
        req = urllib.request.Request(self.url, data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(MAX_BODY)
        except urllib.error.HTTPError as e:
            return e.code, e.read(MAX_BODY)

    def cosign(self, text: bytes, signed: bytes, prove) -> note.Signature | None:
        cp = note.parse_checkpoint(text)
        old = self.size
        try:
            for _ in range(3):
                proof = prove(old, cp.size) if 0 < old < cp.size else []
                status, body = self._post(format_request(old, proof, signed))
                if status == 409:
                    old = note.parse_decimal(body.decode("ascii").strip())
                    if old > cp.size:
                        self.error = f"witness is ahead of the log at size {old}"
                        return None
                    continue
                if status != 200:
                    self.error = f"HTTP {status}: {body.decode('utf-8', 'replace').strip()}"
                    return None
                for line in body.split(b"\n")[:-1]:
                    sig = note.parse_signature_line(line)
                    if (sig.name, sig.key_id) == (self.key.name, self.key.id):
                        self.key.verify(text, sig.payload)
                        self.size, self.error = cp.size, ""
                        return sig
                self.error = "response has no signature from the expected key"
                return None
        except (OSError, ValueError, http.client.HTTPException) as e:
            self.error = str(e) or type(e).__name__
        return None

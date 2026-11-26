import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import merkle, note, policy
from .keys import ED_SIG, ML_SIG, KeyFileError, ReleaseKey, ReleaseSecret

HEADER = "pqsign/v1"
PROOF_HEADER = "c2sp.org/tlog-proof@v1"
FILE_NAME = re.compile(r"[A-Za-z0-9._+~-]{1,255}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_PROOF = 63


class VerifyError(ValueError):
    pass


def check_file_name(name: str) -> str:
    if not FILE_NAME.fullmatch(name) or name in (".", ".."):
        raise VerifyError(f"file name {name!r} must use only letters, digits and . _ + ~ -")
    return name


@dataclass(frozen=True)
class Statement:
    signer: str
    file: str
    size: int
    sha256: str

    def encode(self) -> bytes:
        lines = [HEADER, f"signer {self.signer}", f"file {self.file}", f"size {self.size}", f"sha256 {self.sha256}"]
        return ("\n".join(lines) + "\n").encode()


@dataclass(frozen=True)
class Entry:
    statement: Statement
    ed25519: bytes
    mldsa65: bytes

    def encode(self) -> bytes:
        tail = f"ed25519 {note.b64(self.ed25519)}\nml-dsa-65 {note.b64(self.mldsa65)}\n"
        return self.statement.encode() + tail.encode()


def parse_entry(data: bytes) -> Entry:
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        raise VerifyError("entry is not ASCII") from None
    keys = ["signer", "file", "size", "sha256", "ed25519", "ml-dsa-65"]
    if len(lines) != 8 or lines[0] != HEADER or lines[7] != "":
        raise VerifyError("malformed entry")
    values = []
    for line, key in zip(lines[1:7], keys, strict=True):
        k, _, v = line.partition(" ")
        if k != key:
            raise VerifyError(f"malformed entry, expected {key}")
        values.append(v)
    signer, name, size, digest, ed, ml = values
    if not HEX64.fullmatch(signer) or not HEX64.fullmatch(digest):
        raise VerifyError("malformed entry hash")
    try:
        entry = Entry(Statement(signer, check_file_name(name), note.parse_decimal(size), digest),
                      note.unb64(ed, ED_SIG), note.unb64(ml, ML_SIG))
    except note.NoteError as e:
        raise VerifyError(f"malformed entry: {e}") from None
    if entry.encode() != data:
        raise VerifyError("entry is not canonical")
    return entry


def hash_file(path) -> tuple[int, str]:
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def sign_file(path, secret: ReleaseSecret) -> Entry:
    size, digest = hash_file(path)
    statement = Statement(secret.public.fingerprint, check_file_name(Path(path).name), size, digest)
    ed, ml = secret.sign(statement.encode())
    return Entry(statement, ed, ml)


def check_entry(entry: Entry, signers: dict[str, ReleaseKey]) -> ReleaseKey:
    key = signers.get(entry.statement.signer)
    if key is None:
        raise VerifyError(f"signed by an unknown key {entry.statement.signer[:16]}")
    try:
        key.verify(entry.statement.encode(), entry.ed25519, entry.mldsa65)
    except KeyFileError as e:
        raise VerifyError(str(e)) from None
    return key


def format_proof(entry: bytes, index: int, hashes: list[bytes], checkpoint: bytes) -> bytes:
    lines = [PROOF_HEADER, f"extra {note.b64(entry)}", f"index {index}"] + [note.b64(h) for h in hashes]
    return ("\n".join(lines) + "\n\n").encode() + checkpoint


def parse_proof(data: bytes) -> tuple[bytes, int, list[bytes], bytes]:
    cut = data.find(b"\n\n")
    if cut < 0:
        raise VerifyError("malformed proof file")
    try:
        lines = data[:cut].decode("ascii").split("\n")
        if len(lines) < 3 or lines[0] != PROOF_HEADER or not lines[1].startswith("extra "):
            raise VerifyError("not a pqsign proof file")
        if not lines[2].startswith("index ") or len(lines) - 3 > MAX_PROOF:
            raise VerifyError("malformed proof file")
        extra = note.unb64(lines[1][6:])
        index = note.parse_decimal(lines[2][6:])
        hashes = [note.unb64(line, 32) for line in lines[3:]]
    except (UnicodeDecodeError, note.NoteError) as e:
        raise VerifyError(f"malformed proof file: {e}") from None
    return extra, index, hashes, data[cut + 2:]


@dataclass(frozen=True)
class Verified:
    entry: Entry
    key: ReleaseKey
    index: int
    checkpoint: note.Checkpoint
    witnesses: set


def verify_release(path, proof: bytes, trust: policy.Policy, signers: dict[str, ReleaseKey],
                   now: float | None = None, max_future: int = 600) -> Verified:
    extra, index, hashes, checkpoint = parse_proof(proof)
    entry = parse_entry(extra)
    key = check_entry(entry, signers)
    size, digest = hash_file(path)
    if Path(path).name != entry.statement.file:
        raise VerifyError(f"proof is for {entry.statement.file}, not {Path(path).name}")
    if size != entry.statement.size or digest != entry.statement.sha256:
        raise VerifyError("file contents do not match the signed hash")
    try:
        cp, witnesses = policy.verify_checkpoint(checkpoint, trust, now, max_future)
    except (note.NoteError, policy.PolicyError) as e:
        raise VerifyError(f"checkpoint rejected: {e}") from None
    if not merkle.verify_inclusion(merkle.leaf_hash(extra), index, cp.size, hashes, cp.root):
        raise VerifyError("inclusion proof does not match the checkpoint")
    return Verified(entry, key, index, cp, witnesses)

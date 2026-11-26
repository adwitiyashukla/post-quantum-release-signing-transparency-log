import base64
import binascii
import hashlib
import os
import re
import struct
import time
from dataclasses import dataclass
from functools import cached_property

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

DASH = "\u2014"
SIG_PREFIX = (DASH + " ").encode()
ED25519 = 0x01
MLDSA44 = 0x06
KEY_SIZES = {ED25519: 32, MLDSA44: 1312}
SIG_SIZES = {ED25519: 64, MLDSA44: 8 + 2420}
COSIGN_LABEL = b"subtree/v1\n\x00"
MAX_SIGNATURES = 32
MAX_NOTE = 1 << 18
MAX_TIMESTAMP = 2**63 - 1
DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")


class NoteError(ValueError):
    pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text, size: int | None = None) -> bytes:
    raw = text.encode() if isinstance(text, str) else bytes(text)
    try:
        out = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise NoteError("bad base64") from None
    if base64.b64encode(out) != raw:
        raise NoteError("non-canonical base64")
    if size is not None and len(out) != size:
        raise NoteError(f"expected {size} bytes, got {len(out)}")
    return out


def parse_decimal(text: str, limit: int = 2**63 - 1) -> int:
    if not DECIMAL.fullmatch(text) or int(text) > limit:
        raise NoteError(f"bad decimal: {text!r}")
    return int(text)


def check_name(name: str) -> str:
    if not name or len(name.encode()) > 255:
        raise NoteError("name must be 1 to 255 bytes")
    if "+" in name or any(c.isspace() or ord(c) < 0x20 for c in name):
        raise NoteError(f"bad name: {name!r}")
    return name


def key_id(name: str, alg: int, key: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + key).digest()[:4]


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes

    def text(self) -> bytes:
        return f"{self.origin}\n{self.size}\n{b64(self.root)}\n".encode()


def parse_checkpoint(text: bytes) -> Checkpoint:
    try:
        s = text.decode()
    except UnicodeDecodeError:
        raise NoteError("checkpoint is not UTF-8") from None
    lines = s.split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise NoteError("checkpoint must be exactly three lines")
    return Checkpoint(check_name(lines[0]), parse_decimal(lines[1]), unb64(lines[2], 32))


def cosigned_subtree(name: str, timestamp: int, origin: str, start: int, end: int, root: bytes) -> bytes:
    n, o = check_name(name).encode(), check_name(origin).encode()
    return (COSIGN_LABEL + bytes([len(n)]) + n + struct.pack(">Q", timestamp)
            + bytes([len(o)]) + o + struct.pack(">QQ", start, end) + root)


@dataclass(frozen=True)
class PublicKey:
    name: str
    alg: int
    key: bytes

    def __post_init__(self):
        check_name(self.name)
        if KEY_SIZES.get(self.alg) != len(self.key):
            raise NoteError("unsupported key type or size")

    @cached_property
    def id(self) -> bytes:
        return key_id(self.name, self.alg, self.key)

    @cached_property
    def _impl(self):
        if self.alg == ED25519:
            return ed25519.Ed25519PublicKey.from_public_bytes(self.key)
        return mldsa.MLDSA44PublicKey.from_public_bytes(self.key)

    def vkey(self) -> str:
        return f"{self.name}+{self.id.hex()}+{b64(bytes([self.alg]) + self.key)}"

    def verify(self, text: bytes, payload: bytes) -> int | None:
        if len(payload) != SIG_SIZES[self.alg]:
            raise NoteError(f"bad signature length from {self.name}")
        try:
            if self.alg == ED25519:
                self._impl.verify(payload, text)
                return None
            cp = parse_checkpoint(text)
            ts = int.from_bytes(payload[:8], "big")
            if ts > MAX_TIMESTAMP:
                raise NoteError(f"bad timestamp from {self.name}")
            self._impl.verify(payload[8:], cosigned_subtree(self.name, ts, cp.origin, 0, cp.size, cp.root))
            return ts
        except InvalidSignature:
            raise NoteError(f"invalid signature from {self.name}") from None


@dataclass(frozen=True)
class SecretKey:
    name: str
    alg: int
    seed: bytes

    def __post_init__(self):
        check_name(self.name)
        if self.alg not in KEY_SIZES or len(self.seed) != 32:
            raise NoteError("unsupported secret key")

    @cached_property
    def _impl(self):
        if self.alg == ED25519:
            return ed25519.Ed25519PrivateKey.from_private_bytes(self.seed)
        return mldsa.MLDSA44PrivateKey.from_seed_bytes(self.seed)

    @cached_property
    def public(self) -> PublicKey:
        return PublicKey(self.name, self.alg, self._impl.public_key().public_bytes_raw())

    def skey(self) -> str:
        return f"PRIVATE+KEY+{self.name}+{self.public.id.hex()}+{b64(bytes([self.alg]) + self.seed)}"

    def sign(self, text: bytes, timestamp: int | None = None) -> "Signature":
        if self.alg == ED25519:
            payload = self._impl.sign(text)
        else:
            cp = parse_checkpoint(text)
            ts = int(time.time()) if timestamp is None else timestamp
            msg = cosigned_subtree(self.name, ts, cp.origin, 0, cp.size, cp.root)
            payload = struct.pack(">Q", ts) + self._impl.sign(msg)
        return Signature(self.name, self.public.id, payload)


def generate(name: str, alg: int) -> SecretKey:
    return SecretKey(name, alg, os.urandom(32))


def parse_vkey(text: str) -> PublicKey:
    parts = text.strip().split("+", 2)
    if len(parts) != 3:
        raise NoteError("malformed vkey")
    name, hexid, data = parts
    raw = unb64(data)
    if len(raw) < 2:
        raise NoteError("malformed vkey")
    key = PublicKey(name, raw[0], raw[1:])
    if hexid != key.id.hex():
        raise NoteError("vkey id does not match key")
    return key


def parse_skey(text: str) -> SecretKey:
    text = text.strip()
    if not text.startswith("PRIVATE+KEY+"):
        raise NoteError("malformed skey")
    parts = text[len("PRIVATE+KEY+"):].split("+", 2)
    if len(parts) != 3:
        raise NoteError("malformed skey")
    name, hexid, data = parts
    raw = unb64(data)
    if len(raw) != 33:
        raise NoteError("malformed skey")
    key = SecretKey(name, raw[0], raw[1:])
    if hexid != key.public.id.hex():
        raise NoteError("skey id does not match key")
    return key


@dataclass(frozen=True)
class Signature:
    name: str
    key_id: bytes
    payload: bytes

    def line(self) -> bytes:
        return SIG_PREFIX + f"{self.name} {b64(self.key_id + self.payload)}\n".encode()


def parse_signature_line(line: bytes) -> Signature:
    if not line.startswith(SIG_PREFIX):
        raise NoteError("signature line must start with an em dash")
    try:
        rest = line[len(SIG_PREFIX):].decode()
    except UnicodeDecodeError:
        raise NoteError("signature line is not UTF-8") from None
    parts = rest.split(" ")
    if len(parts) != 2:
        raise NoteError("malformed signature line")
    raw = unb64(parts[1])
    if len(raw) < 5:
        raise NoteError("signature too short")
    return Signature(check_name(parts[0]), raw[:4], raw[4:])


def split_note(data: bytes) -> tuple[bytes, list[Signature]]:
    if len(data) > MAX_NOTE:
        raise NoteError("note too large")
    try:
        s = data.decode()
    except UnicodeDecodeError:
        raise NoteError("note is not UTF-8") from None
    if any(ord(c) < 0x20 and c != "\n" for c in s):
        raise NoteError("note contains control characters")
    cut = data.rfind(b"\n\n")
    if cut < 0:
        raise NoteError("note has no signatures")
    text, block = data[:cut + 1], data[cut + 2:]
    if not block.endswith(b"\n"):
        raise NoteError("note has no signatures")
    lines = block[:-1].split(b"\n")
    if len(lines) > MAX_SIGNATURES:
        raise NoteError("too many signatures")
    return text, [parse_signature_line(line) for line in lines]


def format_note(text: bytes, signatures: list[Signature]) -> bytes:
    if not text.endswith(b"\n") or not signatures:
        raise NoteError("cannot format note")
    return text + b"\n" + b"".join(s.line() for s in signatures)


def verify_note(data: bytes, keys) -> tuple[bytes, list[tuple[PublicKey, int | None]]]:
    text, signatures = split_note(data)
    known = {(k.name, k.id): k for k in keys}
    seen, verified = set(), []
    for sig in signatures:
        ident = (sig.name, sig.key_id)
        if ident in seen:
            raise NoteError(f"duplicate signature from {sig.name}")
        seen.add(ident)
        key = known.get(ident)
        if key is not None:
            verified.append((key, key.verify(text, sig.payload)))
    if not verified:
        raise NoteError("no signature from a trusted key")
    return text, verified

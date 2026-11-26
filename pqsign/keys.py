import getpass
import hashlib
import os
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import note
from .storage import atomic_write

PUBLIC_HEADER = "pqsign-key/v1"
SECRET_HEADER = "pqsign-secret/v1"
CONTEXT = b"pqsign/v1"
ED_SIG = 64
ML_SIG = 3309


class KeyFileError(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseKey:
    name: str
    ed25519: bytes
    mldsa65: bytes

    def __post_init__(self):
        note.check_name(self.name)
        if len(self.ed25519) != 32 or len(self.mldsa65) != 1952:
            raise KeyFileError("bad public key sizes")

    @cached_property
    def fingerprint(self) -> str:
        return hashlib.sha256(PUBLIC_HEADER.encode() + b"\n" + self.ed25519 + self.mldsa65).hexdigest()

    def text(self) -> bytes:
        lines = [PUBLIC_HEADER, f"name {self.name}", f"ed25519 {note.b64(self.ed25519)}",
                 f"ml-dsa-65 {note.b64(self.mldsa65)}"]
        return ("\n".join(lines) + "\n").encode()

    def verify(self, message: bytes, ed_sig: bytes, ml_sig: bytes) -> None:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(self.ed25519).verify(ed_sig, message)
        except InvalidSignature:
            raise KeyFileError("Ed25519 signature does not verify") from None
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(self.mldsa65).verify(ml_sig, message, CONTEXT)
        except InvalidSignature:
            raise KeyFileError("ML-DSA-65 signature does not verify") from None


@dataclass(frozen=True)
class ReleaseSecret:
    name: str
    ed_seed: bytes
    ml_seed: bytes

    @cached_property
    def _ed(self):
        return ed25519.Ed25519PrivateKey.from_private_bytes(self.ed_seed)

    @cached_property
    def _ml(self):
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(self.ml_seed)

    @cached_property
    def public(self) -> ReleaseKey:
        return ReleaseKey(self.name, self._ed.public_key().public_bytes_raw(),
                          self._ml.public_key().public_bytes_raw())

    def sign(self, message: bytes) -> tuple[bytes, bytes]:
        return self._ed.sign(message), self._ml.sign(message, CONTEXT)


def _fields(data: bytes, header: str, keys: list[str]) -> list[str]:
    try:
        lines = data.decode("ascii").replace("\r\n", "\n").split("\n")
    except UnicodeDecodeError:
        raise KeyFileError("key file is not ASCII") from None
    if lines[-1] == "":
        lines.pop()
    if len(lines) != len(keys) + 1 or lines[0] != header:
        raise KeyFileError(f"not a {header} file")
    values = []
    for line, key in zip(lines[1:], keys, strict=True):
        k, _, v = line.partition(" ")
        if k != key or not v:
            raise KeyFileError(f"expected a {key} line")
        values.append(v)
    return values


def parse_public(data: bytes) -> ReleaseKey:
    name, ed, ml = _fields(data, PUBLIC_HEADER, ["name", "ed25519", "ml-dsa-65"])
    try:
        return ReleaseKey(name, note.unb64(ed, 32), note.unb64(ml, 1952))
    except note.NoteError as e:
        raise KeyFileError(str(e)) from None


def generate_release(name: str) -> ReleaseSecret:
    return ReleaseSecret(note.check_name(name), os.urandom(32), os.urandom(32))


def _kdf(passphrase: bytes, salt: bytes, log_n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=1 << log_n, r=8, p=1).derive(passphrase)


def secret_text(secret: ReleaseSecret, passphrase: bytes, log_n: int) -> bytes:
    seeds = secret.ed_seed + secret.ml_seed
    if not passphrase:
        head = f"{SECRET_HEADER}\nname {secret.name}\nkdf none\n"
        return (head + f"seeds {note.b64(seeds)}\n").encode()
    salt, nonce = os.urandom(16), os.urandom(12)
    head = f"{SECRET_HEADER}\nname {secret.name}\nkdf scrypt {log_n} {note.b64(salt)}\n"
    sealed = AESGCM(_kdf(passphrase, salt, log_n)).encrypt(nonce, seeds, head.encode())
    return (head + f"seeds {note.b64(nonce + sealed)}\n").encode()


def parse_secret(data: bytes, passphrase) -> ReleaseSecret:
    name, kdf, seeds = _fields(data, SECRET_HEADER, ["name", "kdf", "seeds"])
    head = f"{SECRET_HEADER}\nname {name}\nkdf {kdf}\n".encode()
    try:
        raw = note.unb64(seeds)
        if kdf == "none":
            plain = raw
        else:
            parts = kdf.split(" ")
            if len(parts) != 3 or parts[0] != "scrypt" or not parts[1].isdigit() or not 10 <= int(parts[1]) <= 22:
                raise KeyFileError("unsupported key encryption")
            key = _kdf(passphrase(), note.unb64(parts[2], 16), int(parts[1]))
            plain = AESGCM(key).decrypt(raw[:12], raw[12:], head)
    except InvalidTag:
        raise KeyFileError("wrong passphrase or damaged key file") from None
    except note.NoteError as e:
        raise KeyFileError(str(e)) from None
    if len(plain) != 64:
        raise KeyFileError("damaged key file")
    return ReleaseSecret(name, plain[:32], plain[32:])


def ask_passphrase(confirm: bool = False) -> bytes:
    env = os.environ.get("PQSIGN_PASSPHRASE")
    if env is not None:
        return env.encode()
    first = getpass.getpass("passphrase for the release key (empty for none): ")
    if confirm and getpass.getpass("same passphrase again: ") != first:
        raise KeyFileError("passphrases do not match")
    return first.encode()


def write_server_keys(path, keys: list[note.SecretKey]) -> None:
    atomic_write(path, "".join(k.skey() + "\n" for k in keys).encode(), private=True)


def read_server_keys(path) -> list[note.SecretKey]:
    try:
        text = Path(path).read_text("ascii")
        return [note.parse_skey(line) for line in text.splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, note.NoteError) as e:
        raise KeyFileError(f"cannot read server key {path}: {e}") from None

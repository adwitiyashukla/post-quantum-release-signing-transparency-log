import json
from pathlib import Path

import pytest

from pqsign import merkle, note

DASH = "\u2014"
PETER_SKEY = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
PETER_VKEY = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
ENOCH_VKEY = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop"
TEXT = b"If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n"
PETER_SIG = (f"{DASH} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FF"
             "YC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n").encode()
ENOCH_SIG = (f"{DASH} EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5"
             "ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n").encode()
SPEC_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
SPEC_NOTE = (f"This is an example message.\n\n{DASH} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2"
             "ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n").encode()
GO_COSIG = json.loads((Path(__file__).parent / "vectors" / "go_cosignature.json").read_text())


def checkpoint(size=5, origin="example.com/log"):
    return note.Checkpoint(origin, size, merkle.leaf_hash(str(size).encode()))


def test_go_signing_vector():
    sk = note.parse_skey(PETER_SKEY)
    assert sk.skey() == PETER_SKEY
    assert sk.public.vkey() == PETER_VKEY
    assert note.format_note(TEXT, [sk.sign(TEXT)]) == TEXT + b"\n" + PETER_SIG


def test_go_multi_signature_note():
    data = TEXT + b"\n" + PETER_SIG + ENOCH_SIG
    _, verified = note.verify_note(data, [note.parse_vkey(PETER_VKEY)])
    assert [k.name for k, _ in verified] == ["PeterNeumann"]
    _, verified = note.verify_note(data, [note.parse_vkey(PETER_VKEY), note.parse_vkey(ENOCH_VKEY)])
    assert [k.name for k, _ in verified] == ["PeterNeumann", "EnochRoot"]


def test_spec_example_note():
    text, verified = note.verify_note(SPEC_NOTE, [note.parse_vkey(SPEC_VKEY)])
    assert text == b"This is an example message.\n"
    assert verified[0][1] is None


def test_go_mldsa_cosignature_vector():
    sk = note.SecretKey(GO_COSIG["name"], note.MLDSA44, bytes.fromhex(GO_COSIG["seed"]))
    assert sk.public.vkey() == GO_COSIG["vkey"]
    text, verified = note.verify_note(GO_COSIG["note"].encode(), [sk.public])
    assert note.parse_checkpoint(text).size == 123
    assert verified[0][1] > 1_700_000_000


def test_mldsa_cosignature_round_trip_and_tamper():
    sk = note.generate("example.com/w1", note.MLDSA44)
    text = checkpoint().text()
    sig = sk.sign(text, timestamp=1_800_000_000)
    _, verified = note.verify_note(note.format_note(text, [sig]), [sk.public])
    assert verified[0][1] == 1_800_000_000
    moved = note.Signature(sig.name, sig.key_id, (1_800_000_001).to_bytes(8, "big") + sig.payload[8:])
    with pytest.raises(note.NoteError):
        note.verify_note(note.format_note(text, [moved]), [sk.public])
    with pytest.raises(note.NoteError):
        note.verify_note(note.format_note(checkpoint(6).text(), [sig]), [sk.public])
    huge = note.Signature(sig.name, sig.key_id, (2**63).to_bytes(8, "big") + sig.payload[8:])
    with pytest.raises(note.NoteError):
        note.verify_note(note.format_note(text, [huge]), [sk.public])


def test_cosignature_is_bound_to_cosigner_name():
    a = note.SecretKey("example.com/a", note.MLDSA44, bytes(32))
    b = note.SecretKey("example.com/b", note.MLDSA44, bytes(32))
    text = checkpoint().text()
    sig = a.sign(text)
    renamed = note.Signature("example.com/b", b.public.id, sig.payload)
    with pytest.raises(note.NoteError):
        note.verify_note(note.format_note(text, [renamed]), [b.public])


def test_known_key_with_bad_signature_rejects_whole_note():
    peter, enoch = note.parse_skey(PETER_SKEY), note.parse_vkey(ENOCH_VKEY)
    bad = note.Signature("EnochRoot", enoch.id, bytes(64))
    with pytest.raises(note.NoteError):
        note.verify_note(note.format_note(TEXT, [peter.sign(TEXT), bad]), [peter.public, enoch])


def test_unknown_keys_are_ignored_but_one_trusted_signature_is_required():
    data = TEXT + b"\n" + ENOCH_SIG
    with pytest.raises(note.NoteError):
        note.verify_note(data, [note.parse_vkey(PETER_VKEY)])


def test_duplicate_signature_lines_are_rejected():
    with pytest.raises(note.NoteError):
        note.verify_note(TEXT + b"\n" + PETER_SIG + PETER_SIG, [note.parse_vkey(PETER_VKEY)])


@pytest.mark.parametrize("data", [
    TEXT + PETER_SIG,
    TEXT + b"\n",
    TEXT + b"\n" + PETER_SIG[:-1],
    TEXT + b"\n" + PETER_SIG.replace(b"AM=", b"AN="),
    TEXT + b"\n" + PETER_SIG.replace(b"Neumann ", b"Neumann  "),
    TEXT + b"\n" + PETER_SIG.replace(DASH.encode(), b"-"),
    b"tab\there\n\n" + PETER_SIG,
    b"carriage\r\n\n" + PETER_SIG,
    b"\xff\n\n" + PETER_SIG,
    TEXT + b"\n" + PETER_SIG * 40,
])
def test_malformed_notes(data):
    with pytest.raises(note.NoteError):
        note.verify_note(data, [note.parse_vkey(PETER_VKEY)])


@pytest.mark.parametrize("text", [
    b"example.com/log\n05\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\n",
    b"example.com/log\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\nextension\n",
    b"example.com/log\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=",
    b"example.com/log\n-1\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\n",
    b"example.com/log\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qV=\n",
    b"example.com/log\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4q==\n",
    b"bad name\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\n",
    b"a+b\n5\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\n",
    b"example.com/log\n99999999999999999999\nKIzz1vI/jwAZ+56JzbO6EMgsLawNzFlE48dpdBOv4qU=\n",
])
def test_malformed_checkpoints(text):
    with pytest.raises(note.NoteError):
        note.parse_checkpoint(text)


@pytest.mark.parametrize("vkey", [
    "PeterNeumann+c74f20a4+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
    "PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==",
    "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
    "PeterNeumann+c74f20a3",
    "Peter Neumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
])
def test_bad_vkeys(vkey):
    with pytest.raises(note.NoteError):
        note.parse_vkey(vkey)


def test_skey_round_trip_for_both_algorithms():
    for alg in (note.ED25519, note.MLDSA44):
        sk = note.generate("example.com/k", alg)
        again = note.parse_skey(sk.skey())
        assert again.public == sk.public
        assert note.parse_vkey(sk.public.vkey()) == sk.public
    with pytest.raises(note.NoteError):
        note.parse_skey(PETER_SKEY.replace("c74f20a3", "c74f20a4"))

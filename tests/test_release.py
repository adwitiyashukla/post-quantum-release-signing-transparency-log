import pytest

from pqsign import keys, merkle, note, policy, release

ORIGIN = "example.com/log"


@pytest.fixture(scope="module")
def signer():
    return keys.generate_release("example.com/release")


@pytest.fixture(scope="module")
def servers():
    log = note.SecretKey(ORIGIN, note.MLDSA44, bytes([9]) * 32)
    ws = [note.SecretKey(f"example.com/w{i}", note.MLDSA44, bytes([10 + i]) * 32) for i in range(3)]
    text = policy.format_policy([(log.public, "http://127.0.0.1:1")],
                                [(f"w{i}", w.public, "http://127.0.0.1:2") for i, w in enumerate(ws)], 2)
    return log, ws, policy.parse_policy(text)


def publish(tmp_path, signer, servers, witnesses=2, names=("app-1.0.zip", "app-1.1.zip", "app-1.2.zip")):
    log, ws, trust = servers
    files, entries = [], []
    for i, name in enumerate(names):
        path = tmp_path / name
        path.write_bytes(f"release {i}\n".encode() * (i + 1))
        files.append(path)
        entries.append(release.sign_file(path, signer).encode())
    tree = merkle.MemoryTree([merkle.leaf_hash(e) for e in entries])
    text = note.Checkpoint(ORIGIN, tree.size, merkle.root(tree.node, tree.size)).text()
    cp = note.format_note(text, [log.sign(text)] + [w.sign(text) for w in ws[:witnesses]])
    proofs = []
    for i in range(len(files)):
        proofs.append(release.format_proof(entries[i], i, merkle.inclusion_proof(tree.node, i, tree.size), cp))
    return files, proofs, trust


def test_full_offline_verification(tmp_path, signer, servers):
    files, proofs, trust = publish(tmp_path, signer, servers)
    for i, (path, proof) in enumerate(zip(files, proofs, strict=True)):
        v = release.verify_release(path, proof, trust, {signer.public.fingerprint: signer.public})
        assert v.index == i and v.checkpoint.size == 3 and v.witnesses == {"w0", "w1"}


def test_tampered_file_is_rejected(tmp_path, signer, servers):
    files, proofs, trust = publish(tmp_path, signer, servers)
    files[0].write_bytes(files[0].read_bytes() + b"extra bytes")
    with pytest.raises(release.VerifyError, match="do not match"):
        release.verify_release(files[0], proofs[0], trust, {signer.public.fingerprint: signer.public})


def test_old_release_under_new_name_is_rejected(tmp_path, signer, servers):
    files, proofs, trust = publish(tmp_path, signer, servers)
    renamed = tmp_path / "app-1.2.zip"
    renamed.write_bytes(files[0].read_bytes())
    with pytest.raises(release.VerifyError, match="proof is for app-1.0.zip"):
        release.verify_release(renamed, proofs[0], trust, {signer.public.fingerprint: signer.public})


def test_unknown_signer_and_missing_quorum(tmp_path, signer, servers):
    files, proofs, trust = publish(tmp_path, signer, servers, witnesses=1)
    other = keys.generate_release("example.com/other").public
    with pytest.raises(release.VerifyError, match="unknown key"):
        release.verify_release(files[0], proofs[0], trust, {other.fingerprint: other})
    with pytest.raises(release.VerifyError, match="quorum"):
        release.verify_release(files[0], proofs[0], trust, {signer.public.fingerprint: signer.public})


def test_proof_for_wrong_index_is_rejected(tmp_path, signer, servers):
    files, proofs, trust = publish(tmp_path, signer, servers)
    extra, index, hashes, cp = release.parse_proof(proofs[1])
    moved = release.format_proof(extra, 0, hashes, cp)
    with pytest.raises(release.VerifyError, match="inclusion"):
        release.verify_release(files[1], moved, trust, {signer.public.fingerprint: signer.public})


def test_hybrid_signature_halves_cannot_be_swapped(tmp_path, signer):
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    a.write_bytes(b"a")
    b.write_bytes(b"b")
    ea, eb = release.sign_file(a, signer), release.sign_file(b, signer)
    known = {signer.public.fingerprint: signer.public}
    swapped = [release.Entry(ea.statement, eb.ed25519, ea.mldsa65), release.Entry(ea.statement, ea.ed25519, eb.mldsa65)]
    for entry in swapped:
        with pytest.raises(release.VerifyError, match="does not verify"):
            release.check_entry(entry, known)
    assert release.check_entry(ea, known) == signer.public


def test_entry_parsing_is_strict(tmp_path, signer):
    path = tmp_path / "x.tar.gz"
    path.write_bytes(b"x")
    data = release.sign_file(path, signer).encode()
    assert release.parse_entry(data).encode() == data
    for bad in [data + b"\n", data.replace(b"size 1", b"size 01"), data.replace(b"file x", b"file  x"),
                data.replace(b"pqsign/v1", b"pqsign/v2"), data[:-1], data.replace(b"sha256 ", b"sha512 ")]:
        with pytest.raises(release.VerifyError):
            release.parse_entry(bad)


@pytest.mark.parametrize("name", ["", ".", "..", "a b.zip", "a/b.zip", "caf\u00e9.zip", "x" * 256, "a\nb"])
def test_bad_file_names(name):
    with pytest.raises(release.VerifyError):
        release.check_file_name(name)


def test_secret_key_encryption(signer):
    text = keys.secret_text(signer, b"correct horse", 10)
    assert b"scrypt" in text and note.b64(signer.ed_seed).encode() not in text
    assert keys.parse_secret(text, lambda: b"correct horse").public == signer.public
    with pytest.raises(keys.KeyFileError, match="wrong passphrase"):
        keys.parse_secret(text, lambda: b"battery staple")
    renamed = text.replace(b"name example.com/release", b"name example.com/evil")
    with pytest.raises(keys.KeyFileError):
        keys.parse_secret(renamed, lambda: b"correct horse")
    plain = keys.secret_text(signer, b"", 10)
    assert keys.parse_secret(plain, lambda: pytest.fail("no prompt expected")).public == signer.public


def test_public_key_file_round_trip(signer):
    pub = keys.parse_public(signer.public.text())
    assert pub == signer.public and len(pub.fingerprint) == 64
    with pytest.raises(keys.KeyFileError):
        keys.parse_public(signer.public.text().replace(b"ml-dsa-65", b"ml-dsa-44"))

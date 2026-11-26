import base64
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqsign import merkle

LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
ROOTS = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
VECTORS = json.loads((Path(__file__).parent / "vectors" / "merkle_proofs.json").read_text())


def tree(leaves):
    return merkle.MemoryTree([merkle.leaf_hash(x) for x in leaves])


def unb64(text):
    return base64.b64decode(text)


def expected(case, *hashes):
    return not case["wantErr"] and all(len(h) == 32 for h in hashes)


@pytest.mark.parametrize("size", range(9))
def test_reference_roots(size):
    t = tree([bytes.fromhex(x) for x in LEAVES[:size]])
    assert merkle.root(t.node, size).hex() == ROOTS[size]
    f = merkle.Frontier()
    for x in LEAVES[:size]:
        f.append(merkle.leaf_hash(bytes.fromhex(x)))
    assert f.root().hex() == ROOTS[size]


@pytest.mark.parametrize("case", VECTORS["inclusion"], ids=lambda c: c["desc"])
def test_reference_inclusion_vectors(case):
    leaf, root, proof = unb64(case["leafHash"]), unb64(case["root"]), [unb64(p) for p in case["proof"]]
    ok = merkle.verify_inclusion(leaf, case["leafIdx"], case["treeSize"], proof, root)
    assert ok is expected(case, leaf, root, *proof)


@pytest.mark.parametrize("case", VECTORS["consistency"], ids=lambda c: c["desc"])
def test_reference_consistency_vectors(case):
    root1, root2, proof = unb64(case["root1"]), unb64(case["root2"]), [unb64(p) for p in case["proof"]]
    ok = merkle.verify_consistency(case["size1"], case["size2"], root1, root2, proof)
    assert ok is expected(case, root1, root2, *proof)


@settings(max_examples=60, deadline=None)
@given(st.lists(st.binary(max_size=8), min_size=1, max_size=70))
def test_every_inclusion_proof_verifies(leaves):
    t = tree(leaves)
    root = merkle.root(t.node, t.size)
    for i, x in enumerate(leaves):
        proof = merkle.inclusion_proof(t.node, i, t.size)
        assert merkle.verify_inclusion(merkle.leaf_hash(x), i, t.size, proof, root)
        assert not merkle.verify_inclusion(merkle.leaf_hash(x + b"!"), i, t.size, proof, root)
        if t.size > 1:
            assert not merkle.verify_inclusion(merkle.leaf_hash(x), (i + 1) % t.size, t.size, proof, root) or \
                leaves[(i + 1) % t.size] == x


@settings(max_examples=60, deadline=None)
@given(st.lists(st.binary(max_size=8), min_size=1, max_size=70), st.data())
def test_every_consistency_proof_verifies(leaves, data):
    t = tree(leaves)
    new_root = merkle.root(t.node, t.size)
    old = data.draw(st.integers(0, t.size))
    old_root = merkle.root(t.node, old)
    proof = merkle.consistency_proof(t.node, old, t.size)
    assert merkle.verify_consistency(old, t.size, old_root, new_root, proof)
    for i in range(len(proof)):
        bad = list(proof)
        bad[i] = bytes([bad[i][0] ^ 1]) + bad[i][1:]
        assert not merkle.verify_consistency(old, t.size, old_root, new_root, bad)
    if 0 < old < t.size:
        assert not merkle.verify_consistency(old, t.size, merkle.leaf_hash(b"x"), new_root, proof)


@settings(max_examples=40, deadline=None)
@given(st.lists(st.binary(max_size=8), max_size=300))
def test_frontier_matches_tree(leaves):
    t = tree(leaves)
    f = merkle.Frontier()
    for x in leaves:
        f.append(merkle.leaf_hash(x))
    assert f.root() == merkle.root(t.node, t.size)
    g = merkle.Frontier.from_tree(t.node, t.size)
    assert g.hashes == f.hashes


def test_frontier_rejects_wrong_hash_count():
    with pytest.raises(ValueError):
        merkle.Frontier(3, [merkle.EMPTY])


def test_proof_arguments_are_checked():
    t = tree([b"a", b"b", b"c"])
    with pytest.raises(ValueError):
        merkle.inclusion_proof(t.node, 3, 3)
    with pytest.raises(ValueError):
        merkle.consistency_proof(t.node, 4, 3)
    assert not merkle.verify_inclusion(merkle.leaf_hash(b"a"), 0, 0, [], merkle.EMPTY)
    assert not merkle.verify_consistency(2, 1, merkle.EMPTY, merkle.EMPTY, [])

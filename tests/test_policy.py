import pytest

from pqsign import merkle, note, policy

ORIGIN = "example.com/log"


@pytest.fixture(scope="module")
def keys():
    return {
        "log": note.SecretKey(ORIGIN, note.MLDSA44, bytes([1]) * 32),
        "w1": note.SecretKey("example.com/w1", note.MLDSA44, bytes([2]) * 32),
        "w2": note.SecretKey("example.com/w2", note.MLDSA44, bytes([3]) * 32),
        "w3": note.SecretKey("example.com/w3", note.MLDSA44, bytes([4]) * 32),
    }


def make_policy(keys, threshold=2):
    witnesses = [(n, keys[n].public, f"http://127.0.0.1:{9000 + i}") for i, n in enumerate(["w1", "w2", "w3"])]
    return policy.format_policy([(keys["log"].public, "http://127.0.0.1:8999")], witnesses, threshold)


def signed(keys, signers, size=7, timestamp=None):
    text = note.Checkpoint(ORIGIN, size, merkle.leaf_hash(b"x")).text()
    return note.format_note(text, [keys[s].sign(text, timestamp) for s in signers])


def test_round_trip_and_quorum(keys):
    p = policy.parse_policy(make_policy(keys))
    assert [k.name for k in p.logs] == [ORIGIN]
    assert p.groups["witnesses"] == (2, ["w1", "w2", "w3"])
    cp, cosigned = policy.verify_checkpoint(signed(keys, ["log", "w1", "w3"]), p)
    assert cp.size == 7 and cosigned == {"w1", "w3"}
    with pytest.raises(policy.PolicyError):
        policy.verify_checkpoint(signed(keys, ["log", "w2"]), p)
    with pytest.raises(policy.PolicyError):
        policy.verify_checkpoint(signed(keys, ["w1", "w2", "w3"]), p)


def test_future_cosignature_is_ignored_not_fatal(keys):
    p = policy.parse_policy(make_policy(keys))
    now = 1_900_000_000
    text = note.Checkpoint(ORIGIN, 7, merkle.leaf_hash(b"x")).text()
    sigs = [keys["log"].sign(text, now), keys["w1"].sign(text, now), keys["w2"].sign(text, now + 3600),
            keys["w3"].sign(text, now)]
    assert policy.verify_checkpoint(note.format_note(text, sigs), p, now=now)[1] == {"w1", "w3"}
    with pytest.raises(policy.PolicyError, match="quorum"):
        policy.verify_checkpoint(note.format_note(text, sigs[:3]), p, now=now)
    late_log = [keys["log"].sign(text, now + 3600)] + sigs[1:]
    with pytest.raises(policy.PolicyError, match="log signature is dated in the future"):
        policy.verify_checkpoint(note.format_note(text, late_log), p, now=now)


def test_unknown_origin(keys):
    p = policy.parse_policy(make_policy(keys))
    text = note.Checkpoint("example.com/other", 1, merkle.EMPTY).text()
    with pytest.raises(policy.PolicyError):
        policy.verify_checkpoint(note.format_note(text, [keys["log"].sign(text)]), p)


def test_nested_groups_and_comments(keys):
    text = make_policy(keys).decode().replace("group witnesses 2 w1 w2 w3\nquorum witnesses\n", "")
    text = "# trust policy\n\n" + text + "group a any w1 w2\n  group b all a w3\t\nquorum b\n"
    p = policy.parse_policy(text.replace("\n", "\r\n").encode())
    assert p.satisfied({"w2", "w3"}) and not p.satisfied({"w1", "w2"}) and not p.satisfied({"w3"})


def test_witness_cannot_count_twice_through_groups(keys):
    base = make_policy(keys).decode().replace("group witnesses 2 w1 w2 w3\nquorum witnesses\n", "")
    with pytest.raises(policy.PolicyError, match="already a member"):
        policy.parse_policy((base + "group a any w1 w2\ngroup b 2 a w1\nquorum b\n").encode())


def test_quorum_none(keys):
    p = policy.parse_policy(f"log {keys['log'].public.vkey()}\nquorum none\n".encode())
    assert policy.verify_checkpoint(signed(keys, ["log"]), p)[1] == set()


@pytest.mark.parametrize("edit", [
    lambda t: t.replace("quorum witnesses\n", ""),
    lambda t: t + "quorum witnesses\n",
    lambda t: t.replace("group witnesses 2", "group witnesses 4"),
    lambda t: t.replace("group witnesses 2", "group witnesses 0"),
    lambda t: t.replace("group witnesses 2 w1", "group witnesses 2 w9"),
    lambda t: t.replace("group witnesses 2 w1 w2", "group witnesses 2 w1 w1"),
    lambda t: t.replace("witness w2", "witness w1"),
    lambda t: t.replace("witness w2", "witness none"),
    lambda t: t.replace("quorum witnesses", "quorum nobody"),
    lambda t: t + "frobnicate\n",
    lambda t: t + "bell\x07\n",
])
def test_bad_policies(keys, edit):
    with pytest.raises(policy.PolicyError):
        policy.parse_policy(edit(make_policy(keys).decode()).encode())


def test_duplicate_keys_are_rejected(keys):
    w1 = keys["w1"].public
    renamed = note.PublicKey("example.com/other", w1.alg, w1.key)
    text = f"witness a {w1.vkey()}\nwitness b {renamed.vkey()}\nquorum a\n"
    with pytest.raises(policy.PolicyError):
        policy.parse_policy(text.encode())


def test_ed25519_witness_keys_are_not_accepted():
    k = note.generate("example.com/w", note.ED25519)
    with pytest.raises(policy.PolicyError):
        policy.parse_policy(f"witness a {k.public.vkey()}\nquorum a\n".encode())

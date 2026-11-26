import http.client
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

from pqsign import keys, log, merkle, monitor, note, policy, release, tiles, witness
from pqsign.storage import DirStore

ORIGIN = "test.local/log"


def start(httpd):
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return httpd


def url_of(httpd):
    return f"http://127.0.0.1:{httpd.server_address[1]}/"


class Stack:
    def __init__(self, root, n=3, quorum=2, timeout=5.0):
        self.root = root
        self.log_keys = [note.generate(ORIGIN, note.ED25519), note.generate(ORIGIN, note.MLDSA44)]
        self.wkeys = [note.generate(f"test.local/w{i}", note.MLDSA44) for i in range(n)]
        self.signer = keys.generate_release("test.local/release")
        self.signers = {self.signer.public.fingerprint: self.signer.public}
        self.quorum, self.timeout = quorum, timeout
        self.witnesses = [self._start_witness(i) for i in range(n)]
        self.trust = policy.parse_policy(policy.format_policy(
            [(self.log_keys[1].public, "http://127.0.0.1:1/")],
            [(k.name, k.public, url_of(w)) for k, w in zip(self.wkeys, self.witnesses, strict=True)], quorum))
        self.start_log()

    def _start_witness(self, i):
        w = witness.Witness(self.wkeys[i], {ORIGIN: [k.public for k in self.log_keys]}, self.root / f"w{i}.json")
        return start(witness.serve(w, "127.0.0.1", 0))

    def restart_witness(self, i):
        self.witnesses[i] = self._start_witness(i)
        self.trust.urls[self.wkeys[i].name] = url_of(self.witnesses[i])
        self.log.witnesses[i].url = url_of(self.witnesses[i]) + "add-checkpoint"

    def stop_witness(self, i):
        self.witnesses[i].shutdown()
        self.witnesses[i].server_close()

    def start_log(self):
        clients = [witness.WitnessClient(k.name, self.trust.urls[k.name], k.public, 2.0) for k in self.wkeys]
        self.log = log.Log(self.root / "log", ORIGIN, self.log_keys, clients, self.quorum, 2.0)
        self.seq = log.Sequencer(self.log, 5, 256, 1000, retry_ms=50).start()
        self.httpd = start(log.serve(self.log, self.seq, self.signers, "127.0.0.1", 0, 8192, self.timeout))
        self.url = url_of(self.httpd)

    def stop_log(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.seq.stop()
        self.log.close()

    def close(self):
        self.stop_log()
        for w in self.witnesses:
            w.shutdown()
            w.server_close()

    def sign(self, path):
        e = release.sign_file(path, self.signer).encode()
        index = log.submit(self.url, e, 10)
        return index, log.prove(self.url, e, index, self.trust, 10)


@pytest.fixture
def stack(tmp_path):
    s = Stack(tmp_path)
    yield s
    s.close()


def entry(signer, name):
    st = release.Statement(signer.public.fingerprint, name, len(name), merkle.leaf_hash(name.encode()).hex())
    return release.Entry(st, *signer.sign(st.encode())).encode()


def files(tmp_path, *names):
    out = []
    for name in names:
        p = tmp_path / name
        p.write_bytes(name.encode() * 1000)
        out.append(p)
    return out


def post(url, body):
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def forged_request(log_keys, entries, old):
    tree = merkle.MemoryTree([merkle.leaf_hash(e) for e in entries])
    text = note.Checkpoint(ORIGIN, tree.size, merkle.root(tree.node, tree.size)).text()
    signed = note.format_note(text, [k.sign(text) for k in log_keys])
    proof = merkle.consistency_proof(tree.node, old, tree.size) if 0 < old < tree.size else []
    return witness.format_request(old, proof, signed)


def wait_until(check, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.05)
    return False


def answers(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status == 200
    except OSError:
        return False


def closed(sock, seconds=5):
    sock.settimeout(seconds)
    try:
        return sock.recv(100) == b""
    except ConnectionError:
        return True


def plain_log(tmp_path, name="log"):
    return log.Log(tmp_path / name, ORIGIN, [note.generate(ORIGIN, note.ED25519)], [], 0)


def test_sign_and_verify_offline(stack, tmp_path):
    for i, path in enumerate(files(tmp_path, "a-1.0.zip", "a-1.1.zip", "a-1.2.zip")):
        index, proof = stack.sign(path)
        v = release.verify_release(path, proof, stack.trust, stack.signers)
        assert v.index == index == i and len(v.witnesses) == 3


def test_parallel_submissions_get_distinct_indexes(stack, tmp_path):
    paths = files(tmp_path, *[f"b-{i}.zip" for i in range(40)])
    with ThreadPoolExecutor(16) as pool:
        results = list(pool.map(stack.sign, paths))
    assert sorted(i for i, _ in results) == list(range(40))
    for path, (_, proof) in zip(paths, results, strict=True):
        release.verify_release(path, proof, stack.trust, stack.signers)


def test_log_waits_for_quorum_and_recovers(stack, tmp_path):
    a, b = files(tmp_path, "c-1.zip", "c-2.zip")
    stack.sign(a)
    stack.stop_witness(1)
    stack.stop_witness(2)
    stack.httpd.submit_timeout = 0.5
    e = release.sign_file(b, stack.signer).encode()
    assert log.submit(stack.url, e, 10) == 1
    with pytest.raises(log.LogError, match="index 1, but no witnessed checkpoint"):
        log.prove(stack.url, e, 1, stack.trust, 5, wait_s=0.5)
    down = {"test.local/w1", "test.local/w2"}
    assert wait_until(lambda: {p.split(": ")[0] for p in stack.log.problems()} == down)
    stack.restart_witness(1)
    proof = log.prove(stack.url, e, 1, stack.trust, 5, wait_s=30)
    assert release.verify_release(b, proof, stack.trust, stack.signers).index == 1


def test_slow_witness_does_not_hold_up_publishing(stack, tmp_path):
    slow = stack.witnesses[2].witness
    real = slow.add_checkpoint

    def sleepy(body):
        time.sleep(3)
        return real(body)

    slow.add_checkpoint = sleepy
    (path,) = files(tmp_path, "slow.zip")
    t = time.monotonic()
    _, proof = stack.sign(path)
    assert time.monotonic() - t < 2.5
    assert release.verify_release(path, proof, stack.trust, stack.signers).witnesses == {"test.local/w0",
                                                                                          "test.local/w1"}


def test_timeout_before_sequencing_logs_nothing(tmp_path):
    lg = plain_log(tmp_path)
    seq = log.Sequencer(lg, 5, 256, 10)
    with pytest.raises(log.LogError, match="nothing was logged"):
        seq.submit(b"entry", 0.2)
    assert seq.pending == [] and lg.size == 0
    seq.start()
    assert seq.submit(b"entry", 5) == (0, True)
    seq.stop()


def failing_write(real, prefix):
    def write(path, data):
        if path.startswith(prefix):
            raise OSError("disk full")
        return real(path, data)
    return write


def test_failed_write_leaves_the_log_consistent(tmp_path):
    lg = plain_log(tmp_path)
    lg.append([b"a", b"b"])
    real = lg.store.write
    for prefix in ("tile/0/", "tile/entries/", "staged"):
        lg.store.write = failing_write(real, prefix)
        with pytest.raises(OSError):
            lg.append([b"c"])
        assert lg.size == lg.frontier.size == 2
        assert log.Log(tmp_path / "log", ORIGIN, lg.keys, [], 0).size == 2
    lg.store.write = real
    lg.append([b"c", b"d"])
    again = log.Log(tmp_path / "log", ORIGIN, lg.keys, [], 0)
    assert again.size == 4 and again.frontier.root() == lg.frontier.root()


def test_log_restart_keeps_history(stack, tmp_path):
    a, b = files(tmp_path, "d-1.zip", "d-2.zip")
    _, proof_a = stack.sign(a)
    old_cp = note.parse_checkpoint(note.split_note(release.parse_proof(proof_a)[3])[0])
    stack.stop_log()
    stack.start_log()
    index, proof_b = stack.sign(b)
    new_cp = note.parse_checkpoint(note.split_note(release.parse_proof(proof_b)[3])[0])
    assert index == 1
    reader = tiles.TileReader(DirStore(stack.root / "log"), new_cp.size)
    cons = merkle.consistency_proof(reader.node, old_cp.size, new_cp.size)
    assert merkle.verify_consistency(old_cp.size, new_cp.size, old_cp.root, new_cp.root, cons)
    release.verify_release(a, proof_a, stack.trust, stack.signers)


def test_witness_refuses_forks_and_rollbacks(stack, tmp_path):
    for p in files(tmp_path, "e-1.zip", "e-2.zip", "e-3.zip"):
        stack.sign(p)
    url = url_of(stack.witnesses[0]) + "add-checkpoint"
    size = stack.log.size
    fork = [b"other %d" % i for i in range(size + 2)]
    status, _ = post(url, forged_request(stack.log_keys, fork, size))
    assert status == 422
    status, _ = post(url, forged_request(stack.log_keys, fork[:size], size))
    assert status == 422
    status, body = post(url, forged_request(stack.log_keys, fork[:2], 2))
    assert status == 409 and body == f"{size}\n".encode()
    status, _ = post(url, forged_request(stack.log_keys, fork[:2], 3))
    assert status == 400
    other = note.generate(ORIGIN, note.MLDSA44)
    text = note.Checkpoint(ORIGIN, 1, merkle.leaf_hash(b"x")).text()
    status, _ = post(url, witness.format_request(0, [], note.format_note(text, [other.sign(text)])))
    assert status == 403
    text = note.Checkpoint("someone.else/log", 1, merkle.leaf_hash(b"x")).text()
    status, _ = post(url, witness.format_request(0, [], note.format_note(text, [other.sign(text)])))
    assert status == 404
    state = json.loads((stack.root / "w0.json").read_text())
    assert state[ORIGIN]["size"] == size


def test_witness_state_survives_restart(stack, tmp_path):
    for p in files(tmp_path, "f-1.zip", "f-2.zip"):
        stack.sign(p)
    stack.stop_witness(0)
    stack.restart_witness(0)
    status, body = post(url_of(stack.witnesses[0]) + "add-checkpoint", forged_request(stack.log_keys, [b"x"], 0))
    assert status == 409 and body == b"2\n"


def test_log_rejects_bad_submissions(stack, tmp_path):
    (path,) = files(tmp_path, "g.zip")
    stranger = keys.generate_release("test.local/stranger")
    status, body = post(stack.url + "add", release.sign_file(path, stranger).encode())
    assert status == 403 and b"unknown key" in body
    e = release.sign_file(path, stack.signer)
    forged = release.Entry(release.Statement(e.statement.signer, "h.zip", 1, "0" * 64), e.ed25519, e.mldsa65)
    status, _ = post(stack.url + "add", forged.encode())
    assert status == 403
    status, _ = post(stack.url + "add", b"x" * 9000)
    assert status == 413
    for length in ["abc", "-5", "0", "1e3"]:
        conn = http.client.HTTPConnection("127.0.0.1", stack.httpd.server_address[1], timeout=5)
        conn.putrequest("POST", "/add")
        conn.putheader("Content-Length", length)
        conn.endheaders()
        assert conn.getresponse().status == 400
        conn.close()
    for bad in ["staged", "tile/0/../../staged", "tile/0/x000/000", "w0.json", "tile/entries/000.p/0"]:
        try:
            urllib.request.urlopen(stack.url + bad, timeout=5)
            raise AssertionError(bad)
        except urllib.error.HTTPError as e:
            assert e.code == 404


def test_refused_upload_is_read_before_the_connection_closes(stack):
    sock = socket.create_connection(("127.0.0.1", stack.httpd.server_address[1]), timeout=5)
    sock.sendall(b"POST /add HTTP/1.1\r\nHost: x\r\nContent-Length: 9000\r\n\r\n")
    reply = b""
    while chunk := sock.recv(4096):
        reply += chunk
    assert reply.startswith(b"HTTP/1.0 413")
    for _ in range(3):
        sock.sendall(b"x" * 3000)
        time.sleep(0.2)
    sock.close()


def test_slow_and_idle_clients_are_cut_off(tmp_path):
    lg = plain_log(tmp_path)
    seq = log.Sequencer(lg, 5, 256, 10).start()
    httpd = start(log.serve(lg, seq, {}, "127.0.0.1", 0, 8192, 1.0, max_connections=2, request_timeout=1.0))
    addr = ("127.0.0.1", httpd.server_address[1])
    try:
        idle = socket.create_connection(addr)
        trickle = socket.create_connection(addr)
        trickle.sendall(b"POST /add HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n")
        extra = socket.create_connection(addr)
        assert closed(extra)
        t = time.monotonic()
        try:
            while time.monotonic() - t < 8:
                trickle.sendall(b"x")
                time.sleep(0.2)
        except OSError:
            pass
        assert time.monotonic() - t < 6
        assert closed(idle) and closed(trickle)
        assert wait_until(lambda: answers(url_of(httpd) + "checkpoint"))
    finally:
        httpd.shutdown()
        httpd.server_close()
        seq.stop()


def test_monitor_flags_unexpected_release(stack, tmp_path):
    a, b, c = files(tmp_path, "m-1.zip", "m-2.zip", "m-3.zip")
    for p in (a, b, c):
        stack.sign(p)
    expected = {(p.name, release.hash_file(p)[1]) for p in (a, b)}
    m = monitor.Monitor(DirStore(stack.root / "log"), stack.trust, stack.signers, expected, tmp_path / "mon.json")
    r = m.run()
    assert r.checked == 3 and r.watched == 3
    assert len(r.alerts) == 1 and r.alerts[0].startswith("unexpected release m-3.zip")
    assert sum("consistent" in n for n in r.notes) == 3
    again = m.run()
    assert again.checked == 0 and not again.alerts


def test_monitor_detects_rewritten_history(tmp_path):
    k = [note.generate(ORIGIN, note.ED25519), note.generate(ORIGIN, note.MLDSA44)]
    trust = policy.parse_policy(f"log {k[1].public.vkey()}\nquorum none\n".encode())
    signer = keys.generate_release("test.local/release")
    for name, names in [("real", ["one", "two", "three"]), ("same", ["one", "TWO", "three"]),
                        ("longer", ["one", "TWO", "three", "four"]), ("shorter", ["one"])]:
        lg = log.Log(tmp_path / name, ORIGIN, k, [], 0)
        lg.append([entry(signer, n) for n in names])
        assert lg.publish()
    m = monitor.Monitor(DirStore(tmp_path / "real"), trust, {}, set(), tmp_path / "mon.json")
    assert not m.run().alerts
    m.fetch = DirStore(tmp_path / "same")
    assert m.run().alerts == ["log shows a different tree at size 3"]
    m.fetch = DirStore(tmp_path / "longer")
    assert m.run().alerts == ["log entries do not hash to the checkpoint root"]
    m.fetch = DirStore(tmp_path / "shorter")
    assert m.run().alerts == ["log went backwards from size 3 to 1"]


def test_monitor_reports_a_missing_checkpoint(tmp_path):
    (tmp_path / "empty").mkdir()
    trust = policy.parse_policy(f"log {note.generate(ORIGIN, note.MLDSA44).public.vkey()}\nquorum none\n".encode())
    r = monitor.Monitor(DirStore(tmp_path / "empty"), trust, {}, set(), tmp_path / "mon.json").run()
    assert len(r.alerts) == 1 and r.alerts[0].startswith("could not fetch the checkpoint")


def test_monitor_detects_split_view(stack, tmp_path):
    for p in files(tmp_path, "s-1.zip", "s-2.zip"):
        stack.sign(p)
    split = log.Log(tmp_path / "split", ORIGIN, stack.log_keys, [], 0)
    split.append([entry(stack.signer, n) for n in ("something", "else", "entirely")])
    assert split.publish()
    trust = policy.Policy(stack.trust.logs, stack.trust.witnesses, {}, "none", stack.trust.urls)
    m = monitor.Monitor(DirStore(tmp_path / "split"), trust, {}, set(), tmp_path / "mon.json")
    alerts = m.run().alerts
    assert len(alerts) == 3 and all(a.startswith("split view") for a in alerts)


class SoloWitness:
    def __init__(self, tmp_path, log_keys):
        self.key = note.generate("test.local/solo", note.MLDSA44)
        self.witness = witness.Witness(self.key, {ORIGIN: [k.public for k in log_keys]}, tmp_path / "solo.json")
        self.httpd = start(witness.serve(self.witness, "127.0.0.1", 0))
        self.trust = policy.Policy([log_keys[1].public], {"solo": self.key.public}, {}, "none",
                                   {"solo": url_of(self.httpd)})

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def real(tmp_path):
    lk = [note.generate(ORIGIN, note.ED25519), note.generate(ORIGIN, note.MLDSA44)]
    signer = keys.generate_release("test.local/release")
    lg = log.Log(tmp_path / "real", ORIGIN, lk, [], 0)
    entries = [entry(signer, n) for n in ("one", "two", "three", "four")]
    lg.append(entries[:3])
    assert lg.publish()
    solo = SoloWitness(tmp_path, lk)
    yield lg, solo, signer, entries
    solo.close()
    lg.close()


def audit(tmp_path, real, name):
    lg, solo, _, _ = real
    return monitor.Monitor(DirStore(tmp_path / "real"), solo.trust, {}, set(), tmp_path / name).run()


def test_split_view_is_found_even_when_the_log_forges_tiles(tmp_path, real):
    lg, solo, signer, _ = real
    fork = [entry(signer, n) for n in ("fork-1", "fork-2")]
    assert solo.witness.add_checkpoint(forged_request(lg.keys, fork, 0))[0] == 200
    assert any(a.startswith("split view") for a in audit(tmp_path, real, "m1.json").alerts)
    path = tmp_path / "real" / "tile" / "0" / "000.p" / "3"
    tile = path.read_bytes()
    path.write_bytes(merkle.leaf_hash(fork[0]) + merkle.leaf_hash(fork[1]) + tile[64:])
    r = audit(tmp_path, real, "m2.json")
    assert r.checked == 3 and any(a.startswith("split view") for a in r.alerts)


def test_witness_ahead_of_the_log_is_checked(tmp_path, real):
    lg, solo, signer, names = real
    lg.append([names[3]])
    assert solo.witness.add_checkpoint(forged_request(lg.keys, names, 0))[0] == 200
    r = audit(tmp_path, real, "m1.json")
    assert not r.alerts and r.notes == ["solo has already seen size 4, consistent"]


def test_inconsistent_witness_ahead_of_the_log_is_an_alert(tmp_path, real):
    lg, solo, signer, names = real
    fork = names[:3] + [entry(signer, "evil")]
    lg.append([names[3]])
    assert solo.witness.add_checkpoint(forged_request(lg.keys, fork, 0))[0] == 200
    assert any(a.startswith("split view") for a in audit(tmp_path, real, "m1.json").alerts)


def test_witness_view_the_log_cannot_back_up_is_an_alert(tmp_path, real):
    lg, solo, signer, names = real
    assert solo.witness.add_checkpoint(forged_request(lg.keys, names + [entry(signer, "five")], 0))[0] == 200
    alerts = audit(tmp_path, real, "m1.json").alerts
    assert len(alerts) == 1 and "cannot prove it matches" in alerts[0]

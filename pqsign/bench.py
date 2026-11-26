import os
import platform
import random
import statistics
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import keys, log, merkle, monitor, note, policy, release, tiles, witness
from .storage import DirStore


def median_ms(fn, runs: int) -> float:
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1000


def disk_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


class LocalStack:
    def __init__(self, root: Path, cfg, signers: dict):
        origin = cfg.log.name
        self.log_keys = [note.generate(origin, note.ED25519), note.generate(origin, note.MLDSA44)]
        self.servers, wit = [], []
        for i, node in enumerate(cfg.witnesses):
            k = note.generate(node.name, note.MLDSA44)
            w = witness.Witness(k, {origin: [x.public for x in self.log_keys]}, root / f"w{i}.json")
            httpd = witness.serve(w, "127.0.0.1", 0)
            self.servers.append(httpd)
            wit.append((node.name, k.public, f"http://127.0.0.1:{httpd.server_address[1]}/"))
        text = policy.format_policy([(self.log_keys[1].public, "http://127.0.0.1:1/")], wit, cfg.quorum)
        self.trust = policy.parse_policy(text)
        clients = [witness.WitnessClient(n, u, k, cfg.witness_timeout_s) for n, k, u in wit]
        self.log = log.Log(root / "log", origin, self.log_keys, clients, cfg.quorum, cfg.witness_timeout_s,
                           cfg.grace_ms / 1000)
        self.seq = log.Sequencer(self.log, cfg.batch_ms, cfg.max_batch, cfg.max_pending).start()
        httpd = log.serve(self.log, self.seq, signers, "127.0.0.1", 0, cfg.max_entry_bytes, cfg.submit_timeout_s)
        self.servers.append(httpd)
        self.url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        for s in self.servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def close(self) -> None:
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.seq.stop()
        self.log.close()


def signatures(cfg, signer, row) -> None:
    st = release.Statement(signer.public.fingerprint, "app-1.0.zip", 1 << 20, "ab" * 32).encode()
    ed, ml = signer.sign(st)
    w = note.generate("bench/witness", note.MLDSA44)
    text = note.Checkpoint("bench/log", 123, merkle.EMPTY).text()
    sig = w.sign(text)
    row("hybrid sign, Ed25519 + ML-DSA-65", f"{median_ms(lambda: signer.sign(st), 200):.3f} ms")
    row("hybrid verify", f"{median_ms(lambda: signer.public.verify(st, ed, ml), 200):.3f} ms")
    row("ML-DSA-44 cosignature sign", f"{median_ms(lambda: w.sign(text), 200):.3f} ms")
    row("ML-DSA-44 cosignature verify", f"{median_ms(lambda: w.public.verify(text, sig.payload), 200):.3f} ms")
    row("signature sizes", f"Ed25519 {len(ed)}, ML-DSA-65 {len(ml)}, cosignature {len(sig.payload)} bytes")


def end_to_end(cfg, root: Path, signer, signers: dict, row) -> None:
    stack = LocalStack(root / "stack", cfg, signers)
    try:
        dist = root / "dist"
        dist.mkdir()
        paths = []
        for i in range(60):
            p = dist / f"app-{i}.zip"
            p.write_bytes(os.urandom(1 << 20))
            paths.append(p)

        def sign_one(p):
            e = release.sign_file(p, signer).encode()
            return log.prove(stack.url, e, log.submit(stack.url, e, 60), stack.trust, 60, 60)

        lat = [median_ms(lambda p=p: sign_one(p), 1) for p in paths[:20]]
        row("sign one 1 MiB release, median", f"{statistics.median(lat):.1f} ms")
        t = time.perf_counter()
        with ThreadPoolExecutor(32) as pool:
            proofs = list(pool.map(sign_one, paths[20:]))
        row("40 releases signed in parallel", f"{time.perf_counter() - t:.2f} s")

        def check():
            return release.verify_release(paths[20], proofs[0], stack.trust, signers)

        check()
        row("proof file size", f"{len(proofs[0])} bytes")
        row("offline verify of one release", f"{median_ms(check, 50):.2f} ms")
    finally:
        stack.close()


def ingest(root: Path, signer, entries: int, row) -> None:
    pool = []
    for i in range(256):
        s = release.Statement(signer.public.fingerprint, f"pkg-{i}.tar.gz", 1000 + i, os.urandom(32).hex())
        pool.append(release.Entry(s, *signer.sign(s.encode())).encode())
    lg = log.Log(root / "ingest", "bench/log", [note.generate("bench/log", note.ED25519)], [], 0)
    t = time.perf_counter()
    done = 0
    while done < entries:
        n = min(256, entries - done)
        lg.append([pool[(done + j) % 256] for j in range(n)])
        done += n
    lg.publish()
    elapsed = time.perf_counter() - t
    row("entries per second", f"{entries / elapsed:.0f}")
    row("disk per entry", f"{disk_bytes(root / 'ingest') / entries:.0f} bytes")
    store, rng = DirStore(root / "ingest"), random.Random(1)

    def one_proof():
        return merkle.inclusion_proof(tiles.TileReader(store, entries).node, rng.randrange(entries), entries)

    row("inclusion proof built from tiles", f"{median_ms(one_proof, 200):.2f} ms, {len(one_proof())} hashes")
    trust = policy.parse_policy(f"log {lg.keys[0].public.vkey()}\nquorum none\n".encode())
    mon = monitor.Monitor(store, trust, {}, set(), root / "monitor.json")
    t = time.perf_counter()
    report = mon.run()
    elapsed = time.perf_counter() - t
    row("monitor audit, entries per second", f"{report.checked / elapsed:.0f}")
    row("monitor alerts", str(len(report.alerts)))


def run(cfg, entries: int, say) -> None:
    def row(label: str, value: str) -> None:
        say(f"  {label:<36}{value}")

    say(f"machine: {platform.processor() or platform.machine()}, {os.cpu_count()} threads, "
        f"Python {platform.python_version()}, {platform.system()}")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        signer = keys.generate_release(cfg.signer)
        signers = {signer.public.fingerprint: signer.public}
        say("signatures")
        signatures(cfg, signer, row)
        say(f"end to end, {len(cfg.witnesses)} witnesses on localhost, quorum {cfg.quorum}, batch {cfg.batch_ms} ms")
        end_to_end(cfg, root, signer, signers, row)
        say(f"log ingest, {entries} entries in batches of 256, fsync on")
        ingest(root, signer, entries, row)

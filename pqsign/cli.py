import argparse
import sys
import threading
import time
from pathlib import Path

from . import bench, keys, log, monitor, note, policy, release, witness
from . import config as configs
from .storage import atomic_write, fetcher


def say(message: str) -> None:
    print(message, flush=True)


def load_trust(path) -> policy.Policy:
    return policy.parse_policy(Path(path).read_bytes())


def load_signers(paths) -> dict[str, keys.ReleaseKey]:
    found = {}
    for p in paths:
        key = keys.parse_public(Path(p).read_bytes())
        found[key.fingerprint] = key
    return found


def cmd_init(cfg: configs.Config, args) -> int:
    if cfg.state.exists() and any(cfg.state.iterdir()):
        raise configs.ConfigError(f"{cfg.state} already exists, delete it to start a new local setup")
    passphrase = keys.ask_passphrase(confirm=True)
    log_keys = [note.generate(cfg.log.name, note.ED25519), note.generate(cfg.log.name, note.MLDSA44)]
    keys.write_server_keys(cfg.keys / "log.key", log_keys)
    atomic_write(cfg.keys / "log.vkeys", "".join(k.public.vkey() + "\n" for k in log_keys).encode())
    witnesses = []
    for i, node in enumerate(cfg.witnesses):
        k = note.generate(node.name, note.MLDSA44)
        keys.write_server_keys(cfg.witness_key(i), [k])
        witnesses.append((node.name, k.public, node.url))
    secret = keys.generate_release(cfg.signer)
    atomic_write(cfg.keys / "release.key", keys.secret_text(secret, passphrase, cfg.scrypt_log_n), private=True)
    atomic_write(cfg.keys / "release.pub", secret.public.text())
    atomic_write(cfg.policy, policy.format_policy([(log_keys[1].public, cfg.log.url)], witnesses, cfg.quorum))
    say(f"created keys for the log, {len(witnesses)} witnesses and the release signer in {cfg.keys}")
    say(f"release key fingerprint {secret.public.fingerprint[:16]}"
        + ("" if passphrase else " (stored without a passphrase)"))
    say(f"trust policy written to {cfg.policy}, quorum {cfg.quorum} of {len(witnesses)}")
    return 0


def cmd_serve(cfg: configs.Config, args) -> int:
    servers = []
    log_vkeys = [note.parse_vkey(line) for line in (cfg.keys / "log.vkeys").read_text("ascii").split()]
    for i, node in enumerate(cfg.witnesses):
        if args.only in (None, node.name, f"witness-{i + 1}"):
            w = witness.Witness(keys.read_server_keys(cfg.witness_key(i))[0], {cfg.log.name: log_vkeys},
                                cfg.witness_state(i))
            servers.append((node, witness.serve(w, node.host, node.port, cfg.max_connections,
                                                cfg.request_timeout_s)))
    sequencer = None
    if args.only in (None, "log"):
        log_keys = keys.read_server_keys(cfg.keys / "log.key")
        trust = load_trust(cfg.policy)
        clients = [witness.WitnessClient(n.name, n.url, trust.witnesses[n.name], cfg.witness_timeout_s)
                   for n in cfg.witnesses]
        lg = log.Log(cfg.log_dir, cfg.log.name, log_keys, clients, cfg.quorum, cfg.witness_timeout_s,
                     cfg.grace_ms / 1000)
        sequencer = log.Sequencer(lg, cfg.batch_ms, cfg.max_batch, cfg.max_pending, on_event=say).start()
        signers = load_signers([cfg.keys / "release.pub"])
        servers.append((cfg.log, log.serve(lg, sequencer, signers, cfg.log.host, cfg.log.port, cfg.max_entry_bytes,
                                           cfg.submit_timeout_s, cfg.max_connections, cfg.request_timeout_s)))
    if not servers:
        raise configs.ConfigError(f"nothing named {args.only}")
    for node, httpd in servers:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        say(f"{node.name} listening on {node.url}")
    say("press Ctrl+C to stop")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        say("stopping")
    for _, httpd in servers:
        httpd.shutdown()
    if sequencer:
        sequencer.stop()
    return 0


def cmd_sign(cfg: configs.Config, args) -> int:
    trust = load_trust(cfg.policy)
    secret = keys.parse_secret((cfg.keys / "release.key").read_bytes(), keys.ask_passphrase)
    known = {secret.public.fingerprint: secret.public}
    for f in args.files:
        path = Path(f)
        entry = release.sign_file(path, secret).encode()
        index = log.submit(cfg.log.url, entry, cfg.submit_timeout_s + 5)
        proof = log.prove(cfg.log.url, entry, index, trust, cfg.submit_timeout_s, cfg.submit_timeout_s)
        v = release.verify_release(path, proof, trust, known, max_future=cfg.max_future_s)
        atomic_write(Path(f"{path}.tlog-proof"), proof)
        say(f"signed {path.name}: index {v.index}, tree size {v.checkpoint.size}, "
            f"witnessed by {', '.join(sorted(v.witnesses))}")
    return 0


def cmd_verify(cfg: configs.Config, args) -> int:
    trust = load_trust(args.policy or cfg.policy)
    signers = load_signers(args.key or [cfg.keys / "release.pub"])
    if args.proof and len(args.files) != 1:
        raise configs.ConfigError("--proof works with one file at a time")
    failed = 0
    for f in args.files:
        path = Path(f)
        proof = Path(args.proof or f"{path}.tlog-proof")
        try:
            v = release.verify_release(path, proof.read_bytes(), trust, signers, max_future=cfg.max_future_s)
            say(f"ok    {path.name}  index {v.index}  signer {v.key.name}  "
                f"witnesses {len(v.witnesses)} of {len(trust.witnesses)}")
        except (OSError, release.VerifyError) as e:
            failed += 1
            say(f"FAIL  {path.name}  {e}")
    return 1 if failed else 0


def cmd_monitor(cfg: configs.Config, args) -> int:
    expected_path = Path(args.expected or cfg.expected)
    if not expected_path.exists():
        raise configs.ConfigError(f"{expected_path} not found, list your real releases there in sha256sum format")
    m = monitor.Monitor(fetcher(args.log or cfg.log.url, cfg.witness_timeout_s), load_trust(cfg.policy),
                        load_signers([cfg.keys / "release.pub"]), monitor.read_sums(expected_path),
                        cfg.state / "monitor.json", cfg.witness_timeout_s)
    r = m.run()
    say(f"{cfg.log.name}: tree size {r.old_size} to {r.size}, new entries checked: {r.checked}, "
        f"signed by your key: {r.watched}")
    for line in r.notes:
        say(f"  {line}")
    for line in r.alerts:
        say(f"ALERT {line}")
    return 1 if r.alerts else 0


def cmd_sums(cfg: configs.Config, args) -> int:
    for f in args.files:
        say(f"{release.hash_file(f)[1]}  {Path(f).name}")
    return 0


def cmd_bench(cfg: configs.Config, args) -> int:
    bench.run(cfg, args.entries, say)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pqsign", description="Post-quantum release signing with a witnessed log")
    p.add_argument("--config", default="config.toml")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create keys and the trust policy")
    s = sub.add_parser("serve", help="run the log and the witnesses")
    s.add_argument("--only", help="run just the log or one witness (log, witness-1, ...)")
    s = sub.add_parser("sign", help="sign files, log them and write .tlog-proof files")
    s.add_argument("files", nargs="+")
    s = sub.add_parser("verify", help="check files against their .tlog-proof offline")
    s.add_argument("files", nargs="+")
    s.add_argument("--proof")
    s.add_argument("--policy")
    s.add_argument("--key", action="append")
    s = sub.add_parser("monitor", help="audit the log and alert on releases you did not make")
    s.add_argument("--expected")
    s.add_argument("--log")
    s = sub.add_parser("sums", help="print sha256sum style lines for files")
    s.add_argument("files", nargs="+")
    s = sub.add_parser("bench", help="measure signing, logging and verification")
    s.add_argument("--entries", type=int, default=50_000)
    return p


COMMANDS = {"init": cmd_init, "serve": cmd_serve, "sign": cmd_sign, "verify": cmd_verify,
            "monitor": cmd_monitor, "sums": cmd_sums, "bench": cmd_bench}


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        cfg = configs.load(args.config)
        return COMMANDS[args.command](cfg, args)
    except (configs.ConfigError, keys.KeyFileError, log.LogError, policy.PolicyError, note.NoteError,
            release.VerifyError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

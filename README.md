# post-quantum-release-signing-transparency-log

[![ci](https://github.com/adwitiyashukla/post-quantum-release-signing-transparency-log/actions/workflows/ci.yml/badge.svg)](https://github.com/adwitiyashukla/post-quantum-release-signing-transparency-log/actions/workflows/ci.yml)

`pqsign` signs software releases with Ed25519 and ML-DSA-65 at the same time and records every signature in an append-only Merkle log. A release only counts as valid if the log can prove it recorded the signature and a quorum of independent witnesses cosigned that state of the log.

I built this to learn how release signing and transparency logs work under the hood (Sigstore, Certificate Transparency, the Go checksum database), and to get ready for the move to post-quantum signatures. NIST plans to deprecate RSA-2048 after 2030 and to stop allowing RSA and elliptic curve signatures after 2035, so the keys that sign software will have to move too.

## Why a log and not just a signature

If someone steals a release key, they can sign a malicious build that looks exactly like a real release. A signature alone can't tell the difference. With a transparency log every signature is public, so the real owner can see a signature they never made. Witnesses make sure the log can't show one history to the owner and a different one to everyone else. The hybrid signature keeps old releases safe if either Ed25519 or ML-DSA gets broken later.

## How it works

1. `pqsign sign app.zip` hashes the file and signs a short statement with both Ed25519 and ML-DSA-65. Both signatures cover a fingerprint of both public keys, so one half can't be pulled out and reused on its own.
2. The signed statement goes to the log. The log only accepts entries from registered signing keys. It adds the entry to a Merkle tree stored as static tiles, signs a new checkpoint with Ed25519 and ML-DSA-44, and sends the checkpoint to the witnesses.
3. Each witness checks a consistency proof from the last checkpoint it saw before it cosigns with ML-DSA-44. It never cosigns two different trees, and it saves its state to disk before it answers.
4. Once a quorum of witnesses has cosigned, the log publishes the checkpoint and the signer writes `app.zip.tlog-proof` next to the file.
5. `pqsign verify app.zip` works offline. It checks both signatures, the file hash and file name, the inclusion proof and the witness quorum from a trust policy file.
6. `pqsign monitor` downloads every new entry, rebuilds the tree root itself, compares each witness's view with a consistency proof, and raises an alert for any release signed with your key that is not in your SHA256SUMS file.

The log writes tiles and a signed "staged" checkpoint to disk before it asks any witness, so a crash can never leave witnesses holding a tree the log has lost.

## Quick start

Needs Python 3.11 or newer. Create a venv, activate it, then:

```
pip install -e ".[test]"
pqsign init
pqsign serve
```

`init` creates keys for the log, three witnesses and the release signer, and asks for a passphrase for the release key (scrypt plus AES-256-GCM, leave it empty to skip). `serve` runs the log on port 7380 and the witnesses on 7381 to 7383, all on localhost. In a second terminal:

```
pqsign sign dist/myapp-1.0.zip
pqsign verify dist/myapp-1.0.zip
pqsign sums dist/myapp-1.0.zip > SHA256SUMS
pqsign monitor
```

Everything the demo creates lives in `local/`. Delete that folder to start over. All settings (quorum, batch window, timeouts, connection limit, scrypt cost) are in `config.toml` and get checked when it loads.

## What it catches

I ran the first three by hand on my laptop against this project's own wheel. Every row is also a test in `tests/`, and the whole suite passes on that laptop.

| Scenario | Result |
|---|---|
| One byte added to a signed release | verify fails: file contents do not match the signed hash |
| Old release renamed as a newer version | verify fails: proof is for the old file name |
| Stolen key signs a build you never made | monitor alert: unexpected release |
| Log rewrites old entries | monitor alert: entries do not hash to the checkpoint root |
| Log shows a witness a forked tree | witness refuses (HTTP 422), monitor alert: split view |
| Log forges its tiles to hide that fork | monitor still alerts, the consistency proof can't be faked |
| Fewer witnesses than the quorum | verify fails: witness quorum not met |
| Ed25519 or ML-DSA half swapped between releases | rejected, the other half no longer matches |
| One witness listed twice through nested groups | policy file rejected |
| Disk error in the middle of an append | log keeps its old state and restarts cleanly |
| Idle or very slow clients | cut off after `request_timeout_s`, connection cap holds |

## Results

Measured with `pqsign bench` on my HP OmniBook 5 (Intel Core 5 120U, 12 threads, 8 GB RAM, Windows 11, Python 3.13.7).

| Measurement | Value |
|---|---|
| Hybrid sign, Ed25519 + ML-DSA-65 | 0.89 ms |
| Hybrid verify | 0.29 ms |
| ML-DSA-44 cosignature sign | 0.74 ms |
| ML-DSA-44 cosignature verify | 0.14 ms |
| Signature sizes | Ed25519 64 B, ML-DSA-65 3,309 B, cosignature 2,428 B |
| Sign one 1 MiB release end to end, 3 witnesses, quorum 2 | 222 ms median |
| 40 releases signed in parallel | 1.84 s |
| Proof file size | 19,835 B |
| Offline verify of one release | 9.3 ms |
| Log ingest, 50,000 entries, fsync on | 7,890 entries/s |
| Disk per log entry | 4,750 B |
| Inclusion proof read from tiles at 50,000 entries | 4.2 ms, 16 hashes |
| Monitor full audit | 5,657 entries/s |

Most of the 222 ms is the 100 ms batch window (`batch_ms`), the fsyncs and the witness round trips, not the crypto. The full test suite (358 tests) passes on the same laptop in 24 seconds.

## How I checked it

- Merkle roots, every tile at every published tree size, and 3,200 inclusion and consistency proofs match Go's checksum database code (golang.org/x/mod/sumdb/tlog) byte for byte, on logs of up to 300,000 entries.
- The proof files, checkpoints and trust policy files verify with torchwood, a Go implementation of the same C2SP specs, and Go's note package verifies the Ed25519 log signature.
- ML-DSA keys and signatures pass the NIST ACVP vectors, Ed25519 passes the RFC 8032 vectors, and the Merkle proof checks are tested against the 184 transparency-dev reference cases. A subset of these vectors runs in CI.
- A stress run signed about 2,000 releases while restarting the log and the witnesses and injecting disk failures. Every proof it produced verified.

## Formats

The wire formats follow the C2SP specs, so other tools can read them.

| Piece | Spec |
|---|---|
| Checkpoints | c2sp.org/signed-note, c2sp.org/tlog-checkpoint |
| Witness cosignatures | c2sp.org/tlog-cosignature (ML-DSA-44) |
| Witness API | c2sp.org/tlog-witness |
| Log storage | c2sp.org/tlog-tiles |
| Proof files | c2sp.org/tlog-proof |
| Trust policy | c2sp.org/tlog-policy |

The release statement is my own small text format. Both signatures cover these lines, and the log stores them with the two signatures appended:

```
pqsign/v1
signer <sha256 of both public keys>
file myapp-1.0.zip
size 1048576
sha256 <hex digest of the file>
```

## Code

| File | What it does |
|---|---|
| `pqsign/merkle.py` | RFC 6962 hashing, inclusion and consistency proofs |
| `pqsign/tiles.py` | tile and entry bundle storage |
| `pqsign/note.py` | signed notes, checkpoints, ML-DSA-44 cosignatures |
| `pqsign/policy.py` | trust policy parsing and quorum checks |
| `pqsign/keys.py`, `pqsign/release.py` | hybrid keys, statements, proof files, offline verify |
| `pqsign/log.py` | sequencer, crash safe log, witness collection |
| `pqsign/witness.py` | witness server and client |
| `pqsign/web.py` | HTTP server with timeouts and a connection cap |
| `pqsign/monitor.py` | full audit and split view checks |
| `pqsign/config.py`, `pqsign/cli.py`, `pqsign/bench.py` | settings, commands, benchmark |

Run the tests with `pytest -q`. CI runs them on Linux, Windows and macOS with Python 3.11, 3.12 and 3.13.

## License

MIT

import hashlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pqsign import cli, config

ROOT = Path(__file__).parent.parent


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("PQSIGN_PASSPHRASE", "test passphrase")
    text = (ROOT / "config.toml").read_text().replace("scrypt_log_n = 17", "scrypt_log_n = 14")
    for old, new in zip([7380, 7381, 7382, 7383], free_ports(4), strict=True):
        text = text.replace(f"127.0.0.1:{old}", f"127.0.0.1:{new}")
    cfg = tmp_path / "config.toml"
    cfg.write_text(text)
    assert cli.main(["--config", str(cfg), "init"]) == 0
    return cfg


def wait_for_port(port, proc, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(proc.stdout.read().decode())
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("server did not start")


def test_init_refuses_to_overwrite(setup, capsys):
    assert cli.main(["--config", str(setup), "init"]) == 2
    assert "already exists" in capsys.readouterr().err


def test_full_command_line_flow(setup, tmp_path, capsys):
    cfg = config.load(setup)
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    proc = subprocess.Popen([sys.executable, "-m", "pqsign", "--config", str(setup), "serve"], cwd=tmp_path,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        wait_for_port(cfg.log.port, proc)
        dist = tmp_path / "dist"
        dist.mkdir()
        good = [dist / "tool-1.0.tar.gz", dist / "tool-1.1.tar.gz"]
        for i, p in enumerate(good):
            p.write_bytes(os.urandom(5000 + i))
        run = ["--config", str(setup)]
        assert cli.main(run + ["sign"] + [str(p) for p in good]) == 0
        assert cli.main(run + ["verify"] + [str(p) for p in good]) == 0
        sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in good)
        (tmp_path / "SHA256SUMS").write_text(sums)
        assert cli.main(run + ["monitor"]) == 0
        (tmp_path / "nolog").mkdir()
        assert cli.main(run + ["monitor", "--log", str(tmp_path / "nolog")]) == 1
        extra = dist / "tool-6.6.tar.gz"
        extra.write_bytes(b"not a real release")
        assert cli.main(run + ["sign", str(extra)]) == 0
        assert cli.main(run + ["monitor"]) == 1
        good[0].write_bytes(good[0].read_bytes() + b"!")
        assert cli.main(run + ["verify", str(good[0])]) == 1
        assert cli.main(run + ["verify", str(good[1]), "--proof", str(good[0]) + ".tlog-proof"]) == 1
        out = capsys.readouterr().out
        assert "signed tool-1.0.tar.gz: index 0" in out
        assert "ALERT unexpected release tool-6.6.tar.gz" in out
        assert "ALERT could not fetch the checkpoint" in out
        assert "FAIL  tool-1.0.tar.gz  file contents do not match the signed hash" in out
        assert "FAIL  tool-1.1.tar.gz  proof is for tool-1.0.tar.gz" in out
    finally:
        proc.terminate()
        proc.wait(timeout=30)
        proc.stdout.close()

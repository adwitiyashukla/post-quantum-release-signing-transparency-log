from pathlib import Path

import pytest

from pqsign import config

BASE = (Path(__file__).parent.parent / "config.toml").read_text()


def load(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return config.load(p)


def test_repo_config_is_valid():
    cfg = config.load(Path(__file__).parent.parent / "config.toml")
    assert cfg.log.name == "localhost/pqsign" and cfg.log.url == "http://127.0.0.1:7380/"
    assert len(cfg.witnesses) == 3 and cfg.quorum == 2
    assert cfg.policy.name == "policy.txt" and cfg.witness_key(0).name == "witness-1.key"


@pytest.mark.parametrize("old,new", [
    ("[paths]", "[extra]\nx = 1\n\n[paths]"),
    ("batch_ms = 100", "batch_ms = 100\nbatch_size = 5"),
    ("batch_ms = 100\n", ""),
    ("batch_ms = 100", "batch_ms = 0"),
    ("batch_ms = 100", "batch_ms = true"),
    ("batch_ms = 100", 'batch_ms = "100"'),
    ('origin = "localhost/pqsign"', 'origin = "local host"'),
    ('origin = "localhost/pqsign"', 'origin = "a+b"'),
    ('origin = "localhost/pqsign"', 'origin = "caf\\u00e9"'),
    ('listen = "127.0.0.1:7380"', 'listen = "127.0.0.1"'),
    ('listen = "127.0.0.1:7380"', 'listen = "example.com:7380"'),
    ('listen = "127.0.0.1:7380"', 'listen = "127.0.0.1:70000"'),
    ('listen = "127.0.0.1:7380"', 'listen = "127.0.0.1:7381"'),
    ("quorum = 2", "quorum = 4"),
    ("quorum = 2", "quorum = 0"),
    ('"localhost/witness-2"', '"localhost/witness-1"'),
    ('"localhost/witness-2"', '"localhost/pqsign"'),
    ("scrypt_log_n = 17", "scrypt_log_n = 13"),
    ("max_connections = 64", "max_connections = 0"),
    ("request_timeout_s = 10", "request_timeout_s = 0"),
    ("[http]\nmax_connections = 64\nrequest_timeout_s = 10\n", ""),
    ("timeout_s = 5", "timeout_s = -1"),
    ("grace_ms = 250", "grace_ms = -1"),
    ('{ name = "localhost/witness-3", listen = "127.0.0.1:7383" },', '{ name = "localhost/witness-3" },'),
    ('expected = "SHA256SUMS"', 'expected = ""'),
    ("[log]", "[log\n"),
])
def test_bad_configs(tmp_path, old, new):
    assert old in BASE
    with pytest.raises(config.ConfigError):
        load(tmp_path, BASE.replace(old, new, 1))


def test_paths_are_relative_to_the_config_file(tmp_path):
    cfg = load(tmp_path, BASE)
    assert cfg.state == (tmp_path / "local").resolve()
    assert cfg.expected == (tmp_path / "SHA256SUMS").resolve()

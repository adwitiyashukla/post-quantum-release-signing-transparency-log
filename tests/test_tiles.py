import random

import pytest

from pqsign import merkle, tiles
from pqsign.storage import NotFound


class MemStore(dict):
    def __call__(self, path):
        if path not in self:
            raise NotFound(path)
        return self[path]


def build(entries, batches, reload_every=0):
    store = MemStore()
    w = tiles.TileWriter()
    pos = 0
    for n, b in enumerate(batches):
        if reload_every and n % reload_every == 0:
            w = tiles.TileWriter.load(store, w.size)
        store.update(w.extend(entries[pos:pos + b]))
        pos += b
    return store, w


@pytest.mark.parametrize("n,path", [
    (0, "000"), (5, "005"), (255, "255"), (1000, "x001/000"), (1234067, "x001/x234/067"),
])
def test_index_encoding(n, path):
    assert tiles.encode_index(n) == path


def test_tile_paths():
    assert tiles.tile_path(0, 1234067, 256) == "tile/0/x001/x234/067"
    assert tiles.tile_path(2, 3, 17) == "tile/2/003.p/17"
    assert tiles.bundle_path(0, 1) == "tile/entries/000.p/1"
    assert tiles.parse_path("tile/0/x001/x234/067") == ("0", 1234067, 256)
    assert tiles.parse_path("tile/entries/003.p/255") == ("entries", 3, 255)


@pytest.mark.parametrize("path", [
    "tile/64/000", "tile/00/000", "tile/0/x000/005", "tile/0/000.p/256", "tile/0/000.p/0", "tile/0/000.p/07",
    "tile/0/0005", "tile/0/005/", "../checkpoint", "tile/entries/../../key", "tile/0/x001", "tile/data/000",
])
def test_bad_paths_are_rejected(path):
    assert tiles.parse_path(path) is None


def test_spec_example_tree_of_70000():
    entries = [i.to_bytes(4, "big") for i in range(70000)]
    store, w = build(entries, [70000])
    for path in ["tile/0/272", "tile/0/273.p/112", "tile/1/000", "tile/1/001.p/17", "tile/2/000.p/1"]:
        assert path in store
    assert "tile/0/273" not in store and "tile/1/001" not in store
    r = tiles.TileReader(store, 70000)
    mem = merkle.MemoryTree([merkle.leaf_hash(e) for e in entries])
    assert merkle.root(r.node, 70000) == merkle.root(mem.node, 70000)


@pytest.mark.parametrize("seed", range(6))
def test_reader_matches_memory_tree_across_reloads(seed):
    rng = random.Random(seed)
    entries = [rng.randbytes(rng.randint(1, 30)) for _ in range(rng.randint(1, 3000))]
    batches, left = [], len(entries)
    while left:
        b = min(left, rng.choice([1, 2, 255, 256, 257, 700]))
        batches.append(b)
        left -= b
    store, w = build(entries, batches, reload_every=3)
    mem = merkle.MemoryTree([merkle.leaf_hash(e) for e in entries])
    sizes = [sum(batches[:i + 1]) for i in range(len(batches))]
    for size in sizes:
        r = tiles.TileReader(store, size)
        assert merkle.root(r.node, size) == merkle.root(mem.node, size)
        i = rng.randrange(size)
        assert merkle.inclusion_proof(r.node, i, size) == merkle.inclusion_proof(mem.node, i, size)
    r = tiles.TileReader(store, len(entries))
    got = []
    for t in range((len(entries) + 255) // 256):
        got += r.entries(t)
    assert got == entries


def test_reader_falls_back_to_full_tile():
    entries = [bytes([i % 251 + 1]) for i in range(600)]
    store, _ = build(entries, [100, 500])
    del store["tile/0/000.p/100"]
    del store["tile/entries/000.p/100"]
    r = tiles.TileReader(store, 100)
    mem = merkle.MemoryTree([merkle.leaf_hash(e) for e in entries[:100]])
    assert merkle.root(r.node, 100) == merkle.root(mem.node, 100)
    assert r.entries(0) == entries[:100]


def test_bundles_are_strict():
    data = tiles.encode_bundle([b"ab", b"c"])
    assert tiles.decode_bundle(data, 2) == ([b"ab", b"c"], len(data))
    with pytest.raises(ValueError):
        tiles.decode_bundle(data[:-1], 2)
    with pytest.raises(ValueError):
        tiles.encode_bundle([b""])
    store = MemStore({"tile/entries/000.p/2": data + b"\x00"})
    with pytest.raises(ValueError):
        tiles.TileReader(store, 2).entries(0)


def test_short_tile_is_rejected():
    store = MemStore({"tile/0/000.p/3": b"\x00" * 64})
    with pytest.raises(ValueError):
        tiles.TileReader(store, 3).node(0, 0)

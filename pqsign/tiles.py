import re

from . import merkle
from .storage import NotFound

HEIGHT = 8
WIDTH = 256
HASH = 32
MAX_ENTRY = 0xFFFF

PATH_RE = re.compile(r"tile/(0|[1-9][0-9]?|entries)/((?:x[0-9]{3}/)*[0-9]{3})(?:\.p/([1-9][0-9]{0,2}))?")


def encode_index(n: int) -> str:
    if n < 0:
        raise ValueError("negative tile index")
    digits = str(n)
    digits = "0" * (-len(digits) % 3) + digits
    groups = [digits[i:i + 3] for i in range(0, len(digits), 3)]
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def _suffix(width: int) -> str:
    if not 1 <= width <= WIDTH:
        raise ValueError("bad tile width")
    return "" if width == WIDTH else f".p/{width}"


def tile_path(level: int, index: int, width: int) -> str:
    if not 0 <= level <= 63:
        raise ValueError("bad tile level")
    return f"tile/{level}/{encode_index(index)}{_suffix(width)}"


def bundle_path(index: int, width: int) -> str:
    return f"tile/entries/{encode_index(index)}{_suffix(width)}"


def parse_path(path: str):
    m = PATH_RE.fullmatch(path)
    if not m:
        return None
    kind, raw, partial = m.groups()
    index = int(raw.replace("x", "").replace("/", ""))
    if encode_index(index) != raw:
        return None
    if partial and int(partial) >= WIDTH:
        return None
    if kind != "entries" and int(kind) > 63:
        return None
    return kind, index, int(partial) if partial else WIDTH


def tile_root(hashes: list[bytes]) -> bytes:
    while len(hashes) > 1:
        hashes = [merkle.node_hash(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


def split_hashes(data: bytes) -> list[bytes]:
    if len(data) % HASH:
        raise ValueError("tile length is not a multiple of 32")
    return [data[i:i + HASH] for i in range(0, len(data), HASH)]


def encode_bundle(entries: list[bytes]) -> bytes:
    out = bytearray()
    for e in entries:
        if not 0 < len(e) <= MAX_ENTRY:
            raise ValueError("entry size out of range")
        out += len(e).to_bytes(2, "big") + e
    return bytes(out)


def decode_bundle(data: bytes, count: int) -> tuple[list[bytes], int]:
    entries, pos = [], 0
    while len(entries) < count:
        if pos + 2 > len(data):
            raise ValueError("truncated entry bundle")
        n = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        if n == 0 or pos + n > len(data):
            raise ValueError("truncated entry bundle")
        entries.append(data[pos:pos + n])
        pos += n
    return entries, pos


def _width(count: int, index: int) -> int:
    width = min(WIDTH, count - index * WIDTH)
    if index < 0 or width <= 0:
        raise ValueError("tile is beyond the tree size")
    return width


class TileReader:
    def __init__(self, fetch, size: int):
        self.fetch = fetch
        self.size = size
        self.cache = {}

    def tile(self, level: int, index: int) -> bytes:
        key = (level, index)
        if key not in self.cache:
            width = _width(self.size >> (HEIGHT * level), index)
            try:
                data = self.fetch(tile_path(level, index, width))
            except NotFound:
                if width == WIDTH:
                    raise
                data = self.fetch(tile_path(level, index, WIDTH))
                if len(data) != WIDTH * HASH:
                    raise ValueError(f"tile {level}/{index} has the wrong size") from None
                data = data[:width * HASH]
            if len(data) != width * HASH:
                raise ValueError(f"tile {level}/{index} has the wrong size")
            self.cache[key] = data
        return self.cache[key]

    def node(self, height: int, index: int) -> bytes:
        level, sub = divmod(height, HEIGHT)
        tile, offset = divmod(index << sub, WIDTH)
        data = self.tile(level, tile)
        end = offset + (1 << sub)
        if end * HASH > len(data):
            raise ValueError("node is beyond the tree size")
        return tile_root(split_hashes(data[offset * HASH:end * HASH]))

    def entries(self, index: int) -> list[bytes]:
        width = _width(self.size, index)
        try:
            data = self.fetch(bundle_path(index, width))
        except NotFound:
            if width == WIDTH:
                raise
            return decode_bundle(self.fetch(bundle_path(index, WIDTH)), width)[0]
        entries, used = decode_bundle(data, width)
        if used != len(data):
            raise ValueError("entry bundle has trailing data")
        return entries


class TileWriter:
    def __init__(self):
        self.size = 0
        self.edges: list[list[bytes]] = []
        self.bundle: list[bytes] = []

    def copy(self) -> "TileWriter":
        w = TileWriter()
        w.size, w.edges, w.bundle = self.size, [list(e) for e in self.edges], list(self.bundle)
        return w

    @classmethod
    def load(cls, fetch, size: int) -> "TileWriter":
        w = cls()
        w.size = size
        level = 0
        while size >> (HEIGHT * level):
            count = size >> (HEIGHT * level)
            width = count % WIDTH
            edge = []
            if width:
                edge = split_hashes(fetch(tile_path(level, count // WIDTH, width)))
                if len(edge) != width:
                    raise ValueError("partial tile has the wrong size")
            w.edges.append(edge)
            level += 1
        if size % WIDTH:
            data = fetch(bundle_path(size // WIDTH, size % WIDTH))
            w.bundle, used = decode_bundle(data, size % WIDTH)
            if used != len(data):
                raise ValueError("entry bundle has trailing data")
        return w

    def _push(self, h: bytes, out: dict, touched: set) -> None:
        level = 0
        while True:
            if len(self.edges) == level:
                self.edges.append([])
            edge = self.edges[level]
            edge.append(h)
            touched.add(level)
            if len(edge) < WIDTH:
                return
            count = self.size >> (HEIGHT * level)
            out[tile_path(level, count // WIDTH - 1, WIDTH)] = b"".join(edge)
            self.edges[level] = []
            h = tile_root(edge)
            level += 1

    def extend(self, entries: list[bytes]) -> dict[str, bytes]:
        out, touched = {}, set()
        for e in entries:
            if not 0 < len(e) <= MAX_ENTRY:
                raise ValueError("entry size out of range")
            self.bundle.append(e)
            if len(self.bundle) == WIDTH:
                out[bundle_path(self.size // WIDTH, WIDTH)] = encode_bundle(self.bundle)
                self.bundle = []
            self.size += 1
            self._push(merkle.leaf_hash(e), out, touched)
        if entries and self.bundle:
            out[bundle_path(self.size // WIDTH, len(self.bundle))] = encode_bundle(self.bundle)
        for level in sorted(touched):
            edge = self.edges[level]
            if edge:
                count = self.size >> (HEIGHT * level)
                out[tile_path(level, count // WIDTH, len(edge))] = b"".join(edge)
        return out

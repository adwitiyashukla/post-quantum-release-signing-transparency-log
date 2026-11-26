import hashlib

EMPTY = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def subtree(node, start: int, end: int) -> bytes:
    size = end - start
    if size & (size - 1) == 0:
        height = size.bit_length() - 1
        if start % size:
            raise ValueError("unaligned subtree")
        return node(height, start >> height)
    k = split(size)
    return node_hash(subtree(node, start, start + k), subtree(node, start + k, end))


def root(node, size: int) -> bytes:
    if size < 0:
        raise ValueError("negative tree size")
    return EMPTY if size == 0 else subtree(node, 0, size)


def inclusion_proof(node, index: int, size: int) -> list[bytes]:
    if not 0 <= index < size:
        raise ValueError("index out of range")
    proof = []
    start, end = 0, size
    while end - start > 1:
        k = split(end - start)
        if index < start + k:
            proof.append(subtree(node, start + k, end))
            end = start + k
        else:
            proof.append(subtree(node, start, start + k))
            start += k
    proof.reverse()
    return proof


def consistency_proof(node, old: int, new: int) -> list[bytes]:
    if not 0 <= old <= new:
        raise ValueError("sizes out of order")
    if old == 0 or old == new:
        return []
    proof = []
    start, end, m, complete = 0, new, old, True
    while m != end - start:
        k = split(end - start)
        if m <= k:
            proof.append(subtree(node, start + k, end))
            end = start + k
        else:
            proof.append(subtree(node, start, start + k))
            start += k
            m -= k
            complete = False
    if not complete:
        proof.append(subtree(node, start, end))
    proof.reverse()
    return proof


def _hashes(*hashes: bytes) -> bool:
    return all(isinstance(h, bytes) and len(h) == 32 for h in hashes)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root_hash: bytes) -> bool:
    if not 0 <= index < size or not _hashes(leaf, root_hash, *proof):
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root_hash


def verify_consistency(old: int, new: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    if not 0 <= old <= new or not _hashes(old_root, new_root, *proof):
        return False
    if old == 0:
        return not proof and old_root == EMPTY and (new > 0 or new_root == EMPTY)
    if old == new:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if old & (old - 1) == 0:
        path.insert(0, old_root)
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


class Frontier:
    def __init__(self, size: int = 0, hashes: list[bytes] | None = None):
        hashes = list(hashes or [])
        if len(hashes) != bin(size).count("1"):
            raise ValueError("frontier does not match size")
        self.size = size
        self.hashes = hashes

    @classmethod
    def from_tree(cls, node, size: int) -> "Frontier":
        hashes, start = [], 0
        for height in range(size.bit_length() - 1, -1, -1):
            if size >> height & 1:
                hashes.append(node(height, start >> height))
                start += 1 << height
        return cls(size, hashes)

    def copy(self) -> "Frontier":
        return Frontier(self.size, self.hashes)

    def append(self, leaf: bytes) -> None:
        h, n = leaf, self.size
        while n & 1:
            h = node_hash(self.hashes.pop(), h)
            n >>= 1
        self.hashes.append(h)
        self.size += 1

    def root(self) -> bytes:
        if not self.hashes:
            return EMPTY
        r = self.hashes[-1]
        for h in reversed(self.hashes[:-1]):
            r = node_hash(h, r)
        return r


class MemoryTree:
    def __init__(self, leaves: list[bytes] | None = None):
        self.levels: list[list[bytes]] = [[]]
        for leaf in leaves or []:
            self.append(leaf)

    @property
    def size(self) -> int:
        return len(self.levels[0])

    def append(self, leaf: bytes) -> None:
        self.levels[0].append(leaf)
        level = 0
        while len(self.levels[level]) % 2 == 0:
            pair = self.levels[level][-2:]
            if len(self.levels) == level + 1:
                self.levels.append([])
            self.levels[level + 1].append(node_hash(pair[0], pair[1]))
            level += 1

    def node(self, height: int, index: int) -> bytes:
        return self.levels[height][index]

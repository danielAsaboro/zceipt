"""Orchard primitives used by payment disclosures, from the Zcash protocol specification.

Sinsemilla (5.4.1.9, 5.4.8.4), NoteCommit and MerkleCRH (5.4.8.4, 5.4.1.3), value commitments
(5.4.8.3), DiversifyHash (5.4.1.6), PRF^expand / ToScalar / ToBase (5.4.2, 4.2.3), KDF (5.4.5.6),
the note-plaintext derivations of 4.7.3 including the NU6.3 rcm for lead byte 0x03, and
SpendAuthSig^Orchard = RedPallas (5.4.7, 5.4.7.1).
"""

import hashlib

from . import pallas as pl
from .pallas import P, R

K = 10
C = 253
L_ORCHARD_BASE = 255
MERKLE_DEPTH = 32
UNCOMMITTED = 2


def blake2b(person: bytes, data: bytes, n: int) -> bytes:
    assert len(person) == 16
    return hashlib.blake2b(data, digest_size=n, person=person).digest()


def i2lebsp(n_bits: int, x: int):
    assert 0 <= x < (1 << n_bits)
    return [(x >> i) & 1 for i in range(n_bits)]


def bytes_to_bits(b: bytes):
    return [(byte >> i) & 1 for byte in b for i in range(8)]


# ---- Sinsemilla ----

def sinsemilla_s(j: int):
    return pl.group_hash(b"z.cash:SinsemillaS", j.to_bytes(4, "little"))


def sinsemilla_q(domain: bytes):
    return pl.group_hash(b"z.cash:SinsemillaQ", domain)


def incomplete_add(a, b):
    if a == "bot" or b == "bot" or a is None or b is None or a[0] == b[0]:
        return "bot"
    return pl.add(a, b)


def sinsemilla_hash_to_point(domain: bytes, bits):
    if len(bits) > K * C:
        raise ValueError("message too long")
    n = -(-len(bits) // K)
    padded = bits + [0] * (n * K - len(bits))
    acc = sinsemilla_q(domain)
    for i in range(n):
        m = sum(padded[i * K + j] << j for j in range(K))
        acc = incomplete_add(incomplete_add(acc, sinsemilla_s(m)), acc)
    return acc


def sinsemilla_hash(domain: bytes, bits):
    pt = sinsemilla_hash_to_point(domain, bits)
    return "bot" if pt == "bot" else pl.extract_p(pt)


def sinsemilla_commit(r: int, domain: bytes, bits):
    m = sinsemilla_hash_to_point(domain + b"-M", bits)
    if m == "bot":
        return "bot"
    return pl.add(m, pl.mul(r, pl.group_hash(domain + b"-r", b"")))


def note_commit(rcm: int, g_d_repr: bytes, pk_d_repr: bytes, v: int, rho: int, psi: int):
    bits = (bytes_to_bits(g_d_repr) + bytes_to_bits(pk_d_repr) + i2lebsp(64, v)
            + i2lebsp(L_ORCHARD_BASE, rho) + i2lebsp(L_ORCHARD_BASE, psi))
    return sinsemilla_commit(rcm, b"z.cash:Orchard-NoteCommit", bits)


# ---- Merkle tree ----

def merkle_crh(layer: int, left: int, right: int, depth: int = MERKLE_DEPTH) -> int:
    bits = i2lebsp(10, depth - 1 - layer) + i2lebsp(L_ORCHARD_BASE, left) + i2lebsp(L_ORCHARD_BASE, right)
    h = sinsemilla_hash(b"z.cash:Orchard-MerkleCRH", bits)
    return 0 if h == "bot" else h


_EMPTY = None


def empty_roots():
    """empty_roots()[h] is the root of an empty subtree of height h (h = 0 is a leaf)."""
    global _EMPTY
    if _EMPTY is None:
        e = [UNCOMMITTED]
        for h in range(MERKLE_DEPTH):
            e.append(merkle_crh(MERKLE_DEPTH - 1 - h, e[h], e[h]))
        _EMPTY = e
    return _EMPTY


def root_from_path(leaf: int, position: int, path):
    """The root reached from leaf at position along path (path[h] is the sibling at height h).

    The tree depth is len(path); MerkleCRH's layer input is depth - 1 - h at height h.
    """
    depth = len(path)
    node = leaf
    for h in range(depth):
        layer = depth - 1 - h
        if (position >> h) & 1:
            node = merkle_crh(layer, path[h], node, depth)
        else:
            node = merkle_crh(layer, node, path[h], depth)
    return node


def single_leaf_root(cmx: int) -> int:
    """The root of a tree holding only cmx, at position 0."""
    return root_from_path(cmx, 0, empty_roots()[:MERKLE_DEPTH])


# ---- Generators and commitments ----

def value_commit(rcv: int, v: int):
    """ValueCommit^Orchard_rcv(v) for a signed v (taken mod r_P)."""
    V = pl.group_hash(b"z.cash:Orchard-cv", b"v")
    Rb = pl.group_hash(b"z.cash:Orchard-cv", b"r")
    return pl.add(pl.mul(v % R, V), pl.mul(rcv, Rb))


def spend_auth_base():
    return pl.group_hash(b"z.cash:Orchard", b"G")


def diversify_hash(d: bytes):
    pt = pl.group_hash(b"z.cash:Orchard-gd", d)
    return pl.group_hash(b"z.cash:Orchard-gd", b"") if pt is None else pt


# ---- PRFs and derivations ----

def prf_expand(sk: bytes, t: bytes) -> bytes:
    return blake2b(b"Zcash_ExpandSeed", sk + t, 64)


def to_scalar(x: bytes) -> int:
    return int.from_bytes(x, "little") % R


def to_base(x: bytes) -> int:
    return int.from_bytes(x, "little") % P


def kdf_orchard(shared_secret, ephemeral_key: bytes) -> bytes:
    return blake2b(b"Zcash_OrchardKDF", pl.repr_p(shared_secret) + ephemeral_key, 32)


def derive_esk(rseed: bytes, rho: bytes) -> int:
    return to_scalar(prf_expand(rseed, bytes([4]) + rho))


def derive_psi(rseed: bytes, rho: bytes) -> int:
    return to_base(prf_expand(rseed, bytes([9]) + rho))


def derive_rcm(lead_byte: int, rseed: bytes, g_d_repr: bytes, pk_d_repr: bytes, v: int, rho: bytes, psi: int) -> int:
    """Derive_rcm^Orchard (4.7.3): lead byte 0x02 as at NU5, 0x03 per NU6.3 (ZIP 2005)."""
    if lead_byte == 0x02:
        return to_scalar(prf_expand(rseed, bytes([5]) + rho))
    if lead_byte == 0x03:
        t = bytes([0x0B]) + g_d_repr + pk_d_repr + v.to_bytes(8, "little") + rho + psi.to_bytes(32, "little")
        return to_scalar(prf_expand(rseed, t))
    raise ValueError("unsupported note plaintext lead byte")


# ---- RedPallas (SpendAuthSig^Orchard) ----

def redpallas_verify(vk_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    """RedDSA.Validate over Pallas with BLAKE2b-512("Zcash_RedPallasH"), cofactor 1."""
    if len(sig) != 64:
        return False
    r_bytes, s_bytes = sig[:32], sig[32:]
    r_pt = pl.abst_p(r_bytes)
    vk = pl.abst_p(vk_bytes)
    if r_pt == "bot" or vk == "bot":
        return False
    if pl.repr_p(r_pt) != r_bytes or pl.repr_p(vk) != vk_bytes:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= R:
        return False
    c = int.from_bytes(blake2b(b"Zcash_RedPallasH", r_bytes + vk_bytes + msg, 64), "little") % R
    check = pl.add(pl.add(pl.neg(pl.mul(s, spend_auth_base())), r_pt), pl.mul(c, vk))
    return check is None

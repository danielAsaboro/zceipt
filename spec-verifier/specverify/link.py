"""Same-payer proofs (zip311k1, crates/receipts-core/src/link.rs), checked from the description:
several receipts were signed with one spend authorizing key.

  link  := "ZRCK" | 1 | coinType:u32le | msgLen:u16le | msg | nReceipts:u8 | digest[32]*
           | nLinks:u16le | (R[32] | s[32])*
  c     := BLAKE2b-512("ZIP311Linked" || coinType, link without the s values || every rk) mod r
  check := [s_i]G == R_i + [c](rk_i - rk_0),  G = GroupHash("z.cash:Orchard", "G")
"""
import hashlib

from . import pallas as pl
from .receipt import DecodeError, b64decode

PREFIX = "zip311k1"


def decode(text: str):
    s = text.strip()
    if not s.startswith(PREFIX):
        raise DecodeError("not a zip311k1 same-payer proof")
    b = b64decode(s[len(PREFIX):])
    p = 0

    def take(n):
        nonlocal p
        if p + n > len(b):
            raise DecodeError("truncated")
        out = b[p:p + n]
        p += n
        return out

    if take(4) != b"ZRCK" or take(1)[0] != 1:
        raise DecodeError("bad magic or version")
    coin = int.from_bytes(take(4), "little")
    msg = take(int.from_bytes(take(2), "little"))
    nr = take(1)[0]
    if nr == 0 or nr > 64:
        raise DecodeError("bad receipt count")
    digests = [take(32) for _ in range(nr)]
    head_len = p + 2
    nl = int.from_bytes(take(2), "little")
    links = [(take(32), take(32)) for _ in range(nl)]
    if p != len(b):
        raise DecodeError("trailing bytes")
    if any(int.from_bytes(s, "little") >= pl.R for _, s in links):
        raise DecodeError("non-canonical scalar")
    return {"coin": coin, "msg": msg, "digests": digests, "links": links, "head": b[:head_len]}


def _digest(r):
    person = b"ZIP311Signed" + r.coin_type.to_bytes(4, "little")
    return hashlib.blake2b(r.unsigned_bytes, digest_size=32, person=person).digest()


def verify(proof, receipts) -> int:
    """Raises ValueError unless `proof` links `receipts` (in order). Returns the spends linked."""
    if len(receipts) != len(proof["digests"]) or any(r.coin_type != proof["coin"] for r in receipts):
        raise ValueError("the proof names other receipts")
    if any(_digest(r) != d for r, d in zip(receipts, proof["digests"])):
        raise ValueError("the proof names other receipts")
    rks = [s.rk for r in receipts for s in r.spends]
    if len(proof["links"]) + 1 != len(rks):
        raise ValueError("wrong number of links")
    h = hashlib.blake2b(digest_size=64, person=b"ZIP311Linked" + proof["coin"].to_bytes(4, "little"))
    h.update(proof["head"])
    for big_r, _ in proof["links"]:
        h.update(big_r)
    for rk in rks:
        h.update(rk)
    c = int.from_bytes(h.digest(), "little") % pl.R
    g = pl.group_hash(b"z.cash:Orchard", b"G")
    rk0 = pl.decode_point(rks[0])
    for (big_r, s), rk in zip(proof["links"], rks[1:]):
        lhs = pl.mul(int.from_bytes(s, "little"), g)
        rhs = pl.add(pl.decode_point(big_r), pl.mul(c, pl.add(pl.decode_point(rk), pl.neg(rk0))))
        if lhs != rhs:
            raise ValueError("the same-payer proof doesn't hold")
    return len(rks)

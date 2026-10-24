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


def verify_policy(text: str, receipt):
    """A policy proof (zip311p1, crates/receipts-core/src/policy.rs): every spend's rk is
    C_0 + [alpha]G with alpha known to the prover, C_0 the published t-of-n key. Returns (t, n)."""
    s = text.strip()
    if not s.startswith("zip311p1"):
        raise DecodeError("not a zip311p1 policy proof")
    b = b64decode(s[8:])
    p = 0

    def take(n):
        nonlocal p
        if p + n > len(b):
            raise DecodeError("truncated")
        out = b[p:p + n]
        p += n
        return out

    if take(4) != b"ZRCP" or take(1)[0] != 1:
        raise DecodeError("bad magic or version")
    coin = int.from_bytes(take(4), "little")
    take(int.from_bytes(take(2), "little"))
    digest = take(32)
    holders = int.from_bytes(take(2), "little")
    t = take(1)[0]
    commitment = [take(32) for _ in range(t)]
    ns = take(1)[0]
    head = b[:p]
    links = [(take(32), take(32)) for _ in range(ns)]
    if p != len(b) or t == 0 or holders < t or ns == 0:
        raise DecodeError("malformed policy proof")
    if receipt.coin_type != coin or _digest(receipt) != digest or ns != len(receipt.spends):
        raise ValueError("the proof is for another receipt")
    rks = [sp.rk for sp in receipt.spends]
    h = hashlib.blake2b(digest_size=64, person=b"ZIP311Policy" + coin.to_bytes(4, "little"))
    h.update(head)
    for big_r, _ in links:
        h.update(big_r)
    for rk in rks:
        h.update(rk)
    c = int.from_bytes(h.digest(), "little") % pl.R
    g = pl.group_hash(b"z.cash:Orchard", b"G")
    ak = pl.decode_point(commitment[0])
    for (big_r, sc), rk in zip(links, rks):
        if int.from_bytes(sc, "little") >= pl.R:
            raise ValueError("non-canonical scalar")
        if pl.mul(int.from_bytes(sc, "little"), g) != pl.add(pl.decode_point(big_r), pl.mul(c, pl.add(pl.decode_point(rk), pl.neg(ak)))):
            raise ValueError("the policy proof doesn't hold")
    return t, holders


def verify_keyset(text: str, receipt) -> int:
    """A key-set proof (zip311m1, crates/receipts-core/src/keyset.rs): for every spend, a
    one-of-many Schnorr proof that rk - K_j = [alpha]G for one published key K_j. Returns the
    number of keys."""
    s = text.strip()
    if not s.startswith("zip311m1"):
        raise DecodeError("not a zip311m1 key-set proof")
    b = b64decode(s[8:])
    p = 0

    def take(n):
        nonlocal p
        if p + n > len(b):
            raise DecodeError("truncated")
        out = b[p:p + n]
        p += n
        return out

    if take(4) != b"ZRCM" or take(1)[0] != 1:
        raise DecodeError("bad magic or version")
    coin = int.from_bytes(take(4), "little")
    take(int.from_bytes(take(2), "little"))
    digest = take(32)
    n = int.from_bytes(take(2), "little")
    keys = [take(32) for _ in range(n)]
    ns = take(1)[0]
    head = b[:p]
    spends = [[(take(32), take(32)) for _ in range(n)] for _ in range(ns)]
    if p != len(b) or n == 0 or ns == 0:
        raise DecodeError("malformed key-set proof")
    if receipt.coin_type != coin or _digest(receipt) != digest or ns != len(receipt.spends):
        raise ValueError("the proof is for another receipt")
    g = pl.group_hash(b"z.cash:Orchard", b"G")
    ks = [pl.decode_point(k) for k in keys]
    h = hashlib.blake2b(digest_size=64, person=b"ZIP311KeySet" + coin.to_bytes(4, "little"))
    h.update(head)
    sums = []
    for sp, pairs in zip(receipt.spends, spends):
        rk = pl.decode_point(sp.rk)
        h.update(sp.rk)
        total = 0
        for (c, z), k in zip(pairs, ks):
            c, z = int.from_bytes(c, "little"), int.from_bytes(z, "little")
            if c >= pl.R or z >= pl.R:
                raise ValueError("non-canonical scalar")
            r = pl.add(pl.mul(z, g), pl.neg(pl.mul(c, pl.add(rk, pl.neg(k)))))
            h.update(pl.repr_p(r))
            total = (total + c) % pl.R
        sums.append(total)
    c = int.from_bytes(h.digest(), "little") % pl.R
    if any(t != c for t in sums):
        raise ValueError("the key-set proof doesn't hold")
    return n


def verify_designated(text: str, verifier_key: bytes = None):
    """A receipt for one verifier (zip311d1, crates/receipts-core/src/designated.rs): per spend, a
    one-of-two Schnorr proof that the prover knows rk's or V's discrete log, in place of the
    signature. Returns (receipt, V); verify the receipt's proofs against the chain as usual. If
    `verifier_key` is given, V must be it (a receipt for another key proves nothing to you)."""
    from . import receipt as rc
    s = text.strip()
    if not s.startswith("zip311d1"):
        raise DecodeError("not a zip311d1 receipt")
    b = b64decode(s[8:])
    if len(b) < 38 or b[:4] != b"ZRCD" or b[4] != 1:
        raise DecodeError("bad magic or version")
    v, n = b[5:37], b[37]
    proofs = [[b[38 + i * 128 + j * 32: 38 + i * 128 + j * 32 + 32] for j in range(4)] for i in range(n)]
    r = rc.decode(b[38 + n * 128:])
    if len(r.spends) != n or n == 0 or any(sig != bytes(64) for sig in r.sigs):
        raise DecodeError("malformed designated receipt")
    if verifier_key is not None and v != verifier_key:
        raise ValueError("made for another verifier's key: it proves nothing to you")
    g = pl.group_hash(b"z.cash:Orchard", b"G")
    vp = pl.decode_point(v)
    digest = _digest(r)
    for sp, (c1, s1, c2, s2) in zip(r.spends, proofs):
        c1, s1, c2, s2 = (int.from_bytes(x, "little") for x in (c1, s1, c2, s2))
        if max(c1, s1, c2, s2) >= pl.R:
            raise ValueError("non-canonical scalar")
        rk = pl.decode_point(sp.rk)
        r1 = pl.add(pl.mul(s1, g), pl.neg(pl.mul(c1, rk)))
        r2 = pl.add(pl.mul(s2, g), pl.neg(pl.mul(c2, vp)))
        h = hashlib.blake2b(digest_size=64, person=b"ZIP311Desig\0" + r.coin_type.to_bytes(4, "little"))
        h.update(digest + v + sp.rk + pl.repr_p(r1) + pl.repr_p(r2))
        if (c1 + c2) % pl.R != int.from_bytes(h.digest(), "little") % pl.R:
            raise ValueError("the one-verifier proof doesn't hold")
    return r, v


def verify_delegated(text: str):
    """A delegated receipt (zip311a1, crates/receipts-core/src/delegated.rs): the certificate's
    SpendAuthSig under rk_c, a Schnorr link from every spend's rk to rk_c, and the session key's
    Schnorr signature. Returns (receipt, policy); check the policy against the verified receipt."""
    from . import receipt as rc
    from . import orchard as o
    s = text.strip()
    if not s.startswith("zip311a1"):
        raise DecodeError("not a zip311a1 receipt")
    b = b64decode(s[8:])
    if len(b) < 7 or b[:4] != b"ZRCA" or b[4] != 1:
        raise DecodeError("bad magic or version")
    n = int.from_bytes(b[5:7], "little")
    cert = b[7:7 + n]
    if len(cert) != n or cert[:4] != b"ZRCG" or cert[4] != 1:
        raise DecodeError("bad certificate")
    coin = int.from_bytes(cert[5:9], "little")
    session, max_zats, until = cert[9:41], int.from_bytes(cert[41:49], "little"), int.from_bytes(cert[49:53], "little")
    npay = cert[53]
    payees = [cert[54 + i * 43: 97 + i * 43] for i in range(npay)]
    q = 54 + npay * 43
    rk_c, sig_c = cert[q:q + 32], cert[q + 32:q + 96]
    if q + 96 != len(cert):
        raise DecodeError("bad certificate length")
    p = 7 + n
    nl = b[p]
    links = [(b[p + 1 + i * 64: p + 33 + i * 64], b[p + 33 + i * 64: p + 65 + i * 64]) for i in range(nl)]
    p += 1 + nl * 64
    session_sig = b[p:p + 64]
    r = rc.decode(b[p + 64:])
    if len(r.spends) != nl or nl == 0 or any(sig != bytes(64) for sig in r.sigs) or r.coin_type != coin:
        raise DecodeError("malformed delegated receipt")
    cdig = hashlib.blake2b(cert[:q + 32], digest_size=32, person=b"ZIP311Deleg\0" + coin.to_bytes(4, "little")).digest()
    if not o.redpallas_verify(rk_c, cdig, sig_c):
        raise ValueError("the certificate isn't signed by its spend key")
    g = pl.group_hash(b"z.cash:Orchard", b"G")
    digest = _digest(r)
    h = hashlib.blake2b(digest_size=64, person=b"ZIP311DLink\0" + coin.to_bytes(4, "little"))
    h.update(digest + rk_c)
    for sp in r.spends:
        h.update(sp.rk)
    for big_r, _ in links:
        h.update(big_r)
    c = int.from_bytes(h.digest(), "little") % pl.R
    rkc = pl.decode_point(rk_c)
    for sp, (big_r, z) in zip(r.spends, links):
        z = int.from_bytes(z, "little")
        if z >= pl.R or pl.mul(z, g) != pl.add(pl.decode_point(big_r), pl.mul(c, pl.add(pl.decode_point(sp.rk), pl.neg(rkc)))):
            raise ValueError("a spend isn't under the certificate's key")
    sr, sz = session_sig[:32], int.from_bytes(session_sig[32:], "little")
    h = hashlib.blake2b(digest_size=64, person=b"ZIP311DSess\0" + coin.to_bytes(4, "little"))
    h.update(digest + cert)
    for big_r, z in links:
        h.update(big_r + z)
    h.update(session + sr)
    e = int.from_bytes(h.digest(), "little") % pl.R
    if sz >= pl.R or pl.mul(sz, g) != pl.add(pl.decode_point(sr), pl.mul(e, pl.decode_point(session))):
        raise ValueError("the session key didn't sign this receipt")
    return r, {"max_zatoshis": max_zats, "until_height": until, "payees": payees}

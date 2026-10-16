"""Receipt encodings, written from docs/SPEC.md (Encoding, Cross-pool receipts, Batches,
Sign in with Zcash), not from the Rust code.

Canonical decoding: the version is determined by the contents (4 iff some spend carries a source
proof or 5 iff some output is opened without its memo, else 3 iff the outputs are in another pool than the spends, else 2 iff some spend carries an
address proof, else 1), address flags are exactly 0 or 1 (v2/v3) and spend flags 0..3 (v4), a
revealed source value is at least 1, nothing may follow the signatures. Any other byte string is
rejected.
"""

import base64
from dataclasses import dataclass, field
from typing import List, Optional

MAX_PROOF_LEN = 1 << 16
POOLS = {0: "orchard", 1: "ironwood"}


class DecodeError(ValueError):
    pass


@dataclass
class AddressProof:
    address: bytes  # 43-byte raw Orchard address: d (11) || pk_d (32)
    rho: bytes
    rseed: bytes
    nf: bytes
    cv_net: bytes
    cmx: bytes
    proof: bytes


@dataclass
class SourceProof:
    txid: bytes
    index: int
    value: Optional[int]  # None: hidden
    cmx: Optional[bytes]  # hidden value: the proof's output commitment
    out_address: Optional[bytes]  # revealed value: the proof's opened zero-value output
    out_rseed: Optional[bytes]
    proof: bytes


@dataclass
class Spend:
    index: int
    cv_net: bytes
    rk: bytes
    cmx: bytes
    proof: bytes
    address: Optional[AddressProof] = None
    source: Optional[SourceProof] = None


@dataclass
class Output:
    index: int
    ock: bytes


@dataclass
class OpenedOutput:
    """An output disclosed without its memo: recipient, value and the commitment opening (psi, rcm)."""
    index: int
    address: bytes
    value: int
    psi: bytes
    rcm: bytes


@dataclass
class Receipt:
    version: int
    coin_type: int
    pool: str
    output_pool: Optional[str]
    txid: bytes
    msg: bytes
    outputs: List[Output]
    spends: List[Spend]
    sigs: List[bytes] = field(default_factory=list)
    unsigned_bytes: bytes = b""
    opened: List[OpenedOutput] = field(default_factory=list)


class _R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise DecodeError("truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def int(self, n):
        return int.from_bytes(self.take(n), "little")


def _proof(r):
    n = r.int(4)
    if n > MAX_PROOF_LEN:
        raise DecodeError("proof too large")
    return r.take(n)


def decode(b: bytes) -> Receipt:
    r = _R(b)
    if r.take(4) != b"ZRCT":
        raise DecodeError("bad magic")
    version = r.take(1)[0]
    if version not in (1, 2, 3, 4, 5):
        raise DecodeError(f"unsupported version {version}")
    coin_type = r.int(4)
    pb = r.take(1)[0]
    if pb not in POOLS:
        raise DecodeError("unknown pool")
    output_pool = None
    if version == 3:
        ob = r.take(1)[0]
        if ob not in POOLS:
            raise DecodeError("unknown output pool")
        if ob == pb:
            raise DecodeError("version 3 needs two different pools")
        output_pool = POOLS[ob]
    elif version in (4, 5):
        ob = r.take(1)[0]
        if ob not in POOLS:
            raise DecodeError("unknown output pool")
        output_pool = POOLS[ob] if ob != pb else None
    txid = r.take(32)
    msg = r.take(r.int(2))
    outputs = [Output(r.int(4), r.take(32)) for _ in range(r.take(1)[0])]
    opened = []
    if version == 5:
        opened = [OpenedOutput(r.int(4), r.take(43), r.int(8), r.take(32), r.take(32)) for _ in range(r.take(1)[0])]
    spends = []
    for _ in range(r.take(1)[0]):
        s = Spend(r.int(4), r.take(32), r.take(32), r.take(32), _proof(r))
        if version in (2, 3):
            flag = r.take(1)[0]
            if flag > 1:
                raise DecodeError("non-canonical address flag")
            if flag:
                s.address = AddressProof(r.take(43), r.take(32), r.take(32), r.take(32), r.take(32), r.take(32), _proof(r))
        elif version in (4, 5):
            flag = r.take(1)[0]
            if flag > 3:
                raise DecodeError("non-canonical spend flags")
            if flag & 1:
                s.address = AddressProof(r.take(43), r.take(32), r.take(32), r.take(32), r.take(32), r.take(32), _proof(r))
            if flag & 2:
                stxid, sindex, vflag = r.take(32), r.int(4), r.take(1)[0]
                if vflag == 0:
                    s.source = SourceProof(stxid, sindex, None, r.take(32), None, None, b"")
                elif vflag == 1:
                    value = r.int(8)
                    if value == 0:
                        raise DecodeError("non-canonical: a revealed source value of zero")
                    s.source = SourceProof(stxid, sindex, value, None, r.take(43), r.take(32), b"")
                else:
                    raise DecodeError("non-canonical source value flag")
                s.source.proof = _proof(r)
        spends.append(s)
    unsigned = b[: r.i]
    if version == 2 and not any(s.address for s in spends):
        raise DecodeError("non-canonical: version 2 without an address proof")
    if version == 4 and not any(s.source for s in spends):
        raise DecodeError("non-canonical: version 4 without a source proof")
    if version == 5 and not opened:
        raise DecodeError("non-canonical: version 5 without an opened output")
    sigs = [r.take(64) for _ in spends]
    if r.i != len(b):
        raise DecodeError("trailing bytes")
    return Receipt(version, coin_type, POOLS[pb], output_pool, txid, msg, outputs, spends, sigs, unsigned, opened)


def from_text(s: str) -> Receipt:
    s = s.strip()
    if not s.startswith("zrcpt1"):
        raise DecodeError("not a zrcpt1 receipt")
    return decode(b64decode(s[len("zrcpt1"):]))


def b64decode(body: str) -> bytes:
    """Unpadded base64url, strictly: no padding, no other alphabet, no non-zero trailing bits."""
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if any(c not in alphabet for c in body) or len(body) % 4 == 1:
        raise DecodeError("invalid base64url")
    out = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if base64.urlsafe_b64encode(out).decode().rstrip("=") != body:
        raise DecodeError("non-canonical base64url")
    return out


def decode_batch(b: bytes):
    r = _R(b)
    if r.take(4) != b"ZRCB":
        raise DecodeError("bad batch magic")
    if r.take(1)[0] != 1:
        raise DecodeError("unsupported batch version")
    n = r.int(2)
    if n == 0 or n > 256:
        raise DecodeError("bad batch size")
    out = [decode(r.take(r.int(4))) for _ in range(n)]
    if r.i != len(b):
        raise DecodeError("trailing bytes")
    return out


@dataclass
class SignIn:
    coin_type: int
    domain: str
    nonce: str
    issued_at: int
    rk: bytes
    address: AddressProof
    sig: bytes
    signed_message: bytes


def decode_sign_in(text: str) -> SignIn:
    s = text.strip()
    if not s.startswith("zsig1"):
        raise DecodeError("not a zsig1 sign-in")
    r = _R(b64decode(s[5:]))
    if r.take(4) != b"ZSIG" or r.take(1)[0] != 1:
        raise DecodeError("bad sign-in magic or version")
    coin_type = r.int(4)
    try:
        domain = r.take(r.int(2)).decode()
        nonce = r.take(r.int(2)).decode()
    except UnicodeDecodeError:
        raise DecodeError("domain or nonce is not UTF-8")
    issued_at = r.int(8)
    rk = r.take(32)
    a = AddressProof(r.take(43), r.take(32), r.take(32), r.take(32), r.take(32), r.take(32), _proof(r))
    sig = r.take(64)
    if r.i != len(r.b):
        raise DecodeError("trailing bytes")
    m = b"Receipts sign-in v1"
    for part in (domain.encode(), nonce.encode()):
        m += len(part).to_bytes(4, "little") + part
    m += issued_at.to_bytes(8, "little") + rk + a.address + a.rho + a.rseed + a.nf + a.cv_net + a.cmx + a.proof
    return SignIn(coin_type, domain, nonce, issued_at, rk, a, sig, m)

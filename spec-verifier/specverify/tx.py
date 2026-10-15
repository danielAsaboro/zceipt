"""Version 5 and 6 transaction parsing and transaction identifiers.

Encoding: protocol 7.1 (v5) and ZIP 229 (v6, adds the Ironwood component). Identifiers: ZIP 244,
with the ZIP 229 changes for v6 (Ironwood digest; anchors move to the authorizing data).
"""

import hashlib


def _h(person: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise ValueError("transaction is truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def compact(self):
        n = self.take(1)[0]
        if n < 253:
            return n
        size = {253: 2, 254: 4, 255: 8}[n]
        v = int.from_bytes(self.take(size), "little")
        if v < {2: 253, 4: 0x10000, 8: 0x100000000}[size]:
            raise ValueError("non-canonical compactSize")
        if v > 0x02000000:
            raise ValueError("compactSize too large")
        return v


def compact_bytes(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _orchard_like(r, strict):
    n = r.compact()
    actions = []
    for _ in range(n):
        a = r.take(820)
        actions.append({"cv": a[0:32], "nf": a[32:64], "rk": a[64:96], "cmx": a[96:128],
                        "epk": a[128:160], "enc": a[160:740], "out": a[740:820]})
    bundle = {"actions": actions}
    if n:
        bundle["flags"] = r.take(1)[0]
        bundle["value_balance"] = r.take(8)
        bundle["anchor"] = r.take(32)
        size = r.compact()
        if strict and size != 2720 + 2272 * n:
            raise ValueError("proof size does not match the number of actions")
        bundle["proofs"] = r.take(size)
        bundle["spend_auth_sigs"] = [r.take(64) for _ in range(n)]
        bundle["binding_sig"] = r.take(64)
    return bundle


def parse(raw: bytes, strict: bool = True):
    """strict: apply the consensus rule on the Orchard proof size (off for synthetic vectors)."""
    r = Reader(raw)
    header = r.take(4)
    h = int.from_bytes(header, "little")
    overwintered, version = h >> 31, h & 0x7FFFFFFF
    if not overwintered or version not in (5, 6):
        raise ValueError(f"unsupported transaction version {version}")
    tx = {"header": header, "version": version, "version_group_id": r.take(4),
          "branch_id": r.take(4), "lock_time": r.take(4), "expiry_height": r.take(4)}
    vin = []
    for _ in range(r.compact()):
        prevout = r.take(36)
        script = r.take(r.compact())
        vin.append({"prevout": prevout, "script": script, "sequence": r.take(4)})
    vout = []
    for _ in range(r.compact()):
        value = r.take(8)
        vout.append({"value": value, "script": r.take(r.compact())})
    tx["vin"], tx["vout"] = vin, vout
    ns = r.compact()
    spends = [{"cv": s[0:32], "nf": s[32:64], "rk": s[64:96]} for s in (r.take(96) for _ in range(ns))]
    no = r.compact()
    outputs = [{"cv": o[0:32], "cmu": o[32:64], "epk": o[64:96], "enc": o[96:676], "out": o[676:756]}
               for o in (r.take(756) for _ in range(no))]
    sap = {"spends": spends, "outputs": outputs}
    if ns + no:
        sap["value_balance"] = r.take(8)
    if ns:
        sap["anchor"] = r.take(32)
    sap["spend_proofs"] = r.take(192 * ns)
    sap["spend_auth_sigs"] = r.take(64 * ns)
    sap["output_proofs"] = r.take(192 * no)
    if ns + no:
        sap["binding_sig"] = r.take(64)
    tx["sapling"] = sap
    tx["orchard"] = _orchard_like(r, strict)
    if version == 6:
        tx["ironwood"] = _orchard_like(r, strict)
    if r.i != len(raw):
        raise ValueError("trailing bytes after the transaction")
    return tx


def _orchard_digest(b, v6, ironwood):
    if ironwood:
        P = (b"ZTxIdIronwd_H_v6", b"ZTxIdIrnActCH_v6", b"ZTxIdIrnActMH_v6", b"ZTxIdIrnActNH_v6")
    elif v6:
        P = (b"ZTxIdOrchardH_v6", b"ZTxIdOrcActCHash", b"ZTxIdOrcActMHash", b"ZTxIdOrcActNHash")
    else:
        P = (b"ZTxIdOrchardHash", b"ZTxIdOrcActCHash", b"ZTxIdOrcActMHash", b"ZTxIdOrcActNHash")
    acts = b["actions"]
    if not acts:
        return _h(P[0], b"")
    compact = _h(P[1], b"".join(a["nf"] + a["cmx"] + a["epk"] + a["enc"][:52] for a in acts))
    memos = _h(P[2], b"".join(a["enc"][52:564] for a in acts))
    noncompact = _h(P[3], b"".join(a["cv"] + a["rk"] + a["enc"][564:] + a["out"] for a in acts))
    data = compact + memos + noncompact + bytes([b["flags"]]) + b["value_balance"]
    if not v6:
        data += b["anchor"]
    return _h(P[0], data)


def txid(tx) -> bytes:
    """The transaction identifier (internal byte order; explorers show it reversed)."""
    v6 = tx["version"] == 6
    header = _h(b"ZTxIdHeadersHash", tx["header"] + tx["version_group_id"] + tx["branch_id"] + tx["lock_time"] + tx["expiry_height"])
    if not tx["vin"] and not tx["vout"]:
        transparent = _h(b"ZTxIdTranspaHash", b"")
    else:
        prevouts = _h(b"ZTxIdPrevoutHash", b"".join(i["prevout"] for i in tx["vin"]))
        sequence = _h(b"ZTxIdSequencHash", b"".join(i["sequence"] for i in tx["vin"]))
        outputs = _h(b"ZTxIdOutputsHash", b"".join(o["value"] + compact_bytes(len(o["script"])) + o["script"] for o in tx["vout"]))
        transparent = _h(b"ZTxIdTranspaHash", prevouts + sequence + outputs)
    s = tx["sapling"]
    if not s["spends"] and not s["outputs"]:
        sapling = _h(b"ZTxIdSaplingHash", b"")
    else:
        if s["spends"]:
            sc = _h(b"ZTxIdSSpendCHash", b"".join(x["nf"] for x in s["spends"]))
            if v6:
                sn = _h(b"ZTxIdSSpendNH_v6", b"".join(x["cv"] + x["rk"] for x in s["spends"]))
            else:
                sn = _h(b"ZTxIdSSpendNHash", b"".join(x["cv"] + s["anchor"] + x["rk"] for x in s["spends"]))
            spends = _h(b"ZTxIdSSpendsHash", sc + sn)
        else:
            spends = _h(b"ZTxIdSSpendsHash", b"")
        if s["outputs"]:
            oc = _h(b"ZTxIdSOutC__Hash", b"".join(x["cmu"] + x["epk"] + x["enc"][:52] for x in s["outputs"]))
            om = _h(b"ZTxIdSOutM__Hash", b"".join(x["enc"][52:564] for x in s["outputs"]))
            on = _h(b"ZTxIdSOutN__Hash", b"".join(x["cv"] + x["enc"][564:] + x["out"] for x in s["outputs"]))
            outs = _h(b"ZTxIdSOutputHash", oc + om + on)
        else:
            outs = _h(b"ZTxIdSOutputHash", b"")
        sapling = _h(b"ZTxIdSaplingHash", spends + outs + s["value_balance"])
    parts = header + transparent + sapling + _orchard_digest(tx["orchard"], v6, False)
    if v6:
        parts += _orchard_digest(tx["ironwood"], True, True)
    return _h(b"ZcashTxHash_" + tx["branch_id"], parts)

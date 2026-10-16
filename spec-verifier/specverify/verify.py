"""An independent ZIP 311 receipt verifier for Orchard and Ironwood, from the specifications.

It checks everything a receipt claims except the Halo 2 proofs themselves: the transaction and
its identifier, the receipt encoding, indices, every spend-authorization signature, every
disclosed output (full 4.20.3 recovery with the disclosed ock), and the exact public inputs each
proof must be verified against (including the recomputed anchor of every sender-address proof).
A Halo 2 verifier for the Orchard circuit is not reimplemented here; the report marks each proof
"not checked" and lists its public inputs, which docs/ASSURANCE.md compares with the Rust
verifier's. So "valid" from this verifier means "valid if the proofs verify against these
public inputs".
"""

import hashlib

from . import orchard as o, pallas as pl, receipt as rc, tx as txmod
from .notes import recover_with_ock, recover_with_pkd_esk

LEAD_BYTE = {"orchard": 0x02, "ironwood": 0x03}


class Invalid(Exception):
    pass


def signing_digest(r: rc.Receipt) -> bytes:
    person = b"ZIP311Signed" + r.coin_type.to_bytes(4, "little")
    return hashlib.blake2b(r.unsigned_bytes, digest_size=32, person=person).digest()


def address_proof_cv_net() -> bytes:
    """ValueCommit_0(1 - 0) = [1] V: the only value commitment an address proof may carry."""
    return pl.repr_p(o.value_commit(0, 1))


def _canonical_base(b: bytes, what: str):
    v = int.from_bytes(b, "little")
    if v >= pl.P:
        raise Invalid(f"{what} is not a canonical field element")
    return v


def check_address_proof(a: rc.AddressProof, pool: str):
    """Everything about an address proof except its Halo 2 proof. Returns its public inputs."""
    d, pk_d_repr = a.address[:11], a.address[11:]
    try:
        pk_d = pl.decode_point(pk_d_repr)
    except ValueError:
        raise Invalid("address proof: pk_d is not a valid non-zero point")
    rho = _canonical_base(a.rho, "address proof rho")
    _canonical_base(a.nf, "address proof nullifier")
    cmx = _canonical_base(a.cmx, "address proof cmx")
    if o.derive_esk(a.rseed, a.rho) == 0:
        raise Invalid("address proof: rseed gives a zero esk")
    if a.cv_net != address_proof_cv_net():
        raise Invalid("address proof: cv_net is not ValueCommit_0(1), so the value-1 anchor check would not be enforced")
    g_d = o.diversify_hash(d)
    psi = o.derive_psi(a.rseed, a.rho)
    rcm = o.derive_rcm(LEAD_BYTE[pool], a.rseed, pl.repr_p(g_d), pk_d_repr, 1, a.rho, psi)
    cm = o.note_commit(rcm, pl.repr_p(g_d), pk_d_repr, 1, rho, psi)
    if cm == "bot":
        raise Invalid("address proof: the note has no commitment")
    anchor = o.single_leaf_root(pl.extract_p(cm))
    return {"anchor": anchor.to_bytes(32, "little").hex(), "cv_net": a.cv_net.hex(), "nf": a.nf.hex(),
            "cmx": cmx.to_bytes(32, "little").hex(), "enable_spends": 1, "enable_outputs": 1}


def source_cv_net(value) -> bytes:
    """ValueCommit_0(v) for a revealed value v >= 1, ValueCommit_0(1) for a hidden one: fixed by the
    verifier, so the spent value is non-zero and the circuit enforces the one-leaf anchor."""
    v = 1 if value is None else value
    if v < 1:
        raise Invalid("a source value must be at least 1")
    return pl.repr_p(o.value_commit(0, v))


def check_source_proof(src: rc.SourceProof, pool: str, nf: bytes, source_cmx: bytes):
    """Everything about a source proof except its Halo 2 proof, given the cmx of the source
    output read from the source transaction. Returns its public inputs (rk is the spend's)."""
    anchor = o.single_leaf_root(_canonical_base(source_cmx, "source output cmx"))
    if src.value is None:
        cmx = _canonical_base(src.cmx, "source proof cmx")
    else:
        # The opened output: value 0 to the given address, rho = the spend's nullifier.
        d, pk_d_repr = src.out_address[:11], src.out_address[11:]
        try:
            pl.decode_point(pk_d_repr)
        except ValueError:
            raise Invalid("source proof: output pk_d is not a valid non-zero point")
        rho = _canonical_base(nf, "nullifier")
        if o.derive_esk(src.out_rseed, nf) == 0:
            raise Invalid("source proof: rseed gives a zero esk")
        g_d = o.diversify_hash(d)
        psi = o.derive_psi(src.out_rseed, nf)
        rcm = o.derive_rcm(LEAD_BYTE[pool], src.out_rseed, pl.repr_p(g_d), pk_d_repr, 0, nf, psi)
        cm = o.note_commit(rcm, pl.repr_p(g_d), pk_d_repr, 0, rho, psi)
        if cm == "bot":
            raise Invalid("source proof: the output note has no commitment")
        cmx = pl.extract_p(cm)
    return {"anchor": anchor.to_bytes(32, "little").hex(), "cv_net": source_cv_net(src.value).hex(), "nf": nf.hex(),
            "cmx": cmx.to_bytes(32, "little").hex(), "enable_spends": 1, "enable_outputs": 1}


def verify(receipt_bytes: bytes, raw_tx: bytes, expected_coin_type: int, source_txs=()):
    """Returns a report dict; raises Invalid or rc.DecodeError on any failed check.
    source_txs: raw source transactions for source proofs (each must precede the payment; the
    caller checks heights, since raw bytes carry none)."""
    r = rc.decode(receipt_bytes)
    tx = txmod.parse(raw_tx)
    if txmod.txid(tx) != r.txid:
        raise Invalid("the receipt is for another transaction")
    sources = {}
    for raw in source_txs:
        stx = txmod.parse(raw)
        sources[txmod.txid(stx)] = {"orchard": stx["orchard"], "ironwood": stx.get("ironwood")}
    return verify_bundles(r, {"orchard": tx["orchard"], "ironwood": tx.get("ironwood")}, expected_coin_type, sources)


def verify_bundles(r: rc.Receipt, tx: dict, expected_coin_type: int, sources=None):
    """The checks after the transaction is known: tx maps a pool name to its parsed bundle, and
    sources maps a source txid (internal byte order) to its {pool: bundle} map."""
    sources = sources or {}
    if r.coin_type != expected_coin_type:
        raise Invalid("wrong network (coin type)")
    if not r.spends:
        raise Invalid("no spends: a receipt must prove spend authority for at least one action")
    spend_bundle = tx.get(r.pool)
    out_pool = r.output_pool or r.pool
    out_bundle = tx.get(out_pool)
    if not spend_bundle or not spend_bundle["actions"] or not out_bundle or not out_bundle["actions"]:
        raise Invalid("the transaction has no bundle in the receipt's pool")
    for items, bundle in ((r.outputs + r.opened, out_bundle), (r.spends, spend_bundle)):
        seen = set()
        for it in items:
            if it.index >= len(bundle["actions"]):
                raise Invalid(f"action index {it.index} out of range")
            if it.index in seen:
                raise Invalid(f"action index {it.index} disclosed twice")
            seen.add(it.index)
    digest = signing_digest(r)
    report = {"txid": r.txid[::-1].hex(), "coin_type": r.coin_type, "pool": r.pool, "output_pool": r.output_pool,
              "msg": r.msg.hex(), "spends": [], "outputs": []}
    for s, sig in zip(r.spends, r.sigs):
        try:
            rk = pl.decode_point(s.rk)
        except ValueError:
            raise Invalid(f"spend {s.index}: rk is not a valid non-zero point")
        if not o.redpallas_verify(s.rk, digest, sig):
            raise Invalid(f"spend {s.index}: bad spend-authorization signature")
        try:
            pl.decode_point(s.cv_net, allow_zero=True)
        except ValueError:
            raise Invalid(f"spend {s.index}: cv_net is not a point")
        cmx = _canonical_base(s.cmx, f"spend {s.index} cmx")
        act = spend_bundle["actions"][s.index]
        entry = {"index": s.index, "signature": True, "proof": "not checked",
                 "public_inputs": {"anchor": spend_bundle["anchor"].hex(), "cv_net": s.cv_net.hex(), "nf": act["nf"].hex(),
                                   "rk": pl.repr_p(rk).hex(), "cmx": cmx.to_bytes(32, "little").hex(),
                                   "enable_spends": 1, "enable_outputs": 1}}
        if s.address:
            pi = check_address_proof(s.address, r.pool)
            pi["rk"] = s.rk.hex()
            entry["address"] = {"address": s.address.address.hex(), "proof": "not checked", "public_inputs": pi}
        if s.source:
            sb = sources.get(s.source.txid, {}).get(r.pool)
            if s.source.txid == r.txid or not sb or s.source.index >= len(sb["actions"]):
                raise Invalid(f"spend {s.index}: the source transaction output is not available")
            pi = check_source_proof(s.source, r.pool, act["nf"], sb["actions"][s.source.index]["cmx"])
            pi["rk"] = s.rk.hex()
            entry["source"] = {"txid": s.source.txid[::-1].hex(), "index": s.source.index, "value": s.source.value,
                               "proof": "not checked", "public_inputs": pi}
        report["spends"].append(entry)
    for out in r.outputs:
        note = recover_with_ock(out_bundle["actions"][out.index], out.ock, LEAD_BYTE[out_pool])
        if note is None:
            raise Invalid(f"output {out.index} does not open with the disclosed key")
        report["outputs"].append({"index": out.index, "recipient": (note["d"] + note["pk_d"]).hex(),
                                  "value": note["value"], "memo": note["memo"].hex()})
    for out in r.opened:
        # NoteCommit from (g_d, pk_d, v, rho, psi) with the given rcm; rho is the action's nf.
        act = out_bundle["actions"][out.index]
        d, pk_d_repr = out.address[:11], out.address[11:]
        try:
            pl.decode_point(pk_d_repr)
        except ValueError:
            raise Invalid(f"opened output {out.index}: pk_d is not a valid non-zero point")
        psi = _canonical_base(out.psi, f"opened output {out.index} psi")
        rcm = int.from_bytes(out.rcm, "little")
        if rcm >= pl.R:
            raise Invalid(f"opened output {out.index}: rcm is not a canonical scalar")
        rho = _canonical_base(act["nf"], "nullifier")
        cm = o.note_commit(rcm, pl.repr_p(o.diversify_hash(d)), pk_d_repr, out.value, rho, psi)
        if cm == "bot" or pl.extract_p(cm).to_bytes(32, "little") != act["cmx"]:
            raise Invalid(f"opened output {out.index} does not match its note commitment")
        report["outputs"].append({"index": out.index, "recipient": out.address.hex(), "value": out.value,
                                  "memo": None, "memo_withheld": True})
    report["outputs"].sort(key=lambda x: x["index"])
    return report


def verify_sign_in(text: str, expected_coin_type: int, domain: str, nonce: str):
    s = rc.decode_sign_in(text)
    if s.coin_type != expected_coin_type:
        raise Invalid("wrong network (coin type)")
    if s.domain != domain or s.nonce != nonce:
        raise Invalid("sign-in is for another domain or nonce")
    try:
        pl.decode_point(s.rk)
    except ValueError:
        raise Invalid("rk is not a valid non-zero point")
    person = b"ZcashSignIn\0" + s.coin_type.to_bytes(4, "little")
    digest = hashlib.blake2b(s.signed_message, digest_size=32, person=person).digest()
    if not o.redpallas_verify(s.rk, digest, s.sig):
        raise Invalid("bad signature")
    pi = check_address_proof(s.address, "ironwood")
    pi["rk"] = s.rk.hex()
    return {"address": s.address.address.hex(), "proof": "not checked", "public_inputs": pi}


def verify_incoming(text: str, raw_tx: bytes, expected_coin_type: int):
    """An incoming receipt: the recipient proves it was paid. Checks the signature, the address
    proof (except its Halo 2 proof: public inputs returned), and opens each output with the
    recipient's pk_d and the disclosed esk (4.20.3); every output must be to the proven address."""
    r = rc.decode_incoming(text)
    if r.coin_type != expected_coin_type:
        raise Invalid("wrong network (coin type)")
    tx = txmod.parse(raw_tx)
    if txmod.txid(tx) != r.txid:
        raise Invalid("the receipt is for another transaction")
    bundle = tx.get(r.pool)
    if not bundle or not bundle["actions"]:
        raise Invalid("the transaction has no bundle in the receipt's pool")
    if not r.outputs:
        raise Invalid("no outputs")
    try:
        pl.decode_point(r.rk)
    except ValueError:
        raise Invalid("rk is not a valid non-zero point")
    person = b"ZIP311Incomg" + r.coin_type.to_bytes(4, "little")
    digest = hashlib.blake2b(r.unsigned_bytes, digest_size=32, person=person).digest()
    if not o.redpallas_verify(r.rk, digest, r.sig):
        raise Invalid("bad signature")
    pi = check_address_proof(r.address, r.pool)
    pi["rk"] = r.rk.hex()
    pk_d = r.address.address[11:]
    seen, outs = set(), []
    for index, esk in r.outputs:
        if index >= len(bundle["actions"]) or index in seen:
            raise Invalid(f"output index {index} out of range or repeated")
        seen.add(index)
        note = recover_with_pkd_esk(bundle["actions"][index], pk_d, esk, LEAD_BYTE[r.pool])
        if note is None or note["d"] != r.address.address[:11]:
            raise Invalid(f"output {index} does not open to the proven address with the disclosed esk")
        outs.append({"index": index, "value": note["value"], "memo": note["memo"].hex()})
    return {"recipient": r.address.address.hex(), "outputs": outs, "address_proof": {"proof": "not checked", "public_inputs": pi}}


def verify_request(text: str, expected_coin_type: int, now: int):
    """A signed payment request: signature by rk, and rk's key controls the payee (address proof,
    Halo 2 proof not checked: public inputs returned). The caller checks the domain's
    /.well-known/zcash-receipts.json lists the payee."""
    r = rc.decode_request(text)
    if r.coin_type != expected_coin_type:
        raise Invalid("wrong network (coin type)")
    try:
        pl.decode_point(r.rk)
    except ValueError:
        raise Invalid("rk is not a valid non-zero point")
    person = b"ZIP321Signed" + r.coin_type.to_bytes(4, "little")
    digest = hashlib.blake2b(r.unsigned_bytes, digest_size=32, person=person).digest()
    if not o.redpallas_verify(r.rk, digest, r.sig):
        raise Invalid("bad signature")
    pi = check_address_proof(r.address, "ironwood")
    pi["rk"] = r.rk.hex()
    if now > r.expires_at:
        raise Invalid("expired")
    return {"payee": r.address.address.hex(), "domain": r.domain, "amount": r.amount, "memo": r.memo, "code": r.code,
            "address_proof": {"proof": "not checked", "public_inputs": pi}}

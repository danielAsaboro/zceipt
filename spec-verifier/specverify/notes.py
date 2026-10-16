"""Recovering an Orchard-protocol note with an outgoing cipher key (protocol 4.20.3).

The algorithm of 4.20.3 with the NU6.3 note-commitment trapdoor of 4.7.3 for lead byte 0x03
(see docs/SPEC-AMBIGUITIES.md: 4.20.3 itself still derives rcm the NU5 way for every lead byte).
"""

from . import aead, orchard as o, pallas as pl


def recover_with_ock(action, ock: bytes, lead_byte: int):
    """action: dict of the Action's cv, nf, cmx, epk, enc (580 bytes), out (80 bytes) fields.

    lead_byte: the note plaintext lead byte the pool allows (0x02 Orchard, 0x03 Ironwood).
    Returns {d, pk_d, value, rseed, memo, rho, psi, rcm} or None (the spec's bottom).
    """
    op = aead.sym_decrypt(ock, action["out"])
    if op is None or len(op) != 64:
        return None
    return recover_with_pkd_esk(action, op[:32], op[32:], lead_byte)


def recover_with_pkd_esk(action, pk_d_repr: bytes, esk_bytes: bytes, lead_byte: int):
    """The second half of 4.20.3: open an output given its recipient's pk_d and its esk (used by
    incoming receipts, where the recipient discloses esk). Same return value as recover_with_ock."""
    esk = int.from_bytes(esk_bytes, "little")
    pk_d = pl.abst_p(pk_d_repr)
    if esk >= pl.R or pk_d == "bot":
        return None
    # KA^Orchard public keys are of type G*_P: the zero point is not a valid pk_d.
    if pk_d is None:
        return None
    if pl.repr_p(pk_d) != pk_d_repr:
        return None
    shared = pl.mul(esk, pk_d)
    k_enc = o.kdf_orchard(shared, action["epk"])
    np = aead.sym_decrypt(k_enc, action["enc"])
    if np is None or len(np) != 564:
        return None
    lead, d, v, rseed, memo = np[0], np[1:12], int.from_bytes(np[12:20], "little"), np[20:52], np[52:564]
    if lead != lead_byte:
        return None
    rho = action["nf"]
    if o.derive_esk(rseed, rho) != esk:
        return None
    g_d = o.diversify_hash(d)
    psi = o.derive_psi(rseed, rho)
    rcm = o.derive_rcm(lead, rseed, pl.repr_p(g_d), pk_d_repr, v, rho, psi)
    rho_int = int.from_bytes(rho, "little")
    if rho_int >= pl.P:
        return None
    cm = o.note_commit(rcm, pl.repr_p(g_d), pk_d_repr, v, rho_int, psi)
    if cm == "bot" or pl.extract_p(cm).to_bytes(32, "little") != action["cmx"]:
        return None
    if pl.repr_p(pl.mul(esk, g_d)) != action["epk"]:
        return None
    return {"d": d, "pk_d": pk_d_repr, "value": v, "rseed": rseed, "memo": memo, "rho": rho, "psi": psi, "rcm": rcm}

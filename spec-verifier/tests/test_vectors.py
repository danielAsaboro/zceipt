"""Checks the spec-derived primitives against zcash-test-vectors (an independent Python
reference implementation by the protocol designers), and ChaCha20-Poly1305 against RFC 8439.

Run: python3 -m unittest discover -s spec-verifier/tests   (set ZCASH_TEST_VECTORS to the
test-vectors/json directory of a zcash-test-vectors checkout; the JSON files are not copied).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from specverify import aead, orchard as o, pallas as pl  # noqa: E402

TV = os.environ.get("ZCASH_TEST_VECTORS", os.path.join(os.path.dirname(__file__), "zcash-test-vectors"))


def rows(name):
    with open(os.path.join(TV, name + ".json")) as f:
        return json.load(f)[2:]


def le(h):
    return int.from_bytes(bytes.fromhex(h), "little")


@unittest.skipUnless(os.path.isdir(TV), "zcash-test-vectors not found")
class ZcashTestVectors(unittest.TestCase):
    def test_map_to_curve(self):
        for u, pt in rows("orchard_map_to_curve"):
            self.assertEqual(pl.repr_p(pl.map_to_curve_simple_swu(le(u))).hex(), pt)

    def test_group_hash(self):
        for dom, msg, pt in rows("orchard_group_hash"):
            self.assertEqual(pl.repr_p(pl.group_hash(bytes.fromhex(dom), bytes.fromhex(msg))).hex(), pt)

    def test_sinsemilla(self):
        for dom, msg, pt, h in rows("orchard_sinsemilla"):
            bits = [int(b) for b in msg] if isinstance(msg, list) else list(bytes.fromhex(msg))
            self.assertEqual(pl.repr_p(o.sinsemilla_hash_to_point(bytes.fromhex(dom), bits)).hex(), pt)
            self.assertEqual(o.sinsemilla_hash(bytes.fromhex(dom), bits).to_bytes(32, "little").hex(), h)

    def test_empty_roots(self):
        expect = rows("orchard_empty_roots")[0][0]
        self.assertEqual([r.to_bytes(32, "little").hex() for r in o.empty_roots()][: len(expect)], expect)

    def test_merkle_paths(self):
        for leaves, paths, root in rows("orchard_merkle_tree"):
            for pos, (leaf, path) in enumerate(zip(leaves, paths)):
                self.assertEqual(o.root_from_path(le(leaf), pos, [le(x) for x in path]).to_bytes(32, "little").hex(), root)

    def test_generators(self):
        skb, nkb, vcvb, vcrb, cmb, cmq, ivkb, ivkq, mcq = rows("orchard_generators")[0]
        self.assertEqual(pl.repr_p(o.spend_auth_base()).hex(), skb)
        self.assertEqual(pl.repr_p(pl.group_hash(b"z.cash:Orchard-cv", b"v")).hex(), vcvb)
        self.assertEqual(pl.repr_p(pl.group_hash(b"z.cash:Orchard-cv", b"r")).hex(), vcrb)
        self.assertEqual(pl.repr_p(o.sinsemilla_q(b"z.cash:Orchard-NoteCommit-M")).hex(), cmq)
        self.assertEqual(pl.repr_p(pl.group_hash(b"z.cash:Orchard-NoteCommit-r", b"")).hex(), cmb)
        self.assertEqual(pl.repr_p(o.sinsemilla_q(b"z.cash:Orchard-MerkleCRH")).hex(), mcq)

    def test_note_commitments(self):
        for r in rows("orchard_key_components"):
            sk, ask, ak, nk, rivk, ivk, ovk, dk, d, pk_d, *_rest, v, rho, rseed, cmx, nf = r
            rho_b, rseed_b = bytes.fromhex(rho), bytes.fromhex(rseed)
            g_d = o.diversify_hash(bytes.fromhex(d))
            psi = o.derive_psi(rseed_b, rho_b)
            rcm = o.derive_rcm(0x02, rseed_b, pl.repr_p(g_d), bytes.fromhex(pk_d), v, rho_b, psi)
            cm = o.note_commit(rcm, pl.repr_p(g_d), bytes.fromhex(pk_d), v, le(rho), psi)
            self.assertEqual(pl.extract_p(cm).to_bytes(32, "little").hex(), cmx)
            # ak is the spend-authorization base times ask (RedDSA.DerivePublic), x only
            self.assertEqual(pl.extract_p(pl.mul(le(ask), o.spend_auth_base())).to_bytes(32, "little").hex(), ak)

    def test_note_encryption_recovery_with_ock(self):
        from specverify.notes import recover_with_ock
        for r in rows("orchard_note_encryption"):
            (ivk, ovk, d, pk_d, v, rseed, memo, cv_net, rho, cmx, esk, epk, ss, k_enc, p_enc, c_enc, ock, op, c_out) = r
            action = {"cv": bytes.fromhex(cv_net), "nf": bytes.fromhex(rho), "cmx": bytes.fromhex(cmx),
                      "epk": bytes.fromhex(epk), "enc": bytes.fromhex(c_enc), "out": bytes.fromhex(c_out)}
            note = recover_with_ock(action, bytes.fromhex(ock), lead_byte=0x02)
            self.assertIsNotNone(note)
            self.assertEqual(note["d"].hex(), d)
            self.assertEqual(note["pk_d"].hex(), pk_d)
            self.assertEqual(note["value"], v)
            self.assertEqual(note["memo"].hex(), memo)
            # Any other key fails.
            self.assertIsNone(recover_with_ock(action, bytes(32), lead_byte=0x02))
            # And so does the wrong pool.
            self.assertIsNone(recover_with_ock(action, bytes.fromhex(ock), lead_byte=0x03))


class Rfc8439(unittest.TestCase):
    def test_aead_vector(self):
        # RFC 8439 section 2.8.2
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        ct, tag = aead.encrypt(key, nonce, pt, aad)
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(ct[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")
        self.assertEqual(aead.decrypt(key, nonce, ct + tag, aad), pt)
        self.assertIsNone(aead.decrypt(key, nonce, ct + bytes(16), aad))


if __name__ == "__main__":
    unittest.main()

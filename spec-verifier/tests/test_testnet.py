"""Every real testnet receipt in examples/testnet, checked offline against its raw transaction
(examples/testnet/raw/<txid>.hex, fetched from lightwalletd; the txid is recomputed here, so the
fetch need not be trusted). The receipts made before the 2026-10-15 address-proof fix must fail.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from specverify import receipt as rc, verify as v  # noqa: E402

EX = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "testnet")

EXPECT = {
    "receipt": [(1_000_000, "Invoice 42: two coffees")],
    "receipt-with-sender-address": [(500_000, "Grant round 3: docs translation (Tolu)")],
    "receipt-with-refund-address": [(300_000, None)],
    "refund-receipt": [(100_000, None)],
    "deposit-receipt": [],
}


def receipt_bytes(name):
    with open(os.path.join(EX, name + ".txt")) as f:
        m = re.search(r"zip311r1[A-Za-z0-9_-]+", f.read())
    return rc.b64decode(m.group(0)[len("zip311r1"):])


def raw(r):
    with open(os.path.join(EX, "raw", r.txid[::-1].hex() + ".hex")) as f:
        return bytes.fromhex(f.read().strip())


class Testnet(unittest.TestCase):
    def test_receipts(self):
        for name, outs in EXPECT.items():
            b = receipt_bytes(name)
            rep = v.verify(b, raw(rc.decode(b)), 1)
            self.assertEqual(len(rep["outputs"]), len(outs), name)
            for o, (value, memo) in zip(rep["outputs"], outs):
                self.assertEqual(o["value"], value, name)
                if memo:
                    self.assertEqual(bytes.fromhex(o["memo"]).rstrip(b"\0").decode(), memo, name)
        rep = v.verify(receipt_bytes("receipt-with-sender-address"), raw(rc.decode(receipt_bytes("receipt-with-sender-address"))), 1)
        self.assertEqual(len([s for s in rep["spends"] if "address" in s]), 1)

    def test_batch(self):
        with open(os.path.join(EX, "batch.txt")) as f:
            m = re.search(r"zip311b1[A-Za-z0-9_-]+", f.read())
        batch = rc.decode_batch(rc.b64decode(m.group(0)[len("zip311b1"):]))
        self.assertEqual(len(batch), 3)
        self.assertTrue(rc.check_batch(batch))
        for r in batch:
            v.verify(r.unsigned_bytes + b"".join(r.sigs), raw(r), 1)
        # The batch rules: dropping, repeating or re-networking a receipt is refused.
        import copy
        with self.assertRaisesRegex(rc.DecodeError, "wrong number"):
            rc.check_batch(batch[:2])
        with self.assertRaisesRegex(rc.DecodeError, "repeated|more than once"):
            rc.check_batch([batch[0], batch[0], batch[2]])
        other = copy.copy(batch[1])
        other.coin_type = 133
        with self.assertRaisesRegex(rc.DecodeError, "different networks"):
            rc.check_batch([batch[0], other, batch[2]])
        moved = copy.copy(batch[0])
        moved.msg = b"Grant round 3\n" + batch[0].msg
        with self.assertRaisesRegex(rc.DecodeError, "no batch position"):
            rc.check_batch([moved, batch[1], batch[2]])

    def test_source_of_funds(self):
        """examples/testnet/source: the payment 571de6e4… with a proof that its spent note came
        from 2a2bd721… action 0, once with the value hidden and once revealed."""
        src = os.path.join(EX, "source")
        rd = lambda n: bytes.fromhex(open(os.path.join(src, n)).read().strip())
        for name, value in (("receipt-source-hidden", None), ("receipt-source-value", 12_500_000)):
            b = receipt_bytes(os.path.join("source", name))
            rep = v.verify(b, rd("tx.hex"), 1, [rd("source-tx.hex")])
            [s] = [s for s in rep["spends"] if "source" in s]
            self.assertEqual((s["source"]["txid"][:8], s["source"]["index"], s["source"]["value"]), ("2a2bd721", 0, value), name)
            with self.assertRaisesRegex(v.Invalid, "source transaction output is not available"):
                v.verify(b, rd("tx.hex"), 1)

    def test_memo_withheld(self):
        """examples/testnet/memo-withheld: the 0.01 TAZ payment disclosed without its memo."""
        d = os.path.join(EX, "memo-withheld")
        b = receipt_bytes(os.path.join("memo-withheld", "receipt"))
        self.assertEqual(rc.decode(b).version, 5)
        rep = v.verify(b, bytes.fromhex(open(os.path.join(d, "tx.hex")).read().strip()), 1)
        [o] = rep["outputs"]
        self.assertEqual((o["value"], o["memo"], o["memo_withheld"]), (1_000_000, None, True))
        self.assertNotIn(b"Invoice 42", b)

    def test_incoming(self):
        """examples/testnet/incoming: the merchant proves it received the 0.01 TAZ payment."""
        d = os.path.join(EX, "incoming")
        text = open(os.path.join(d, "receipt.txt")).read()
        text = text[text.index("zrcin1"):].split()[0]
        raw = bytes.fromhex(open(os.path.join(d, "tx.hex")).read().strip())
        rep = v.verify_incoming(text, raw, 1)
        [o] = rep["outputs"]
        self.assertEqual(o["value"], 1_000_000)
        self.assertEqual(bytes.fromhex(o["memo"]).rstrip(b"\0").decode(), "Invoice 42: two coffees")
        with self.assertRaises(v.Invalid):
            v.verify_incoming(text, raw, 133)
        # A flipped signature byte is refused.
        b = rc.b64decode(text[6:])
        bad = "zrcin1" + rc.base64.urlsafe_b64encode(b[:-1] + bytes([b[-1] ^ 1])).decode().rstrip("=")
        with self.assertRaises(v.Invalid):
            v.verify_incoming(bad, raw, 1)

    def test_signed_request(self):
        """examples/testnet/request: a payment request signed by the testnet merchant's key."""
        t = open(os.path.join(EX, "request", "request.txt")).read().strip()
        r = v.verify_request(t, 1, 1_792_120_000)
        self.assertEqual((r["domain"], r["amount"], r["memo"], r["code"]), ("kemis-coffee.test", 250_000, "Order 42: two coffees", "0c0ffee042"))
        with self.assertRaisesRegex(v.Invalid, "expired"):
            v.verify_request(t, 1, 10**12)
        b = bytearray(rc.b64decode(t[5:]))
        i = 9
        for _ in range(3):
            i += 2 + int.from_bytes(b[i:i + 2], "little")
        b[i] ^= 1  # the amount
        with self.assertRaisesRegex(v.Invalid, "bad signature"):
            v.verify_request("zreq1" + rc.base64.urlsafe_b64encode(bytes(b)).decode().rstrip("="), 1, 1_792_120_000)

    def test_proof_of_funds(self):
        """examples/testnet/reserve: a proof of funds over the sender's unspent Ironwood note, with
        the tree root lightwalletd reported at that height (anchor.hex)."""
        d = os.path.join(EX, "reserve")
        t = open(os.path.join(d, "proof.txt")).read().strip()
        anchor = bytes.fromhex(open(os.path.join(d, "anchor.hex")).read().strip())
        rep = v.verify_reserve(t, 1, anchor)
        self.assertEqual(rep["total"], 9_690_000)
        with self.assertRaisesRegex(v.Invalid, "anchor"):
            v.verify_reserve(t, 1, bytes(32))

    def test_proof_of_funds_with_values_hidden(self):
        """reserve-hidden.txt (written by roundtrip.rs::proof_of_funds_can_hide_each_value_and_show_only_the_total):
        only the total is shown, and the notes' value commitments must add up to it."""
        with open(os.path.join(os.path.dirname(__file__), "reserve-hidden.txt")) as f:
            t, anchor = f.read().split()
        rep = v.verify_reserve(t, 1, bytes.fromhex(anchor))
        self.assertEqual(rep["total"], 100_000)
        self.assertTrue(all(n["value"] is None for n in rep["notes"]))
        # A different total (the signature covers it, so re-signing is needed in practice; the sum check refuses it regardless).
        r = rc.decode_reserve(t)
        b = bytearray(rc.b64decode(t[5:]))
        i = r.unsigned_bytes.index(r.msg) + len(r.msg)
        b[i:i + 8] = (100_001).to_bytes(8, "little")
        lie = "zrsv1" + rc.base64.urlsafe_b64encode(bytes(b)).decode().rstrip("=")
        with self.assertRaises(v.Invalid):
            v.verify_reserve(lie, 1, bytes.fromhex(anchor))

    def test_screened_set_proof(self):
        """screened.json (written by roundtrip.rs::screened_set_proof_shows_membership_not_which_member):
        the list's root, computed here with Sinsemilla, is the proof's; the value commitment is
        fixed from the floor; a list without the note, or in another order, is refused."""
        import json as _json
        with open(os.path.join(os.path.dirname(__file__), "screened.json")) as f:
            fx = _json.load(f)
        leaves = [bytes.fromhex(c) for c in fx["set"]]
        args = (bytes.fromhex(fx["rk"]), bytes.fromhex(fx["nf"]), 1, bytes.fromhex(fx["txid"]))
        pi = v.check_screened(fx["proof"], leaves, *args)
        self.assertEqual(pi["floor"], 60_000)
        self.assertEqual(pi["anchor"], rc.decode_screened(fx["proof"]).set_root.hex())
        with self.assertRaisesRegex(v.Invalid, "root"):
            v.check_screened(fx["proof"], leaves[:1] + leaves[2:], *args)
        with self.assertRaisesRegex(v.Invalid, "root"):
            v.check_screened(fx["proof"], list(reversed(leaves)), *args)

    def test_screened_list_root(self):
        """The testnet screened-set proof is against the root of the published list, computed here."""
        with open(os.path.join(EX, "screened", "list.txt")) as f:
            leaves = [bytes.fromhex(l.strip()) for l in f if l.strip() and not l.startswith("#")]
        with open(os.path.join(EX, "screened", "proof.txt")) as f:
            p = rc.decode_screened(f.read())
        self.assertEqual(len(leaves), 16)
        self.assertEqual(v.screened_set_root(leaves), p.set_root)
        self.assertNotEqual(v.screened_set_root(leaves[:-1]), p.set_root)

    def test_proof_of_income(self):
        """The testnet proof of income: one signature over four items, floors summing to 0.02 TAZ;
        a floor changed after signing is refused."""
        with open(os.path.join(EX, "income", "proof.txt")) as f:
            t = f.read().strip()
        one = lambda pool, txid, index: b"\x01" + bytes(31)
        r = v.verify_income(t, 1, one)
        self.assertEqual((r["total"], len(r["items"]), r["message"]), (2_000_000, 4, b"challenge:10a4e7c3d2b1"))
        raw = bytearray(rc.b64decode(t[8:]))
        # The first item's floor sits after magic, version, coin type, msg, rk, count, pool, txid, index, height.
        at = 4 + 1 + 4 + 2 + len(r["message"]) + 32 + 2 + 1 + 32 + 4 + 4
        raw[at] ^= 1
        import base64 as _b
        bent = "zip311i1" + _b.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        with self.assertRaises(v.Invalid):
            v.verify_income(bent, 1, one)

    def test_policy_proof(self):
        """conformance/policy.json: a 2-of-3 FROST treasury's receipt and its policy proof."""
        import json as _json
        from specverify import link
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "conformance", "policy.json")) as f:
            vec = _json.load(f)
        r = rc.from_text(vec["receipt"])
        self.assertEqual(link.verify_policy(vec["policy"], r), (vec["threshold"], vec["holders"]))
        other = rc.from_text(vec["receipt"])
        other.unsigned_bytes = other.unsigned_bytes[:-1] + bytes([other.unsigned_bytes[-1] ^ 1])
        with self.assertRaises(ValueError):
            link.verify_policy(vec["policy"], other)

    def test_same_payer_proof(self):
        """The batch's same-payer proof holds for its receipts, in order, and for nothing else."""
        import re as _re
        from specverify import link
        with open(os.path.join(EX, "batch-same-payer-link.txt")) as f:
            t = f.read()
        rs = rc.decode_batch(rc.b64decode(_re.search(r"zip311b1[A-Za-z0-9_-]+", t).group(0)[8:]))
        proof = link.decode(_re.search(r"zip311k1[A-Za-z0-9_-]+", t).group(0))
        self.assertEqual(proof["msg"], b"batch:" + rc.check_batch(rs).encode())
        self.assertEqual(link.verify(proof, rs), 3)
        with self.assertRaises(ValueError):
            link.verify(proof, [rs[1], rs[0], rs[2]])
        bent = dict(proof, links=[(r, bytes([s[0] ^ 1]) + s[1:]) for r, s in proof["links"]])
        with self.assertRaises(ValueError):
            link.verify(bent, rs)

    def test_prepared_receipts(self):
        """conformance/prepared.json, shared with the Rust tests."""
        import json as _json, hashlib as _h
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "conformance", "prepared.json")) as f:
            for case in _json.load(f)["cases"]:
                try:
                    p = rc.prepared_from_text(case["text"])
                except rc.DecodeError:
                    self.assertFalse(case["valid"], case["name"])
                    continue
                self.assertTrue(case["valid"], case["name"])
                self.assertEqual(len(p.spends), case["spends"])
                person = b"ZIP311Signed" + p.coin_type.to_bytes(4, "little")
                self.assertEqual(_h.blake2b(p.unsigned_bytes, digest_size=32, person=person).hexdigest(), case["signing_digest"])

    def test_challenge_rule(self):
        """conformance/challenge.json, shared with the Rust and npm tests."""
        import json as _json
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "conformance", "challenge.json")) as f:
            for case in _json.load(f)["cases"]:
                self.assertEqual(v.challenge_of(case["message"]), case["challenge"], repr(case["message"]))

    def test_pre_fix_address_proof_is_refused(self):
        b = receipt_bytes("pre-fix/receipt-with-sender-address")
        with self.assertRaisesRegex(v.Invalid, "ValueCommit_0"):
            v.verify(b, raw(rc.decode(b)), 1)


if __name__ == "__main__":
    unittest.main()

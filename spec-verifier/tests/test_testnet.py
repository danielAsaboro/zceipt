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
        m = re.search(r"zrcpt1[A-Za-z0-9_-]+", f.read())
    return rc.b64decode(m.group(0)[6:])


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
            m = re.search(r"zrcptb1[A-Za-z0-9_-]+", f.read())
        batch = rc.decode_batch(rc.b64decode(m.group(0)[7:]))
        self.assertEqual(len(batch), 3)
        for r in batch:
            v.verify(r.unsigned_bytes + b"".join(r.sigs), raw(r), 1)

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

    def test_pre_fix_address_proof_is_refused(self):
        b = receipt_bytes("pre-fix/receipt-with-sender-address")
        with self.assertRaisesRegex(v.Invalid, "ValueCommit_0"):
            v.verify(b, raw(rc.decode(b)), 1)


if __name__ == "__main__":
    unittest.main()

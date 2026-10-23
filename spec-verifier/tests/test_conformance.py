"""Runs every shared conformance vector (conformance/vectors.json) through the spec verifier.

The vectors' expectations come from the Rust verifier; this verifier was written separately from
the specifications. They must agree on every vector: accept/reject, amounts and memos.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from specverify import receipt as rc, ua, verify as v  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def memo_text(memo_hex):
    m = bytes.fromhex(memo_hex)
    if m[0] > 0xF4:
        return None
    m = m.rstrip(b"\0")
    if not m:
        return None
    try:
        return m.decode()
    except UnicodeDecodeError:
        return None


def run(vec):
    if vec["type"] == "receipt":
        text = vec["receipt"].strip()
        if not text.startswith("zip311r1"):
            raise rc.DecodeError("not a receipt")
        b = rc.b64decode(text[len("zip311r1"):])
        coin = int.from_bytes(b[5:9], "little") if len(b) >= 9 else 1
        # A source must be mined no later than the payment: raw bytes carry no height, so the
        # caller enforces it, as the docstring of verify() says.
        sources = [bytes.fromhex(t["raw_tx"]) for t in vec.get("source_txs", []) if t["height"] <= vec["height"]]
        return v.verify(b, bytes.fromhex(vec["raw_tx"]), coin, sources)
    if vec["type"] == "incoming":
        text = vec["receipt"].strip()
        b = rc.b64decode(text[6:]) if text.startswith("zrcin1") else b""
        coin = int.from_bytes(b[5:9], "little") if len(b) >= 9 else 1
        rep = v.verify_incoming(text, bytes.fromhex(vec["raw_tx"]), coin)
        return {"outputs": [{"value": o["value"], "memo": o["memo"]} for o in rep["outputs"]]}
    if vec["type"] == "expectation":
        # "Was I paid": the expected address must be on the receipt's network (mainnet or a test
        # network), and only outputs disclosed with their memo count.
        text = vec["receipt"].strip()
        b = rc.b64decode(text[len("zip311r1"):])
        coin = int.from_bytes(b[5:9], "little")
        rep = v.verify(b, bytes.fromhex(vec["raw_tx"]), coin)
        net, _ = ua.decode(vec["expect_address"])
        want = ua.orchard_receiver(vec["expect_address"]).hex()
        same_net = (net == "mainnet") == (coin == 133)
        paid = sum(o["value"] for o in rep["outputs"] if o["recipient"] == want and not o.get("memo_withheld"))
        ok = same_net and paid > 0 and paid >= vec.get("min_zatoshis", 0)
        return {"satisfied": ok}
    if vec["type"] == "sign_in":
        si = rc.decode_sign_in(vec["sign_in"])
        return v.verify_sign_in(vec["sign_in"], si.coin_type, vec["domain"], vec["nonce"])
    raise AssertionError(vec["type"])


class Conformance(unittest.TestCase):
    def test_every_vector(self):
        with open(os.path.join(ROOT, "conformance", "vectors.json")) as f:
            vectors = json.load(f)["vectors"]
        disagreements = []
        halo2_only = 0
        for vec in vectors:
            try:
                got, err = run(vec), None
            except (v.Invalid, rc.DecodeError, ValueError) as e:
                got, err = None, e
            want = vec["expect"]["valid"]
            if got is not None and vec["expect"].get("fails_only_on") == "halo2_proof":
                # This verifier does not check Halo 2 proofs, so it can't reject these: the
                # vectors exist to catch a full verifier that skips the proof.
                halo2_only += 1
                continue
            if (got is not None) != want:
                disagreements.append((vec["name"], want, str(err)))
                continue
            for i, o in enumerate(vec["expect"].get("outputs", [])):
                self.assertEqual(got["outputs"][i]["value"], o["zatoshis"], vec["name"])
                m = got["outputs"][i]["memo"]
                self.assertEqual(None if m is None else memo_text(m), o["memo"], vec["name"])
            if "satisfied" in vec["expect"]:
                self.assertEqual(got["satisfied"], vec["expect"]["satisfied"], vec["name"])
            for i, src in enumerate(vec["expect"].get("sources", [])):
                self.assertEqual([s["source"]["value"] for s in got["spends"] if "source" in s][i], src["zatoshis"], vec["name"])
        self.assertEqual(disagreements, [], f"{len(disagreements)} of {len(vectors)} vectors disagree")
        print(f"{len(vectors)} conformance vectors agree ({halo2_only} rejected only by the Halo 2 check, which this verifier leaves to the caller)")


if __name__ == "__main__":
    unittest.main()

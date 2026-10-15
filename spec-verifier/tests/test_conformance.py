"""Runs every shared conformance vector (conformance/vectors.json) through the spec verifier.

The vectors' expectations come from the Rust verifier; this verifier was written separately from
the specifications. They must agree on every vector: accept/reject, amounts and memos.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from specverify import receipt as rc, verify as v  # noqa: E402

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
        if not text.startswith("zrcpt1"):
            raise rc.DecodeError("not a receipt")
        b = rc.b64decode(text[6:])
        coin = int.from_bytes(b[5:9], "little") if len(b) >= 9 else 1
        return v.verify(b, bytes.fromhex(vec["raw_tx"]), coin)
    if vec["type"] == "sign_in":
        si = rc.decode_sign_in(vec["sign_in"])
        return v.verify_sign_in(vec["sign_in"], si.coin_type, vec["domain"], vec["nonce"])
    raise AssertionError(vec["type"])


class Conformance(unittest.TestCase):
    def test_every_vector(self):
        with open(os.path.join(ROOT, "conformance", "vectors.json")) as f:
            vectors = json.load(f)["vectors"]
        disagreements = []
        for vec in vectors:
            try:
                got, err = run(vec), None
            except (v.Invalid, rc.DecodeError, ValueError) as e:
                got, err = None, e
            want = vec["expect"]["valid"]
            if (got is not None) != want:
                disagreements.append((vec["name"], want, str(err)))
                continue
            for i, o in enumerate(vec["expect"].get("outputs", [])):
                self.assertEqual(got["outputs"][i]["value"], o["zatoshis"], vec["name"])
                self.assertEqual(memo_text(got["outputs"][i]["memo"]), o["memo"], vec["name"])
        self.assertEqual(disagreements, [], f"{len(disagreements)} of {len(vectors)} vectors disagree")
        print(f"{len(vectors)} conformance vectors agree")


if __name__ == "__main__":
    unittest.main()

"""Differential test: the spec verifier against the Rust verifier on signed adversarial receipts.

tests/corpus.json is written by the Rust test `differential_corpus`
(DIFF_CORPUS=spec-verifier/tests/corpus.json cargo test -p receipts-core --test roundtrip differential_corpus).
Each altered receipt is re-signed by the spender, so the signature can't be what rejects it.

For every case the two verifiers must agree, with one allowed difference: when the Rust verifier
rejects only because a Halo 2 proof fails (BadProof / BadAddressProof), the spec verifier, which
does not check Halo 2 proofs, accepts conditionally. Then the public inputs it says the proof must
be checked against must equal exactly the ones the Rust verifier used, so the proof check is the
only step the two verifiers share.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from specverify import receipt as rc, verify as v  # noqa: E402

CORPUS = os.path.join(os.path.dirname(__file__), "corpus.json")


def bundle(j):
    acts = [{k: bytes.fromhex(a[k]) for k in ("cv", "nf", "rk", "cmx", "epk", "enc", "out")} for a in j["actions"]]
    return {"anchor": bytes.fromhex(j["anchor"]), "actions": acts}


@unittest.skipUnless(os.path.exists(CORPUS), "no corpus.json; generate it with the Rust test")
class Differential(unittest.TestCase):
    def test_corpus(self):
        with open(CORPUS) as f:
            corpus = json.load(f)
        b = {k: bundle(x) for k, x in corpus["bundles"].items()}
        proof_only = 0
        sources_checked = 0
        for c in corpus["cases"]:
            name, rust = c["name"], c["rust"]
            tx = {c["pool"]: b[c["pool"]]}
            sources = {}
            if "source_bundles" in corpus:
                sources[bytes.fromhex(corpus["source_txid"])] = {c["pool"]: bundle(corpus["source_bundles"][c["pool"]])}
            try:
                got, err = v.verify_bundles(rc.decode(bytes.fromhex(c["receipt"])), tx, c["coin_type"], sources), None
            except (v.Invalid, rc.DecodeError, ValueError, IndexError) as e:
                got, err = None, str(e)
            if rust["ok"]:
                self.assertIsNotNone(got, f"{name}: Rust accepts, spec verifier says {err}")
                self.assertEqual([(o["index"], o["recipient"], o["value"], o["memo"]) for o in got["outputs"]],
                                 [(o["index"], o["recipient"], o["value"], o["memo"]) for o in rust["outputs"]], name)
                self.assertEqual([s["address"]["address"] for s in got["spends"] if "address" in s], rust["proven_addresses"], name)
                self.assertEqual([(s["index"], s["source"]["index"], s["source"]["value"]) for s in got["spends"] if "source" in s],
                                 [(x["spend"], x["index"], x["value"]) for x in rust.get("sources", [])], name)
            elif got is not None:
                # Allowed only when the Rust verifier failed on a Halo 2 proof.
                self.assertTrue(rust["error"].startswith(("BadProof", "BadAddressProof", "BadSourceProof")), f"{name}: Rust says {rust['error']}, spec verifier accepts")
                proof_only += 1
            if got is not None:
                for mine, theirs in zip(got["spends"], rust["public_inputs"]):
                    for k in ("anchor", "cv_net", "nf", "rk", "cmx"):
                        self.assertEqual(mine["public_inputs"][k], theirs[k], f"{name}: public input {k}")
                    if "address" in mine:
                        self.assertEqual(mine["address"]["public_inputs"]["anchor"], theirs["address_anchor"], f"{name}: address anchor")
                    if "source" in mine:
                        for k in ("anchor", "cv_net", "cmx"):
                            self.assertEqual(mine["source"]["public_inputs"][k], theirs["source"][k], f"{name}: source public input {k}")
                        sources_checked += 1
        print(f"{len(corpus['cases'])} cases agree ({proof_only} differ only in the Halo 2 proof, with identical public inputs; {sources_checked} source proofs' public inputs match)")


if __name__ == "__main__":
    unittest.main()

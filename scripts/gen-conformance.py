#!/usr/bin/env python3
"""Builds conformance/vectors.json from the real receipts in examples/.

Every verifier (Rust, wasm/JS, anything a third party writes) must give the expected result
for every vector. Mutated vectors flip one base64 character at spread-out positions, so they
cover the header, the message, the outputs, the proof and the signature."""
import json, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
ex = lambda p: (root / "examples" / p).read_text().strip()

def flip(s, i):
    c = s[i]
    return s[:i] + ("B" if c == "A" else "A") + s[i + 1:]

def spread(s, prefix, n):
    body = len(s) - len(prefix) - 2  # never the last character (it may carry only padding bits)
    return [len(prefix) + 1 + (body * k) // n for k in range(n)]

vectors = []
cases = [
    ("regtest", ex("regtest/receipt.txt"), ex("regtest/tx.hex"), 222, True, [{"zatoshis": 42_000_000, "memo": "Invoice 42: two coffees"}]),
    ("regtest-orchard", ex("regtest-orchard/receipt.txt"), ex("regtest-orchard/tx.hex"), 212, True, [{"zatoshis": 42_000_000, "memo": "Invoice 7: Orchard espresso"}]),
    ("regtest-crosspool", ex("regtest-crosspool/receipt.txt"), ex("regtest-crosspool/tx.hex"), int(ex("regtest-crosspool/height")), True, None),
    ("testnet", ex("testnet/receipt.txt"), ex("testnet/tx.hex"), 4_500_997, False, [{"zatoshis": 1_000_000, "memo": "Invoice 42: two coffees"}]),
    ("testnet-memo-withheld", ex("testnet/memo-withheld/receipt.txt"), ex("testnet/memo-withheld/tx.hex"), 4_500_997, False, [{"zatoshis": 1_000_000, "memo": None}]),
    ("testnet-sender-address", ex("testnet/receipt-with-sender-address.txt"), ex("testnet/sender-address-tx.hex"), 4_501_025, False, [{"zatoshis": 500_000, "memo": "Grant round 3: docs translation (Tolu)"}]),
]
for name, r, tx, h, regtest, outs in cases:
    base = {"type": "receipt", "raw_tx": tx, "height": h, "regtest": regtest}
    if regtest:
        base["heights"] = f"examples/{name}/heights.toml"
    expect = {"valid": True, "outputs": outs} if outs else {"valid": True}
    vectors.append({"name": f"{name}/valid", **base, "receipt": r, "expect": expect})
    for i in spread(r, "zip311r1", 24):
        vectors.append({"name": f"{name}/flip-{i}", **base, "receipt": flip(r, i), "expect": {"valid": False}})
    vectors.append({"name": f"{name}/truncated", **base, "receipt": r[:-40], "expect": {"valid": False}})
    vectors.append({"name": f"{name}/extra-bytes", **base, "receipt": r + "AAAA", "expect": {"valid": False}})
    vectors.append({"name": f"{name}/wrong-prefix", **base, "receipt": "zip311r2" + r[len("zip311r1"):], "expect": {"valid": False}})
# Source of funds (format v4): each vector also carries the source transaction(s), and a
# verifier must refuse the receipt without them, or with a source mined after the payment.
src_cases = [
    ("testnet-source-hidden", ex("testnet/source/receipt-source-hidden.txt"), ex("testnet/source/tx.hex"), 4_500_997, False, ex("testnet/source/source-tx.hex"), 4_500_984, None),
    ("testnet-source-value", ex("testnet/source/receipt-source-value.txt"), ex("testnet/source/tx.hex"), 4_500_997, False, ex("testnet/source/source-tx.hex"), 4_500_984, 12_500_000),
    ("regtest-source", ex("regtest-source/receipt-source-hidden.txt"), ex("regtest-source/tx.hex"), 538, True, ex("regtest-source/source-tx.hex"), 530, None),
    ("regtest-source-value", ex("regtest-source/receipt-source-value.txt"), ex("regtest-source/tx.hex"), 538, True, ex("regtest-source/source-tx.hex"), 530, 14_992_500),
]
for name, r, tx, h, regtest, stx, sh, value in src_cases:
    base = {"type": "receipt", "raw_tx": tx, "height": h, "regtest": regtest, "source_txs": [{"raw_tx": stx, "height": sh}]}
    if regtest:
        base["heights"] = "examples/regtest-source/heights.toml"
    vectors.append({"name": f"{name}/valid", **base, "receipt": r, "expect": {"valid": True, "sources": [{"zatoshis": value}]}})
    for i in spread(r, "zip311r1", 12):
        vectors.append({"name": f"{name}/flip-{i}", **base, "receipt": flip(r, i), "expect": {"valid": False}})
    vectors.append({"name": f"{name}/no-source-tx", **base, "source_txs": [], "receipt": r, "expect": {"valid": False}})
    vectors.append({"name": f"{name}/source-after-payment", **base, "source_txs": [{"raw_tx": stx, "height": h + 1}], "receipt": r, "expect": {"valid": False}})
# Made before 2026-10-15, when address proofs took cv_net from the prover (forgeable; see
# docs/CLAIM.md). Honest when made, refused now: their cv_net is not ValueCommit_0(1).
vectors.append({"name": "pre-fix/receipt-with-sender-address", "type": "receipt", "raw_tx": ex("testnet/sender-address-tx.hex"), "height": 4_501_025, "regtest": False, "receipt": ex("testnet/pre-fix/receipt-with-sender-address.txt"), "expect": {"valid": False}})
# A receipt checked against some other transaction.
vectors.append({"name": "cross/regtest-receipt-testnet-tx", "type": "receipt", "receipt": cases[0][1], "raw_tx": cases[1][2], "height": 4_500_997, "regtest": True, "heights": "examples/regtest/heights.toml", "expect": {"valid": False}})

# Incoming receipts (the recipient proves it was paid).
import re as _re
inc = _re.search(r"zrcin1[A-Za-z0-9_-]+", ex("testnet/incoming/receipt.txt")).group(0)
ib = {"type": "incoming", "raw_tx": ex("testnet/incoming/tx.hex"), "height": 4_500_997, "regtest": False}
vectors.append({"name": "incoming/valid", **ib, "receipt": inc, "expect": {"valid": True, "outputs": [{"zatoshis": 1_000_000, "memo": "Invoice 42: two coffees"}]}})
for i in spread(inc, "zrcin1", 16):
    vectors.append({"name": f"incoming/flip-{i}", **ib, "receipt": flip(inc, i), "expect": {"valid": False}})
vectors.append({"name": "incoming/other-tx", **ib, "raw_tx": ex("testnet/sender-address-tx.hex"), "height": 4_501_025, "receipt": inc, "expect": {"valid": False}})
vectors.append({"name": "incoming/truncated", **ib, "receipt": inc[:-20], "expect": {"valid": False}})

s = ex("testnet/sign-in.txt")
si = {"type": "sign_in", "domain": "kemis-coffee.test", "nonce": "example-nonce-0001"}
vectors.append({"name": "sign-in/valid", **si, "sign_in": s, "expect": {"valid": True, "network": "testnet"}})
vectors.append({"name": "sign-in/other-domain", **si, "domain": "kemis-coffee.test.evil", "sign_in": s, "expect": {"valid": False}})
vectors.append({"name": "sign-in/other-nonce", **si, "nonce": "example-nonce-0002", "sign_in": s, "expect": {"valid": False}})
for i in spread(s, "zsig1", 16):
    vectors.append({"name": f"sign-in/flip-{i}", **si, "sign_in": flip(s, i), "expect": {"valid": False}})
vectors.append({"name": "sign-in/truncated", **si, "sign_in": s[:-10], "expect": {"valid": False}})
vectors.append({"name": "sign-in/pre-fix", **si, "sign_in": ex("testnet/pre-fix/sign-in.txt"), "expect": {"valid": False}})

# "Was I paid" expectations: a valid receipt checked against an expected payee and minimum. Every
# false acceptance found in review lived in this layer, so every verifier runs these too.
merchant, sender, merchant_main = ex("testnet/merchant.ua"), ex("testnet/sender.ua"), ex("testnet/merchant-mainnet.ua")
eb = {"type": "expectation", "raw_tx": ex("testnet/tx.hex"), "height": 4_500_997, "regtest": False}
for name, receipt, addr, minz, ok in [
    ("pays-merchant", ex("testnet/receipt.txt"), merchant, None, True),
    ("pays-merchant-exact-minimum", ex("testnet/receipt.txt"), merchant, 1_000_000, True),
    ("below-minimum", ex("testnet/receipt.txt"), merchant, 1_000_001, False),
    ("wrong-payee", ex("testnet/receipt.txt"), sender, None, False),
    ("mainnet-address-same-receiver", ex("testnet/receipt.txt"), merchant_main, None, False),
    ("memo-withheld-output-does-not-count", ex("testnet/memo-withheld/receipt.txt"), merchant, None, False),
]:
    raw = ex("testnet/memo-withheld/tx.hex") if "memo-withheld" in name else eb["raw_tx"]
    e = {"name": f"expect/{name}", **eb, "raw_tx": raw, "receipt": receipt, "expect_address": addr, "expect": {"valid": True, "satisfied": ok}}
    if minz is not None:
        e["min_zatoshis"] = minz
    vectors.append(e)

# Known answers for every valid receipt, computed by the independent spec verifier (written from
# the protocol specification): the signing digest, each spend's proof public inputs and each
# opened output. A new implementation can compare its intermediate values, not just yes/no.
import sys
sys.path.insert(0, str(root / "spec-verifier"))
from specverify import receipt as rc, verify as sv  # noqa: E402
for v in vectors:
    if v["type"] != "receipt" or not v["expect"]["valid"]:
        continue
    t = v["receipt"]
    r = rc.decode(rc.b64decode(t[len("zip311r1"):]))
    coin = r.coin_type
    rep = sv.verify(r.unsigned_bytes + b"".join(r.sigs), bytes.fromhex(v["raw_tx"]), coin,
                    [bytes.fromhex(s["raw_tx"]) for s in v.get("source_txs", [])])
    v["known_answers"] = {
        "signing_digest": sv.signing_digest(r).hex(),
        "spends": [{"index": sp["index"], "public_inputs": sp["public_inputs"]} for sp in rep["spends"]],
        "outputs": [{"index": o["index"], "recipient_raw": o["recipient"], "zatoshis": o["value"]} for o in rep["outputs"]],
    }

out = {"version": 1, "description": "Conformance vectors for ZIP 311 receipts and Sign in with Zcash. Generated by scripts/gen-conformance.py; do not edit.", "vectors": vectors}
(root / "conformance" / "vectors.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"{len(vectors)} vectors")

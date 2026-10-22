#!/usr/bin/env bash
# Every check that needs no build, install or wallet, in about two minutes: the independent spec
# verifier against the conformance vectors and adversarial corpus, the npm package's tests, and
# (if a `receipts` binary is on PATH or in $RECEIPTS) the real and edited testnet receipts.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== spec verifier (Python, written from the protocol specification)"
echo "   (it checks everything but the Halo 2 proofs; for the adversarial cases that only a Halo 2"
echo "   proof tells apart, it confirms both verifiers derive the same public inputs)"
python3 -m unittest discover -s spec-verifier/tests 2>&1 | tail -3
echo "== npm package (WebAssembly verifier, conformance vectors, offline testnet receipts)"
echo "   (the skipped tests call a running Receipts API: RECEIPTS_URL and RECEIPTS_KEY)"
(cd packages/zcash-receipts && node --test test/*.test.js 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)")
R=${RECEIPTS:-$(command -v receipts || true)}
if [ -n "$R" ]; then
  echo "== CLI: the real testnet receipt, fetched by block, then the edited copy"
  "$R" verify "$(tr -d '\n' < examples/testnet/receipt-link.txt)" 2>&1 | head -3
  if "$R" verify @examples/testnet/receipt-edited.txt >/dev/null 2>&1; then echo "edited receipt ACCEPTED (bug)"; exit 1; else echo "edited receipt refused"; fi
else
  echo "== CLI skipped (no receipts binary; cargo install --locked --path crates/receipts-cli)"
fi

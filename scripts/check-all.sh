#!/usr/bin/env bash
# Every check that needs no build, install or wallet, in about two minutes: the independent spec
# verifier against the conformance vectors and adversarial corpus, the npm package's tests, and
# (if a `receipts` binary is on PATH or in $RECEIPTS) the real and edited testnet receipts, and the
# verifier page in headless Chrome.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== spec verifier (Python, written from the protocol specification)"
echo "   (it checks everything but the Halo 2 proofs; for the adversarial cases that only a Halo 2"
echo "   proof tells apart, it confirms both verifiers derive the same public inputs)"
python3 -m unittest discover -s spec-verifier/tests 2>&1 | tail -3
echo "== npm package (WebAssembly verifier, conformance vectors, offline testnet receipts)"
echo "   (the skipped tests call a running Receipts API; with a receipts binary they run below)"
(cd packages/zcash-receipts && node --test test/*.test.js 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)")
R=${RECEIPTS:-$(command -v receipts || true)}
if [ -n "$R" ]; then
  echo "== CLI: the real testnet receipt, fetched by block, then the edited copy"
  "$R" verify "$(tr -d '\n' < examples/testnet/receipt-link.txt)" > "${TMPDIR:-/tmp}/receipts-verify.txt" 2>&1 && head -3 "${TMPDIR:-/tmp}/receipts-verify.txt" || { cat "${TMPDIR:-/tmp}/receipts-verify.txt"; exit 1; }
  if "$R" verify @examples/testnet/receipt-edited.txt >/dev/null 2>&1; then echo "edited receipt ACCEPTED (bug)"; exit 1; else echo "edited receipt refused"; fi
  echo "== CLI: a receipt checked against the request it answers (payee, amount, challenge)"
  L=$(tr -d '\n' < examples/testnet/request-answer-link.txt); TO=$(echo "$L" | grep -o 'to=[a-z0-9]*' | cut -c4-)
  "$R" verify "$L" --challenge e1e14a5d182a --expect-address "$TO" --min 0.01 >/dev/null 2>&1 && ! "$R" verify "$L" --challenge ffffff >/dev/null 2>&1 && ! "$R" verify "$L" --expect-address "$TO" --min 0.02 >/dev/null 2>&1 && echo "request checks: right one passes, other challenge and higher minimum refused" || { echo "request checks failed"; exit 1; }
  ! "$R" verify @examples/testnet/batch-link.txt --challenge 7f3a9c21e0b4 >/dev/null 2>&1 && echo "request checks on a batch: refused, not skipped" || { echo "a batch passed --challenge"; exit 1; }
  echo "== CLI: both into a spreadsheet and a case file"
  REC=$(mktemp -d)
  "$R" export @examples/testnet/receipt-link.txt @examples/testnet/receipt-edited.txt --records "$REC" 2>/dev/null > "$REC/out.csv" || true
  grep -q '^examples/testnet/receipt-link.txt,verified,571de6e4' "$REC/out.csv" && grep -q '^examples/testnet/receipt-edited.txt,invalid' "$REC/out.csv" && [ -f "$REC/001-571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73.json" ] && echo "export: 1 verified row, 1 invalid row, 1 record" || { echo "export check failed"; cat "$REC/out.csv"; exit 1; }
  echo "== SDKs against a throwaway sandbox API (the tests skipped above, and the Python SDK's)"
  API_DB=$(mktemp -d)/api.db
  API_PORT=$((8900 + RANDOM % 90))
  "$R" shop serve --listen "127.0.0.1:$API_PORT" --db "$API_DB" > "$API_DB.log" 2>&1 &
  API_PID=$!
  KEY=""
  for _ in $(seq 1 60); do KEY=$(cat "$API_DB.log" "$API_DB.keys" 2>/dev/null | grep -o 'rcpt_test_[A-Za-z0-9_]*' | head -1 || true); [ -n "$KEY" ] && curl -sf "http://127.0.0.1:$API_PORT/v1/health" >/dev/null && break; sleep 1; done
  (cd packages/zcash-receipts && RECEIPTS_URL="http://127.0.0.1:$API_PORT" RECEIPTS_KEY="$KEY" node --test test/*.test.js 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)")
  (cd packages/receipts-python && RECEIPTS_URL="http://127.0.0.1:$API_PORT" RECEIPTS_KEY="$KEY" python3 -m unittest discover -s tests 2>&1 | tail -1)
  kill "$API_PID" 2>/dev/null || true
  RAN="all 7 sections"
else
  echo "== CLI skipped (no receipts binary; cargo install --locked --path crates/receipts-cli)"
  RAN="3 of 7 sections (the CLI, request, export and SDK-against-API sections need a receipts binary)"
fi
echo "== browser: the verifier page in headless Chrome (skipped if Chrome isn't installed)"
rm -rf web/zcash-receipts && mkdir -p web/zcash-receipts
cp -R packages/zcash-receipts/{index.js,grpc.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zcash-receipts/
P=$((5400 + RANDOM % 500))
python3 -m http.server --bind 127.0.0.1 -d web "$P" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1
# One retry: on a loaded machine the first warm-up of the verifier can exceed the time limit.
node scripts/browser-smoke.mjs "http://127.0.0.1:$P/" || { echo "(retrying once)"; node scripts/browser-smoke.mjs "http://127.0.0.1:$P/"; }
echo
echo "check-all: ran $RAN"

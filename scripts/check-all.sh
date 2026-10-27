#!/usr/bin/env bash
# Every check that needs no build, install or wallet, in about two minutes: the independent spec
# verifier against the conformance vectors and adversarial corpus, the npm package's tests, and
# (if a `zceipt` binary is on PATH or in $ZCEIPT) the real and edited testnet receipts, and the
# verifier page in headless Chrome.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== spec verifier (Python, written from the protocol specification)"
echo "   (it checks everything but the Halo 2 proofs; for the adversarial cases that only a Halo 2"
echo "   proof tells apart, it confirms both verifiers derive the same public inputs)"
python3 -m unittest discover -s spec-verifier/tests 2>&1 | tail -3
echo "== npm package (WebAssembly verifier, conformance vectors, offline testnet receipts)"
echo "   (the skipped tests call a running Zceipt API; with a zceipt binary they run below)"
(cd packages/zceipt && node --test test/*.test.js 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)")
R=${ZCEIPT:-$(command -v zceipt || true)}
if [ -n "$R" ]; then
  echo "== CLI: the real testnet receipt, fetched by block, then the edited copy"
  "$R" verify "$(tr -d '\n' < examples/testnet/receipt-link.txt)" > "${TMPDIR:-/tmp}/zceipt-verify.txt" 2>&1 && head -3 "${TMPDIR:-/tmp}/zceipt-verify.txt" || { cat "${TMPDIR:-/tmp}/zceipt-verify.txt"; exit 1; }
  if "$R" verify @examples/testnet/receipt-edited.txt >/dev/null 2>&1; then echo "edited receipt ACCEPTED (bug)"; exit 1; else echo "edited receipt refused"; fi
  echo "== CLI: a receipt checked against the request it answers (payee, amount, challenge)"
  L=$(tr -d '\n' < examples/testnet/request-answer-link.txt); TO=$(echo "$L" | grep -o 'to=[a-z0-9]*' | cut -c4-)
  "$R" verify "$L" --challenge e1e14a5d182a --expect-address "$TO" --min 0.01 >/dev/null 2>&1 && ! "$R" verify "$L" --challenge ffffff >/dev/null 2>&1 && ! "$R" verify "$L" --expect-address "$TO" --min 0.02 >/dev/null 2>&1 && echo "request checks: right one passes, other challenge and higher minimum refused" || { echo "request checks failed"; exit 1; }
  ! "$R" verify @examples/testnet/batch-link.txt --challenge 7f3a9c21e0b4 >/dev/null 2>&1 && echo "request checks on a batch: refused, not skipped" || { echo "a batch passed --challenge"; exit 1; }
  # One request answered by a batch of two payments: every receipt signs it, the total is checked.
  B="#$(cat examples/testnet/batch-request/link.txt)"; M=$(cat examples/testnet/merchant.ua)
  "$R" verify "$B" --challenge b7e2c41a9d03 --expect-address "$M" --min 0.01 >/dev/null 2>&1 && ! "$R" verify "$B" --challenge 000000aaaaaa >/dev/null 2>&1 && ! "$R" verify "$B" --expect-address "$M" --min 0.02 >/dev/null 2>&1 && echo "a batch answers one request: right challenge and total pass, others refused" || { echo "batch request checks failed"; exit 1; }
  # Proof of income: at least 0.02 TAZ across four payments, no amount shown.
  I=examples/testnet/income/proof.txt
  "$R" verify @$I --challenge 10a4e7c3d2b1 --min 0.02 >/dev/null 2>&1 && ! "$R" verify @$I --min 0.03 >/dev/null 2>&1 && ! "$R" verify @$I --challenge 000000aaaaaa >/dev/null 2>&1 && echo "proof of income: at least 0.02 across 4 payments, more refused" || { echo "proof of income checks failed"; exit 1; }
  # Signed under one of a published key set: holds for the set, refused for another.
  K="#$(cat examples/testnet/keyset/link.txt)"; KS=$(mktemp); head -2 examples/testnet/keyset/keys.txt > "$KS"
  "$R" verify "$K" --key-set examples/testnet/keyset/keys.txt 2>/dev/null | grep >/dev/null "one of the 4 keys" && ! "$R" verify "$K" --key-set "$KS" >/dev/null 2>&1 && ! "$R" verify @$I --min-payments 5 >/dev/null 2>&1 && echo "key set: one of 4 published keys, another set refused; income needs 5 payments, has 4: refused" || { echo "key-set checks failed"; exit 1; }
  rm -f "$KS"
  # The public demo wallet: anyone can sign for it, so it shows as a demo and answers no challenge.
  D=$(mktemp); "$R" demo -m "challenge:abcdef12" 2>/dev/null > "$D"
  "$R" verify @"$D" 2>/dev/null | grep >/dev/null "public demo wallet" && ! "$R" verify @"$D" --challenge abcdef12 >/dev/null 2>&1 && echo "a demo-wallet receipt says so and answers no challenge" || { echo "a demo-wallet receipt passed as a real one"; exit 1; }
  rm -f "$D"
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
  (cd packages/zceipt && ZCEIPT_URL="http://127.0.0.1:$API_PORT" ZCEIPT_KEY="$KEY" node --test test/*.test.js 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)")
  (cd packages/zceipt-python && ZCEIPT_URL="http://127.0.0.1:$API_PORT" ZCEIPT_KEY="$KEY" python3 -m unittest discover -s tests 2>&1 | tail -1)
  kill "$API_PID" 2>/dev/null || true
  RAN="all 7 sections"
else
  echo "== CLI skipped (no zceipt binary; cargo install --locked --path crates/zceipt-cli)"
  RAN="3 of 7 sections (the CLI, request, export and SDK-against-API sections need a zceipt binary)"
fi
echo "== browser: the verifier page in headless Chrome (skipped if Chrome isn't installed)"
rm -rf web/zceipt && mkdir -p web/zceipt
cp -R packages/zceipt/{index.js,grpc.js,maker.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zceipt/
P=$((5400 + RANDOM % 500))
python3 -m http.server --bind 127.0.0.1 -d web "$P" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1
# One retry: on a loaded machine the first warm-up of the verifier can exceed the time limit.
node scripts/browser-smoke.mjs "http://127.0.0.1:$P/" || { echo "(retrying once)"; node scripts/browser-smoke.mjs "http://127.0.0.1:$P/"; }
echo
echo "check-all: ran $RAN"

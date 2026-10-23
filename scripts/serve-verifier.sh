#!/usr/bin/env bash
# Serves the browser verifier from the committed WebAssembly build: no Rust, no wallet, no keys.
# The page has buttons for a real testnet receipt (PAID TO YOU), an edited copy (NOT VALID) and a
# claim by someone who only saw the payment.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-5321}"
rm -rf web/zcash-receipts
mkdir -p web/zcash-receipts
cp -R packages/zcash-receipts/{index.js,grpc.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zcash-receipts/
base="http://127.0.0.1:$PORT/"
echo "Open $base and click \"Try a real testnet receipt\" (PAID TO YOU) or \"Try an edited copy\" (NOT VALID)."
echo "The receipt stays in the #fragment and never leaves the browser; the page fetches the payment"
echo "among its block's transactions from zcash-testnet.chainsafe.dev, so the server sees a set, not the one."
echo "Serving web/ on $base (Ctrl-C to stop)."
exec python3 -m http.server --bind 127.0.0.1 -d web "$PORT"

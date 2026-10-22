#!/usr/bin/env bash
# Serves the browser verifier from the committed WebAssembly build: no Rust, no wallet, no keys.
# The page has buttons for a real testnet receipt (VERIFIED) and the same receipt with its signed
# note edited (refused).
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-5321}"
rm -rf web/zcash-receipts
mkdir -p web/zcash-receipts
cp -R packages/zcash-receipts/{index.js,grpc.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zcash-receipts/
base="http://127.0.0.1:$PORT/"
echo "Open $base and click \"Try a real testnet receipt\" (VERIFIED) or \"Try an edited copy\" (NOT VALID)."
echo "The receipt stays in the #fragment and never leaves the browser; the page fetches block 4,500,997"
echo "from zcash-testnet.chainsafe.dev. Direct links, if you prefer:"
echo "  real:   ${base}#$(tr -d '\n' < examples/testnet/receipt.txt)&h=4500997"
echo "  edited: ${base}#$(tr -d '\n' < examples/testnet/receipt-edited.txt)&h=4500997"
echo
echo "Serving web/ on $base (Ctrl-C to stop)."
exec python3 -m http.server --bind 127.0.0.1 -d web "$PORT"

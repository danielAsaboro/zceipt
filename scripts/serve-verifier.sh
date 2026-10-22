#!/usr/bin/env bash
# Serves the browser verifier from the committed WebAssembly build: no Rust, no wallet, no keys.
# Prints two links: a real testnet receipt (VERIFIED) and the same receipt with one word of its
# note changed (refused).
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-5321}"
rm -rf web/zcash-receipts
mkdir -p web/zcash-receipts
cp -R packages/zcash-receipts/{index.js,grpc.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zcash-receipts/
base="http://127.0.0.1:$PORT/"
echo "Real testnet receipt (0.01 TAZ, \"Invoice 42: two coffees\", block 4,500,997):"
echo "  ${base}#$(tr -d '\n' < examples/testnet/receipt.txt)&h=4500997"
echo
echo "The same receipt with its note edited from \"Order #42\" to \"Order #43\" (must be refused):"
echo "  ${base}#$(tr -d '\n' < examples/testnet/receipt-edited.txt)&h=4500997"
echo
echo "Serving web/ on $base (Ctrl-C to stop). The page fetches block 4,500,997 from"
echo "zcash-testnet.chainsafe.dev; the receipt itself stays in the #fragment and never leaves the browser."
exec python3 -m http.server --bind 127.0.0.1 -d web "$PORT"

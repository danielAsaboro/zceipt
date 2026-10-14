#!/usr/bin/env bash
# Builds the browser verifier: Rust -> wasm32 -> wasm-bindgen -> web/pkg.
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in wasm-bindgen wasm-tools; do
  command -v "$tool" >/dev/null || { echo "error: $tool is required (cargo install wasm-bindgen-cli --version 0.2.104; cargo install wasm-tools)" >&2; exit 1; }
done
rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown || { echo "error: run: rustup target add wasm32-unknown-unknown" >&2; exit 1; }
# Strip local paths (home directory, registry) from panic messages in the wasm.
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=." \
  cargo build -p receipts-wasm --release --target wasm32-unknown-unknown
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
PKG=packages/zcash-receipts/pkg
rm -rf "$PKG"
wasm-bindgen --target web --out-dir "$PKG" "$TARGET_DIR"/wasm32-unknown-unknown/release/receipts_wasm.wasm

# zcash_primitives links secp256k1 for transparent signatures. Receipts never touch
# transparent signing, and the C library is not compiled for wasm32-unknown-unknown, so the
# module imports three context functions from "env". Satisfy them with stubs that fail
# loudly if they are ever called.
syms=$(wasm-tools print "$PKG"/receipts_wasm_bg.wasm | grep -o '(import "env" "[A-Za-z0-9_]*"' | sed 's/.*"env" "//; s/"$//' | sort -u)
if [ -n "$syms" ]; then
  stub="const __wbg_star0 = {"
  for s in $syms; do stub="$stub $s: () => { throw new Error('secp256k1 is not available in the receipts verifier'); },"; done
  stub="$stub };"
  python3 - "$stub" <<'PY'
import sys
p = "packages/zcash-receipts/pkg/receipts_wasm.js"
t = open(p).read()
t = t.replace("import * as __wbg_star0 from 'env';", sys.argv[1], 1)
open(p, "w").write(t)
PY
fi
# The page serves the package as-is (no bundler).
rm -rf web/zcash-receipts web/pkg
mkdir -p web/zcash-receipts
cp -R packages/zcash-receipts/{index.js,grpc.js,widget.js,worker.js,background.js,client.js,react.js,package.json,pkg} web/zcash-receipts/
grep -q "from 'env'" "$PKG"/receipts_wasm.js && { echo "error: env imports were not stubbed" >&2; exit 1; }
echo "web build OK: $(du -h "$PKG"/receipts_wasm_bg.wasm | cut -f1) wasm"

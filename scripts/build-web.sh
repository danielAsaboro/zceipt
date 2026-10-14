#!/usr/bin/env bash
# Builds the browser verifier: Rust -> wasm32 -> wasm-bindgen -> web/pkg.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p receipts-wasm --release --target wasm32-unknown-unknown
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
rm -rf web/pkg
wasm-bindgen --target web --out-dir web/pkg "$TARGET_DIR"/wasm32-unknown-unknown/release/receipts_wasm.wasm

# zcash_primitives links secp256k1 for transparent signatures. Receipts never touch
# transparent signing, and the C library is not compiled for wasm32-unknown-unknown, so the
# module imports three context functions from "env". Satisfy them with stubs that fail
# loudly if they are ever called.
syms=$(wasm-tools print web/pkg/receipts_wasm_bg.wasm | grep -o '(import "env" "[A-Za-z0-9_]*"' | sed 's/.*"env" "//; s/"$//' | sort -u || true)
if [ -n "$syms" ]; then
  stub="const __wbg_star0 = {"
  for s in $syms; do stub="$stub $s: () => { throw new Error('secp256k1 is not available in the receipts verifier'); },"; done
  stub="$stub };"
  python3 - "$stub" <<'PY'
import sys
p = "web/pkg/receipts_wasm.js"
t = open(p).read()
t = t.replace("import * as __wbg_star0 from 'env';", sys.argv[1], 1)
open(p, "w").write(t)
PY
fi
ls -la web/pkg

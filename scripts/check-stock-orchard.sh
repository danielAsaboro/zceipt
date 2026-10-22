#!/usr/bin/env bash
# Builds receipts-core against stock orchard 0.16 from crates.io (no vendor/ patch) and without
# the `orchard-ext` feature, as a wallet that depends on the crate would. Receipts v1-v4,
# batches, source proofs, sign-in, payment requests and proof of funds all build this way.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK=$(mktemp -d "${TMPDIR:-/tmp}/receipts-stock.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/crates"
cp -R crates/receipts-core "$WORK/crates/"
rm -rf "$WORK/crates/receipts-core/fuzz"
cp Cargo.lock rust-toolchain.toml "$WORK/"
python3 - "$WORK/Cargo.toml" <<'PY'
import re, sys
s = open("Cargo.toml").read()
s = re.sub(r'members = \[[^\]]*\]', 'members = ["crates/receipts-core"]', s)
s = s[: s.index("[patch.crates-io]")]
open(sys.argv[1], "w").write(s)
PY
cd "$WORK"
cargo check --lib -p receipts-core --no-default-features
cargo tree -p receipts-core -i orchard --depth 0 | head -1
echo "receipts-core builds on stock orchard (no orchard-ext feature)."

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
mkdir -p "$WORK/examples" && cp -R examples/testnet "$WORK/examples/"
python3 - "$WORK/Cargo.toml" <<'PY'
import re, sys
s = open("Cargo.toml").read()
s = re.sub(r'members = \[[^\]]*\]', 'members = ["crates/receipts-core"]', s)
s = s[: s.index("[patch.crates-io]")]
open(sys.argv[1], "w").write(s)
PY
# The crate's own dev-dependency turns orchard-ext on for its tests; drop it here.
sed -i.bak '/^receipts-core = { path = "\.", features = /d' "$WORK/crates/receipts-core/Cargo.toml"
cd "$WORK"
# The ZIP 311 profile alone, then with every extension.
cargo check --lib -p receipts-core --no-default-features
cargo check --lib -p receipts-core --no-default-features --features extensions
cargo tree -p receipts-core -i orchard --depth 0 | head -1
# Real testnet receipts through the public API, on stock orchard: valid, edited, altered proof.
cargo test --release -q -p receipts-core --no-default-features --test stock_orchard
echo "receipts-core builds and verifies real receipts on stock orchard (no orchard-ext feature)."

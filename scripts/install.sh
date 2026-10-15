#!/usr/bin/env bash
# Install `receipts` from this checkout and show the tour. Needs Rust (rustup); the pinned
# toolchain is installed automatically.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo "Rust is required: https://rustup.rs" >&2; exit 1; }
cargo install --locked --path crates/receipts-cli
echo
receipts --version 2>/dev/null || true
receipts demo --no-wait
echo
echo "Installed. Next: 'receipts demo' (keeps the server up), 'receipts serve', 'receipts doctor'."

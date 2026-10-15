#!/usr/bin/env bash
# Install `receipts` from this checkout and show the tour. Needs Rust (rustup); the pinned
# toolchain is installed automatically.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo "Rust is required: https://rustup.rs" >&2; exit 1; }
cargo install --locked --path crates/receipts-cli
# Fresh rustup installs often haven't put cargo's bin dir on PATH yet.
BIN="${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin"
command -v receipts >/dev/null || export PATH="$BIN:$PATH"
echo
receipts --version 2>/dev/null || true
receipts demo --no-wait
echo
echo "Installed in $BIN (add it to your PATH if your shell can't find 'receipts'). Next: 'receipts demo' (keeps the server up), 'receipts serve', 'receipts doctor'."

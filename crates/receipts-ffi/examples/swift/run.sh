#!/usr/bin/env bash
# Builds the library, compiles the generated Swift binding with main.swift, and runs it (macOS).
set -euo pipefail
cd "$(dirname "$0")/../../../.."
T="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p receipts-ffi
out=$(mktemp -d)
swiftc -O -module-name ReceiptsDemo -I crates/receipts-ffi/bindings/swift -Xcc -fmodule-map-file=crates/receipts-ffi/bindings/swift/receipts_ffiFFI.modulemap \
  "$T/release/libreceipts_ffi.a" -framework Security -framework SystemConfiguration -framework CoreFoundation crates/receipts-ffi/bindings/swift/receipts_ffi.swift crates/receipts-ffi/examples/swift/main.swift -o "$out/demo"
"$out/demo" "$PWD/examples/testnet/demo/"

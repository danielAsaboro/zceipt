#!/usr/bin/env bash
# Builds the library, compiles the generated Swift binding with main.swift, and runs it (macOS).
set -euo pipefail
cd "$(dirname "$0")/../../../.."
T="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p zceipt-ffi
out=$(mktemp -d)
swiftc -O -module-name ReceiptsDemo -I crates/zceipt-ffi/bindings/swift -Xcc -fmodule-map-file=crates/zceipt-ffi/bindings/swift/zceipt_ffiFFI.modulemap \
  "$T/release/libzceipt_ffi.a" -framework Security -framework SystemConfiguration -framework CoreFoundation crates/zceipt-ffi/bindings/swift/zceipt_ffi.swift crates/zceipt-ffi/examples/swift/main.swift -o "$out/demo"
"$out/demo" "$PWD/examples/testnet/demo/"

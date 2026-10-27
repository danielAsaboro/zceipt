#!/usr/bin/env bash
# Builds a release archive of the zceipt CLI for this machine into dist/, with its SHA-256,
# the same layout the release workflow attaches to a version tag.
set -euo pipefail
cd "$(dirname "$0")/.."
T="${CARGO_TARGET_DIR:-target}"
cargo build --release --locked -p zceipt-cli
target=$(rustc -vV | sed -n 's/^host: //p')
name="zceipt-$(git describe --tags --always)-$target"
mkdir -p dist && rm -rf "dist/$name" && mkdir "dist/$name"
cp "$T/release/zceipt" README.md LICENSE* "dist/$name/"
(cd dist && tar czf "$name.tar.gz" "$name" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256" && rm -rf "$name")
echo "dist/$name.tar.gz"

#!/usr/bin/env bash
# Runs the vendored orchard crate's own tests, including the claim circuit's witness-mutation test
# (every private witness changed on its own must be refused). The crate is not a workspace member,
# so it is copied to a scratch directory with its own workspace table and the repository's lockfile
# and toolchain; dependencies are fetched from crates.io.
#   ./scripts/test-vendored-orchard.sh [test filter, default claim::tests]
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d "${TMPDIR:-/tmp}/orchard-test.XXXXXX")
trap 'rm -rf "$W"' EXIT
(cd vendor/orchard && tar cf - --exclude=target .) | (cd "$W" && tar xf -)
printf '\n[workspace]\n' >> "$W/Cargo.toml"
cp Cargo.lock rust-toolchain.toml "$W/"
cd "$W"
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$W/target} cargo test --release --lib "${1:-claim::tests}"

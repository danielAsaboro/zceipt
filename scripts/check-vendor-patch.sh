#!/usr/bin/env bash
# Applies vendor/orchard-0.16.0-zceipt.patch to the published orchard 0.16.0 and checks the
# result is exactly vendor/orchard/src, so the patch is the whole diff a reviewer needs.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d "${TMPDIR:-/tmp}/orchard-patch.XXXXXX")
trap 'rm -rf "$W"' EXIT
curl -sL https://static.crates.io/crates/orchard/orchard-0.16.0.crate | tar xz -C "$W"
(cd "$W/orchard-0.16.0" && patch -p1 -s < "$OLDPWD/vendor/orchard-0.16.0-zceipt.patch")
diff -r "$W/orchard-0.16.0/src" vendor/orchard/src && echo "the patch reproduces vendor/orchard/src"

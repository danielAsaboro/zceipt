#!/usr/bin/env bash
# Builds zcash-devtool with the NU7 port and the `wallet receipt` command:
# upstream zcash-devtool at 5a26ee8, minus removed-files.txt, plus zcash-devtool-nu7.patch.
#   ./integrations/zcash-devtool/build.sh [dir]     # default: ./target/zcash-devtool
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:-$here/../../target/zcash-devtool}"
if [ ! -d "$dir/.git" ]; then
  git clone --quiet https://github.com/zcash/zcash-devtool.git "$dir"
fi
cd "$dir"
git checkout --quiet 5a26ee8
# The port drops commands this build doesn't need (PCZT, migration, inspect, TUI…), which don't
# compile against the NU7 librustzcash revision Zceipt pins; then applies the changes.
xargs rm -f < "$here/removed-files.txt"
git apply --whitespace=nowarn "$here/zcash-devtool-nu7.patch"
# Point the zceipt-wallet dependency and the orchard patch at this checkout.
repo="$(cd "$here/../.." && pwd)"
sed -i.bak "s#@ZCEIPT_REPO@#$repo#g" Cargo.toml && rm -f Cargo.toml.bak
cargo build --release
echo "built $dir/target/release/zcash-devtool"

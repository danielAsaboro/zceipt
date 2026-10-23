#!/usr/bin/env bash
# Every test in the repository: the Rust workspace (tests and clippy), the independent spec
# verifier, the npm, Python and Go SDKs (live against a throwaway local API), and, when
# ZCASH_DEVTOOL and LIGHTWALLETD are set, the end-to-end run on a private regtest chain.
#   ./scripts/test-all.sh
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
step() { echo; echo "== $1"; }
check() { if "$@"; then :; else echo "FAILED: $*"; fail=1; fi; }

step "Rust workspace"
check cargo clippy --workspace --release --quiet -- -D warnings
cargo test --workspace --release --quiet > target/test-all.log 2>&1 || { tail -30 target/test-all.log; fail=1; }
grep -E "^test result" target/test-all.log | awk '{p+=$4; f+=$6} END {print "  passed " p ", failed " f}'

step "spec verifier"
check python3 -m unittest discover -s spec-verifier/tests

R="${CARGO_TARGET_DIR:-target}/release/receipts"
cargo build --release --quiet -p receipts-cli || fail=1
DB=$(mktemp -d)/api.db
PORT=$((8800 + RANDOM % 100))
"$R" serve --listen "127.0.0.1:$PORT" --db "$DB" > "$DB.log" 2>&1 &
API=$!
trap 'kill $API 2>/dev/null' EXIT
sleep 2
export RECEIPTS_URL="http://127.0.0.1:$PORT" RECEIPTS_KEY
RECEIPTS_KEY=$(grep -o "rcpt_test_[A-Za-z0-9_]*" "$DB.log" | head -1)

step "npm package (live SDK tests against the local API)"
(cd packages/zcash-receipts && node --test test/*.test.js 2>&1 | grep -E "^ℹ (pass|fail|skipped)|^not ok") || true
(cd packages/zcash-receipts && node --test test/*.test.js >/dev/null 2>&1) || { echo "FAILED: npm tests"; fail=1; }

step "Python SDK"
(cd packages/receipts-python && check python3 -m unittest discover -s tests)

step "Go SDK"
(cd packages/receipts-go && check go test -count=1 ./...)
kill $API 2>/dev/null
unset RECEIPTS_URL RECEIPTS_KEY

if [ -n "${ZCASH_DEVTOOL:-}" ] && [ -n "${LIGHTWALLETD:-}" ]; then
  step "regtest end to end"
  RECEIPTS="$R" ./scripts/e2e-regtest.sh > target/e2e.log 2>&1 || fail=1; grep -E -A3 "^  FAIL" target/e2e.log; grep -E "passed, " target/e2e.log
else
  step "regtest end to end skipped (set ZCASH_DEVTOOL and LIGHTWALLETD)"
fi

echo
[ $fail -eq 0 ] && echo "all tests passed" || { echo "some tests failed"; exit 1; }

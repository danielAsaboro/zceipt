#!/usr/bin/env bash
# End-to-end on a private Zebra regtest chain, both shielded pools, one command:
#
#   ZCASH_DEVTOOL=/path/to/zcash-devtool LIGHTWALLETD=/path/to/lightwalletd ./scripts/e2e-regtest.sh
#
# Orchard era (blocks < 300): fund a wallet with Orchard coinbase, pay a merchant, make a
# receipt, verify it. Then NU6.3 activates (Ironwood): fund again, run the Receipts API on the
# chain, and have `receipts pay` answer a proof request end to end, then refund it with the
# merchant's own receipt, attest it, and sign in with the payer's address.
# Needs Docker (zfnd/zebra:6.4.2), lightwalletd, zcash-devtool built with regtest support, and
# `receipts` (cargo install --path crates/receipts-cli). Everything runs on 127.0.0.1.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
D=${ZCASH_DEVTOOL:-zcash-devtool}
LWD=${LIGHTWALLETD:-lightwalletd}
R=${RECEIPTS:-receipts}
NU63=300
RPC=18252; GRPC=9078; API=8733
WORK=$(mktemp -d "${TMPDIR:-/tmp}/receipts-e2e.XXXXXX")
NAME=receipts-e2e-$$
PASS=(); FAIL=()
ok() { PASS+=("$1"); echo "  ok   $1"; }
bad() { FAIL+=("$1"); echo "  FAIL $1"; }
cleanup() {
  [ -n "${MINER:-}" ] && kill "$MINER" 2>/dev/null || true
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
  [ -n "${LWD_PID:-}" ] && kill "$LWD_PID" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
for t in docker "$D" "$LWD" "$R" jq curl; do command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }; done
cd "$WORK"

echo "== chain (NU6.3 at $NU63), work dir $WORK"
sed -e "s/\"NU6.3\" = 1/\"NU6.3\" = $NU63/" "$ROOT/scripts/regtest/zebrad.toml" > zebrad.toml
sed -e "s/nu6_3 = 1/nu6_3 = $NU63/" "$ROOT/scripts/regtest/heights.toml" > heights.toml
printf 'rpcuser=x\nrpcpassword=x\nrpcbind=127.0.0.1\nrpcport=%s\nregtest=1\n' "$RPC" > zcash.conf
mkdir -p zebra-state lwd-data
docker run -d --name "$NAME" -p "$RPC":18232 -v "$PWD/zebrad.toml":/etc/zebrad.toml:ro -v "$PWD/zebra-state":/var/cache/zebra \
  --entrypoint zebrad zfnd/zebra:6.4.2 -c /etc/zebrad.toml start >/dev/null
rpc() { curl -s -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "http://127.0.0.1:$RPC"; }
for i in $(seq 1 60); do rpc getblockchaininfo '[]' | grep -q '"blocks"' && break; sleep 1; done
TADDR=tmGys6dBuEGjch5LFnhdo5gpSa7jiNRWse6
mine() { rpc generatetoaddress "[$1,\"${2:-$TADDR}\"]" >/dev/null; }
height() { rpc getblockchaininfo '[]' | jq .result.blocks; }
# A few blocks first: a wallet born at height 1 can't fetch the tree state before it.
mine 10
"$LWD" --no-tls-very-insecure --grpc-bind-addr "127.0.0.1:$GRPC" --http-bind-addr "127.0.0.1:$((GRPC + 100))" --zcash-conf-path ./zcash.conf --data-dir ./lwd-data --log-file ./lwd.log &
LWD_PID=$!
sleep 4
S="-s 127.0.0.1:$GRPC"
for w in sender merchant; do "$D" wallet -w "./$w" init --name "$w" -i "./$w.age" -n regtest --activation-heights ./heights.toml --birthday "$(height)" $S >/dev/null 2>&1; done
SENDER=$("$D" wallet -w ./sender list-addresses | sed -n 's/.*Default Address: //p')
MERCHANT=$("$D" wallet -w ./merchant list-addresses | sed -n 's/.*Default Address: //p')
sync() { "$D" wallet -w "./$1" sync $S >/dev/null 2>&1 || echo "  (sync of $1 failed; retrying later)" >&2; }
# Received notes need confirmations before they're spendable: retry while blocks arrive.
send() {
  for i in $(seq 1 40); do
    out=$("$D" wallet -w "./$1" send -i "./$1.age" --address "$2" --value "$3" --memo "$4" $S 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
    [ -n "$out" ] && { echo "$out"; return; }
    sleep 3; sync "$1"
  done
  return 1
}

echo "== Orchard era (height $(height))"
mine 4 "$SENDER"; mine 101; sync sender
T1=$(send sender "$MERCHANT" 42000000 "Invoice 7: Orchard espresso"); mine 2; sync sender
"$R" create -w ./sender -i ./sender.age --txid "$T1" -m "Order 7 (Orchard)" -s "127.0.0.1:$GRPC" --out orchard.txt >/dev/null 2>&1 && ok "Orchard receipt created for $T1" || bad "Orchard receipt"
"$R" verify @orchard.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" --expect-address "$MERCHANT" | grep -q "pool      Orchard" && ok "Orchard receipt verifies against the chain" || bad "Orchard verify"

echo "== NU6.3 / Ironwood (mining past $NU63)"
mine $((NU63 - $(height) + 5)); mine 4 "$SENDER"; mine 101; sync sender; sync merchant
"$R" serve --listen "127.0.0.1:$API" --db ./api.db --test-network regtest --heights ./heights.toml --test-lightwalletd "127.0.0.1:$GRPC" --verifier-url "http://127.0.0.1:$API/verify/" 2> api.log &
API_PID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$API/v1/health" >/dev/null && break; sleep 1; done
KEY=$(grep -o 'rcpt_test_[0-9a-f]*' api.log | head -1)
auth=(-H "authorization: Bearer $KEY")
REQ=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests" -d "{\"payee\":\"$MERCHANT\",\"amount_zatoshis\":25000000,\"label\":\"e2e order\"}")
RID=$(echo "$REQ" | jq -r .id); HOSTED=$(echo "$REQ" | jq -r .hosted_url)
( while true; do mine 1; sleep 3; done ) & MINER=$!
"$R" pay "$HOSTED" -w ./sender -i ./sender.age --devtool "$D" -s "127.0.0.1:$GRPC" --refund-to "$SENDER" > pay.log 2>&1 && ok "receipts pay answered $RID" || { bad "receipts pay"; tail -5 pay.log; }
STATUS=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID" | jq -r '.status + " " + .fulfillment.verification.pool')
[ "$STATUS" = "fulfilled ironwood" ] && ok "request fulfilled by an Ironwood receipt" || bad "request status: $STATUS"
RF=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID/refunds" -d '{"amount_zatoshis":5000000,"reason":"e2e"}')
RFID=$(echo "$RF" | jq -r .id); CH=$(echo "$RF" | jq -r .challenge); TO=$(echo "$RF" | jq -r .address)
[ "$TO" = "$SENDER" ] && ok "refund goes to the address the payer signed" || bad "refund address $TO"
sync merchant; T2=$(send merchant "$TO" 5000000 "Refund $RFID"); sleep 8; sync merchant
for i in $(seq 1 10); do "$R" create -w ./merchant -i ./merchant.age --txid "$T2" -m "challenge:$CH" -s "127.0.0.1:$GRPC" --out refund.txt > create-refund.log 2>&1 && break; sleep 4; sync merchant; done
"$R" tx "$T2" --network regtest --heights ./heights.toml -s "127.0.0.1:$GRPC" --hex > refund-tx.txt 2>/dev/null || true
XP=$("$R" verify @refund.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" 2>&1 | sed -n 's/^  pool *//p')
echo "  (refund receipt pools: $XP)"
RS=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/refunds/$RFID/receipts" -d "{\"receipt\":\"$(grep -o 'zrcpt1[A-Za-z0-9_-]*' refund.txt)\"}" | jq -r .status)
[ "$RS" = "succeeded" ] && ok "refund settled with the merchant's receipt" || { bad "refund status $RS"; tail -3 create-refund.log; }
ATT=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID/attestations" -d '{}' | jq -r .presentation)
curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/attestations/verify" -d "{\"attestation\":\"$ATT\"}" | jq -e '.valid and .claims.paid_at_least_zatoshis == 20000000' >/dev/null && ok "attestation: paid at least 0.2 ZEC net of the refund" || bad "attestation"
NONCE=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/sign_in/challenges" -d '{"domain":"e2e.test"}' | jq -r .nonce)
RECEIPTS_KEY=$KEY "$R" sign-in -w ./sender -i ./sender.age --domain e2e.test --nonce "$NONCE" --submit "http://127.0.0.1:$API" 2>/dev/null | jq -e .verified >/dev/null && ok "Sign in with Zcash as the payer" || bad "sign-in"

echo
echo "${#PASS[@]} passed, ${#FAIL[@]} failed"
[ ${#FAIL[@]} -eq 0 ]

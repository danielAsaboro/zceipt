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
RPC=${RPC:-18252}; GRPC=${GRPC:-9078}; API=${API:-8733}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/receipts-e2e.XXXXXX")
NAME=receipts-e2e-$$
PASS=(); FAIL=()
ok() { PASS+=("$1"); echo "  ok   $1"; }
bad() { FAIL+=("$1"); echo "  FAIL $1"; }
cleanup() {
  [ -n "${MINER:-}" ] && kill "$MINER" 2>/dev/null || true
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
  [ -n "${WK_PID:-}" ] && kill "$WK_PID" 2>/dev/null || true
  [ -n "${LWD_PID:-}" ] && kill "$LWD_PID" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -z "${KEEP:-}" ] && [ ${#FAIL[@]} -eq 0 ]; then rm -rf "$WORK"; else echo "logs kept in $WORK"; fi
}
trap cleanup EXIT
for t in docker "$D" "$LWD" "$R" jq curl nc; do command -v "$t" >/dev/null || { echo "missing: $t (set ZCASH_DEVTOOL, LIGHTWALLETD or RECEIPTS for ours)" >&2; exit 1; }; done
for p in $RPC $GRPC $((GRPC + 100)) $((GRPC + 200)) $API; do nc -z 127.0.0.1 "$p" 2>/dev/null && { echo "port $p is in use; set RPC/GRPC/API" >&2; exit 1; }; done
cd "$WORK"

echo "== chain (NU6.3 at $NU63), work dir $WORK"
sed -e "s/\"NU6.3\" = 1/\"NU6.3\" = $NU63/" "$ROOT/scripts/regtest/zebrad.toml" > zebrad.toml
sed -e "s/nu6_3 = 1/nu6_3 = $NU63/" "$ROOT/scripts/regtest/heights.toml" > heights.toml
printf 'rpcuser=x\nrpcpassword=x\nrpcbind=127.0.0.1\nrpcport=%s\nregtest=1\n' "$RPC" > zcash.conf
mkdir -p zebra-state lwd-data
docker run -d --name "$NAME" -p "127.0.0.1:$RPC:18232" -v "$PWD/zebrad.toml":/etc/zebrad.toml:ro -v "$PWD/zebra-state":/var/cache/zebra \
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
for i in $(seq 1 30); do nc -z 127.0.0.1 "$GRPC" 2>/dev/null && break; sleep 1; done
S="-s 127.0.0.1:$GRPC"
# Wallet init occasionally hangs right after lightwalletd starts: give each try 60 s, then retry.
init_wallet() {
  for try in 1 2 3; do
    rm -rf "./$1" "./$1.age"
    "$D" wallet -w "./$1" init --name "$1" -i "./$1.age" -n regtest --activation-heights ./heights.toml --birthday "$(height)" $S > "init-$1.log" 2>&1 &
    local pid=$!
    for i in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; echo "  (wallet init for $1 hung; retrying)" >&2; continue; fi
    wait "$pid" && return 0
    sleep 2
  done
  echo "wallet init failed for $1:"; tail -3 "init-$1.log"; return 1
}
for w in sender merchant; do init_wallet "$w" || exit 1; done
SENDER=$("$D" wallet -w ./sender list-addresses | sed -n 's/.*Default Address: //p')
MERCHANT=$("$D" wallet -w ./merchant list-addresses | sed -n 's/.*Default Address: //p')
sync() { "$D" wallet -w "./$1" sync $S >/dev/null 2>&1 || echo "  (sync of $1 failed; retrying later)" >&2; }
# Received notes need confirmations before they're spendable: retry while blocks arrive.
send() {
  for i in $(seq 1 40); do
    memo=(); [ -n "$4" ] && memo=(--memo "$4")
    out=$("$D" wallet -w "./$1" send -i "./$1.age" --address "$2" --value "$3" "${memo[@]}" $S 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
    [ -n "$out" ] && { echo "$out"; return; }
    sleep 3; sync "$1"
  done
  return 1
}

echo "== Orchard era (height $(height))"
mine 4 "$SENDER"; mine 101; sync sender
T1=$(send sender "$MERCHANT" 42000000 "Invoice 7: Orchard espresso") || { bad "Orchard payment could not be sent"; T1=none; }; mine 2; sync sender
"$R" create -w ./sender -i ./sender.age --txid "$T1" -m "Order 7 (Orchard)" -s "127.0.0.1:$GRPC" --out orchard.txt >/dev/null 2>&1 && ok "Orchard receipt created for $T1" || bad "Orchard receipt"
"$R" verify @orchard.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" --expect-address "$MERCHANT" | grep -q "pool      Orchard" && ok "Orchard receipt verifies against the chain" || bad "Orchard verify"

# Watch-only machine makes the proofs; the key holder signs from keys.toml alone.
rm -rf watch signer; cp -R sender watch; mkdir signer; cp sender/keys.toml signer/
awk '/^mnemonic = """/{skip=1;next} skip&&/^"""/{skip=0;next} !skip' sender/keys.toml > watch/keys.toml
"$R" create -w ./watch --unsigned prepared.txt --txid "$T1" -m "Order 7 (watch-only)" -s "127.0.0.1:$GRPC" >/dev/null 2>&1 && ! grep -q mnemonic watch/keys.toml && ok "a wallet with no mnemonic made the proofs" || bad "watch-only prepare"
"$R" sign prepared.txt --yes -w ./merchant -i ./merchant.age > other-sign.log 2>&1 || true; grep -q "did not make these spends" other-sign.log && ok "another wallet's key refuses to sign" || bad "another wallet's key was not refused"
[ "$(stat -f %Lp prepared.txt 2>/dev/null || stat -c %a prepared.txt)" = 600 ] && ok "the prepared file is readable only by its owner" || bad "prepared file permissions"
echo no | "$R" sign prepared.txt -w ./signer -i ./sender.age > declined.log 2>&1 || true; grep -q "not signed" declined.log && [ -f prepared.txt ] && ok "the signer shows what it signs and stops unless told yes" || bad "sign prompt"
"$R" sign prepared.txt --yes -w ./signer -i ./sender.age --out signed.txt >/dev/null 2>&1 && [ ! -f prepared.txt ] && "$R" verify @signed.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" --expect-address "$MERCHANT" | grep -q "pool      Orchard" && ok "signed with keys.toml alone (no wallet database), and it verifies" || bad "offline sign"

# Keys only: a viewing key and a birthday, no wallet files (how Zodl, Zingo or YWallet users would do it).
UFVK=$(sqlite3 sender/data.sqlite "SELECT ufvk FROM accounts WHERE hd_account_index = 0")
BDAY=$(sed -n 's/^birthday = //p' sender/keys.toml)
"$R" create --ufvk "$UFVK" --birthday "$BDAY" --regtest ./heights.toml --unsigned keys-prepared.txt --txid "$T1" -m "Order 7 (keys only)" -s "127.0.0.1:$GRPC" > keys.log 2>&1 && ok "a viewing key alone found the spent note on chain and made the proofs" || { bad "keys-only prepare"; tail -3 keys.log; }
"$R" sign keys-prepared.txt --yes -w ./signer -i ./sender.age --out keys-signed.txt >/dev/null 2>&1 && "$R" verify @keys-signed.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" --expect-address "$MERCHANT" | grep -q "pool      Orchard" && ok "the keys-only receipt signs and verifies" || bad "keys-only sign/verify"

# Screened set: the exchange lists the outputs it vetted; the payer proves the spent note is one of them.
SRCS=$(sqlite3 sender/data.sqlite "SELECT DISTINCT hex(t.txid) FROM orchard_received_notes rn JOIN transactions t ON t.id_tx = rn.transaction_id" | python3 -c 'import sys; print(" ".join("--txid " + bytes.fromhex(l.strip())[::-1].hex() for l in sys.stdin if l.strip()))')
"$R" screened-list $SRCS --regtest ./heights.toml -s "127.0.0.1:$GRPC" > screened.txt 2> screened.log && "$R" screened-list --txid "$T1" --regtest ./heights.toml -s "127.0.0.1:$GRPC" > unscreened.txt 2>>screened.log || bad "screened-list"
"$R" create -w ./sender -i ./sender.age --txid "$T1" -m "Deposit 12" --screened-set screened.txt --screened-proof screened-proof.txt -s "127.0.0.1:$GRPC" --out screened-receipt.txt > screened-create.log 2>&1 && ok "the payer proved the spent note is in the exchange's screened list ($(grep -vc '^#' screened.txt) outputs)" || { bad "screened-set create"; tail -3 screened-create.log; }
"$R" verify @screened-receipt.txt --screened-set screened.txt --screened-proof @screened-proof.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" 2>/dev/null | grep -q "funds     every spent note came from the screened list" && ok "the verifier accepts it against the published list, without learning which output" || bad "screened-set verify"
"$R" verify @screened-receipt.txt --screened-set unscreened.txt --screened-proof @screened-proof.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" > unscreened.log 2>&1 || true; grep -q "not in the screened set" unscreened.log && ok "against a list without that note it is refused" || bad "screened-set refusal"

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
"$R" pay "$HOSTED" --yes -w ./sender -i ./sender.age --devtool "$D" -s "127.0.0.1:$GRPC" --refund-to "$SENDER" > pay.log 2>&1 && ok "receipts pay answered $RID" || { bad "receipts pay"; tail -5 pay.log; }
STATUS=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID" | jq -r '.status + " " + .fulfillment.verification.pool')
[ "$STATUS" = "fulfilled ironwood" ] && ok "request fulfilled by an Ironwood receipt" || bad "request status: $STATUS"
RF=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID/refunds" -d '{"amount_zatoshis":5000000,"reason":"e2e"}')
RFID=$(echo "$RF" | jq -r .id); CH=$(echo "$RF" | jq -r .challenge); TO=$(echo "$RF" | jq -r .address)
[ "$TO" = "$SENDER" ] && ok "refund goes to the address the payer signed" || bad "refund address $TO"
sync merchant; T2=$(send merchant "$TO" 5000000 "Refund $RFID") || { bad "refund could not be sent"; T2=none; }; sleep 8; sync merchant
for i in $(seq 1 10); do "$R" create -w ./merchant -i ./merchant.age --txid "$T2" -m "challenge:$CH" -s "127.0.0.1:$GRPC" --out refund.txt > create-refund.log 2>&1 && break; sleep 4; sync merchant; done
"$R" tx "$T2" --network regtest --heights ./heights.toml -s "127.0.0.1:$GRPC" --hex > refund-tx.txt 2>/dev/null || true
XP=$("$R" verify @refund.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" 2>&1 | sed -n 's/^  pool *//p')
[ "$XP" = "Orchard to Ironwood" ] && ok "the refund is a cross-pool receipt (Orchard notes into an Ironwood output)" || echo "  (refund receipt pools: $XP)"
RS=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/refunds/$RFID/receipts" -d "{\"receipt\":\"$(grep -o 'zip311r1[A-Za-z0-9_-]*' refund.txt)\"}" | jq -r .status)
[ "$RS" = "succeeded" ] && ok "refund settled with the merchant's receipt" || { bad "refund status $RS"; tail -3 create-refund.log; }
ATT=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$RID/attestations" -d '{}' | jq -r .presentation)
curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/attestations/verify" -d "{\"attestation\":\"$ATT\"}" | jq -e '.valid and .claims.paid_at_least_zatoshis == 20000000' >/dev/null && ok "attestation: paid at least 0.2 ZEC net of the refund" || bad "attestation"
NONCE=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/sign_in/challenges" -d '{"domain":"e2e.test"}' | jq -r .nonce)
RECEIPTS_KEY=$KEY "$R" sign-in -w ./sender -i ./sender.age --domain e2e.test --nonce "$NONCE" --submit "http://127.0.0.1:$API" 2>/dev/null | jq -e .verified >/dev/null && ok "Sign in with Zcash as the payer" || bad "sign-in"

echo "== Source of funds: an exchange withdrawal to a transparent address, shielded, then spent"
for w in exchange customer; do init_wallet "$w" || bad "wallet $w"; done
EXCHANGE=$("$D" wallet -w ./exchange list-addresses | sed -n 's/.*Default Address: //p')
MN=$("$D" wallet -w ./customer display-mnemonic --enable -i ./customer.age 2>/dev/null | tail -1)
CUST_T=$("$D" wallet derive-address --mnemonic "$MN" -n regtest | sed -n 's/^Transparent Address: //p'); MN=
mine 4 "$EXCHANGE"; mine 101; sync exchange
W=$(send exchange "$CUST_T" 30000000 "") && ok "exchange withdrew 0.3 ZEC to the customer's transparent address ($W)" || { bad "withdrawal"; W=none; }
SH=
for i in $(seq 1 40); do
  sync customer
  SH=$("$D" wallet -w ./customer shield -i ./customer.age $S 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
  [ -n "$SH" ] && break; sleep 3
done
[ -n "$SH" ] && ok "customer shielded it ($SH)" || { bad "shield"; SH=none; }
DEP=$(send customer "$MERCHANT" 12000000 "Deposit 99") && ok "customer paid the merchant from the shielded note ($DEP)" || { bad "deposit"; DEP=none; }
sleep 8; sync customer
for i in $(seq 1 10); do "$R" create -w ./customer -i ./customer.age --txid "$DEP" -m "Deposit 99" --prove-source -s "127.0.0.1:$GRPC" --out source.txt > create-source.log 2>&1 && break; sleep 4; sync customer; done
SRC=$("$R" verify @source.txt --json --regtest ./heights.toml -s "127.0.0.1:$GRPC" 2>/dev/null || true)
echo "$SRC" > source-report.json
echo "$SRC" | jq -e --arg sh "$SH" --arg t "$CUST_T" '.sources[0].source_txid == $sh and .sources[0].zatoshis == null and .sources[0].transparent_inputs[0].address == $t and .sources[0].transparent_inputs[0].zatoshis == 30000000' >/dev/null \
  && ok "source proof: the deposit's note came from the shielding of 0.3 ZEC withdrawn to $CUST_T (value hidden)" || { bad "source proof"; tail -3 create-source.log; }
"$R" create -w ./customer -i ./customer.age --txid "$DEP" -m "Deposit 99" --prove-source --reveal-source-value -s "127.0.0.1:$GRPC" --out source-value.txt > create-source-value.log 2>&1
"$R" verify @source-value.txt --json --regtest ./heights.toml -s "127.0.0.1:$GRPC" > source-value-report.json 2>&1 || true
jq -e '.sources[0].zatoshis > 0 and .sources[0].zatoshis <= .sources[0].net_into_shielded_zatoshis' source-value-report.json >/dev/null 2>&1 \
  && ok "source proof with the note's exact value revealed ($(jq -r .sources[0].zec source-value-report.json) ZEC of the shielded $(jq -r .sources[0].net_into_shielded_zatoshis source-value-report.json) zats)" || { bad "source proof with value"; tail -3 source-value-report.json; }
"$R" tx "$DEP" --network regtest --heights ./heights.toml -s "127.0.0.1:$GRPC" --hex > source-deposit-tx.txt 2>/dev/null || true
"$R" tx "$SH" --network regtest --heights ./heights.toml -s "127.0.0.1:$GRPC" --hex > source-shield-tx.txt 2>/dev/null || true

echo "== Multi-hop source of funds: withdrawal -> shield -> self-transfer -> payment, one batch"
init_wallet saver || bad "wallet saver"
SAVER=$("$D" wallet -w ./saver list-addresses | sed -n 's/.*Default Address: //p')
MN=$("$D" wallet -w ./saver display-mnemonic --enable -i ./saver.age 2>/dev/null | tail -1)
SAVER_T=$("$D" wallet derive-address --mnemonic "$MN" -n regtest | sed -n 's/^Transparent Address: //p'); MN=
sync exchange
W2=$(send exchange "$SAVER_T" 50000000 "") || bad "withdrawal to saver"
SH2=
for i in $(seq 1 40); do
  sync saver
  SH2=$("$D" wallet -w ./saver shield -i ./saver.age $S 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
  [ -n "$SH2" ] && break; sleep 3
done
HOP=$(send saver "$SAVER" 45000000 "move to savings") && ok "saver shielded ($SH2) and moved 0.45 ZEC to itself ($HOP)" || { bad "self-transfer"; HOP=none; }
PAY2=$(send saver "$MERCHANT" 30000000 "Deposit 100") && ok "saver paid the merchant 0.3 ZEC from the moved note ($PAY2)" || { bad "second deposit"; PAY2=none; }
sleep 8; sync saver
for i in $(seq 1 10); do "$R" create -w ./saver -i ./saver.age --txid "$HOP" --txid "$PAY2" -m "Deposit 100" --prove-source -s "127.0.0.1:$GRPC" --out hops.txt > create-hops.log 2>&1 && break; sleep 4; sync saver; done
"$R" verify @hops.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" > hops-report.txt 2>&1 || true
grep -q "tx ${PAY2:0:12}… action .* from tx ${HOP:0:12}…" hops-report.txt && grep -q "tx ${HOP:0:12}… action .* from tx ${SH2:0:12}…" hops-report.txt && grep -q "was funded in the clear: 0.50000000 ZEC from $SAVER_T" hops-report.txt \
  && ok "the batch proves the chain: payment <- self-transfer <- shielding of 0.5 ZEC from $SAVER_T" || { bad "multi-hop provenance"; tail -8 hops-report.txt; tail -3 create-hops.log; }

echo "== Proof of funds: the saver proves what it holds; once it spends, the same proof is refused"
sync saver
"$R" reserve -w ./saver -i ./saver.age -m "challenge:otc-e2e" --out reserve.txt > reserve.log 2>&1 || { bad "proof of funds"; tail -3 reserve.log; }
HELD=$(grep -o 'Proof of funds: [0-9.]* ZEC' reserve.log | grep -o '[0-9.]*')
"$R" verify @reserve.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" > reserve-report.txt 2>&1 && grep -q "holds     $HELD TAZ" reserve-report.txt \
  && ok "proof of funds: holds $HELD ZEC, unspent as of the tip (every Ironwood nullifier scanned)" || { bad "verify proof of funds"; tail -3 reserve-report.txt; }
SPEND=$(send saver "$MERCHANT" 1000000 "spend after proving") || bad "spend after proving"
for i in $(seq 1 10); do "$R" verify @reserve.txt --regtest ./heights.toml -s "127.0.0.1:$GRPC" > reserve-after.txt 2>&1 && sleep 4 || break; done
grep -q "has been spent" reserve-after.txt && ok "after the saver spends, the same proof is refused (its nullifier is on chain)" || { bad "spent funds still proven"; tail -3 reserve-after.txt; }

if [ -n "${EXPORT_SOURCE:-}" ]; then mkdir -p "$EXPORT_SOURCE"; cp source.txt source-value.txt source-report.json source-value-report.json hops.txt hops-report.txt source-deposit-tx.txt source-shield-tx.txt heights.toml "$EXPORT_SOURCE"/ 2>/dev/null || true; fi

echo "== Signed payment request: the shop signs, its domain lists the address, the payer checks both"
WK=$((GRPC + 200)); mkdir -p shop/.well-known
printf '{"payees":["%s"]}' "$MERCHANT" > shop/.well-known/zcash-receipts.json
python3 -m http.server "$WK" --bind 127.0.0.1 --directory shop > wk.log 2>&1 & WK_PID=$!
for i in $(seq 1 20); do nc -z 127.0.0.1 "$WK" 2>/dev/null && break; sleep 0.5; done
REQ1=$("$R" request -w ./merchant -i ./merchant.age --domain "127.0.0.1:$WK" --amount 0.07 --memo "Order 77" --code c0ffee77 --payee "$MERCHANT" 2>/dev/null) && ok "shop signed a payment request" || bad "sign request"
# A thief's request (own key, own address) for the shop's domain is refused: the domain doesn't list it.
init_wallet thief || bad "wallet thief"
FAKE=$("$R" request -w ./thief -i ./thief.age --domain "127.0.0.1:$WK" --amount 0.07 --memo "Order 77" --code c0ffee77 2>/dev/null)
"$R" pay "$FAKE" --dry-run -w ./sender -i ./sender.age --devtool "$D" -s "127.0.0.1:$GRPC" > fake.log 2>&1 && bad "a thief's request was accepted" || { grep -q "does not list" fake.log && ok "a request for an address the domain doesn't list is refused" || { bad "fake request: unexpected error"; tail -2 fake.log; }; }
# An edited request (amount changed in transit) is refused.
EDIT=$(python3 - "$REQ1" <<'PY'
import sys, base64
t = sys.argv[1].strip(); b = bytearray(base64.urlsafe_b64decode(t[5:] + "=" * (-len(t[5:]) % 4)))
i = 9
for _ in range(3):  # domain, memo, code: u16 length + bytes each; the amount follows
    i += 2 + int.from_bytes(b[i:i + 2], "little")
b[i] ^= 1
print("zreq1" + base64.urlsafe_b64encode(bytes(b)).decode().rstrip("="))
PY
)
"$R" pay "$EDIT" --dry-run -w ./sender -i ./sender.age --devtool "$D" -s "127.0.0.1:$GRPC" > edit.log 2>&1 && bad "an edited request was accepted" || ok "an edited request is refused ($(tail -1 edit.log | cut -c1-60))"
"$R" pay "$REQ1" --yes -w ./sender -i ./sender.age --devtool "$D" -s "127.0.0.1:$GRPC" > pay-signed.log 2>&1 && ok "payer paid the signed request" || { bad "pay signed request"; tail -3 pay-signed.log; }
SR=$(grep -o 'zip311r1[A-Za-z0-9_-]*' pay-signed.log | tail -1)
"$R" verify "$SR" --json --regtest ./heights.toml -s "127.0.0.1:$GRPC" --expect-address "$MERCHANT" > signed-receipt.json 2>&1
jq -e '.message == "challenge:c0ffee77" and .outputs[0].zatoshis == 7000000 and .outputs[0].memo == "Order 77"' signed-receipt.json >/dev/null && ok "the receipt answers request c0ffee77: 0.07 ZEC with the shop's memo" || { bad "signed request receipt"; tail -3 signed-receipt.json; }
kill "$WK_PID" 2>/dev/null || true

echo "== Deposit desk: an exchange accepts a shielded deposit with proof of where it came from"
init_wallet trader || bad "wallet trader"
TRADER=$("$D" wallet -w ./trader list-addresses | sed -n 's/.*Default Address: //p')
MN=$("$D" wallet -w ./trader display-mnemonic --enable -i ./trader.age 2>/dev/null | tail -1)
TRADER_T=$("$D" wallet derive-address --mnemonic "$MN" -n regtest | sed -n 's/^Transparent Address: //p'); MN=
sync exchange
send exchange "$TRADER_T" 40000000 "" > /dev/null || bad "withdrawal to trader"
for i in $(seq 1 40); do
  sync trader
  TSH=$("$D" wallet -w ./trader shield -i ./trader.age $S 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
  [ -n "$TSH" ] && break; sleep 3
done
[ -n "${TSH:-}" ] && ok "trader withdrew 0.4 ZEC to $TRADER_T and shielded it ($TSH)" || bad "trader shield"
desk() { curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests" -d "{\"payee\":\"$MERCHANT\",\"amount_zatoshis\":$1,\"label\":\"deposit\",\"source_of_funds\":{\"required\":true,\"blocked_addresses\":[$2]}}"; }
DQ=$(desk 5000000 ""); DID=$(echo "$DQ" | jq -r .id); DH=$(echo "$DQ" | jq -r .hosted_url)
[ "$(echo "$DQ" | jq -r .source_of_funds.required)" = "true" ] && ok "desk created deposit request $DID that requires source of funds" || bad "desk request: $(echo "$DQ" | head -c 200)"
# A receipt without source proofs is refused, with a message saying what to do.
sync trader
NOSRC=$(send trader "$MERCHANT" 5000000 "Deposit $DID") || bad "deposit payment"
sleep 6; sync trader
DL=$(echo "$DQ" | jq -r .receipt_link)
for i in $(seq 1 10); do "$R" create -w ./trader -i ./trader.age --txid "$NOSRC" --request "$DL" -s "127.0.0.1:$GRPC" --out nosrc.txt > nosrc.log 2>&1 && break; sleep 4; sync trader; done
E1=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$DID/receipts" -d "{\"receipt\":\"$(grep -o 'zip311r1[A-Za-z0-9_-]*' nosrc.txt)\"}" | jq -r .error.code)
[ "$E1" = "source_of_funds_required" ] && ok "a deposit receipt without proof of source is refused (source_of_funds_required)" || bad "no-source receipt: $E1"
"$R" create -w ./trader -i ./trader.age --txid "$NOSRC" --request "$DL" --prove-source --reveal-source-value -s "127.0.0.1:$GRPC" --out withsrc.txt > withsrc.log 2>&1
D1=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$DID/receipts" -d "{\"receipt\":\"$(grep -o 'zip311r1[A-Za-z0-9_-]*' withsrc.txt)\"}")
echo "$D1" > desk-cleared.json
echo "$D1" | jq -e --arg t "$TRADER_T" '.status == "fulfilled" and .provenance.status == "cleared" and (.provenance.funding | map(.address) | index($t)) != null' >/dev/null \
  && ok "with --prove-source the deposit is credited: funding screened and cleared ($TRADER_T)" || { bad "cleared deposit"; echo "$D1" | head -c 400; }
# Screened against a list that holds the trader's address: receipts pay attaches the proof; the deposit is held.
DQ2=$(desk 19000000 "\"$TRADER_T\""); DID2=$(echo "$DQ2" | jq -r .id); DH2=$(echo "$DQ2" | jq -r .hosted_url)
"$R" pay "$DH2" --yes --refund-to "$TRADER" -w ./trader -i ./trader.age --devtool "$D" -s "127.0.0.1:$GRPC" > desk-pay.log 2>&1 || { bad "receipts pay (deposit)"; tail -3 desk-pay.log; }
grep -q "held while the shop reviews" desk-pay.log && ok "receipts pay attached the proof by itself; the deposit is held: its funding address is on the desk's list" || { bad "held deposit"; tail -3 desk-pay.log; }
H=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$DID2")
echo "$H" | jq -e '.status == "held_for_review" and .provenance.status == "review" and (.provenance.reasons | any(test("blocked address")))' >/dev/null && ok "the desk sees why: funded by a blocked address" || { bad "held reasons"; echo "$H" | head -c 400; }
RJ=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$DID2/review" -d '{"decision":"reject","note":"listed address"}' | jq -r .status)
RF=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/requests/$DID2/refunds" -d '{"reason":"deposit rejected"}' | jq -r .address)
[ "$RJ" = "rejected" ] && [ "$RF" = "$TRADER" ] && ok "the desk rejected it and refunds to the address the payer signed" || bad "reject/refund: $RJ $RF"
EV=$(curl -s "${auth[@]}" "http://127.0.0.1:$API/v1/events?limit=50" | jq -r '[.data[].type] | join(",")')
echo "$EV" | grep -q "request.held_for_review" && echo "$EV" | grep -q "request.rejected" && ok "webhook events: request.held_for_review, request.rejected" || bad "events: $EV"

echo
echo "${#PASS[@]} passed, ${#FAIL[@]} failed"
[ ${#FAIL[@]} -eq 0 ]

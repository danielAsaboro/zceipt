#!/usr/bin/env bash
# End to end on the Zcash PUBLIC TESTNET (never mainnet), the features the regtest run covers that
# the committed testnet examples don't: claims, payer tags, sibling accounts, one-verifier and
# delegated receipts, income from distinct payers, and the attacks on each.
#
#   FUNDER=/path/to/funded/testnet/wallet FUNDER_ID=/path/to/its.age \
#   ZCASH_DEVTOOL=/path/to/zcash-devtool RECEIPTS=/path/to/receipts ./scripts/e2e-testnet.sh
#
# FUNDER is a zcash-devtool testnet wallet holding at least 0.05 TAZ in Ironwood (the Valar faucet,
# faucet.testnet.valargroup.dev, gives it; the demo wallet's key is public, never fund it).
# ZCASH_DEVTOOL needs `wallet new-account` (integrations/zcash-devtool). The run makes fresh wallets
# (a payer with accounts 0 and 1, and a merchant), pays real testnet transactions, waits for them to
# be mined, and takes about 15 to 25 minutes, almost all of it block time.
set -euo pipefail
trap 'echo "e2e stopped at line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."
ROOT=$PWD
D=${ZCASH_DEVTOOL:-zcash-devtool}
R=${RECEIPTS:-receipts}
FUNDER=$(cd "${FUNDER:?set FUNDER to a funded testnet wallet directory}" && pwd)
FUNDER_ID=$(cd "$(dirname "${FUNDER_ID:?set FUNDER_ID to its age identity file}")" && pwd)/$(basename "$FUNDER_ID")
ATTACK=${ATTACK:-$(dirname "$(command -v "$R" || echo "$R")")/examples/attack}
SERVER=${SERVER:-}
API=${API:-8744}
WORK=${RESUME:-$(mktemp -d "${TMPDIR:-/tmp}/receipts-e2e-testnet.XXXXXX")}
PASS=(); FAIL=()
ok() { PASS+=("$1"); echo "  ok   $1"; }
bad() { FAIL+=("$1"); echo "  FAIL $1"; }
# No `timeout` on macOS: a hard limit on any one step.
lim() { local s=$1; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; }
cleanup() {
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
  if [ -z "${KEEP:-}" ] && [ ${#FAIL[@]} -eq 0 ]; then rm -rf "$WORK"; else echo "logs and wallets kept in $WORK"; fi
}
trap cleanup EXIT
for t in "$D" "$R" jq curl node perl; do command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }; done
[ -x "$ATTACK" ] || { echo "missing the attack example: cargo build --release -p receipts-wallet --example attack (or set ATTACK)" >&2; exit 1; }
S=(); [ -n "$SERVER" ] && S=(-s "$SERVER")
cd "$WORK"

echo "== testnet wallets (work dir $WORK${RESUME:+, resuming after the payments})"
dev() { lim 600 "$D" wallet "$@"; }
sync() { dev -w "$1" sync "${S[@]}" >/dev/null 2>&1 || echo "  (sync of $1 failed; retrying later)" >&2; }
if [ -n "${RESUME:-}" ]; then
  . "$WORK/state.env"
else
for w in payer merchant; do echo "" | dev -w "./$w" init --name "$w" -i "./$w.age" -n test "${S[@]}" >/dev/null 2>&1 || { echo "wallet init failed for $w"; exit 1; }; done
dev -w ./payer new-account --name payer1 -i ./payer.age "${S[@]}" >/dev/null 2>&1
uuid() { dev -w "./$1" list-accounts 2>/dev/null | awk -v n="$2" '/^Account /{u=$2} /Account index:/{if ($3==n) print u}'; }
U0=$(uuid payer 0); U1=$(uuid payer 1)
[ -n "$U0" ] && [ -n "$U1" ] && ok "a payer wallet with ZIP 32 accounts 0 and 1, and a merchant wallet, on testnet" || { bad "wallet accounts"; exit 1; }
addr() { dev -w "./$1" list-addresses ${2:-} 2>/dev/null | sed -n 's/.*Default Address: //p' | head -1; }
PAYER0=$(addr payer "$U0"); PAYER1=$(addr payer "$U1"); MERCHANT=$(addr merchant)
TIP0=$(dev -w ./payer get-info "${S[@]}" 2>/dev/null | jq -r .chain_tip_height)

# Notes need confirmations before they are spendable: retry the send while blocks arrive.
send() { # wallet-dir identity account-uuid-or-"" address zatoshis memo
  local out
  for _ in $(seq 1 60); do
    sync "$1"
    out=$(dev -w "$1" send ${3:+"$3"} -i "$2" --address "$4" --value "$5" --memo "$6" "${S[@]}" 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1 || true)
    [ -n "$out" ] && { echo "$out"; return; }
    sleep 25
  done
  return 1
}
mined() { # wallet-dir txid -> the block it was mined in (a height above the one the run started at)
  local h
  for _ in $(seq 1 80); do
    sync "$1"
    h=$(dev -w "$1" list-tx 2>/dev/null | awk -v t="$2" '$1==t{f=1;next} f&&/Mined:/{print $2;exit}')
    [ -n "$h" ] && [ "$h" -gt "$TIP0" ] && { echo "$h"; return; }
    sleep 20
  done
  return 1
}

echo "== funding: the funder pays account 0, account 0 pays account 1 (real transactions, waiting for blocks)"
F0=$(send "$FUNDER" "$FUNDER_ID" "" "$PAYER0" 3000000 "e2e funding") && ok "funder paid the payer's account 0 ($F0)" || { bad "funding"; exit 1; }
mined "$FUNDER" "$F0" >/dev/null
F1=$(send ./payer ./payer.age "$U0" "$PAYER1" 1200000 "fund account 1") && ok "account 0 paid account 1 ($F1)" || { bad "account 1 funding"; exit 1; }
mined ./payer "$F1" >/dev/null

echo "== payments to the merchant: account 0 twice, account 1 once, and the funder (a separate wallet) once"
TA=$(send ./payer ./payer.age "$U0" "$MERCHANT" 200000 "Round R: payer account 0, first") || bad "payment A"
TC=$(send ./payer ./payer.age "$U1" "$MERCHANT" 200000 "Round R: payer account 1") || bad "payment C"
TS=$(send "$FUNDER" "$FUNDER_ID" "" "$MERCHANT" 200000 "Round R: funder pays") || bad "payment S"
TB=$(send ./payer ./payer.age "$U0" "$MERCHANT" 200000 "Round R: payer account 0, second") || bad "payment B"
for n in TA TB TC TS; do echo "  payment $n ${!n}"; done
HA=$(mined ./payer "$TA"); HC=$(mined ./payer "$TC"); HB=$(mined ./payer "$TB"); HS=$(mined "$FUNDER" "$TS")
ok "all four payments mined (blocks $HA, $HB, $HC, $HS)"
sync ./merchant

cat > "$WORK/state.env" <<STATE
U0=$U0; U1=$U1; PAYER0=$PAYER0; PAYER1=$PAYER1; MERCHANT=$MERCHANT; TIP0=$TIP0
TA=$TA; TB=$TB; TC=$TC; TS=$TS; HA=$HA; HB=$HB; HC=$HC; HS=$HS
STATE
fi
echo "== payer tags: a round counts different wallets, not payments"
RS=(); [ -n "$SERVER" ] && RS=(-s "$SERVER")
tag() { "$R" --account "$3" tag -w "$1" -i "$2" --txid "$4" --domain round-e2e "${RS[@]}" --out "tag-$5.txt" > "tag-$5.log" 2>&1 || { bad "payer tag $5"; tail -3 "tag-$5.log"; }; }
tag ./payer ./payer.age 0 "$TA" A; tag ./payer ./payer.age 0 "$TB" B; tag ./payer ./payer.age 1 "$TC" C; tag "$FUNDER" "$FUNDER_ID" 0 "$TS" S
for t in A B C S; do "$R" verify @tag-$t.txt --json --domain round-e2e "${RS[@]}" > tag-$t.json 2> tag-$t.err || { bad "verify payer tag $t"; tail -2 tag-$t.err; }; done
TGA=$(jq -r .tag tag-A.json); TGB=$(jq -r .tag tag-B.json); TGC=$(jq -r .tag tag-C.json); TGS=$(jq -r .tag tag-S.json)
[ "${#TGA}" = 64 ] && [ "$TGA" = "$TGB" ] && [ "$TGA" != "$TGC" ] && [ "$TGA" != "$TGS" ] && [ "$TGC" != "$TGS" ] \
  && ok "payer tags: account 0's two payments share a tag; account 1 and the funder's wallet differ" || bad "payer tag equality"
"$R" verify @tag-A.txt --domain round-other "${RS[@]}" > tag-wrong.txt 2>&1 && bad "a payer tag passed for another round" || ok "a payer tag is refused for another round"
perl -pe 's/^(zip311t1.{900})./${1}A/' tag-A.txt > tag-edited.txt
"$R" verify @tag-edited.txt --domain round-e2e "${RS[@]}" > tag-edited.out 2>&1 && bad "an edited payer tag passed" || ok "an edited payer tag is refused"

echo "== sibling accounts: the payer's two account tags are one wallet's (k=17, about a minute)"
lim 900 "$R" siblings -w ./payer -i ./payer.age --accounts 0,1 --domain round-e2e --out sib.txt > sib.log 2>&1 || { bad "sibling-account proof"; tail -3 sib.log; }
"$R" verify @sib.txt --json --domain round-e2e > sib.json 2> sib.err && jq -e --arg a "$TGA" --arg c "$TGC" '.valid and .tags[0] == $a and .tags[1] == $c' sib.json >/dev/null \
  && ok "sibling proof: the tags of account 0's and account 1's real payments are of one wallet" || { bad "verify sibling accounts"; tail -3 sib.err; }
"$R" verify @sib.txt --domain round-other > sib-wrong.txt 2>&1 && bad "a sibling proof passed for another round" || ok "a sibling proof is refused for another round"

echo "== income from distinct payers: the merchant's proof plus the payers' tags"
"$R" income -w ./merchant -i ./merchant.age --txid "$TA" --txid "$TC" --txid "$TS" --min 0.005 "${RS[@]}" --out income.txt > income.log 2>&1 || { bad "income proof"; tail -3 income.log; }
"$R" verify @income.txt --payer-tag @tag-A.txt --payer-tag @tag-C.txt --payer-tag @tag-S.txt --domain round-e2e --min-payers 3 "${RS[@]}" > income-3.txt 2>&1 && grep -q "3 different wallet" income-3.txt \
  && ok "three payer tags count three wallets (accounts 0 and 1 look like two)" || { bad "income, three tags"; tail -3 income-3.txt; }
"$R" verify @income.txt --payer-tag @tag-A.txt --payer-tag @tag-C.txt --payer-tag @tag-S.txt --siblings @sib.txt --domain round-e2e --min-payers 3 "${RS[@]}" > income-2.txt 2>&1 && bad "sibling accounts counted twice" \
  || { grep -q "2 different wallet" income-2.txt && ok "with the sibling proof the same tags count two wallets, so three are refused"; } || bad "income with siblings"
"$R" verify @income.txt --payer-tag @tag-A.txt --payer-tag @tag-A.txt --payer-tag @tag-C.txt --domain round-e2e --min-payers 3 "${RS[@]}" > income-dup.txt 2>&1 && bad "one payer counted twice" || ok "one payer's tag twice counts once"
"$R" verify @income.txt --payer-tag @tag-B.txt --domain round-e2e "${RS[@]}" > income-uncounted.txt 2>&1 && bad "a tag for an uncounted payment passed" || ok "a tag for a payment the proof doesn't count is refused"

echo "== one-verifier and delegated receipts on the testnet payment A"
rm -rf watch signer; rm -f office.session over-limit.session expired.session wrong-payee.session; cp -R payer watch; mkdir signer; cp payer/keys.toml signer/
awk '/^mnemonic = """/{skip=1;next} skip&&/^"""/{skip=0;next} !skip' payer/keys.toml > watch/keys.toml
rm -f shop.key other.key; "$R" verifier-key --out shop.key > shop.pub 2>/dev/null; "$R" verifier-key --out other.key > /dev/null 2>&1
"$R" create -w ./watch --unsigned dv-prep.txt --txid "$TA" -m "Order A (for the shop)" "${RS[@]}" > /dev/null 2>&1 || bad "prepare for the shop"
"$R" sign dv-prep.txt --yes -w ./signer -i ./payer.age --for "$(cat shop.pub)" --out dv.txt > /dev/null 2>&1 || bad "sign for the shop"
"$R" verify @dv.txt --verifier-key shop.key --expect-address "$MERCHANT" "${RS[@]}" > dv.log 2>&1 && grep -q "made for your key only" dv.log && ok "a receipt for the shop alone verifies with the shop's key" || { bad "designated receipt"; tail -3 dv.log; }
"$R" verify @dv.txt --verifier-key other.key "${RS[@]}" > dv-other.log 2>&1 && bad "a designated receipt convinced another verifier" || { grep -q "another verifier" dv-other.log && ok "and convinces no one else"; } || bad "designated: unexpected error"
"$R" delegate -w ./payer -i ./payer.age --max 0.5 --until 99999999 --payee "$MERCHANT" --out office.session > /dev/null 2>&1 || bad "delegate"
"$R" create -w ./watch --unsigned dg-prep.txt --txid "$TA" -m "Order A (back office)" "${RS[@]}" > /dev/null 2>&1; "$R" sign dg-prep.txt --session office.session --out dg.txt > /dev/null 2>&1 || bad "issue under the delegation"
"$R" verify @dg.txt --expect-address "$MERCHANT" "${RS[@]}" > dg.log 2>&1 && grep -q "session key the spend key authorized" dg.log && ok "a back office issued a receipt under the payer's delegation (no spend key)" || { bad "delegated receipt"; tail -3 dg.log; }
delegated_refused() { # name, then the delegate flags
  local name=$1; shift
  "$R" delegate -w ./payer -i ./payer.age "$@" --out "$name.session" > /dev/null 2>&1
  "$R" create -w ./watch --unsigned "$name-prep.txt" --txid "$TA" -m "$name" "${RS[@]}" > /dev/null 2>&1; "$R" sign "$name-prep.txt" --session "$name.session" --out "$name.txt" > /dev/null 2>&1
  "$R" verify @"$name.txt" "${RS[@]}" > "$name.log" 2>&1 && bad "a delegated receipt $name passed" || { grep -q "outside its delegation" "$name.log" && ok "a delegated receipt $name is refused"; } || bad "$name: unexpected error"
}
delegated_refused over-limit --max 0.001 --until 99999999
delegated_refused expired --max 0.5 --until "$((HA - 1))"
delegated_refused wrong-payee --max 0.5 --until 99999999 --payee "$PAYER0"

echo "== claims: one per wallet per airdrop, from a note held at the snapshot block"
sync "$FUNDER"
lim 300 "$R" claim -w "$FUNDER" -i "$FUNDER_ID" --domain airdrop-e2e --floor 0.01 -m "payout to me" --out claim1.txt > claim1.log 2>&1 || { bad "claim"; tail -3 claim1.log; }
SNAP=$(grep -o 'held at block [0-9]*' claim1.log | grep -o '[0-9]*$')
{ "$R" claim -w "$FUNDER" -i "$FUNDER_ID" --domain airdrop-e2e --floor 0.01 --height "$SNAP" -m "another payout" --out claim2.txt; "$R" claim -w "$FUNDER" -i "$FUNDER_ID" --domain airdrop-other --floor 0.01 --height "$SNAP" --out claim3.txt; } > claim23.log 2>&1 || { bad "second claim"; tail -3 claim23.log; }
for f in 1 2; do "$R" verify @claim$f.txt --json --domain airdrop-e2e --height "$SNAP" --min 0.01 "${RS[@]}" > claim$f.json 2> claim$f.err || { bad "verify claim $f"; tail -2 claim$f.err; }; done
"$R" verify @claim3.txt --json --domain airdrop-other --height "$SNAP" --min 0.01 "${RS[@]}" > claim3.json 2> claim3.err || { bad "verify claim 3"; tail -2 claim3.err; }
CT1=$(jq -r .tag claim1.json); CT3=$(jq -r .tag claim3.json)
[ "${#CT1}" = 64 ] && [ "$CT1" = "$(jq -r .tag claim2.json)" ] && ok "two claims from one wallet carry one tag at block $SNAP: the second is caught" || bad "claim tags differ"
[ "$CT1" != "$CT3" ] && ok "in another airdrop the wallet's tag doesn't link to the first" || bad "claim tags link across domains"
[ "$CT1" != "$TGS" ] && ok "and the funder's claim tag is not its payer tag in a round of the same name (kinds hash apart)" || bad "claim and payer tag link"
"$R" verify @claim1.txt --domain airdrop-other --height "$SNAP" --min 0.01 "${RS[@]}" > claim-wrong.txt 2>&1 && bad "a claim passed for the wrong airdrop" || ok "a claim for one airdrop is refused for another"
"$R" verify @claim1.txt --domain airdrop-e2e --height $((SNAP + 1)) --min 0.01 "${RS[@]}" > claim-wrong.txt 2>&1 && bad "a claim passed for another snapshot" || ok "and for another snapshot block"
"$R" verify @tag-A.txt --json --domain round-e2e --height "$SNAP" --min 0.01 "${RS[@]}" 2>/dev/null | jq -e '.kind == "payer_tag"' >/dev/null && ok "a payer tag is checked as a payer tag, never as a claim (their tags differ by kind)" || bad "payer tag kind"
perl -pe 's/^(zip311t1.{900})./${1}A/' claim1.txt > claim-edited.txt
"$R" verify @claim-edited.txt --domain airdrop-e2e --height "$SNAP" --min 0.01 "${RS[@]}" > claim-edited.out 2>&1 && bad "an edited claim passed" || ok "an edited claim is refused"
# The attacker's claim from a note the chain had spent by the snapshot proves fine; the chain check refuses it.
TIP=$(sqlite3 "$FUNDER/data.sqlite" "select max(checkpoint_id) from ironwood_tree_checkpoints")
if "$ATTACK" claim-spent "$FUNDER" "$FUNDER_ID" airdrop-attack "$TIP" claim-spent.txt > attack.log 2>&1; then
  "$R" verify @claim-spent.txt --domain airdrop-attack --height "$TIP" --min 0.01 "${RS[@]}" > claim-spent.out 2>&1 && bad "a claim from a spent note passed" || { grep -q "was spent before block" claim-spent.out && ok "a claim from a note already spent at the snapshot is refused by the chain check"; } || bad "spent-note claim: unexpected error"
else
  echo "  (the funder spent no note before block $TIP; skipping the spent-note claim)"
fi

echo "== the npm package checks what the CLI made, offline, as a browser would"
HEXA=$("$R" tx "$TA" --network testnet --hex "${RS[@]}" 2>/dev/null | tail -1)
node "$ROOT/scripts/e2e-npm-testnet.mjs" "$PWD" "$HEXA" "$HA" > npm-e2e.txt 2>&1
[ "$(grep -c ' true$' npm-e2e.txt)" = 5 ] && ok "npm: the one-verifier and delegated receipts and a payer tag verify, the other key and the over-limit receipt are refused" || { bad "npm checks"; tail -5 npm-e2e.txt; }

echo "== the API verifies a claim and a payer tag"
"$R" serve --listen "127.0.0.1:$API" --db ./api.db --test-network test --verifier-url "http://127.0.0.1:$API/verify/" 2> api.log &
API_PID=$!
for _ in $(seq 1 90); do curl -sf "http://127.0.0.1:$API/v1/health" >/dev/null && break; sleep 1; done
KEY=""; for _ in $(seq 1 30); do KEY=$(cat api.log api.db.keys 2>/dev/null | grep -o 'rcpt_test_[0-9a-f]*' | head -1 || true); [ -n "$KEY" ] && break; sleep 1; done
jq -n --rawfile c claim2.txt --argjson h "$SNAP" '{claim: ($c | rtrimstr("\n")), domain: "airdrop-e2e", height: $h, min_floor_zatoshis: 1000000}' | curl -s -H "authorization: Bearer $KEY" "http://127.0.0.1:$API/v1/claims/verify" -d @- | jq -e --arg t "$CT1" '.valid and .tag == $t' >/dev/null && ok "the API checks a claim on testnet and returns the same tag" || bad "API claim verify"
jq -n --rawfile c tag-C.txt '{claim: ($c | rtrimstr("\n")), domain: "round-e2e"}' | curl -s -H "authorization: Bearer $KEY" "http://127.0.0.1:$API/v1/claims/verify" -d @- | jq -e --arg t "$TGC" '.kind == "payer_tag" and .tag == $t' >/dev/null && ok "and a payer tag" || bad "API payer tag verify"

echo
echo "${#PASS[@]} passed, ${#FAIL[@]} failed"
[ ${#FAIL[@]} -eq 0 ]

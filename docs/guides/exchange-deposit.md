# Runbook: accept shielded deposits at an exchange

Exchanges restrict shielded ZEC deposits because they can't see where the money came from. A
**deposit desk** asks the customer for a receipt that proves, for each note the deposit spent,
which earlier transaction created it, and how much it held. The desk screens the transparent
addresses that funded that transaction in the clear (an exchange withdrawal the customer
shielded, say) against your own list, and credits, holds or refunds. You learn what a
transparent deposit would have shown you; nothing else about the customer's wallet.

## 1. Run the API

```bash
zceipt serve --listen 127.0.0.1:8723 --db desk.db     # prints a test key and a live key
export ZCEIPT_KEY=rcpt_test_…                          # test mode: testnet
```

Subscribe your backend to the desk's events (signed webhooks, see [WEBHOOKS.md](../WEBHOOKS.md)):

```bash
curl -s 127.0.0.1:8723/v1/webhook_endpoints -H "Authorization: Bearer $ZCEIPT_KEY" \
  -d '{"url":"https://exchange.example/hooks/receipts","events":["request.fulfilled","request.held_for_review","request.rejected","refund.succeeded"]}'
```

## 2. Ask for each deposit

```bash
curl -s 127.0.0.1:8723/v1/requests -H "Authorization: Bearer $ZCEIPT_KEY" -d '{
  "payee": "utest1…your deposit address…", "amount_zatoshis": 50000000, "label": "account 7731",
  "source_of_funds": { "required": true, "blocked_addresses": ["tm…", "tm…"] } }'
```

The response has a `hosted_url` (a pay page for the customer, guarded by its client secret) and a
`receipt_link`. The blocked list stays on your server; requests only show how many addresses are
screened.

## 3. What the customer does

With a zcash-devtool wallet, one command pays, waits for the block and answers the request:

```bash
zceipt pay '<hosted_url>' -w ./wallet -i ./wallet.age --refund-to fresh
```

`zceipt pay` adds the source-of-funds proof and reveals the spent notes' values by itself for a
desk, signs a fresh refund address of the wallet into the receipt, and waits for the payment by
syncing the wallet (the chain server never learns which transaction it is waiting for). Wallets
that embed zceipt-core make the same receipt with `prepare` (viewing key) and a signature from
wherever the spending key lives ([DEVELOPERS.md](../DEVELOPERS.md)).

## 4. What the desk decides

| Outcome | When | Event |
|---|---|---|
| Refused, the request stays open | the receipt doesn't prove where every spent note came from | `receipt.rejected` (422 `source_of_funds_required`) |
| **Cleared**, credited | every spent note's source was funded in the clear, every transparent input of it was read, none is on your list, and the clear funding covers the note's revealed value | `request.fulfilled` |
| **Held for review** | an address on your list; a source funded from shielded notes the customer didn't show (or newly mined coins); an input that couldn't be read; a hidden note value; funding in the clear smaller than the note | `request.held_for_review`, with the reasons and the funding addresses in `provenance` |

Review a held deposit:

```bash
curl -s 127.0.0.1:8723/v1/requests/<id>/review -H "Authorization: Bearer $ZCEIPT_KEY" \
  -d '{"decision":"reject","note":"funded by a listed address"}'
curl -s 127.0.0.1:8723/v1/requests/<id>/refunds -H "Authorization: Bearer $ZCEIPT_KEY" -d '{}'
```

A rejected deposit is refunded to the address the customer signed into the receipt; only the
customer could have chosen it. `accept` credits the deposit instead (`request.fulfilled`).

Money that moved through several of the customer's own transactions (a withdrawal, a
self-transfer, then the deposit) can be shown as a batch with `zceipt create --txid <hop>
--txid <deposit> --prove-source`, which verifiers print as a chain back to the withdrawal. The
desk itself takes one receipt per request: such deposits land in review, where the batch answers
the question.

## 5. Check it end to end

`./scripts/e2e-regtest.sh` runs this whole flow on a private chain: a customer withdraws to a
transparent address, shields it, deposits, is refused without a source proof, is cleared with
one; a second deposit funded by a listed address is held, rejected and refunded.

## One deposit, without a desk

For a single held deposit, ask the customer for a receipt answering a proof request and check
it, optionally with `--prove-address` to show it came from their known address:

```python
v = receipts.verify(receipt, expect_address=EXCHANGE_DEPOSIT_UA, min_zatoshis=amount)
v["sender_addresses"]   # present only if the customer chose to prove it
```

The proof request's challenge makes a receipt forwarded from someone else fail (`challenge_mismatch`).

## Funds from a screened set, without naming the source

A source proof names the exact transaction that funded the deposit. A screened set lets the
customer prove less: that the note they spent came from one of a list of outputs you have
already vetted (your own withdrawals, or the shield deposits your screening passed), without
saying which. This is the association-set idea of Privacy Pools, done with the Orchard circuit
as it is.

```bash
# You: publish the list (one note commitment per line) of the outputs you vetted.
zceipt screened-list --network main --txid <vetted tx> --txid <vetted tx> … > screened.txt
# The customer: a receipt plus a proof against that list.
zceipt create … --screened-set screened.txt --screened-proof deposit.screened
# You: check both. The list's root is computed from your own file, never taken from the proof.
zceipt verify '<link>' --screened-set screened.txt --screened-proof @deposit.screened
```

The proof covers one hop: the spent note itself must be one of the listed outputs.

## Deposits to a TEX address (ZIP 320)

Some exchanges only accept transparent funds and publish a TEX address (`tex1…`, `textest1…`).
A shielded wallet pays one in two steps: the first transaction spends shielded notes to a
one-time transparent address, the second sends that output to the exchange. Both steps are
public, but nothing on chain says who made them, so the exchange can't tell which customer
deposited. A deposit receipt fixes that:

```bash
zceipt create -w ./wallet -i ./wallet.age --txid <first step> \
  --tex-deposit textest1… --second-tx <second step> -m "Account 7731"
```

Every verifier (CLI, API, browser, npm) checks the spend proof for the first step, that the second
step spends the first one's output, and how much reached the TEX address, and reports it as
`deposit`. **It links the customer's shielded funds to the deposit:** share it with the exchange
only. `examples/testnet/deposit-receipt.txt` is a real testnet deposit. (A TEX receipt proves who
made the deposit, not where the money came from; for that, use a desk.)

# Recipe: clear a compliance hold on one deposit

An exchange or bridge holds a deposit and asks "where did this come from?". Instead of a
viewing key for the whole wallet, the customer sends a receipt for the one transaction,
optionally with `--prove-address` to show it came from their known address.

```python
v = receipts.verify(receipt, expect_address=EXCHANGE_DEPOSIT_UA, min_zatoshis=amount)
v["sender_addresses"]   # present only if the customer chose to prove it
```

Pair it with a proof request (`challenge`) so a receipt forwarded from someone else is
rejected (`challenge_mismatch`).

## Deposits to a TEX address (ZIP 320)

Some exchanges only accept transparent funds and publish a TEX address (`tex1…`, `textest1…`).
A shielded wallet pays one in two steps: the first transaction spends shielded notes to a
one-time transparent address, the second sends that output to the exchange. Both steps are public,
but nothing on chain says who made them, so the exchange can't tell which customer deposited.

A deposit receipt fixes that. The customer makes a receipt for the first transaction that names
the TEX address and the second transaction:

```bash
receipts create -w ./wallet -i ./wallet.age --txid <first step> \
  --tex-deposit textest1… --second-tx <second step> -m "Account 7731"
```

Every verifier (CLI, API, browser, npm) then checks the spend proof for the first step, that the
second step spends the first one's output, and how much reached the TEX address, and reports it
as `deposit`. The page shows it as an exchange deposit.

**Warning:** the receipt proves that the holder of those shielded funds made this deposit. Share
it with the exchange only. `examples/testnet/deposit-receipt.txt` is a real testnet deposit.

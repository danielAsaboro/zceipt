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

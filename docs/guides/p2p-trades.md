# Settling a P2P trade dispute over shielded ZEC

On peer-to-peer exchanges the buyer pays the seller directly. When the seller says the
money never arrived, an arbitrator decides who keeps the escrow. With a shielded payment
the arbitrator can't see that payment on a block explorer, and asking the buyer for a
viewing key would expose the buyer's whole wallet. That is why Bisq accepts ZEC only from
transparent addresses. A receipt lets the arbitrator check the one payment and nothing else.

## The trade

1. When the trade opens, the platform gives it an id of 6 to 64 lowercase hex digits, for
   example `7f3a9c21e0b4`. It also records the seller's shielded address and the amount.
2. The buyer pays from any wallet, with the trade id in the payment's memo. Then the buyer
   makes a receipt that signs the trade id too:

   ```bash
   zceipt create --seed-stdin --birthday <wallet birthday> --network main \
     --txid <payment txid> --height <its block> -m "challenge:7f3a9c21e0b4"
   ```

   The buyer posts the link it prints in the trade chat. Nothing is published anywhere else.

## The dispute

The arbitrator runs one command:

```bash
zceipt verify '<link>' --challenge 7f3a9c21e0b4 --memo-contains 7f3a9c21e0b4 \
  --expect-address <seller's address> --min <amount>
```

The verdict is either valid or one specific reason. The command exits 0 only when all of
these hold:

- the payment is mined;
- the buyer's wallet authorized it (spend authority, not just an output);
- the seller's address received at least the amount;
- the receipt was made for this trade;
- the payment itself names this trade (its memo), so an older payment to the same seller can't
  be passed off as this one.

A receipt made for another trade, or one forwarded by someone else, fails on the challenge.

To keep a record for the case file:

```bash
zceipt export '<link>' --records ./case-7f3a9c21e0b4 > trade.csv
```

This writes a JSON record holding the receipt, everything it proved, the confirmations, and
when and against which server it was checked.

## What it does not settle

- **Whether the seller's wallet has seen the payment.** The seller checks that with their own
  wallet. The receipt proves the money was sent to the seller's address.
- **Confirmations.** Settle once the block is final; `verify` and the record show the count.
- **A receipt the buyer never posts.** A missing receipt is not evidence of anything. The buyer
  might not have the CLI.

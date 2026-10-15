# `zcash-devtool wallet receipt`: receipts from inside the wallet

A local patch (not proposed upstream) that adds one command to
[zcash-devtool](https://github.com/zcash/zcash-devtool), so a payer makes a receipt with the same
tool and wallet they paid from:

```bash
zcash-devtool wallet -w ./wallet receipt -i ./wallet.age --txid <txid> -m "Invoice 42"
zcash-devtool wallet -w ./wallet receipt -i ./wallet.age --txid <txid> --request '<shop receipt link>' --refund-to <your address>
```

It prints a verifier link (`…/verify/#zrcpt1…&h=<block>`). All the work is in
[`crates/receipts-wallet`](../../crates/receipts-wallet), the same library the `receipts` CLI uses.

## Applying it

To a zcash-devtool checkout on the same librustzcash revision as this repository:

1. Copy `receipt.rs` to `src/commands/wallet/receipt.rs`.
2. In `src/commands/wallet.rs`, add `pub(crate) mod receipt;` and a variant
   `Receipt(receipt::Command)` (doc comment: "Prove one payment you sent, without a viewing key").
3. In `src/main.rs`, dispatch it: `commands::wallet::Command::Receipt(command) => command.run(wallet_dir).await,`.
4. In `Cargo.toml`, add `receipts-wallet = { path = "<this repo>/crates/receipts-wallet" }` and
   `[patch.crates-io] orchard = { path = "<this repo>/vendor/orchard" }`.

Checked on 2026-10-15 against the testnet wallet that paid transaction `ac5cf500…`: the receipt
made inside zcash-devtool verifies with `receipts verify` (0.0015 TAZ, Ironwood, memo intact).

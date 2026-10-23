# `zcash-devtool wallet receipt`: receipts from inside the wallet

A local patch (not proposed upstream) that adds one command to
[zcash-devtool](https://github.com/zcash/zcash-devtool), so a payer makes a receipt with the same
tool and wallet they paid from:

```bash
zcash-devtool wallet -w ./wallet receipt -i ./wallet.age --txid <txid> -m "Invoice 42"
zcash-devtool wallet -w ./wallet receipt -i ./wallet.age --txid <txid> --request '<shop receipt link>' --refund-to <your address>
```

With `--request` it checks, like `receipts create --request`, that the transaction actually paid
the requested address at least the requested amount, and refuses otherwise; `--refund-to` must be
an address a receipt can prove (an Orchard receiver). It prints a verifier link (`…/verify/#zip311r1…&h=<block>`). All the work is in
[`crates/receipts-wallet`](../../crates/receipts-wallet), the same library the `receipts` CLI uses.

## Building it

```bash
./integrations/zcash-devtool/build.sh        # → target/zcash-devtool/target/release/zcash-devtool
```

It clones upstream zcash-devtool at `5a26ee8`, removes the commands listed in
`removed-files.txt` (inspect, PCZT, migration, TUI: they don't build against the NU7
librustzcash revision this repository pins, `9e3b2e15…`), applies `zcash-devtool-nu7.patch`
(the move to that revision and orchard 0.16, plus `wallet receipt`), and builds. The result is
the same tree the testnet runs below used.

Checked on 2026-10-15 against the testnet wallet that paid transaction `ac5cf500…`: the receipt
made inside zcash-devtool verifies with `receipts verify` (0.0015 TAZ, Ironwood, memo intact).

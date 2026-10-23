# receipts-ffi

Swift and Kotlin bindings (uniffi) for the calls a mobile wallet's signer and a verifier need:

| Call | Does |
|---|---|
| `prepareReceipt(dbPath, network, txid, message)` | every proof, from the wallet's own `zcash_client_sqlite` database (the one the Android and iOS SDKs keep); returns `{ prepared, height }` |
| `describePrepared(prepared)` | what a `zip311u1…` prepared receipt will disclose, for the confirmation screen |
| `signPrepared(prepared, spendingKey, message?)` | checks the key made the spends, signs, returns `zip311r1…` |
| `verifyReceipt(receipt, rawTxHex, height)` | verifies against a transaction the app fetched, returns the report as JSON |
| `challengeOf(message)` | the request challenge a message carries |

A wallet's "Prove this payment" button is `prepareReceipt` then `signPrepared` with the
account's Orchard spending key, then a share sheet for the link. A wallet with its own storage
uses `receipts_core::ReceiptBuilder` in its Rust core instead.

Regenerate the bindings after a change:

```sh
cargo build -p receipts-ffi --release
cargo run -p receipts-ffi --bin uniffi-bindgen -- generate --library target/release/libreceipts_ffi.dylib --language swift --out-dir crates/receipts-ffi/bindings/swift
cargo run -p receipts-ffi --bin uniffi-bindgen -- generate --library target/release/libreceipts_ffi.dylib --language kotlin --out-dir crates/receipts-ffi/bindings/kotlin
```

`cargo test -p receipts-ffi` signs the public demo wallet's prepared receipt (`examples/testnet/demo`)
and verifies it against its testnet transaction through these same functions.

From Swift on a Mac, `crates/receipts-ffi/examples/swift/run.sh` compiles the generated binding
with [`main.swift`](examples/swift/main.swift), signs the demo receipt for a new challenge and
verifies it.

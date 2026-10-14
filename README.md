# Receipts

**Prove one shielded Zcash payment to one person, and reveal nothing else.**

Receipts implements ZIP 311 payment disclosures for **Orchard and Ironwood**. A sender turns
one shielded transaction into a link. Whoever opens the link sees who was paid, how much and
the memo, plus a zero-knowledge proof that the sender authorized the payment. The link
reveals nothing about the sender's address, balance or other transactions, and no viewing key
changes hands.

```
receipts create -w wallet -i key.age --txid <txid> -m "Invoice 42"
→ https://zecathon-receipts.vercel.app/#zrcpt1…
```

Opening the link verifies the receipt entirely in the browser (Rust compiled to WebAssembly).
The receipt sits in the URL `#fragment`, which browsers never send to any server.

> Built for ZECATHON 2026, Core & Tooling track.

## Why

Today, proving a shielded payment means sharing a viewing key, which exposes every past and
future transaction of that account. That is the wrong trade for everyday cases:

- a compliance desk or exchange asking where a deposit came from;
- a merchant dispute ("I paid you on Tuesday");
- a grant, payroll or OTC counterparty that needs proof of one transfer;
- a donation drive proving matched donations.

ZIP 311 describes the right primitive, but it is a **Draft** whose Orchard section is `TODO`
and whose reference implementation is `TBD`. This repository fills that gap for the pools
people use today.

## What a receipt proves

| | Revealed to the verifier | How it is checked |
|---|---|---|
| Recipient, amount, memo of each chosen output | ✅ | The output's `ock` opens the on-chain ciphertext; the note commitment must match `cmx` |
| The sender authorized the transaction | ✅ | A fresh Halo 2 Action proof for the spent note (same anchor and nullifier as on chain) and a spend-authorization signature over the whole receipt |
| An optional message (invoice number, challenge) | ✅ | Covered by the signature, so it cannot be swapped |
| Sender's address, balance, other notes or transactions | ❌ | Never included; `rk` and `cv_net` are freshly randomized |

The full construction is in [docs/SPEC.md](docs/SPEC.md).

## Repository

| Path | What |
|---|---|
| `crates/receipts-core` | Create and verify receipts, the `zrcpt1…` encoding, and tests |
| `crates/receipts-cli` | `receipts` CLI: create from a zcash-devtool wallet, verify against lightwalletd |
| `crates/receipts-wasm` | Browser verifier |
| `web/` | The verifier page (static; fetches the transaction over grpc-web) |
| `docs/SPEC.md` | The Orchard/Ironwood instantiation of ZIP 311 |

## Try it

Requirements: Rust 1.85+ and, for the web page, `wasm-bindgen-cli 0.2.104`.

```bash
cargo test -p receipts-core --release          # 4 tests: Ironwood, Orchard, tampering, wrong key
cargo build -p receipts-cli --release
./scripts/build-web.sh && python3 -m http.server -d web 5321
```

Create a receipt for a payment you sent from a [zcash-devtool](https://github.com/zcash/zcash-devtool)
wallet. Do it within about 100 blocks of sending, while the wallet still has a checkpoint at
the transaction's anchor:

```bash
./target/release/receipts create -w <wallet_dir> -i <identity.age> --txid <txid> -m "Invoice 42"
./target/release/receipts verify '<link or zrcpt1…>' --expect-address <recipient u1…>
```

## Privacy notes

- **The verifier page** fetches only the public transaction, from a lightwalletd grpc-web
  server the viewer can change, or from nothing at all if they paste the raw transaction.
  There is no backend, no analytics and no third-party script.
- **The CLI** decrypts the wallet mnemonic in memory with its age identity, derives the
  Orchard key, and never writes anything back.
- **A receipt** carries one `ock` per disclosed output and a fresh proof per disclosed spend.
  Undisclosed outputs, including change, stay sealed.

## Tests and evidence

`cargo test -p receipts-core --release` builds real Orchard and Ironwood bundles in memory
(halo2 proofs and signatures included), then:

- round-trips a receipt through its text form and verifies it;
- rejects a changed message, a flipped proof byte, stripped spends, a wrong `ock`, a spend
  proof pointed at another action, the wrong txid and the wrong network;
- refuses to create a receipt with a key that does not own the spent note.

Mainnet evidence (to be filled in by the demo run):

| Claim | Evidence |
|---|---|
| A real Ironwood payment | txid: pending |
| A receipt created from the wallet that sent it | receipt link: pending |
| Verified in the browser and the CLI | screenshot and CLI output: pending |

## License

MIT OR Apache-2.0.

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

## For developers

Receipts is a full developer platform, not just a library. Start with [docs/QUICKSTART.md](docs/QUICKSTART.md).

| Piece | What you get |
|---|---|
| **REST API** (`receipts serve`) | proof requests (each with a ZIP-321 payment URI and a payer link), verification of receipts and batches, `rcpt_test_` / `rcpt_live_` keys, idempotency keys, cursor pagination, a stable error `code` on every failure, and an [OpenAPI spec](docs/openapi.yaml) |
| **Webhooks** | HMAC-signed `request.fulfilled`, `request.created` and `receipt.rejected` events, retried with backoff for up to 8 attempts, plus resend |
| **SDKs** | [TypeScript](packages/zcash-receipts) (with types), [Python](packages/receipts-python) (standard library only) and [Rust](crates/receipts-client), all with typed errors, automatic retries and idempotency, and webhook verification |
| **Browser** | `verifyReceipt()` in WebAssembly with no server, and the `<zcash-receipt>` web component |
| **Sandbox** | `zrcpt_test_*` fixtures with a fixed outcome for every error path, so you can integrate with no wallet and no faucet |
| **Local dev tools** | `receipts listen --forward-to …` and `receipts trigger request.fulfilled`, like the Stripe CLI |
| **For AI agents** | `/llms.txt`, `/llms-full.txt`, every doc as Markdown, and `receipts mcp`, an MCP server with `verify_receipt`, `create_proof_request`, `get_proof_request` and `submit_receipt` |
| **Docs** | [quickstart](docs/QUICKSTART.md), [webhooks](docs/WEBHOOKS.md), [errors](docs/ERRORS.md), [sandbox](docs/SANDBOX.md), [SDKs](docs/SDKS.md), and recipes for [checkout](docs/guides/merchant-checkout.md), [exchange deposits](docs/guides/exchange-deposit.md) and [payouts](docs/guides/grant-payouts.md) |

Why it matters: today, Zcash payment processors need the merchant's viewing key to see that
an order was paid, and that key exposes every incoming payment. Receipts turns it around. The
payer proves their one payment, and nobody hands over a viewing key.

## Repository

| Path | What |
|---|---|
| `crates/receipts-core` | Create and verify receipts, the `zrcpt1…` encoding, and tests |
| `crates/receipts-chain` | lightwalletd access, on-chain verification, rebuilding Merkle paths |
| `crates/receipts-server` | the REST API, webhooks, sandbox and docs (`receipts serve`) |
| `crates/receipts-client` | Rust API client |
| `packages/receipts-python` | Python API client |
| `crates/receipts-cli` | `receipts` CLI: create from a zcash-devtool wallet, verify against lightwalletd |
| `crates/receipts-wasm` | Browser verifier |
| `packages/zcash-receipts` | npm package: `verifyReceipt()` for any JS app, plus the `<zcash-receipt>` web component |
| `web/` | The verifier page and the embed demo (`embed.html`); static, fetches the transaction over grpc-web |
| `docs/SPEC.md` | The Orchard/Ironwood instantiation of ZIP 311 |

## Try it

Requirements: Rust 1.89+ (pinned in `rust-toolchain.toml`). For the web page you also need `rustup target add wasm32-unknown-unknown`, `cargo install wasm-bindgen-cli --version 0.2.104` and `cargo install wasm-tools`.

```bash
cargo test --release -p receipts-core -p receipts-cli   # in-memory bundles + the committed regtest receipt
cargo install --locked --path crates/receipts-cli    # puts `receipts` on your PATH
./scripts/build-web.sh && python3 -m http.server -d web 5321
```

Create a receipt for a payment you sent from a [zcash-devtool](https://github.com/zcash/zcash-devtool)
wallet, at any time after sending. If the wallet has pruned the checkpoint at the
transaction's anchor, the CLI rebuilds the Merkle path from public chain data:

```bash
receipts create -w <wallet_dir> -i <identity.age> --txid <txid> -m "Invoice 42"
receipts verify '<link or zrcpt1…>' --expect-address <recipient u1…>
```

## One link for many payments

```bash
receipts create -w wallet -i key.age --txid <a> --txid <b> --txid <c> -m "Grant round 3"
```

This makes a `zrcptb1…` batch link. Each receipt signs `batch:<id> <i>/<n>`, so payments
can't be dropped, added or reordered without breaking a signature. The verifier page shows
every payment and the total. A DAO, payroll or grant program can prove "we paid all of these
people" without exposing its treasury address or balance.

## Optionally prove who paid

By default the sender stays anonymous. For a donation drive or a treasury report, add
`--prove-address <your public u1…>`. The receipt then also proves that the same spend
authority controls that address, and the page shows it as **FROM … (proven)**. The CLI
refuses an address the wallet doesn't own.

## Embed it in any site

```html
<script type="module" src="/zcash-receipts/widget.js"></script>
<zcash-receipt receipt="zrcpt1…" expect-address="u1…" min-zatoshis="1000000"></zcash-receipt>
```

A shop, an exchange's support desk or a grant program can confirm a customer's payment on
its own page without running a node or seeing anyone's viewing key. See `web/embed.html`
and [packages/zcash-receipts](packages/zcash-receipts).

## Proof requests: "prove it's you"

A receipt alone shows that *someone with the spend authority* paid. To know the person in
front of you is that someone, and isn't forwarding an old receipt, ask for a fresh one:

1. On the verifier page, open **Ask someone to prove they paid you**, enter your address
   and the amount you expect, and send the link it makes. It carries a random challenge.
2. The payer runs `receipts create … --request '<link>'`. The receipt signs
   `challenge:<code>`, and the CLI refuses if the transaction didn't pay the requested
   address at least the requested amount.
3. Opening the returned link checks three things against what *you* asked for, which is
   stored only in your browser, not against the link: the challenge was signed, the payee
   matches, and the amount is at least what you asked.

A valid receipt that doesn't sign your challenge shows **REQUEST NOT SATISFIED**. This is
ZIP 311's interactive mode ("a payment disclosure may be tied to a challenge").

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

**On the Zcash public testnet (NU7):**

| Claim | Evidence |
|---|---|
| A real Ironwood payment: 0.01 TAZ, memo "Invoice 42: two coffees" | [`571de6e4…9e0e73`](https://testnet.zcashexplorer.app/transactions/571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73), block 4,500,997 |
| A receipt created from the sending wallet in 2.4 s | [examples/testnet/receipt.txt](examples/testnet/receipt.txt) |
| Verified by the CLI against testnet lightwalletd, with `--expect-address` | `receipts verify … → VALID` |
| Verified in the browser from the public testnet grpc-web server | VERIFIED in 9.3 s (zcash-testnet.chainsafe.dev) |
| A proof request answered on testnet, and a replayed receipt rejected | [examples/testnet/request-answer-link.txt](examples/testnet/request-answer-link.txt) → REQUEST SATISFIED; the earlier receipt, which signs no challenge, → REQUEST NOT SATISFIED |
| A receipt that also proves the sending address | [examples/testnet/receipt-with-sender-address.txt](examples/testnet/receipt-with-sender-address.txt): VALID, FROM shown as proven; a different wallet's address is refused |
| A batch of 3 testnet payments to 2 recipients, verified as one link | [examples/testnet/batch.txt](examples/testnet/batch.txt): CLI `VALID batch`, total 0.022 ZEC; page shows all three |
| A receipt with the Merkle path rebuilt from chain data only (`--from-chain`) | testnet: blocks 4,500,984 to 4,500,997, VALID; regtest: a note 105 blocks old (past the wallet's 100-block pruning window), VALID |

End to end on a private chain as well (Zebra 6.4.2 regtest, NU6.3 active, lightwalletd, zcash-devtool wallets):

| Claim | Evidence |
|---|---|
| A real Ironwood (v6) payment: 0.42 ZEC, memo "Invoice 42: two coffees" | tx `dcd2700def717468e6fe07c29a7a7f0fd7ec4e4157d03737f3a9f64e0fd4b732`, block 222, raw bytes in [examples/regtest](examples/regtest) |
| A receipt created from the wallet that sent it (1.8 s) | [examples/regtest/receipt.txt](examples/regtest/receipt.txt) |
| Verified by the CLI against lightwalletd, including `--expect-address` | `receipts verify … → VALID` |
| Verified in the browser over grpc-web | the receipt page shows VERIFIED; "was it paid to you?" says yes for the merchant |
| An edited receipt is rejected | changing one letter of the note gives `the signature for action 1 is invalid` |
| Anyone can re-check it offline | `cargo test -p receipts-cli --release --test regtest_fixture` |

Reproduce the private chain yourself with [docs/REGTEST.md](docs/REGTEST.md).

## License

MIT OR Apache-2.0.

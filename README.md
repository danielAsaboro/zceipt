# Receipts

**Prove one shielded Zcash payment. Reveal nothing else.**

Shielded Zcash hides who paid whom. But sometimes you have to prove one payment: to a shop, an
exchange, an auditor, a donor. Today that means handing over a **viewing key**, which shows every
payment to that wallet (and, for a full viewing key, from it), past and future. Receipts replaces the key with a **receipt**: a link
that proves one transaction (who was paid, how much, the memo, and that the sender authorized it
with a zero-knowledge proof) and nothing about the sender's address, balance or other payments.

It implements ZIP 311 payment disclosures for **Orchard and Ironwood**, the
pools wallets use today, with an API, SDKs and a browser verifier around it.

**Try it in one command** (no wallet, faucet or setup; about five seconds):

```bash
cargo install --locked --path crates/receipts-cli && receipts demo
```

No Rust? `docker compose run --rm receipts demo --no-wait`. The tour walks a coffee shop through
asking for a payment, getting a receipt instead of a viewing key, finality, a refund and an
accountant's attestation, then checks a real testnet receipt offline. It leaves the API,
dashboard and verifier running for you to click around.

| | With a viewing key | With a receipt |
|---|---|---|
| What the other side sees | every incoming payment, past and future | this one payment, and that you made it |
| Your address and balance | exposed or linkable | hidden (unless you choose to prove your address) |
| Proof in a dispute | the processor's records | the receipt itself, checkable by anyone, offline |

More: [threat model](docs/THREAT-MODEL.md) · [comparison with viewing-key processors](docs/COMPARISON.md) · [how it fills ZIP 311's TODOs](docs/ZIP311-TODOS.md) · [spec](docs/SPEC.md) · [crypto review](docs/CRYPTO-REVIEW.md). Built for ZECATHON 2026, Core & Tooling track.

### Making a receipt

```
receipts create -w wallet -i key.age --txid <txid> -m "Invoice 42"
→ http://127.0.0.1:8723/verify/#zrcpt1…&h=<block>
```

Opening the link verifies the receipt entirely in the browser (Rust compiled to WebAssembly).
The receipt sits in the URL `#fragment`, which browsers never send to any server. Other ways in:
`zcash-devtool wallet receipt` (inside the wallet), `receipts pay '<shop pay link>'` (pay and
prove in one step), `docker compose up` (API, dashboard and verifier on http://127.0.0.1:8723),
`./scripts/install.sh`.

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
| **Webhooks** | HMAC-signed events (`request.created`, `request.payment_received`, `request.fulfilled`, `request.final`, `request.expired`, `receipt.rejected`, `refund.created`, `refund.succeeded`), retried with backoff for up to 8 attempts, plus resend |
| **SDKs** | [TypeScript](packages/zcash-receipts) (with types), [Python](packages/receipts-python) (standard library only), [Rust](crates/receipts-client) and [Go](packages/receipts-go), all with typed errors, automatic retries and idempotency, and webhook verification. Every one of the 31 API operations is covered by all four; `scripts/sdk-parity.py` and a live test per SDK prove it ([table](conformance/sdk-parity.json)) |
| **Browser** | `verifyReceipt()` in WebAssembly with no server, and the `<zcash-receipt>` web component. Links carry an `h=` block hint, so the page downloads the whole block and lightwalletd never learns which transaction was checked; every result says what the server could see |
| **Inside the wallet** | `zcash-devtool wallet receipt --txid …` makes a receipt from the wallet that paid ([local patch](integrations/zcash-devtool), built on the `receipts-wallet` library) |
| **Drop-in integrations** | HTTP 402 "prove you paid" gate and signed-webhook handler for Express, Next.js/fetch servers and FastAPI/Django/Flask ([guide](docs/guides/http-402.md), [paid API example](examples/paid-api/server.mjs)) |
| **Payment-link checker** | `receipts check-link`, `POST /v1/payment_links/check`, `checkPaymentLink()` and a panel on the page lint a `zcash:` link before it goes on an invoice: wrong network, transparent/TEX/Sapling-only recipients a receipt can't prove, missing amount or memo, unknown required params, QR density |
| **Cross-pool payments** | after NU6.3 wallets spend Orchard notes into Ironwood outputs; receipts (format v3) cover the Orchard spend and the Ironwood output together ([example](examples/regtest-crosspool)) |
| **Exchange deposits (ZIP 320)** | `receipts create --tex-deposit <tex> --second-tx <txid>` proves who made a two-step TEX deposit; every verifier checks the second step spends the first and pays the TEX, with a clear warning that it links the shielded funds to the deposit. Proven on testnet |
| **Attestations** | `POST /v1/requests/{id}/attestations`: an Ed25519 SD-JWT stating only "paid at least X on or before day D"; txid, exact amount, time, request and label stay hidden unless revealed one by one; `verifyAttestation(p, { issuer })` checks it offline against the issuer you trust |
| **Refunds** | the payer signs `refund-to:` into their receipt; `POST /v1/requests/{id}/refunds` returns a ZIP-321 link to that address, and a receipt for the refund settles it (`refund.created`, `refund.succeeded`) |
| **Sign in with Zcash** | `POST /v1/sign_in/challenges` + `receipts sign-in`: prove control of a shielded address for one domain and one nonce, with no transaction. Phishing and replay are refused; `verifySignIn()` checks it offline |
| **Conformance** | [133 shared vectors](conformance/README.md) from real Orchard and Ironwood receipts that the Rust and npm verifiers both run, plus a decoder fuzz pass in `cargo test` |
| **Sandbox** | `zrcpt_test_*` fixtures with a fixed outcome for every error path, so you can integrate with no wallet and no faucet, plus test clocks that fast-forward expiry and the 10-confirmation `request.final` event |
| **Local dev tools** | `receipts doctor` (checks servers, API key, clock, wallet), `receipts listen --forward-to …` and `receipts trigger <any event>`, like the Stripe CLI |
| **For AI agents** | `/llms.txt`, `/llms-full.txt`, every doc as Markdown, and `receipts mcp`, an MCP server with `verify_receipt`, `create_proof_request`, `get_proof_request`, `submit_receipt`, `refund_payment` and `check_payment_link` |
| **Docs** | [threat model: who learns what](docs/THREAT-MODEL.md), [crypto review](docs/CRYPTO-REVIEW.md), [how ZIP 311's TODOs are filled](docs/ZIP311-TODOS.md), [next to viewing-key processors](docs/COMPARISON.md), [quickstart](docs/QUICKSTART.md), [webhooks](docs/WEBHOOKS.md), [errors](docs/ERRORS.md), [sandbox](docs/SANDBOX.md), [SDKs](docs/SDKS.md), and recipes for [checkout](docs/guides/merchant-checkout.md), [exchange deposits](docs/guides/exchange-deposit.md), [payouts](docs/guides/grant-payouts.md), [refunds](docs/guides/refunds.md), [attestations](docs/guides/attestations.md), [HTTP 402](docs/guides/http-402.md) and [Sign in with Zcash](docs/guides/sign-in.md) |

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

Requirements: Rust 1.89 or newer (`rust-toolchain.toml` pins 1.95; rustup installs it). For the web page you also need `rustup target add wasm32-unknown-unknown`, `cargo install wasm-bindgen-cli --version 0.2.104` and `cargo install wasm-tools`.

```bash
cargo test --release -p receipts-core -p receipts-cli   # in-memory bundles + the committed regtest receipt
cargo install --locked --path crates/receipts-cli    # puts `receipts` on your PATH
receipts serve        # API + dashboard + the browser verifier at http://127.0.0.1:8723/verify/
```

To rebuild the verifier page after changing the Rust or the page, run `./scripts/build-web.sh`
(the server embeds the result when it's next built; `python3 -m http.server -d web 5321` also
serves it on its own).

Create a receipt for a payment you sent from a [zcash-devtool](https://github.com/zcash/zcash-devtool)
wallet, at any time after sending. If the wallet has pruned the checkpoint at the
transaction's anchor, the CLI rebuilds the Merkle path from public chain data:

```bash
receipts create -w <wallet_dir> -i <identity.age> --txid <txid> -m "Invoice 42"
receipts verify '<link or zrcpt1…>' --expect-address <recipient u1…>
```

Paying a shop's proof request is one command: it pays from the wallet, waits for the block,
builds the receipt and submits it (or prints the link to send back):

```bash
receipts pay 'https://shop.example/pay/preq_…?secret=…' -w <wallet_dir> -i <identity.age>
```

## One link for many payments

```bash
receipts create -w wallet -i key.age --txid <a> --txid <b> --txid <c> -m "Grant round 3"
```

This makes a `zrcptb1…` batch link. Each receipt signs `batch:<id> <i>/<n>`, so payments
can't be dropped, added or reordered without breaking a signature. The verifier page shows
every payment and the total. A DAO, payroll or grant program can prove "we paid all of these
people" without exposing its treasury address or balance.

## Secret tripwire

Every surface refuses viewing keys, spending keys and seed phrases pasted where a receipt
belongs: the API (`secret_detected`, never stored or echoed), the CLI, the verifier page and the
npm package. `receipts privacy-lint <paths>` scans your logs, configs and code for leaked keys,
prints `file:line` and the kind (never the secret), and exits 1 in CI if it finds any.

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

`python3 scripts/soak.py --minutes 15` drives a fresh server with every kind of request, refunds,
attestations, test-clock finality and reorgs, and a webhook receiver that checks every signature.
Last run: 297k calls, 120.9k webhooks, 0 errors, memory flat at 53 MB. (It found two problems,
now fixed: webhook delivery fell behind under load, and missing indexes slowed the database.)

`./scripts/e2e-regtest.sh` reproduces the real-chain story on a private Zebra regtest chain in
about a minute: an Orchard payment and receipt, NU6.3, `receipts pay` answering a proof request
with an Ironwood receipt, a refund settled with a cross-pool (Orchard to Ironwood) receipt, an
attestation and Sign in with Zcash (9 checks; needs Docker, lightwalletd and zcash-devtool).


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

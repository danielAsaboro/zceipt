# Everything Receipts does

The [README](../README.md) covers the core: what a receipt proves, how to check one, and the library. This page lists what is built around it, with commands and evidence.

## For developers

Receipts is a full developer platform, not just a library. Start with [docs/QUICKSTART.md](QUICKSTART.md).

| Piece | What you get |
|---|---|
| **REST API** (`receipts serve`) | proof requests (each with a ZIP-321 payment URI and a payer link), verification of receipts and batches, `rcpt_test_` / `rcpt_live_` keys, idempotency keys, cursor pagination, a stable error `code` on every failure, and an [OpenAPI spec](openapi.yaml) |
| **Webhooks** | HMAC-signed events (`request.created`, `request.payment_received`, `request.fulfilled`, `request.final`, `request.expired`, `receipt.rejected`, `refund.created`, `refund.succeeded`), retried with backoff for up to 8 attempts, plus resend |
| **SDKs** | [TypeScript](../packages/zcash-receipts) (with types), [Python](../packages/receipts-python) (standard library only), [Rust](../crates/receipts-client) and [Go](../packages/receipts-go), all with typed errors, automatic retries and idempotency, and webhook verification. Every one of the 31 API operations is covered by all four; `scripts/sdk-parity.py` and a live test per SDK prove it ([table](../conformance/sdk-parity.json)) |
| **Browser** | `verifyReceipt()` in WebAssembly with no server, and the `<zcash-receipt>` web component. Links carry an `h=` block hint, so the page fetches the payment among up to 64 shielded transactions of that block and lightwalletd learns only the block (in a block with one shielded transaction that hides nothing, and the page says how many there were); every result says what the server could see |
| **Inside the wallet** | `zcash-devtool wallet receipt --txid …` makes a receipt from the wallet that paid ([local patch](../integrations/zcash-devtool), built on the `receipts-wallet` library) |
| **Drop-in integrations** | HTTP 402 "prove you paid" gate and signed-webhook handler for Express, Next.js/fetch servers and FastAPI/Django/Flask ([guide](guides/http-402.md), [paid API example](../examples/paid-api/server.mjs)) |
| **Payment-link checker** | `receipts check-link`, `POST /v1/payment_links/check`, `checkPaymentLink()` and a panel on the page lint a `zcash:` link before it goes on an invoice: wrong network, transparent/TEX/Sapling-only recipients a receipt can't prove, missing amount or memo, unknown required params, QR density |
| **Cross-pool payments** | after NU6.3 wallets spend Orchard notes into Ironwood outputs; receipts (format v3) cover the Orchard spend and the Ironwood output together ([example](../examples/regtest-crosspool)) |
| **Exchange deposits (ZIP 320)** | `receipts create --tex-deposit <tex> --second-tx <txid>` proves who made a two-step TEX deposit; every verifier checks the second step spends the first and pays the TEX, with a clear warning that it links the shielded funds to the deposit. Proven on testnet |
| **Attestations** | `POST /v1/requests/{id}/attestations`: an Ed25519 SD-JWT stating only "paid at least X on or before day D"; txid, exact amount, time, request and label stay hidden unless revealed one by one; `verifyAttestation(p, { issuer })` checks it offline against the issuer you trust |
| **Refunds** | the payer signs `refund-to:` into their receipt; `POST /v1/requests/{id}/refunds` returns a ZIP-321 link to that address, and a receipt for the refund settles it (`refund.created`, `refund.succeeded`) |
| **Sign in with Zcash** | `POST /v1/sign_in/challenges` + `receipts sign-in`: prove control of a shielded address for one domain and one nonce, with no transaction. Phishing and replay are refused; `verifySignIn()` checks it offline |
| **Conformance** | [270 shared vectors](../conformance/README.md) from real Orchard and Ironwood receipts, run by the Rust and npm verifiers and by an independent verifier written from the protocol spec in Python ([`spec-verifier`](../spec-verifier)), plus a decoder fuzz pass in `cargo test` |
| **Sandbox** | `zip311_test_*` fixtures with a fixed outcome for every error path, so you can integrate with no wallet and no faucet, plus test clocks that fast-forward expiry and the 10-confirmation `request.final` event |
| **Local dev tools** | `receipts doctor` (checks servers, API key, clock, wallet), `receipts listen --forward-to …` and `receipts trigger <any event>`, like the Stripe CLI |
| **For AI agents** | `/llms.txt`, `/llms-full.txt`, every doc as Markdown, and `receipts mcp`, an MCP server with `verify_receipt`, `create_proof_request`, `get_proof_request`, `submit_receipt`, `refund_payment` and `check_payment_link` |
| **Docs** | [threat model: who learns what](THREAT-MODEL.md), [crypto review](CRYPTO-REVIEW.md), [how ZIP 311's TODOs are filled](ZIP311-TODOS.md), [next to viewing-key processors](COMPARISON.md), [quickstart](QUICKSTART.md), [webhooks](WEBHOOKS.md), [errors](ERRORS.md), [sandbox](SANDBOX.md), [SDKs](SDKS.md), and recipes for [checkout](guides/merchant-checkout.md), [exchange deposits](guides/exchange-deposit.md), [payouts](guides/grant-payouts.md), [refunds](guides/refunds.md), [attestations](guides/attestations.md), [HTTP 402](guides/http-402.md) and [Sign in with Zcash](guides/sign-in.md) |

Why it matters: today, Zcash payment processors need the merchant's viewing key to see that
an order was paid, and that key exposes every incoming payment. Receipts turns it around. The
payer proves their one payment, and nobody hands over a viewing key.

## Repository

| Path | What |
|---|---|
| `crates/receipts-core` | Create and verify receipts, the `zip311r1…` encoding, and tests |
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

Requirements: Rust (rustup installs the pinned 1.95 automatically; the crates build on 1.89+). For the web page you also need `rustup target add wasm32-unknown-unknown`, `cargo install wasm-bindgen-cli --version 0.2.104` and `cargo install wasm-tools`.

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
receipts verify '<link or zip311r1…>' --expect-address <recipient u1…>
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

This makes a `zip311b1…` batch link. Each receipt signs `batch:<id> <i>/<n>`, so payments
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

## Optionally prove where the money came from

Exchanges keep Zcash transparent because they can't see where shielded deposits come from
(the [pain points](PAIN-POINTS.md) we collected put this first). Add `--prove-source` and
the receipt also proves, for each note you spent, which earlier transaction output created it,
and nothing else about your wallet. If that transaction was you shielding an exchange
withdrawal, the verifier sees the withdrawal address and amount that funded it. Add
`--reveal-source-value` to show each spent note's exact value. It reuses the Orchard circuit
(no new trusted setup, no list operator, no waiting period); see
[SPEC.md](SPEC.md#source-of-funds-version-4) and [CLAIM.md](CLAIM.md).

Several hops (a withdrawal, a self-transfer, then the deposit)? Give each txid: `--txid <hop>
--txid <deposit> --prove-source` makes one batch, and verifiers print the chain back to the
withdrawal.

```
receipts create -w wallet -i key.age --txid <deposit txid> --prove-source
receipts verify @receipt.txt
  source    action 1 spent the note created by tx 5093e033… action 0 (height 530)
            that tx was funded in the clear: 0.30000000 ZEC from tmRyMkJH…
```

## Prove you were paid (the recipient's side)

`receipts received -w wallet -i key.age --txid <txid>` makes a `zrcin1…` link for an accountant,
a tax office or a lender: these payments reached this address, and the presenter controls it.
No incoming viewing key, no other payments, and the payer can't make one for you.
It proves "a note reached an address you control", not "someone else paid you": you can pay
yourself and make one. A lender or tax office that needs income should ask for the payer's
receipt as well (which proves the payer's spend authority), or for a receipt answering its own
proof request.

## Signed payment requests

`receipts request -w wallet -i key.age --domain shop.example --amount 0.25 --memo "Order 42"` signs
a `zreq1…` request with the payee address's key. `receipts pay 'zreq1…'` checks the signature,
the expiry and that `https://shop.example/.well-known/zcash-receipts.json` lists the address, then
pays and returns a receipt for the request code. Nobody can swap the address or change the amount
in transit.

## Deposit desks: shielded deposits an exchange can accept

Create a request with `"source_of_funds": {"required": true, "blocked_addresses": [...]}`. The
customer pays from shielded funds with `receipts pay`, which proves where each spent note came
from. The server screens the transparent addresses that funded it against your list: clear
deposits are credited with a provenance record, listed or unexplained ones are held for review
(`POST /v1/requests/{id}/review`), and rejected ones are refunded to the customer's signed
address. You learn what a transparent deposit would show you; the customer stays shielded.

## Prove you hold funds

`receipts reserve -w wallet -i key.age --at-least 0.05 -m "challenge:<nonce>"` proves you hold at
least that much in unspent shielded notes, for a counterparty, an escrow or a treasury report,
without a viewing key. Verifiers check each note against the chain's tree root and scan every
published nullifier to confirm they're unspent. They learn the notes' values and nullifiers (so
they can see when you spend them), nothing else.

## Optionally keep the memo private

`--withhold-memo` proves who was paid and how much, and leaves the memo encrypted: the receipt
carries the note's commitment opening without the seed the memo key derives from. Useful when
the memo holds an invoice note or a refund address that the verifier doesn't need.

## Embed it in any site

```html
<!-- served by `receipts serve` at /verify/zcash-receipts/, or copy packages/zcash-receipts -->
<script type="module" src="/verify/zcash-receipts/widget.js"></script>
<zcash-receipt receipt="zip311r1…" expect-address="u1…" min-zatoshis="1000000"></zcash-receipt>
```

A shop, an exchange's support desk or a grant program can confirm a customer's payment on
its own page without running a node or seeing anyone's viewing key. See `web/embed.html`
and [packages/zcash-receipts](../packages/zcash-receipts).

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
- **What the chain server sees**, recorded byte for byte ([docs/ASSURANCE.md](ASSURANCE.md)):
  verifying sends one request holding only the txid. Creating a receipt from chain data (when
  the wallet pruned the note's witness) asks for whole 1,000-block windows, from the one the
  spent note was created in to the end of the payment's, so neither exact block is revealed.

## Tests and evidence

The independent checks (second implementation, mutation testing, fuzzing, Miri, the wire
recording, the chain) are collected in [docs/ASSURANCE.md](ASSURANCE.md). The rest of
this section is the product-level testing.

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
| A real Ironwood payment: 0.01 TAZ, memo "Invoice 42: two coffees" | [`571de6e4…9e0e73`](https://testnet.cipherscan.app/tx/571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73), block 4,500,997 |
| A receipt created from the sending wallet in 2.4 s | [examples/testnet/receipt.txt](../examples/testnet/receipt.txt) |
| Verified by the CLI against testnet lightwalletd, with `--expect-address` | `receipts verify … → VALID` |
| Verified in the browser from the public testnet grpc-web server | VERIFIED in 9.3 s (zcash-testnet.chainsafe.dev) |
| A proof request answered on testnet, and a replayed receipt rejected | [examples/testnet/request-answer-link.txt](../examples/testnet/request-answer-link.txt) → REQUEST SATISFIED; the earlier receipt, which signs no challenge, → REQUEST NOT SATISFIED |
| A receipt that also proves the sending address | [examples/testnet/receipt-with-sender-address.txt](../examples/testnet/receipt-with-sender-address.txt) (re-made 2026-10-15 after the address-proof fix): VALID, FROM shown as proven; a different wallet's address is refused, and so is the pre-fix receipt |
| A batch of 3 testnet payments to 2 recipients, verified as one link | [examples/testnet/batch.txt](../examples/testnet/batch.txt): CLI `VALID batch`, total 0.022 ZEC; page shows all three |
| A receipt with the Merkle path rebuilt from chain data only (`--from-chain`) | testnet: blocks 4,500,000 to 4,500,997, VALID (since Oct 22 the range runs to 4,500,999, the end of the window, so the payment's block isn't revealed either); regtest: a note 105 blocks old (past the wallet's 100-block pruning window), VALID |

End to end on a private chain as well (Zebra 6.4.2 regtest, NU6.3 active, lightwalletd, zcash-devtool wallets):

| Claim | Evidence |
|---|---|
| A real Ironwood (v6) payment: 0.42 ZEC, memo "Invoice 42: two coffees" | tx `dcd2700def717468e6fe07c29a7a7f0fd7ec4e4157d03737f3a9f64e0fd4b732`, block 222, raw bytes in [examples/regtest](../examples/regtest) |
| A receipt created from the wallet that sent it (1.8 s) | [examples/regtest/receipt.txt](../examples/regtest/receipt.txt) |
| Verified by the CLI against lightwalletd, including `--expect-address` | `receipts verify … → VALID` |
| Verified in the browser over grpc-web | the receipt page shows VERIFIED; "was it paid to you?" says yes for the merchant |
| An edited receipt is rejected | changing one letter of the note gives `the signature for action 1 is invalid` |
| Anyone can re-check it offline | `cargo test -p receipts-cli --release --test regtest_fixture` |

Reproduce the private chain yourself with [docs/REGTEST.md](REGTEST.md).


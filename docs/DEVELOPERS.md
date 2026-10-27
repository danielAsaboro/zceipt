# For wallet and protocol developers

## The crate

The core is one Rust crate on top of `orchard` and `zcash_primitives`. By
default it is the ZIP 311 profile alone (encoding, create, prepare, sign, verify); the
`extensions` feature adds payment requests, sign-in, proof of
funds, screened sets, exchange deposits and link linting, with their extra dependencies:

```rust
use zceipt_core::{sign_prepared, verify_transaction, Network, Receipt, ReceiptBuilder, ViewingSpendWitness};

// The sender's wallet, after paying: every proof, from the full viewing key alone.
let prepared = ReceiptBuilder::new(Network::Testnet, &tx)
    .message(b"Invoice 42")
    .disclose(1, ovk)
    .spend(ViewingSpendWitness { index: 0, fvk, note, merkle_path, prove_address: None, source: None })
    .prepare(&pk, &mut rng)?;
// The signer: here, or a hardware wallet given the unsigned receipt and the randomizers.
let sigs = sign_prepared(prepared.unsigned(), prepared.alphas(), &[ask], &mut rng)?;
let link = prepared.apply_signatures(sigs)?.to_text(); // "zip311r1…"

// Anyone, with the mined transaction (its txid is computed, not trusted):
let v = verify_transaction(&vk, &Receipt::from_text(&link)?, Network::Testnet.coin_type(), &tx)?;
```

- **Inside a wallet:** the proofs need only the full viewing key (`zceipt_core::prepare`); the
  spend authorizing key signs afterwards, so the key can stay on a hardware wallet. The device is
  given the unsigned receipt and the randomizers, never a digest: it computes the digest itself,
  checks each `rk` against its key and shows what it signs (`zceipt_core::sign_prepared` is the
  reference signer). A device that signed digests handed to it could be made to authorize a spend.
  From the CLI: `zceipt create -w <watch-only wallet> --txid … --unsigned r.txt` makes the
  proofs with no key, and `zceipt sign r.txt -w <wallet> -i <identity>` signs on the machine
  that holds it, from `keys.toml` alone. The core builds on stock
  `orchard` 0.16 and verifies real testnet receipts there, refusing the edited one and the one
  with an altered proof (`scripts/check-stock-orchard.sh`). `crates/zceipt-wallet` makes receipts from
  a seed phrase or viewing key (`prepare_receipt_from_keys`) or a zcash-devtool wallet database.
  A `zcash-devtool wallet receipt --txid …` command is 137 lines on top of it, but devtool itself
  first needs a port to the NU7 librustzcash this workspace pins: together they are a 6,628-line
  patch that also drops 65 devtool files ([integrations/zcash-devtool](../integrations/zcash-devtool)).
- **The spec:** [ZIP311-ORCHARD.md](ZIP311-ORCHARD.md) is the normative core (encoding,
  creation, every verification rule, rationale) written as text for ZIP 311's Orchard `TODO`;
  [SPEC.md](SPEC.md) adds the extensions. [ZIP311-TODOS.md](ZIP311-TODOS.md) maps each
  open item in ZIP 311 to what we chose, and [SPEC-AMBIGUITIES.md](SPEC-AMBIGUITIES.md)
  lists where the specs are silent.
- **Conformance:** [278 vectors](../conformance/README.md): 12 valid receipts from 7 real Orchard and
  Ironwood transactions, their mutations, and "was I paid" expectations,
  run by the native and WebAssembly builds and the npm package.
- **A second implementation of the verifier, written from the protocol specification** in Python,
  with no shared code
  ([spec-verifier](../spec-verifier)). It checks everything except the Halo 2 proof itself (it
  rebuilds the proof's public inputs), agrees on all 278 vectors (leaving the two that only the Halo 2 check rejects to that check) and on 232 adversarial
  receipts (the 9 that only the Halo 2 check rejects get the same public inputs), and its
  primitives match the Zcash test vectors:
  `python3 -m unittest discover -s spec-verifier/tests`.
- **Assurance:** mutation testing of the core, fuzzing of the receipt and batch decoders (plus a
  panic-freedom pass over every decoder in `cargo test`), Miri on the encoding, and a
  self-found forgery (address proofs trusted a prover-chosen value commitment), fixed, with the
  forged artifacts kept as must-fail vectors: [ASSURANCE.md](ASSURANCE.md),
  [CRYPTO-REVIEW.md](CRYPTO-REVIEW.md).
- **Bindings:** the browser verifier (WebAssembly, no server), an npm package and
  `<zcash-receipt>` web component, a CLI, and a REST API with SDKs for TypeScript, Python, Rust
  and Go.
- **A patch to `orchard` 0.16** (the Action circuit is unchanged; it adds accessors and, for claims, a forked circuit beside it: see [vendor/README.md](../vendor/README.md)) that this workspace
  applies for its own binaries, behind zceipt-core's `orchard-ext` feature: precomputed
  verifier parameters (about 2.7x faster key building), incoming receipts and memo-withheld outputs. A
  crate that depends on zceipt-core gets stock `orchard` and everything else
  ([vendor/README.md](../vendor/README.md), `scripts/check-stock-orchard.sh`).

Sapling is out of scope: wallets now pay from Orchard and Ironwood, and ZIP 311 already
specifies Sapling.

## What a receipt proves, precisely

| | Revealed | How it is checked |
|---|---|---|
| Recipient, amount and memo of each chosen output | yes | The output's `ock` opens the on-chain ciphertext; the note commitment must equal the on-chain `cmx` |
| The holder of the spend authority used in the payment made this receipt | yes | A fresh Halo 2 Action proof for the spent note (same anchor, same nullifier as on chain, fresh `rk` and `cv_net`) and a spend-authorization signature over the whole receipt |
| A message (invoice number, verifier's challenge) | yes | Covered by the signature |
| Payer's address, balance, other notes and transactions | no | Never included |
| That the transaction was mined | on a lightwalletd server's word | The verifier fetches it from a lightwalletd server; `zceipt verify --cross-check <server>` confirms the block with a second one |
| That the payee is someone else | no | The sender chooses which outputs to disclose (change discloses like any output); verifiers check the recipient they expect |

Output disclosure alone (an `ock`, or a note opening) can be made by anyone who saw the payment
with a viewing key. The spend proof is what makes it the payer's receipt: ZIP 311 calls a
disclosure complete only with it. Exact claim, assumptions and limits:
[CLAIM.md](CLAIM.md). Construction: [SPEC.md](SPEC.md).

## Beyond one payment

Each of these is built, tested, and proven on testnet or a regtest chain. Commands and evidence
are in [FEATURES.md](FEATURES.md).

- **Proof requests:** a verifier's challenge is signed into the receipt, so an old receipt can't be replayed.
- **Batches:** one link for many payments, each signing its place, with a total that can't count a payment twice.
- **Sender address, optional:** `--prove-address` proves the payer also controls a public address.
- **Source of funds:** `--prove-source` proves which earlier output created each spent note, for exchanges that refuse shielded deposits today.
- **Memo withheld:** `--withhold-memo` proves recipient and amount and keeps the memo encrypted.
- **Incoming receipts:** the recipient proves it was paid, without an incoming viewing key.
- **Cross-pool:** Orchard spends paying Ironwood outputs, as wallets do after NU6.3.
- **Also:** signed payment requests, refunds, attestations, Sign in with Zcash, proof of funds, ZIP 320 TEX deposits, and an API with webhooks for shops.

## Evidence on the public testnet

| Claim | Evidence |
|---|---|
| A real Ironwood payment and its receipt | tx [`571de6e4…`](https://testnet.cipherscan.app/tx/571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73), block 4,500,997; [examples/testnet/receipt.txt](../examples/testnet/receipt.txt) |
| Verified by the CLI and in the browser | `zceipt verify @examples/testnet/receipt-link.txt` → VALID in a few seconds, fetched by block (the link's `&h=`); the page → VERIFIED |
| An edited receipt is refused | [examples/testnet/receipt-edited.txt](../examples/testnet/receipt-edited.txt) → `the signature for action 0 is invalid` |
| A challenge answered; a replayed receipt refused | [request-answer-link.txt](../examples/testnet/request-answer-link.txt) → REQUEST SATISFIED; an older receipt → NOT SATISFIED |
| Sender address proven; another wallet's address refused | [receipt-with-sender-address.txt](../examples/testnet/receipt-with-sender-address.txt) |
| A batch of three payments as one link | [examples/testnet/batch.txt](../examples/testnet/batch.txt), total 0.022 ZEC |
| Source of funds, memo withheld, incoming receipt, signed request, refund, TEX deposit | [examples/testnet](../examples/testnet) and its README |

`./scripts/check-all.sh` runs every check that needs no build, including the verifier page in headless Chrome, in about two minutes.
`./scripts/e2e-regtest.sh` replays the whole story on a private Zebra regtest chain (needs
Docker, lightwalletd and zcash-devtool). Everything else runs with `cargo test --release`.

## Upstreaming plan

After the hackathon, in this order:

1. **Pins.** The workspace pins eight librustzcash crates to a git revision because NU6.3
   (Ironwood) is not in a release yet. When `zcash_primitives` and its siblings release with it,
   replace each `git`/`rev` with the version, and drop the `zcash-devtool` patch's port.
2. **orchard.** `vendor/orchard` adds accessors to orchard 0.16 ([vendor/README.md](../vendor/README.md)).
   Propose the five to orchard upstream as one PR; `build_with_unchecked_params` and `params_bytes` only
   speed up the verifier and can stay local. Until they land, the ZIP 311 profile builds on stock
   orchard (`scripts/check-stock-orchard.sh`).
3. **ZIP text.** Fold [ZIP311-ORCHARD.md](ZIP311-ORCHARD.md) into ZIP 311 beside zcash/zips#1406,
   as the draft's "Mapping onto #1406" section specifies, with `conformance/` as its vectors.
4. **zceipt-core** to crates.io with the default (ZIP 311 profile) feature set; the
   extensions stay behind `extensions` until each has its own ZIP text.
5. **Wallets.** The two-call surface in [the wallet guide](guides/wallet-integration.md) first,
   then a uniffi binding for mobile wallets.

## Repository

| Path | What |
|---|---|
| `crates/zceipt-core` | create and verify receipts; encoding; tests |
| `crates/zceipt-chain` | lightwalletd access, on-chain verification, Merkle path rebuild |
| `crates/zceipt-wallet` | receipts from a zcash-devtool wallet |
| `crates/zceipt-cli` | the `zceipt` command |
| `crates/zceipt-wasm`, `web/` | the browser verifier |
| `crates/zceipt-server`, `crates/zceipt-client`, `packages/` | REST API and SDKs |
| `spec-verifier/` | the independent Python verifier |
| `conformance/` | shared test vectors |
| `docs/` | spec, claim, threat model, assurance, guides |
| `vendor/orchard` | `orchard` 0.16.0, plus the patch described in `vendor/README.md` |

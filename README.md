# Receipts

**Prove one Zcash payment without handing over your viewing key.**

You get a link. Opening it shows who was paid, how much and the memo, and proves it was signed by the key that spent
the money. Change one character and it fails. Nothing else about the payer's wallet is in it.

<img src="docs/img/key-vs-receipt.svg" width="640" alt="A viewing key shows every payment, past and future; a receipt shows one payment and that you made it">

It is ZIP 311 (payment disclosures) for Ironwood payments, Orchard payments made before NU6.3,
and Orchard-to-Ironwood crossings, including the proof of who paid that output-only disclosures
leave out
([related work](docs/RELATED-WORK.md)).

Who needs it now:
- **Exchanges and bridges holding a shielded deposit.** In July 2026 a user's $589K from a
  shielded ZEC swap was held for 50+ days; they offered to "sign a verification message", and
  there was no Zcash-native way to do that ([forum](https://forum.zcashcommunity.com/t/my-experience-exiting-shielded-zec-from-zodl-to-near-intents-589k-usdt-still-held-50-days-despite-a-written-compliance-clearance/57497)).
  See [the held-deposit guide](docs/guides/held-deposit.md).
- **P2P trades and disputes.** An arbitrator checks one payment instead of asking for a viewing
  key ([guide](docs/guides/p2p-trades.md)).
- **Wallets.** Zodl's open issue for an authenticated reply-to address
  ([zodl-project#42](https://github.com/zodl-inc/zodl-project/issues/42)) needs a spend proof;
  a receipt supplies one.
- **Grant programs, payroll and DAOs** proving they paid everyone, with one link.

The contribution is ZIP 311 spend authority for Orchard and Ironwood: the spec text, the
`receipts-core` crate and a second verifier written from the spec. The verifier page and CLI use
it; the payment API for shops (`receipts shop`) and its SDKs are optional tooling around it.
Sapling and transparent spends are out of scope (ZIP 311 already covers Sapling).

Built for ZECATHON 2026, Core & Tooling track. MIT or Apache-2.0.

## See it work (no Rust, no wallet)

```bash
./scripts/serve-verifier.sh        # then open http://127.0.0.1:5321
```

Click **Try a real testnet receipt**: a real 0.01 TAZ payment
([`571de6e4…`](https://testnet.cipherscan.app/tx/571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73))
opens as the merchant it paid (`examples/testnet/merchant.ua`) and shows **PAID TO YOU**; opened
without your address, a receipt shows **VERIFIED · RECIPIENT NOT CHECKED**. Click **Try an
edited copy**: the same receipt with its signed message changed from "Order #42" to "Order #43"
shows **NOT VALID**. Click **Try a claim by someone who only saw it**: the same payment claimed
with another key shows **NOT PROVEN BY THE PAYER**, which is what an output-only disclosure can't
tell apart. **Make one with your own message** signs a real testnet payment from a public demo
wallet ([`examples/testnet/demo`](examples/testnet/demo)) for whatever you type, in the browser,
then verifies it (shown as the demo wallet, since its key is public); `receipts demo -m "…"`
prints one to check with `receipts verify`. The first check also loads the verifier (3 to 10 seconds).

<p><img src="docs/img/verified.png" width="420" alt="The verifier page showing a real receipt for 0.01 TAZ (testnet), memo Invoice 42: two coffees, checked as PAID TO YOU">
<img src="docs/img/refused.png" width="420" alt="The same receipt with its signed message edited, shown as NOT VALID: changed after it was made"></p>

**Check the cryptography with no Rust:** `python3 -m unittest discover -s spec-verifier/tests`
runs a second verifier written from the protocol specification. It checks everything but the
Halo 2 proofs and agrees with ours on all 278 conformance vectors (two are rejected only by the
Halo 2 check, so it flags those as needing it) and on 232 adversarial receipts.

**With Rust:** `cargo install --locked --path crates/receipts-cli && receipts demo` (about ten
minutes to build the first time).

## Make a receipt from your wallet

**No terminal:** the verifier's **Make a receipt** page (`make.html`) takes your wallet's
viewing key, the payment's txid and the wallet's birthday, finds the note and makes the proofs
in your browser (about a minute), then signs with your seed phrase on the same device or saves
the prepared receipt for another signer. Nothing leaves the device but block requests.

**In a wallet:** wallets on the Zcash Android or iOS SDK add the button with two calls from
the Swift/Kotlin bindings, `prepareReceipt(dbPath, …)` and `signPrepared(…)`
([crates/receipts-ffi](crates/receipts-ffi), [guide](docs/guides/wallet-integration.md)).

**In a terminal**, the CLI finds your notes by scanning the chain from the wallet's birthday:

| You have | Command |
|---|---|
| A viewing key (any wallet exports one) | `receipts create --ufvk @key.txt --birthday <height> --txid <txid> --unsigned r.txt`: the proofs, with no spending key |
| Then, on a machine that holds the seed (offline is fine) | `receipts sign r.txt --seed-stdin`: shows everything the receipt reveals and asks before signing |
| Or the seed phrase on one machine | `receipts create --seed-stdin --network main --birthday <height> --txid <txid>` |
| A zcash-devtool wallet | `receipts create -w <wallet> -i <key.age> --txid <txid>` |

The seed phrase is typed (not shown) or piped in, never put on the command line. `receipts export` turns many receipts into a spreadsheet and keeps a
record of each check for a case file.

## What a receipt proves

| | Shown | How it is checked |
|---|---|---|
| Who was paid, how much, the memo | yes | Opened from the transaction on chain with a key that opens only that output |
| That it was signed by the key that spent the money | yes | A fresh zero-knowledge proof for the note the payment spent, and a signature over the whole receipt |
| A message (invoice number, a verifier's challenge) | yes | Signed with the receipt |
| The payer's address, balance, other payments | no | Never included |
| That the payment is on chain | on a chain server's word | `--cross-check <host:port>` asks a second server of your choice (it learns the txid) |

A link is about 7 KB; some chat apps cut long links, so the page also saves a receipt as a file
and opens one. The payer chooses which outputs to show, so a verifier checks the recipient it expects
(`--expect-address`, or the page's "Was it paid to you?"). Exact claim, assumptions and limits:
[CLAIM.md](docs/CLAIM.md).

## Who learns what

| Party | Learns | Doesn't learn |
|---|---|---|
| Whoever you give the receipt to | the shown outputs, your message, that you paid | your address (unless you choose to prove it), balance, other payments |
| The chain server, when someone verifies (by default ChainSafe's for the page, zec.rocks for the CLI, or yours) | the payment's block (or, if it is quiet, its run of 4 blocks) and up to 64 transactions in each; the verifier's IP | which of those transactions (the testnet sample's block has 5), or anything in the receipt |
| The chain server, when you make a receipt | the block range it scans | which note, payment or transaction |

In a quiet block the server can narrow it down, and the page and CLI say so. Full analysis:
[THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Beyond one payment

- **Proof requests and P2P trades:** a verifier's challenge is signed in, so an old receipt can't
  answer a new request ([guide](docs/guides/p2p-trades.md)).
- **Source of funds:** prove which earlier output funded a deposit, or, with a screened-set
  proof, that it came from one of an exchange's vetted outputs without saying which.
- **Proof of funds:** prove you hold at least an amount, showing only the total if you choose.
- **One request, several payments:** a batch answers a proof request for invoices A and B at
  once; every receipt signs the request, and the total is checked
  ([example](examples/testnet/batch-request)).
- **Same payer:** a batch proves every payment was signed with one spend key, without revealing
  it, so a DAO or grant program shows one treasury paid everyone (`k=zip311k1…` on the link).
- **Batches, incoming receipts, memo-withheld outputs, refunds:** see
  [DEVELOPERS.md](docs/DEVELOPERS.md#beyond-one-payment).

## For developers and reviewers

```rust
let prepared = ReceiptBuilder::new(Network::Mainnet, &tx)      // a mined transaction
    .message(b"Invoice 42").disclose(1, ovk).spend(witness)    // proofs from the viewing key
    .prepare(&pk, &mut rng)?;
let sigs = sign_prepared(prepared.unsigned(), prepared.alphas(), &[ask], &mut rng)?;  // or on a signer
let receipt = prepared.apply_signatures(sigs)?;
let shown = verify_transaction(&vk, &receipt, Network::Mainnet.coin_type(), &tx)?;
```

- [docs/README.md](docs/README.md): which document to read for what.
- [DEVELOPERS.md](docs/DEVELOPERS.md): the Rust crate, signing on a separate device (the reference signer), bindings,
  everything beyond one payment, testnet evidence, and the repository layout.
- [ZIP311-ORCHARD.md](docs/ZIP311-ORCHARD.md): the proposed text for ZIP 311's Orchard `TODO`
  (also in ZIP form: [docs/zip/zip-0311-orchard-draft.rst](docs/zip/zip-0311-orchard-draft.rst)).
- [OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md): where a reviewer starts, with the public questions
  about spend authority for Orchard answered, each with its test.
- `./scripts/check-all.sh` runs the checks that need no Rust build, given the prebuilt `receipts` binary for the last three (about two minutes);
  `./scripts/test-all.sh` runs every suite, including the regtest chain end to end.

## Status

Sapling is out of scope: ZIP 311 already specifies it, and this fills its Orchard `TODO`.
Unaudited. The construction has been reviewed only by its author
([CRYPTO-REVIEW.md](docs/CRYPTO-REVIEW.md), which found and fixed one forgery), and checked by
the second verifier, mutation testing and fuzzing ([ASSURANCE.md](docs/ASSURANCE.md)). After
ZECATHON the plan is to propose the ZIP text, offer the core crate (which builds on stock
`orchard`) to librustzcash, and get an external review. [SECURITY.md](SECURITY.md) says how to
report a problem.

## Related work

Three other projects started on ZIP 311 output disclosure this autumn: zreceipt,
zcash-delivery-proof and auzum197's `zcash_disclosure`. They disclose outputs; zreceipt also has
a test prototype of a spend-authority proof. [RELATED-WORK.md](docs/RELATED-WORK.md) compares
them, and [COMPARISON.md](docs/COMPARISON.md) compares viewing-key payment processors.

## License

MIT OR Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

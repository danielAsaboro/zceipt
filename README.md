# Zceipt

**ZIP 311 for Orchard and Ironwood, extended so payments can be proven in relation to each other.**

Zceipt proves one Zcash payment without handing over a viewing key. It then goes further: it
proves facts about *sets* of payments (one payer, different payers, one wallet's accounts, a
delegated issuer, a total) without revealing the wallet's history.

| | |
|---|---|
| Website | [zceipt.xyz](https://zceipt.xyz) |
| Docs | [zceipt.xyz/docs](https://zceipt.xyz/docs/) |
| Check a receipt | [zceipt.xyz/verify](https://zceipt.xyz/verify/) |
| Make a receipt from your wallet | [zceipt.xyz/verify/make](https://zceipt.xyz/verify/make) |
| MetaMask snap | [`zceipt-snap`](https://www.npmjs.com/package/zceipt-snap) on npm |
| Status and caveats | [zceipt.xyz/docs/status](https://zceipt.xyz/docs/status) |

<img src="docs/img/key-vs-receipt.svg" width="640" alt="A viewing key shows every payment, past and future; a receipt shows one payment and that you made it">

## Contents

- [Spend authority](#spend-authority)
- [The eight relationship proofs](#the-eight-relationship-proofs)
- [Supported pools](#supported-pools)
- [Try it](#try-it)
- [Make a receipt](#make-a-receipt)
- [Install the CLI](#install-the-cli)
- [SDKs](#sdks)
- [What a receipt proves](#what-a-receipt-proves)
- [Who learns what](#who-learns-what)
- [Audits and tests](#audits-and-tests)
- [Status](#status)
- [Who needs it](#who-needs-it)
- [For developers and reviewers](#for-developers-and-reviewers)
- [Repository layout](#repository-layout)
- [Related work](#related-work)

## Spend authority

ZIP 311 calls a payment disclosure complete only with a proof that the payer's spend authority
made the payment. For Orchard it says `TODO`. Zceipt fills that in for Orchard and Ironwood:
a fresh Orchard Action proof for the note the payment spent, and a signature by the key that
spent it. Opening a receipt shows who was paid, how much and the memo, and that the payer made it.
Change one character and it fails.

Output disclosure alone (what [zreceipt](docs/RELATED-WORK.md) and the ZIP 311 output-disclosure
draft do) can be made by anyone who saw the payment. The verifier page shows the difference:
the same payment claimed with another key reads **NOT PROVEN BY THE PAYER**.

More: [spend authority](https://zceipt.xyz/docs/concepts/spend-authority),
[what a receipt reveals](https://zceipt.xyz/docs/concepts/what-a-receipt-reveals).

## The eight relationship proofs

On top of spend authority, each of these states one relationship and reveals nothing else about
the wallet:

| Question | Proof | Text prefix | Docs |
|---|---|---|---|
| Did one key make all of these payments? | Same-payer proof | `zip311b1`, `zip311k1` | [same payer](https://zceipt.xyz/docs/composability/same-payer) |
| Did N different wallets pay, not one wallet N times? | Payer tags, claim tags | `zip311t1` | [distinct payers](https://zceipt.xyz/docs/composability/distinct-payers) |
| Are these two payers accounts of one wallet? | Sibling-account proof | `zip311w1` | [sibling accounts](https://zceipt.xyz/docs/composability/sibling-accounts) |
| Was it signed by one of a department's keys? | Key-set proof | `zip311m1` | [key sets](https://zceipt.xyz/docs/composability/key-sets) |
| Can a back office issue receipts without my spend key? | Delegation | `zip311a1`, `zip311g1` | [delegation](https://zceipt.xyz/docs/composability/delegation) |
| Did I receive at least X across payments, from k payers? | Income proof | `zip311i1` | [income](https://zceipt.xyz/docs/composability/income) |
| Was it authorized by this 2-of-3 treasury? | FROST policy proof | `zip311p1` | [FROST policy](https://zceipt.xyz/docs/composability/frost-policy) |
| Did the money come from this vetted set? | Source and screened-set proofs | `zip311s1` | [source of funds](https://zceipt.xyz/docs/composability/source-of-funds) |

Alongside them: the base receipt (`zip311r1`), the Sapling receipt (`zip311z1`) and a receipt
only one named verifier can check (`zip311d1`). Every proof type has run on the Zcash public
testnet; the real proofs are in [examples/testnet/proofs](examples/testnet/proofs).

The design, in order, with why each piece is needed: [TECHNICAL-NOTE.md](TECHNICAL-NOTE.md)
([on the site](https://zceipt.xyz/docs/reference/technical-note)).

## Supported pools

| Pool | Receipt | Relationship proofs | Evidence |
|---|---|---|---|
| **Orchard** | `zip311r1`: fresh Action proof plus spend signature | all eight | real testnet payments, regtest |
| **Ironwood** (NU6.3, NU7 in librustzcash) | `zip311r1`, same construction | all eight | Ironwood outputs opened on testnet transactions, regtest, cross-pool regtest |
| **Sapling** | `zip311z1`, as the ZIP 311 draft specifies: output disclosure by `ock`, a fresh Spend proof and signature per spend | none | a real testnet payment's receipt verified against the chain ([examples/testnet-sapling](examples/testnet-sapling)) |
| Transparent | out of scope | | |

Ironwood is not in a librustzcash release yet, so eight crates are pinned to a git revision.

## Try it

**In the browser, nothing to install:** open [zceipt.xyz/verify](https://zceipt.xyz/verify/) and
click **Try a real testnet receipt**. A real 0.01 TAZ payment
([`571de6e4…`](https://testnet.cipherscan.app/tx/571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73))
opens as the merchant it paid and shows **PAID TO YOU**; opened without your address, a receipt
shows **VERIFIED · RECIPIENT NOT CHECKED**. **Try an edited copy** shows the same receipt with its
signed message changed from "Order #42" to "Order #43": **NOT VALID**. **Try a claim by someone
who only saw it** shows **NOT PROVEN BY THE PAYER**, which is what an output-only disclosure can't
tell apart. **Make one with your own message** signs a real testnet payment from a public demo
wallet ([`examples/testnet/demo`](examples/testnet/demo)) for whatever you type, in the browser,
then verifies it. The first check loads the verifier (3 to 10 seconds).

<p><img src="docs/img/verified.png" width="420" alt="The verifier page showing a real receipt for 0.01 TAZ (testnet), memo Invoice 42: two coffees, checked as PAID TO YOU">
<img src="docs/img/refused.png" width="420" alt="The same receipt with its signed message edited, shown as NOT VALID: changed after it was made"></p>

**The same page locally:**

```bash
./scripts/serve-verifier.sh        # then open http://127.0.0.1:5321
```

**From the terminal:** `zceipt demo` verifies a real testnet receipt and refuses an edited copy;
`zceipt demo -m "…"` prints one with your message to check with `zceipt verify`;
`zceipt demo --shop` runs the payment API flow in the sandbox and leaves the API, dashboard and
verifier running.

## Make a receipt

**In the browser:** [zceipt.xyz/verify/make](https://zceipt.xyz/verify/make). Open your wallet
with its seed phrase or its viewing key and its birthday. The page reads the chain the way a light
wallet syncs, lists the payments the wallet sent as it finds them, and you tap one. It makes the
proofs in your browser (about half a minute) and signs; with a viewing key it asks for the seed
phrase at the end, or saves the prepared receipt for another signer. The phrase and the key stay
in the page's memory; nothing leaves the device but block requests. The page can remember the
wallet on that device behind a passkey (WebAuthn PRF).

**With MetaMask:** the [`zceipt-snap`](https://www.npmjs.com/package/zceipt-snap) snap
([source](packages/zceipt-snap)) holds the wallet inside MetaMask, gives the make page a viewing
key, and signs each receipt after showing what it reveals, so the page never sees a seed. On the
make page choose **Connect MetaMask**. It needs [MetaMask Flask](https://docs.metamask.io/snaps/get-started/install-flask/),
since the snap is not on MetaMask's allowlist, and it only answers zceipt.xyz and localhost.

**In a wallet app:** wallets on the Zcash Android or iOS SDK add the button with two calls from
the Swift/Kotlin bindings, `prepareReceipt(dbPath, …)` and `signPrepared(…)`
([crates/zceipt-ffi](crates/zceipt-ffi), [guide](docs/guides/wallet-integration.md)).

**In a terminal**, the CLI finds your notes by scanning the chain from the wallet's birthday:

| You have | Command |
|---|---|
| A viewing key (any wallet exports one) | `zceipt create --ufvk @key.txt --birthday <height> --txid <txid> --unsigned r.txt`: the proofs, with no spending key |
| Then, on a machine that holds the seed (offline is fine) | `zceipt sign r.txt --seed-stdin`: shows everything the receipt reveals and asks before signing |
| Or the seed phrase on one machine | `zceipt create --seed-stdin --network main --birthday <height> --txid <txid>` |
| A zcash-devtool wallet | `zceipt create -w <wallet> -i <key.age> --txid <txid>` |
| A Sapling payment from a zcash-devtool wallet | `zceipt create-sapling -w <wallet> -i <key.age> --txid <txid>` |

The seed phrase is typed (not shown) or piped in, never put on the command line.
`zceipt export` turns many receipts into a spreadsheet and keeps a record of each check for a
case file. Step by step: [from a wallet](https://zceipt.xyz/docs/use/wallet),
[from the terminal](https://zceipt.xyz/docs/use/terminal),
[checking a receipt](https://zceipt.xyz/docs/use/check).

## Install the CLI

Needs Rust ([rustup](https://rustup.rs)); `rust-toolchain.toml` pins the toolchain and rustup
installs it. The first build takes about ten minutes.

```bash
git clone https://github.com/danielAsaboro/zceipt && cd zceipt
./scripts/install.sh               # cargo install --locked --path crates/zceipt-cli, then zceipt demo
```

Or with Docker: `docker compose run --rm zceipt demo` (`docker compose up` runs the payment API on port 8723). Then:

```bash
zceipt doctor                      # checks servers, API key, clock and wallet, says what to fix
zceipt verify @examples/testnet/receipt.txt
```

| Command | What it does |
|---|---|
| `create`, `create-sapling`, `sign` | make a receipt for a payment you sent, optionally signing on another machine |
| `verify`, `inspect`, `export` | check against the chain, decode offline, verify many into a spreadsheet |
| `received`, `income`, `reserve` | prove you received a payment, received at least an amount, or hold at least an amount |
| `claim`, `tag`, `siblings` | one claim per wallet, payer tags for counting different donors, sibling accounts |
| `key`, `delegate`, `verifier-key` | publish a key for a key set, delegate receipts to a session key, receipts for one verifier only |
| `shop` | the payment API for shops, exchanges and sites |

Full reference: [CLI](https://zceipt.xyz/docs/reference/cli), formats:
[formats](https://zceipt.xyz/docs/reference/formats).

## SDKs

| Language | Path | Client | Webhooks |
|---|---|---|---|
| TypeScript / JS | [packages/zceipt](packages/zceipt) | `new Zceipt(key, { baseUrl })` from `zceipt/client`; `verifyReceipt(link)` in the browser (WASM); `<zcash-receipt>` web component; React; `zceipt/middleware` for Express and fetch-style servers | `webhooks.constructEvent` |
| Python 3.9+ | [packages/zceipt-python](packages/zceipt-python) (standard library only) | `Zceipt(key, base_url=…)`; `zceipt.web` for FastAPI, Django, Flask | `construct_event` |
| Go | [packages/zceipt-go](packages/zceipt-go) (standard library only) | `zceipt.New(key)` | `zceipt.ConstructEvent` |
| Rust | [crates/zceipt-client](crates/zceipt-client) | `Client::new(key).base_url(…)` | `webhooks::construct_event` |
| Rust, in process | [crates/zceipt-core](crates/zceipt-core) | `zceipt_core::verify`, `ReceiptBuilder` | |
| Swift / Kotlin | [crates/zceipt-ffi](crates/zceipt-ffi) | `prepareReceipt`, `signPrepared` | |

The SDKs install from this repository; only the snap is on npm. The API clients share typed
errors with `code` and `param`, an automatic `Idempotency-Key` on every POST, retries on network
errors, 429 and 5xx, and cursor pagination. They talk to the payment API (`zceipt serve`,
[OpenAPI](docs/openapi.yaml)), which with webhooks and a dashboard sits around the same core but
is not part of the cryptographic contribution. More: [SDKS.md](docs/SDKS.md),
[QUICKSTART.md](docs/QUICKSTART.md), [FEATURES.md](docs/FEATURES.md),
[the HTTP 402 guide](docs/guides/http-402.md).

## What a receipt proves

| | Shown | How it is checked |
|---|---|---|
| Who was paid, how much, the memo | yes | Opened from the transaction on chain with a key that opens only that output |
| That it was signed by the key that spent the money | yes | A fresh zero-knowledge proof for the note the payment spent, and a signature over the whole receipt |
| A message (invoice number, a verifier's challenge) | yes | Signed with the receipt |
| The payer's address, balance, other payments | no | Never included |
| That the payment is on chain | on a chain server's word | `--cross-check <host:port>` asks a second server of your choice (it learns the txid) |

A link is about 7 KB; some chat apps cut long links, so the page also saves a receipt as a file
and opens one. The payer chooses which outputs to show, so a verifier checks the recipient it
expects (`--expect-address`, or the page's "Was it paid to you?"). Exact claim, assumptions and
limits: [CLAIM.md](docs/CLAIM.md).

## Who learns what

| Party | Learns | Doesn't learn |
|---|---|---|
| Whoever you give the receipt to | the shown outputs, your message, that you paid | your address (unless you choose to prove it), balance, other payments |
| The chain server, when someone verifies (by default ChainSafe's for the page, zec.rocks for the CLI, or yours) | the payment's block (or, if it is quiet, its run of 4 blocks) and up to 64 transactions in each; the verifier's IP | which of those transactions, or anything in the receipt |
| The chain server, when you make a receipt | the block range it scans | which note, payment or transaction |

In a quiet block the server can narrow it down, and the page and CLI say so. Full analysis:
[THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Audits and tests

**No external audit.** Every review below was done by the author or by tools the author ran.

| Review | What it covered | Result |
|---|---|---|
| [CRYPTO-REVIEW.md](docs/CRYPTO-REVIEW.md) | the construction, proof by proof | found and fixed one forgery: sender-address proofs could claim any address |
| [AUDIT-HOSTILE.md](docs/AUDIT-HOSTILE.md) (2026-10-26) | code read against comments, vendored Orchard diffed against crates.io, proofs of concept on real testnet proofs | no critical; 3 highs, fixed before the rerun |
| [AUDIT-RERUN.md](docs/AUDIT-RERUN.md) (2026-10-27) | eight parallel hunters with Trail of Bits method files, `cargo audit` | no break of circuits, gadget, Schnorr proofs or decoders; every finding fixed |
| [AUDIT-PRIVACY.md](docs/AUDIT-PRIVACY.md) (2026-10-28) | every request the site, SDKs and CLI make, logs, stored columns, git history | four leaks found and fixed |
| [ASSURANCE.md](docs/ASSURANCE.md) | checks whose verdict isn't ours, listed below | |

The checks in [ASSURANCE.md](docs/ASSURANCE.md), each with the command to re-run it:

- **The chain:** every example receipt is for a transaction mined on the public testnet and
  verifies against it. `scripts/e2e-testnet.sh` runs every proof type on real payments (26 checks).
- **A second verifier:** [spec-verifier](spec-verifier), written in Python from the protocol
  specification, checks everything but the Halo 2 proofs. It passes the Zcash test vectors it
  covers and agrees with the Rust verifier on all 278 conformance vectors
  ([conformance](conformance)) and 232 signed adversarial receipts.
- **Mutation testing:** `cargo mutants` on the core, the source proofs, the claim circuit and the
  delegation verifiers, with the misses listed.
- **Fuzzing:** `cargo fuzz` on every decoder, 8 to 12 million executions each, asserting that
  whatever decodes re-encodes to the same bytes.
- **Miri:** the decoders, encoders, batch checks and RedPallas verification, with no undefined
  behaviour reported. The receipt crates contain no `unsafe` code.
- **Stock Orchard:** `scripts/check-stock-orchard.sh` checks that a wallet depending on
  `zceipt-core` without the `orchard-ext` feature builds on unpatched `orchard`.

Run them:

```bash
python3 -m unittest discover -s spec-verifier/tests   # no Rust needed, about a minute
./scripts/check-all.sh                                # checks that need no Rust build, given a prebuilt zceipt
./scripts/test-all.sh                                 # Rust workspace and clippy, spec verifier, npm, Python and Go SDKs, regtest end to end
```

## Status

- **Network:** Zcash public testnet and private regtest chains. Nothing has been run on mainnet.
- **Unaudited** by anyone but the author (above).
- **The base receipt** uses the stock Orchard Action circuit and keys.
- **Two proofs use circuits written or forked here**, and nobody else has reviewed them:
  claim and payer tags (a fork of the Action circuit, `vendor/orchard/src/circuit/claim.rs`) and
  sibling-account proofs (a new Halo 2 circuit with a BLAKE2b gadget ported from
  `eryxcoop/blake2b_halo2`, whose authors say it is unaudited; the port is too). Both run on the
  testnet and have been attacked there and offline; the attacks found and fixed five weaknesses
  around them.
- **Delegation, one-verifier receipts and FROST policy proofs** use no new circuit (the FROST
  treasury on testnet is a testnet wallet's key split by a trusted dealer).
- Binaries here build on `orchard` 0.16 plus a patch ([vendor/README.md](vendor/README.md)); the
  base receipt builds on stock `orchard`.

Per-proof evidence and caveats: [status](https://zceipt.xyz/docs/status). To report a problem:
[SECURITY.md](SECURITY.md).

## Who needs it

- **Exchanges and bridges holding a shielded deposit.** In July 2026 a user's $589K from a
  shielded ZEC swap was held for 50+ days; they offered to "sign a verification message", and
  there was no Zcash-native way to do that ([forum](https://forum.zcashcommunity.com/t/my-experience-exiting-shielded-zec-from-zodl-to-near-intents-589k-usdt-still-held-50-days-despite-a-written-compliance-clearance/57497)).
  See [the held-deposit guide](https://zceipt.xyz/docs/guides/held-deposit).
- **P2P trades and disputes.** An arbitrator checks one payment instead of asking for a viewing
  key ([guide](docs/guides/p2p-trades.md)).
- **Wallets.** Zodl's open issue for an authenticated reply-to address
  ([zodl-project#42](https://github.com/zodl-inc/zodl-project/issues/42)) needs a spend proof;
  a receipt supplies one ([guide](https://zceipt.xyz/docs/guides/wallets)).
- **Grant programs, payroll and DAOs** proving they paid everyone, and counting different
  donors, with one link ([guide](https://zceipt.xyz/docs/guides/grants-and-airdrops)).

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
- [DEVELOPERS.md](docs/DEVELOPERS.md): the Rust crate, signing on a separate device, bindings,
  everything beyond one payment (proof requests, batches, incoming receipts, memo-withheld outputs,
  refunds), testnet evidence.
- [ZIP311-ORCHARD.md](docs/ZIP311-ORCHARD.md): the proposed text for ZIP 311's Orchard `TODO`
  (also in ZIP form: [docs/zip/zip-0311-orchard-draft.rst](docs/zip/zip-0311-orchard-draft.rst)).
- [OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md): where a reviewer starts, with the public questions
  about spend authority for Orchard answered, each with its test.
- [SPEC.md](docs/SPEC.md) and [TRACEABILITY.md](docs/TRACEABILITY.md): the wire format, and
  each requirement mapped to its code and test.
- The docs site source is in [docs-site](docs-site) (`cd docs-site && npx mint dev`).

## Repository layout

| Path | What |
|---|---|
| [crates/zceipt-core](crates/zceipt-core) | receipts and every proof, verify and build |
| [crates/zceipt-cli](crates/zceipt-cli) | the `zceipt` command |
| [crates/zceipt-wasm](crates/zceipt-wasm) | the verifier and maker compiled for the browser |
| [crates/zceipt-ffi](crates/zceipt-ffi) | Swift and Kotlin bindings for wallets |
| [crates/zceipt-wallet](crates/zceipt-wallet) | receipts and Sign in with Zcash from a zcash-devtool wallet |
| [crates/zceipt-chain](crates/zceipt-chain) | chain access and on-chain verification |
| [crates/zceipt-kce](crates/zceipt-kce) | sibling-account proofs |
| [crates/zceipt-server](crates/zceipt-server), [crates/zceipt-client](crates/zceipt-client) | the payment API and its Rust client |
| [packages](packages) | the npm, Python and Go SDKs and the MetaMask snap |
| [web](web) | the verifier and make pages served at zceipt.xyz/verify |
| [site-src](site-src), [docs-site](docs-site) | the landing page and the docs |
| [spec-verifier](spec-verifier), [conformance](conformance) | the independent Python verifier and shared test vectors |
| [vendor](vendor) | the patched `orchard` with the claim circuit |
| [examples](examples) | real testnet receipts and proofs, regtest setups, a shop and a paid API |

## Related work

Three other projects started on ZIP 311 output disclosure this autumn: zreceipt,
zcash-delivery-proof and auzum197's `zcash_disclosure`. They disclose outputs; zreceipt also has
a test prototype of a spend-authority proof. [RELATED-WORK.md](docs/RELATED-WORK.md) compares
them, and [COMPARISON.md](docs/COMPARISON.md) compares viewing-key payment processors.

Built for ZECATHON 2026, Core & Tooling track ([SUBMISSION.md](SUBMISSION.md)).

## License

MIT OR Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

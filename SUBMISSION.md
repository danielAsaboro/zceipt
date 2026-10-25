# Submission: Receipts

**Track:** Core & Tooling.

## In one sentence

We turned ZIP 311 from "prove a payment exists" into "prove anything about a set of payments":
spend authority for Orchard and Ironwood first, then proofs of the relationships between
payments (same payer, different payers, one wallet's accounts, delegation, a total), none of which
reveal the wallet's history.

## The contribution

1. **Spend authority for Orchard and Ironwood.** The part of ZIP 311 that says `TODO` for Orchard:
   a fresh Action proof for the spent note and a signature by the key that spent it, so only the
   payer can make the receipt. Stock Orchard circuit, no new setup. The proposed ZIP text, a
   `receipts-core` crate and a second verifier written from the spec.
2. **Cross-receipt composability.** Same payer, distinct payers (claim and payer tags), sibling
   accounts, key sets, delegation, income, FROST policy, source of funds. Each is a separate proof
   with its own page: [docs-site/composability](docs-site/composability/overview.mdx).

Read [TECHNICAL-NOTE.md](TECHNICAL-NOTE.md) for the design and why each piece is needed. Everything
else in the repository (the shop API, SDKs, dashboard) is tooling around that core.

## The contrast

| | Proves | Can be made by |
|---|---|---|
| Output disclosure (zreceipt and the ZIP 311 draft) | Who was paid and how much | Anyone who saw the payment |
| A Receipts receipt | The above, and that the payer's key made the payment | Only the payer |
| Receipts relationships | One key made all of these; these are different wallets; these accounts are one wallet; an agent issued this within a policy; at least X was received | Only the parties involved |

Run it: `./scripts/serve-verifier.sh`, then click *Try a claim by someone who only saw it*. The same
payment claimed with another key reads **NOT PROVEN BY THE PAYER**.

## Against the judging criteria

| Criterion | Where to look |
|---|---|
| **Privacy** | [docs-site/concepts/what-a-receipt-reveals.mdx](docs-site/concepts/what-a-receipt-reveals.mdx) states, per proof, what the verifier learns, including the leaks: the chain server learns the block (not the transaction); a claim reveals a nullifier; delegated receipts under one certificate link to each other. [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) is the full analysis. |
| **Usefulness** | Held deposits at exchanges and bridges, P2P disputes, wallet reply-to authentication, grant rounds and airdrops that count wallets, income proofs. [README](README.md#who-needs-it) |
| **Execution** | `./scripts/check-all.sh` (about two minutes, no Rust build); `./scripts/test-all.sh` runs every suite including a regtest chain end to end. Real testnet payments are verified in the CLI and browser. 278 conformance vectors, a Python second verifier, mutation testing, fuzzing. |
| **Originality** | Spend authority for Orchard was open in ZIP 311. Related projects disclose outputs only; see [docs/RELATED-WORK.md](docs/RELATED-WORK.md). The relationship proofs, including a forked Action circuit and a sibling-account circuit, have no counterpart there. |

## Honest status

- **Testnet and regtest only.** No mainnet.
- **Unaudited.** Reviewed only by the author, which found and fixed one forgery.
- **Runs on the Zcash public testnet:** every proof type: the base receipt, batches with same-payer
  proofs, key sets, income, source and screened-set proofs, claims, payer tags, sibling accounts,
  delegation, one-verifier receipts and FROST policy. `scripts/e2e-testnet.sh` makes real
  payments and runs the checks and the attacks; the proofs are committed in
  `examples/testnet/proofs` and attacked offline (`testnet_adversarial.rs`).
- **Attacks found and fixed five weaknesses** (claims and payer tags shared one tag per key and
  domain; a claimant picked the floor; a truncated nullifier cache could pass a spent note;
  sibling accounts could not be merged by a verifier; a FROST policy proof didn't say the
  commitment must be pinned). Details: docs/ASSURANCE.md.
- **Two circuits are ours and unreviewed:** the forked claim circuit and the sibling-account
  circuit with a ported BLAKE2b gadget. The base receipt does not depend on either.

Per proof: [docs-site/status.mdx](docs-site/status.mdx).

## Where to start, by role

| You are | Start at |
|---|---|
| A ZK reviewer | [docs-site/reference/forked-circuits.mdx](docs-site/reference/forked-circuits.mdx), then [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) |
| A protocol reviewer | [docs/ZIP311-ORCHARD.md](docs/ZIP311-ORCHARD.md), [docs/CLAIM.md](docs/CLAIM.md) |
| A wallet developer | [docs-site/guides/wallets.mdx](docs-site/guides/wallets.mdx) |
| A judge with five minutes | The verifier page above, then [TECHNICAL-NOTE.md](TECHNICAL-NOTE.md) |

## License

MIT OR Apache-2.0.

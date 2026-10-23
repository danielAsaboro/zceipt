# Reviewer start here: spend authority for Orchard and Ironwood

ZIP 311 calls a payment disclosure complete only with a proof that the payer's spend authority
made the payment. For Sapling it specifies a fresh Spend proof plus a `spendAuthSig`; for Orchard
it says `TODO`. This construction carries the Sapling design over to the Orchard Action circuit.
The questions below are the ones raised in public about doing that (the ZIP 311 grant thread on
the Zcash forum, and the output-disclosure draft zcash/zips#1406); each has the answer this
repository takes and the test or vector that checks it.

## The three statements to check

1. **Only the holder of the spend authorizing key behind a spend can make its disclosure.** The
   verifier takes the anchor and the nullifier from the transaction, never from the receipt, and
   checks a fresh Action proof for them under `rk`, then a `SpendAuthSig` by `rk` over the whole
   receipt. Code: `crates/receipts-core/src/lib.rs`, `verify_cross` (the `Instance::from_parts(*bundle.anchor(), …, *action.nullifier(), …)` call).
   Tests: `roundtrip.rs::only_the_spender_can_create`, `::tampering_is_rejected`,
   `::every_byte_matters`; the 29 re-signed and forged cases in `spec-verifier/tests/corpus.json`.
2. **A disclosed output is the one on chain, to the recipient and amount shown.** Output recovery
   with the `ock` must reproduce the on-chain `cmx`. Code: `recover_with_ock`. Vectors: every
   valid case in `conformance/vectors.json` carries the opened outputs as known answers,
   reproduced by the independent spec verifier.
3. **Nothing else about the payer is revealed, and two disclosures of one spend can't be linked.**
   `rk` and `cv_net` are re-randomized (fresh `alpha`, `rcv`) and the dummy output is fresh. Test:
   `roundtrip.rs::disclosures_are_unlinkable_to_the_action_and_to_each_other`. Argument:
   [CLAIM.md](CLAIM.md).

## The open questions, answered

| Question | Answer here | Checked by |
|---|---|---|
| How big is a spend-authority proof, and should proofs be aggregated? | One Orchard Action proof per disclosed spend, about 4.9 KB; a receipt with one spend and one output is 5,268 bytes (7 KB as a link). No aggregation: most payments spend one or two notes, and a single-action proof keeps the verifier the stock one. | `receipts inspect @examples/testnet/receipt.txt` |
| Which circuit and verifying key? | The stock Orchard Action circuit, post-NU6.3 version, for every receipt whatever the payment's height (the pre-NU6.2 circuit is unsound). No new circuit, no new setup. | `RECEIPT_CIRCUIT` in `lib.rs`; [ZIP311-ORCHARD.md](ZIP311-ORCHARD.md) §Creating |
| How is the anchor checked for v6 (Ironwood) transactions? | The proof is checked against the anchor the transaction's own bundle commits to, and the nullifier the transaction published; the receipt supplies neither. | `verify_cross`; `roundtrip.rs::ironwood_receipt_roundtrip` |
| How is the spent value handled? | In the spend proof `cv_net` is chosen by the prover with a fresh `rcv`, so the value stays hidden; that is safe because the proof only has to show knowledge of the note behind `nf`. Where a value is a claim (address proofs, source proofs) the verifier fixes `cv` itself: an earlier version took it from the prover, which allowed forging an address proof; that was found in review, fixed, and the forged artifacts are kept as must-fail vectors. | [CLAIM.md](CLAIM.md); `roundtrip.rs::sign_in_as_someone_elses_address_is_refused`; conformance `pre-fix/*` |
| Can hardware wallets or FROST signers sign? | Yes: the proofs need only the full viewing key (`receipts_core::prepare`), and the signature is an ordinary RedPallas signature by `ask` randomized with `alpha`. A separate signer must be given the unsigned receipt and the randomizers, never a digest: `sign_prepared` recomputes the digest and checks every `rk` before signing. | `roundtrip.rs::prepare_with_viewing_key_then_sign_elsewhere`; [ZIP311-ORCHARD.md](ZIP311-ORCHARD.md) §Security |
| How are receipts encoded, versioned and shared? | ZIP 311 defines none of these. Here: a canonical binary encoding with a version byte, text `zip311r1` + base64url, links with the receipt in the `#fragment` and an `h=` block hint. Five versions exist (v1 to v5: address proofs, cross-pool, source proofs, memo-withheld outputs); the proposal in ZIP311-ORCHARD.md is v1 and v3, the rest are extensions. | `encoding.rs`; `roundtrip.rs::encodings_are_canonical` |
| Can a disclosure be replayed for someone else? | A receipt is a bearer proof. A verifier who needs freshness puts a challenge in the request; the receipt signs `challenge:<hex>` and fails any other request. | `api.rs::real_receipt_replay_is_refused` |
| What about signatures for other purposes reusing the same key? | Every signed format has its own personalization (`ZIP311Signed`, `ZIP311Incomg`, `ZcashSignIn`, `ZIP321Signed`, `ZcashReserve`), none of which is a transaction sighash. | `properties.rs::all_signing_domains_are_distinct` |

## What is not claimed

- That the transaction is mined: the verifier establishes that from a chain server (and can
  cross-check a second one).
- That a disclosed output went to someone other than the payer: the payer chooses which outputs
  to show. Checking the recipient is the verifier's job.
- That the construction has been reviewed by anyone but its author. It hasn't yet; this page is
  where a review would start.

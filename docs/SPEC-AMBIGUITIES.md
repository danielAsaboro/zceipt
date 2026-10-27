# Ambiguities and gaps in the sources, and how Zceipt resolves them

Each entry names the source text, why it is ambiguous or incomplete for an Orchard/Ironwood
implementation, what Zceipt does, and what checks it. Sources: zcash/zips at `7b9e678`
(ZIP 311 last changed there), `protocol/protocol.tex` at `18d642d`, ZIP 229, ZIP 244, ZIP 304,
and the zcashd v4.0.0 Sprout payment-disclosure code (`src/wallet/paymentdisclosure.h`), the
prior art ZIP 311 replaces. Nothing here has been proposed upstream.

## In ZIP 311

**A1. Orchard is `TODO`.** The data structure, creation and verification are written for Sapling
spends and outputs only.
*Resolution:* an Orchard spend disclosure is an Action proof that spends the same note at the same
anchor and outputs a zero-value dummy note with `ρ = nf`, plus `SpendAuthSig` by the fresh `rk`;
an output disclosure is the Orchard `ock`. (`SPEC.md`, "Spend authority".)
*Checked by:* `roundtrip.rs::orchard_receipt_roundtrip`, `::ironwood_receipt_roundtrip`; the real
receipts in `examples/`; the spec verifier.

**A2. "A ZIP 304 proof for the address" has no Orchard counterpart.** ZIP 304 is Sapling-only.
Its rationale (zero-value notes have "certain constraints disabled" in the circuit, so the fake
note has value 1) and its fixed `cv = ValueCommit_0(1)` carry over, but ZIP 311 does not say
so. *Resolution:* the Orchard address proof uses `ValueCommit_0(1)` too, and the verifier
computes it rather than reading it. Missing this was a real forgery in this repository until
2026-10-15 (`CLAIM.md`, "Address proofs"). *Checked by:*
`roundtrip.rs::claiming_someone_elses_sender_address_is_refused`,
`::sign_in_as_someone_elses_address_is_refused`, corpus cases `forged-address/*`.

**A3. Versioning and encodings are `TODO`.** The signature covers "the encoding of the payment
disclosure without signatures", so its security depends on that encoding being unambiguous.
*Resolution:* `"ZRCT"` magic, a version byte, fixed-width fields, and strict canonical decoding
(re-encoding must reproduce the input). The Sprout code used a magic marker chosen "to be
disjoint from transaction encoding" for the same reason; the BLAKE2b personalization already
separates our digest from transaction digests. *Checked by:* `properties.rs::encoding_is_a_bijection`,
`::only_canonical_encodings_decode`; the spec verifier's decoder, written from `SPEC.md`, agrees on
all vectors.

**A4. "The height … (which we assume was verified by the caller)".** Nothing in a disclosure
binds a height, and nothing proves the transaction was mined. *Resolution:* the chain verifier
fetches the transaction by `txid` and uses the mined height; offline verification now says it
did not check (CLI: "height N as given; not checked against the chain"; page: "as you gave it,
not checked"). Before 2026-10-15 the offline page showed the supplied height as `BLOCK` like a
fetched one. *Checked by:* `zceipt-chain/src/chain.rs::verify_offline` sets `chain_checked = false`.

**A5. Spend proofs use "the same anchor" taken from `tx`.** For v6 transactions the `txid` does
not commit to the anchor (ZIP 229, "Anchor commitment (version 6)"), so "the anchor of `tx`" is
not fixed by `pd.txid = tx.txid()`. *Resolution:* soundness of spend authority does not depend on
the anchor (`CLAIM.md`, argument for (1): the nullifier binds the note). Completeness needs the
anchor of the mined transaction, which is what lightwalletd serves. A receipt made against a
re-anchored copy of the transaction would fail to verify, never verify wrongly.

**A6. Sequence-length checks are redundant.** `length(pd.saplingSpends) ≤ length(tx.shieldedSpends)`
follows from index uniqueness and range. *Resolution:* we check uniqueness and range only.

**A7. Validity levels in UIs are `TODO`.** *Resolution:* verifiers report `spend_authority`,
`outputs`, `sender_address`, `challenge`, `confirmations`, `finality` separately (`SPEC.md`).

**A8. Transparent inputs (BIP 322) are `TODO`.** Out of scope, as in the ZIP.

## In the protocol specification

**A9. §4.20.3 (decryption with an OVK) predates NU6.3's `rcm`.** "Sending Notes (Orchard)" defines
`Derive_rcm` with a ZIP 2005 branch for lead byte `0x03`
(`ToScalar(PRF^expand_rseed([0x0B] ‖ g_d* ‖ pk_d* ‖ v ‖ ρ ‖ ψ))`), but "Decryption using an Outgoing Viewing Key" (§4.20.3 as ZIP 311 cites it) and the IVK decryption section still
derive `rcm = ToScalar(PRF^expand_rseed([5] ‖ ρ))` for every lead byte other than `0x01`.
Following §4.20.3 literally makes every Ironwood output fail to open. *Resolution:* use
`Derive_rcm` in recovery (as the `orchard` crate does, and as the chain's Ironwood notes require).
*Checked by:* the spec verifier opens the real testnet Ironwood output
(`examples/testnet/receipt.txt`: 0.01 TAZ, "Invoice 42: two coffees") only with `Derive_rcm`.

**A10. `allowedLeadBytes` depends on height.** For a given pool after NU6.3 it is a single byte;
a verifier that knows the pool does not need the height. *Resolution:* lead byte `0x02` for
Orchard outputs, `0x03` for Ironwood outputs.

**A11. `rk` may not be the identity.** "Action Descriptions" now says `rk` MUST NOT be the
zero point (a soft fork in zcashd 6.12.1 and Zebra 4.3.1). A disclosure is not a transaction, but
an identity `rk` would let anyone sign. *Resolution:* both verifiers refuse it (Rust through
`Instance::from_parts`, the spec verifier explicitly). *Checked by:* corpus case
`resigned/rk-identity`.

**A12. A decrypted `pk_d` that is the zero point.** `KA^Orchard` public keys are `G*_P`, but
`abst_P` returns the zero point for the all-zero encoding and §4.20.3 does not reject it.
*Resolution:* reject (matches `orchard`'s `NonIdentityPallasPoint`).

## In ZIP 229 / ZIP 244

**A13. The empty Orchard digest in v6.** ZIP 229 states the empty-component hash for Ironwood
(`BLAKE2b-256("ZTxIdIronwd_H_v6", [])`) and gives `ZTxIdOrchardH_v6` as the v6 Orchard
personalization, but does not spell out the empty Orchard case. *Resolution:* `ZTxIdOrchardH_v6`
over empty input. *Checked by:* the spec verifier recomputes the txid of the real testnet
transaction `571de6e4…` (no Orchard actions, two Ironwood actions) and matches.

## In our own SPEC.md (fixed)

**A14.** `SPEC.md` described version 2 as "adds address proofs per spend" without their byte
layout, the proof-length cap, or the fixed `cv`. Writing the spec verifier from `SPEC.md` alone
exposed this; the layout is now in `SPEC.md`.

**A15. Flags of the disclosure proof.** ZIP 311 does not say which `enableSpends` /
`enableOutputs` flags the Orchard disclosure proof uses. Zceipt proves with both enabled
(`Flags::ENABLED`), with a zero-value dummy output, so the action is built by the same unmodified
Orchard builder path as any wallet action and its `cmx`, `cv_net` and `rk` look like ordinary
public inputs. Soundness of spend authority does not depend on the output half: the proof shows
knowledge of the note behind the transaction's nullifier `nf` under the transaction's anchor, and
`rk` is bound to `ak`. Proving spends-only (`0x01`), as zreceipt's prototype does, would also force
`v_new = 0` inside the circuit; it is an equally valid choice, and a later version could adopt it
to converge on one rule. The verifier always passes the same flags it expects, so the two are
not interchangeable within a version.

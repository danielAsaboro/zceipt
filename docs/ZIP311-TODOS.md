# How Receipts fills ZIP 311's open items

ZIP 311 ("Zcash Payment Disclosures", Draft) specifies payment disclosures for Sapling and leaves
several items `TODO`. This page lists each one, what Receipts does about it, and where to check.
It is a local write-up for this repository; nothing here has been proposed upstream.

## The TODOs

| ZIP 311 item | Receipts | Check it |
|---|---|---|
| "Add support for Orchard." | Orchard and Ironwood (NU7) disclosures. Outputs open with the per-output `ock`; spend authority is a fresh Halo 2 action proof over the same anchor and nullifier, with a zero-value dummy output, plus a `SpendAuthSig` by the randomized key. | [SPEC.md](SPEC.md) (spend authority); `receipts-core/tests/roundtrip.rs::orchard_receipt_roundtrip`, `::ironwood_receipt_roundtrip`; real receipts in `examples/regtest-orchard`, `examples/testnet` |
| "Decide on payment disclosure versioning." | A version byte after the magic: v1 (outputs and spends), v2 (adds per-spend address proofs), v3 (outputs in another pool than the spends, for Orchard notes spent into Ironwood after NU6.3). Unknown versions are refused. | [SPEC.md](SPEC.md) (encoding, cross-pool); `receipts-core/src/encoding.rs` |
| "Define encodings for unsigned and signed payment disclosures." | Binary `unsigned` and `receipt := unsigned ‖ signatures`, text `zrcpt1` + base64url for links, `zrcptb1` for batches. Decoding is strict and canonical: one receipt, one encoding. | [SPEC.md](SPEC.md); `roundtrip.rs::encodings_are_canonical`, `::every_byte_matters`; `receipts-cli/tests/conformance.rs::decoders_never_panic` |
| "Set some standards for how UIs should display payment disclosures." | Every verifier reports each property separately (`spend_authority`, `outputs`, `sender_address`, `challenge`, `confirmations`, `finality`) and a verdict (`valid` at 10 confirmations, `valid_provisional` before). The page shows a ticket, what was **not** revealed, and what the chain server could see. | [SPEC.md](SPEC.md) (validity levels); `receipts-server/src/verify.rs::levels`; `web/app.js::render` |
| Block height "assumed verified by the caller." | Verifiers fetch the transaction from lightwalletd, check its txid, and use the mined height for finality; offline verification takes the raw transaction and height explicitly. Note the height selects the consensus branch for parsing and is reported, not proven. | `receipts-chain/src/chain.rs::verify_against_chain`, `::verify_offline`; [conformance/README.md](../conformance/README.md) |
| "Reference implementation: TBD." | This repository: Rust core, CLI, REST API, WebAssembly verifier, and SDKs for TypeScript, Python, Rust and Go. The native and WebAssembly builds of the Rust verifier and an independent verifier written in Python from the protocol specification (`spec-verifier`, everything but the Halo 2 check) all run the same 223 conformance vectors, and the two implementations agree on 224 signed adversarial cases (`docs/TRACEABILITY.md`). | [conformance/README.md](../conformance/README.md) |
| Open issues blocking ZIP 311: payment source disclosure ([zcash#3828](https://github.com/zcash/zcash/issues/3828)) | Source proofs (v4): for a disclosed spend, the earlier transaction output that created the spent note, with the value hidden or exactly revealed; through that transaction, who funded it in the clear. Same circuit, verifier-fixed value commitment | [SPEC.md](SPEC.md#source-of-funds-version-4), `roundtrip.rs::*source*`, `examples/testnet/source` |
| Open issues blocking ZIP 311: per-field disclosure ([zcash#2631](https://github.com/zcash/zcash/issues/2631)) | Not done; see [PAIN-POINTS.md](PAIN-POINTS.md) §4 | — |
| BIP 322 for transparent inputs | Out of scope (still `TODO` in ZIP 311). The ZIP 320 deposit receipts prove a transparent hop that follows a shielded spend, not a transparent input. | [SPEC.md](SPEC.md) (exchange deposits) |
| Caching witness data "may improve performance" | Not needed: if the wallet pruned the note's Merkle path, it is rebuilt from public chain data (tree state + compact blocks). | `receipts-chain/src/chain.rs::rebuild_witness` |

## The requirements

| ZIP 311 requirement | How it holds | Check it |
|---|---|---|
| Zero or more shielded outputs per disclosure | Any subset of a transaction's outputs; zero outputs is allowed (deposit receipts) | `roundtrip.rs::roundtrip`; `examples/testnet/deposit-receipt.txt` |
| Only the sender can create one; non-malleable | Proof needs the spending key's `ak`; one signature over the whole canonical encoding | `roundtrip.rs::only_the_spender_can_create`, `::tampering_is_rejected`, `::encodings_are_canonical` |
| Can be bound to a challenge | `challenge:<hex>` in the signed message; proof requests check it | `receipts-server/tests/api.rs::proof_request_lifecycle_with_fixtures`, `::real_receipt_replay_is_refused` |
| Optionally reveal the sender's address | Address proof under the same randomized key (v2) | `roundtrip.rs::address_proof_roundtrip_and_rejections`; `examples/testnet/receipt-with-sender-address.txt` |
| No ephemeral data kept from sending | Proofs are made later from the wallet's note and a Merkle path (rebuilt if needed) | `receipts-chain/src/chain.rs::rebuild_witness` |
| No new trusted setup | Halo 2 (no trusted setup); the shipped commitment parameters are deterministic and checked against a fresh derivation | `roundtrip.rs::params_match_derivation` |

## The ZIP's use cases

| Use case | In Receipts |
|---|---|
| Contributions for an event | Campaigns with aggregate-only public pages (`api.rs::campaigns_publish_aggregates_only`) |
| Donation drive | Campaigns, opt-in public notes, batch receipts for many payments |
| Merchant dispute | Proof requests, refunds to a payer-signed address with proof both ways (`api.rs::refunds_go_to_the_signed_address_and_need_proof`) |
| Shielded withdrawals from an exchange | Receipts for the withdrawal; ZIP 320 deposit receipts for the other direction |

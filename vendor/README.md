# vendor/

`vendor/orchard` is the published `orchard` 0.16.0 crate from crates.io, unchanged except for the
small patch in [`orchard-0.16.0-receipts.patch`](orchard-0.16.0-receipts.patch) (about 60 changed
lines across four files). Every other file, including its `AGENTS.md`, licences and CI config, is
upstream's, copied as published. Nothing in the circuit or in proving changes.

What the patch adds, and why Receipts needs it:

| Change | File | Used for |
|---|---|---|
| `VerifyingKey::build_with_params`, `params_bytes` | `src/circuit.rs` | load precomputed k=11 commitment parameters instead of deriving them (verifier warm-up 7.7 s → 2.9 s); `params_match_derivation` checks they equal the derived ones |
| `Address::pk_d` public | `src/address.rs` | incoming receipts and outputs without their memo rebuild the note from the address |
| `DiversifiedTransmissionKey::from_bytes` public | `src/keys.rs` | same |
| `Note::esk_bytes` | `src/note.rs` | incoming receipts: the recipient reveals one output's ephemeral secret |
| `Note::commitment_opening`, `extracted_commitment_from_opening` | `src/note.rs` | format v5: disclose recipient and amount by the note-commitment opening without `rseed`, so the memo stays encrypted |

Check it yourself:

```sh
curl -sL https://static.crates.io/crates/orchard/orchard-0.16.0.crate | tar xz -C /tmp
diff -ru /tmp/orchard-0.16.0/src vendor/orchard/src     # shows exactly the patch above
```

It is wired in through `[patch.crates-io]` in the workspace `Cargo.toml`, and used only by
receipts-core's `orchard-ext` feature, which this workspace's binaries turn on. A wallet that
depends on receipts-core without that feature builds on stock orchard 0.16 and gets receipts
v1-v4, batches, source proofs, sign-in, payment requests and proof of funds;
`scripts/check-stock-orchard.sh` checks it.

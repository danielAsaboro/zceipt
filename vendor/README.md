# vendor/

`vendor/orchard` is the published `orchard` 0.16.0 crate from crates.io, unchanged except for the
patch in [`orchard-0.16.0-receipts.patch`](orchard-0.16.0-receipts.patch). Every other file,
including its `AGENTS.md`, licences and CI config, is upstream's, copied as published. The Action
circuit and its keys are unchanged (`params_match_derivation` and every testnet receipt check
that); the patch adds one new circuit beside it, for claims.

What the patch adds, and why Receipts needs it:

| Change | File | Used for |
|---|---|---|
| `VerifyingKey::build_with_params`, `params_bytes` | `src/circuit.rs` | load precomputed k=11 commitment parameters instead of deriving them (verifier warm-up 7.7 s → 2.9 s); `params_match_derivation` checks they equal the derived ones |
| `Address::pk_d` public | `src/address.rs` | incoming receipts and outputs without their memo rebuild the note from the address |
| `DiversifiedTransmissionKey::from_bytes` public | `src/keys.rs` | same |
| `Note::esk_bytes` | `src/note.rs` | incoming receipts: the recipient reveals one output's ephemeral secret |
| `Note::commitment_opening`, `extracted_commitment_from_opening` | `src/note.rs` | format v5: disclose recipient and amount by the note-commitment opening without `rseed`, so the memo stays encrypted |
| `Circuit::synthesize_inner` (the Action synthesis, with the nullifier's public input optional and `nk`'s cell returned) | `src/circuit.rs` | the claim circuit reuses the Action constraints as they are |
| `circuit::claim` (new) | `src/circuit/claim.rs` | claims (`zip311t1`): the Action statement plus public `domain` and `tag = Poseidon(nk, domain)`, its own keys |

Check it yourself:

```sh
curl -sL https://static.crates.io/crates/orchard/orchard-0.16.0.crate | tar xz -C /tmp
diff -ru /tmp/orchard-0.16.0/src vendor/orchard/src     # shows exactly the patch above
```

It is wired in through `[patch.crates-io]` in the workspace `Cargo.toml`, and used only by
receipts-core's `orchard-ext` feature, which this workspace's binaries turn on. A wallet that
depends on receipts-core without that feature builds on stock orchard 0.16 and gets receipts
v1-v4, batches, source proofs, sign-in, payment requests and proof of funds;
`scripts/check-stock-orchard.sh` builds it and runs real testnet receipts through it.

`crates/receipts-kce/src/blake2b_halo2` is eryxcoop/blake2b_halo2 at 6ed2fa2 (Apache-2.0, its
LICENSE beside it), ported from midnight-proofs to zcash's halo2_proofs 0.4: import paths, the
lookup and gate API, and a personalization option for the initial state. Its authors say it has
not been audited, and neither has the port.

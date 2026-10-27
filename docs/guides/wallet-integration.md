# Adding "Prove this payment" to a wallet

What a wallet team needs: where the button goes, what the screens say, the two calls, and how
long they take.

## Where it goes

On a sent transaction's detail screen, next to "Share" or "View on explorer": **Prove this
payment**. Only for transactions this wallet sent from Orchard or Ironwood notes.

## The flow

1. **Choose what to show.** Default: the outputs sent to someone else (not change), with memos.
   Options: hide the memos; add a message (an invoice number, or paste a request link, which
   fills in its challenge).
2. **Confirm.** One screen, the same one `zceipt sign` shows: the transaction, the outputs to
   disclose, the message, and any extra disclosure (an address you also control, the source of the
   funds), each in plain words. "This proves this payment was signed by the key that spent it. It doesn't show your
   balance or other payments. Anyone you send it to can show it to others."
3. **Share** the link the wallet gets back, or save it as a file.

## The calls (Rust, `zceipt-core`)

```rust
// 1. Proofs, from the full viewing key (no spending key): about 2.5 s per spend on a laptop.
let prepared = ReceiptBuilder::new(Network::Mainnet, &tx)
    .message(b"Invoice 42")
    .disclose(output_index, ovk)
    .spend(ViewingSpendWitness { index, fvk, note, merkle_path, prove_address: None, source: None })
    .prepare(&proving_key, &mut rng)?;

// 2. The signature, where the spending key is: milliseconds. A hardware signer gets
//    `prepared.unsigned()` and `prepared.alphas()` and must recompute the digest itself.
let sigs = sign_prepared(prepared.unsigned(), prepared.alphas(), &[ask], &mut rng)?;
let link = format!("{verifier_page}#{}&h={mined_height}", prepared.apply_signatures(sigs)?.to_text());
```

Step 2 is compiled and run against a real testnet payment as the doctest in
`crates/zceipt-core/src/builder.rs`.

Where step 1's inputs come from, in a wallet built on `zcash_client_backend`:

- the transaction: `WalletRead::get_transaction(txid)`;
- the spent note: the wallet's own received note whose nullifier the payment's Action reveals
  (`WalletRead` lists notes; decrypt with the account's IVK if only the output is stored);
- its Merkle path: `WalletCommitmentTrees::with_orchard_tree_mut` (or the Ironwood tree), then
  `witness_at_checkpoint_id_caching` at the checkpoint whose root is the payment's anchor.
  `zceipt_wallet` does this against `zcash_client_sqlite`; a wallet that has pruned the
  witness can rebuild it from public chain data (`zceipt_chain::chain::rebuild_witness`, whole
  1,000-block windows so the server doesn't learn which note).

A wallet that sends with PCZT already has these in the PCZT's Orchard spend (the note, its
Merkle path, and `alpha` is fresh per receipt), so the prover role can prepare the receipt from
the same data once the transaction is mined; the signer role signs as in step 2. The proving key
takes a few seconds to build once; keep it for the session.

For mobile wallets on the Zcash Android or iOS SDK, `crates/zceipt-ffi` is the whole button,
with generated Swift and Kotlin bindings in `crates/zceipt-ffi/bindings/`:
`prepareReceipt(dbPath, network, txid, message)` makes the proofs from the SDK's own wallet
database, and `signPrepared(prepared, spendingKey, nil)` signs them.

Until a wallet ships the button, its users make receipts in the browser: the verifier's
**Make a receipt** page takes the wallet's exported viewing key and the txid, finds the note
and makes the proofs on the device, then signs with the seed phrase there or exports the
prepared receipt for another signer.

## Multisig (FROST) wallets

A wallet whose spending key is split with re-randomized FROST signs a receipt the way it signs a
transaction: the coordinator hands each signer `signing_digest(prepared.unsigned())` as the
message and `prepared.alphas()[i]` as the randomizer (`frost_rerandomized::RandomizedParams::
from_randomizer`), the threshold signs, and `apply_signatures` takes the aggregated signature.
The prover needs only the full viewing key. With the key's published sharing commitment, the
coordinator can add a policy proof (`zceipt_core::policy`): the payment was authorized under
that t-of-n key, without showing which holders signed. `crates/zceipt-core/tests/frost.rs`
does both for a 2-of-3 key with the Zcash Foundation's crates and verifies the results.

## What not to do

- Never sign a digest handed to the signer: recompute it from the unsigned receipt.
- Don't keep the randomizers (`alpha`) after signing: with the receipt they link the wallet's
  receipts.
- Don't make receipts automatically. A receipt is evidence the user chooses to give.

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
2. **Confirm.** One screen, the same one `receipts sign` shows: the transaction, the outputs to
   disclose, the message, and any extra disclosure (an address you also control, the source of the
   funds), each in plain words. "This proves your wallet made this payment. It doesn't show your
   balance or other payments. Anyone you send it to can show it to others."
3. **Share** the link the wallet gets back, or save it as a file.

## The calls (Rust, `receipts-core`)

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

The note, its Merkle path and the transaction come from the wallet's own database. A wallet built
on `zcash_client_sqlite` can follow `receipts_wallet::prepare_receipt` (it reads exactly these);
a wallet that has pruned the note's witness can rebuild it from public chain data
(`receipts_chain::chain::rebuild_witness`, whole 1,000-block windows so the server doesn't learn
which note). The proving key takes a few seconds to build once; keep it for the session.

There is no FFI crate yet. A mobile wallet binds two calls: `ReceiptBuilder::prepare` (then
`PreparedReceipt::to_text` for the `zip311u1…` text) and `PreparedReceipt::from_text` followed by
`sign_prepared` and `apply_signatures` where the spending key is.

## What not to do

- Never sign a digest handed to the signer: recompute it from the unsigned receipt.
- Don't keep the randomizers (`alpha`) after signing: with the receipt they link the wallet's
  receipts.
- Don't make receipts automatically. A receipt is evidence the user chooses to give.

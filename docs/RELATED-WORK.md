# Related work

Other people have started on parts of the same problem during 2026. This page says what each
proves, what it does not, and what Receipts adds. Dates are from each project's public commit
history, read on 2026-10-22.

| Project | Dates | What a check proves | What it does not prove |
|---|---|---|---|
| [zreceipt](https://github.com/Cosmiq2025/zreceipt) (Cosmiq2025) | Oct 7 – Oct 20 | One output's recipient, amount and memo, opened with the sender's outgoing cipher key (`ock`), for Sapling, Orchard and Ironwood. Its author proposed the Orchard/Ironwood output-disclosure text for ZIP 311 (zcash/zips#1406). | Who sent the payment (spend authority exists as a prototype test, not in the product), and, for a pasted transaction, that it was mined. |
| [zcash-delivery-proof](https://github.com/saplingcash/zcash-delivery-proof) (saplingcash) | Sep 28 – Oct 8 | That a transaction delivered one note (receiver, value, memo) in Sapling, Orchard or Ironwood, made with an incoming or outgoing viewing key, checked with no key. | Who sent it, and that it was mined. |
| [`zcash_disclosure`](https://github.com/auzum197/librustzcash/pull/1) and [zcash-disclosure](https://github.com/auzum197/zcash-disclosure) (auzum197) | Sep 29 – Oct 9 | Chosen outputs, as Bech32m disclosures proposed as a candidate encoding for ZIP 311. | No signature or spend authority. |
| Viewing-key processors (BTCPay plugin, CipherPay) | existing products | Everything the key can see. | Nothing is withheld; see [COMPARISON.md](COMPARISON.md). |

All three disclosure projects stop at the part of ZIP 311 that reveals an output. Receipts
implements the part ZIP 311 says makes a disclosure complete: **proof that the payer's spend
authority made the payment.** Each disclosed spend carries a fresh Orchard action proof (Halo 2)
for the same anchor and nullifier, and a spend-authorization signature over the disclosure, so a
receipt cannot be made by someone who only watched the payment or holds a viewing key.

On top of that, and not in the projects above:

- **The verifier checks the chain:** the transaction is fetched by txid and its block checked,
  with the block hint so the server sees only a block number.
- **Optional sender-address proofs** (fixed `ValueCommit_0(1)`, like ZIP 304) and **verifier
  challenges** for replay-proof "prove it now" checks.
- **Source of funds** (format v4): which earlier output created each spent note.
- **Outputs without their memo** (v5), **incoming receipts** made by the recipient, **signed
  payment requests**, **batches** and **proof of unspent funds**.
- **A second, independent verifier** written in Python from the protocol specification, which
  agrees with the Rust verifier on 270 conformance vectors and 232 signed adversarial receipts.
- **Integration points:** a Rust library, a `zcash-devtool wallet receipt` command, a REST API
  with webhooks, SDKs for TypeScript, Python, Rust and Go, and a browser verifier.

## Prefixes

zreceipt writes its receipts as `zrcpt1` followed by base64url JSON. Receipts used the same
prefix by coincidence until Oct 22, 2026, when it moved to `zip311r1` (and `zip311b1` for
batches) so the two incompatible formats can't be confused. The Receipts verifier recognises a
zreceipt link (it begins `zrcpt1eyJ`) and says what it is instead of failing with a decode error.

# Receipts: an Orchard and Ironwood instantiation of ZIP 311

ZIP 311 ("Zcash Payment Disclosures", Draft) defines how the sender of a shielded
transaction proves what they paid without handing over a viewing key. It specifies Sapling
and leaves Orchard as `TODO`. This document describes the Orchard instantiation that this
repository implements. It applies unchanged to Ironwood (NU6.3), which uses the Orchard
protocol with version-3 note plaintexts.

## Goals (from ZIP 311)

- Disclose zero or more outputs of one transaction.
- Prove spend authority for at least one input, so only a sender can make a disclosure.
- Non-malleable: nobody can recombine disclosures into a new one.
- Optional challenge message, so a disclosure can be interactive.
- The sender does not need ephemeral data from transaction creation.
- No new trusted setup. Orchard's Halo 2 needs none at all.

## Output disclosure

For an Orchard action `a` created with outgoing viewing key `ovk`:

```
ock = PRF^ockOrchard_ovk(cv_net(a), cmx(a), ephemeralKey(a))
```

The receipt carries `(index, ock)`. The verifier runs Orchard output recovery with `ock`
(protocol §4.20.3, "decryption using a full viewing key", the `ock` path) on `a`'s
`outCiphertext` and `encCiphertext`. This yields the note `(d, pk_d, v, rho, rseed)` and the
memo. Recovery checks that the recomputed note commitment equals `cmx(a)`, so the opened
note is the one on chain. The note-plaintext version follows the pool: lead byte `0x02` for
Orchard and `0x03` for Ironwood. A disclosure for one output reveals nothing about any
other output.

## Spend authority (the Orchard analogue of the Sapling spend proof)

Sapling proves spend authority with a fresh Spend proof plus a `spendAuthSig`. Orchard has
no separate spend circuit; the Action circuit proves a spend and an output together. For a
spent note `n` (nullifier `nf`, found at action index `i`), the sender:

1. Rebuilds the action statement with the **same anchor** as the transaction (`rt` of the
   bundle). As ZIP 311 notes for Sapling, this costs nothing in privacy, since the original
   spend already fixed the note's anonymity set at that anchor.
2. Spends `n` using its Merkle path to that anchor.
3. Creates a **zero-value dummy output** to a throwaway address, with `rho = nf`, exactly as
   Orchard dummy notes are made.
4. Samples a fresh `alpha` and `rcv`, so
   - `rk = SpendAuthSig.RandomizePublic(alpha, ak)` is unlinkable to the transaction's `rk`, and
   - `cv_net = ValueCommit_rcv(v - 0)` hides `v`.
5. Proves the Action statement with public inputs
   `(rt, cv_net, nf, rk, cmx_dummy, enableSpends = 1, enableOutputs = 1, disableCrossAddress = 0)`
   under the post-NU6.3 Orchard circuit.
6. Signs the receipt digest with `rsk = SpendAuthSig.RandomizePrivate(alpha, ask)`.

The verifier takes `rt` and `nf` from the **transaction**, not from the receipt. It checks
the Halo 2 proof against those public inputs and the receipt's `cv_net`, `rk` and `cmx`, then
checks the signature under `rk`. A valid proof means `rk` is a randomization of the `ak` that
owns the note with nullifier `nf` in the tree at `rt`. A valid signature under `rk` means the
signer knows `ask`. Together they show that the signer controls the spend authority used in
that action. This is the same guarantee ZIP 311 gives for Sapling.

## Signing digest

```
personalization = "ZIP311Signed" || I2LEOSP_32(coinType)       (16 bytes)
digest          = BLAKE2b-256(personalization, unsignedReceipt)
```

`coinType` is the SLIP-44 index (133 for mainnet, 1 for testnet). Every spend signs the same
digest, which covers the txid, pool, message, every disclosed output and every spend's
`(cv_net, rk, cmx, proof)`. Changing any byte invalidates every signature, which makes the
receipt non-malleable.

## Encoding (version 1)

```
unsigned := "ZRCT" | version:u8 = 1 | coin_type:u32le | pool:u8 (0 Orchard, 1 Ironwood)
            | txid[32] | msg_len:u16le | msg
            | n_outputs:u8 | { index:u32le | ock[32] }*
            | n_spends:u8  | { index:u32le | cv_net[32] | rk[32] | cmx[32] | proof_len:u32le | proof }*
receipt  := unsigned | { spend_auth_sig[64] } * n_spends
text     := "zrcpt1" || base64url_nopad(receipt)
```

A receipt with one spend and one output is about 5.2 KB (7 KB as text). That is small enough
for a URL fragment, which browsers never send to a server.

## Verification

1. Decode the receipt and reject it if it has no spends (ZIP 311: stripping signatures must
   never produce something that looks valid).
2. Fetch the transaction by `txid`, check that it is mined, and take its Orchard or Ironwood
   bundle according to `pool`.
3. Check that indices are in range and unique.
4. For each spend, check the signature first, then the proof, with `rt` and `nf` from the
   transaction.
5. For each output, recover the note with `ock`.
6. Report the proven spends and the opened outputs.

## Differences from the Sapling text, and open points

- **Sender address.** Sapling ZIP 311 can optionally prove a payment address with a ZIP 304
  proof. That is not included here. Like Sapling, an Orchard spend authority covers every
  diversified address of the key, so a disclosure proves "the holder of this spend authority
  paid", not "address X paid".
- **Transparent inputs** (BIP 322) are out of scope, as they are still `TODO` in ZIP 311.
- **Witness availability.** The sender needs the spent note's Merkle path at the
  transaction's anchor. `receipts create` first uses the wallet's checkpoints. If they have
  been pruned, it rebuilds the path from public chain data: the pool's tree frontier just
  before the note's block (`GetTreeState`), then every note commitment from that block
  onwards (`GetBlockRange`, compact blocks), until the root equals the transaction's anchor.
  Nothing needs to be cached at send time, which is ZIP 311's requirement. `--from-chain`
  forces this path.
- **Circuit choice.** The disclosure proof always uses the post-NU6.3 circuit, including for
  pre-NU6.3 Orchard transactions. It is a new statement about an old note and is never
  verified by consensus, so it should use the secure circuit.

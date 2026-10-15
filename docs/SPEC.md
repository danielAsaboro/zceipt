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

## Cross-pool receipts (version 3)

After NU6.3, a wallet spending Orchard notes pays into Ironwood outputs: the spends are in the
transaction's Orchard bundle and the payment in its Ironwood bundle. Version 3 adds the outputs'
pool right after the spends' pool and always carries the per-spend address flag:

```
unsigned := "ZRCT" | version:u8 = 3 | coin_type:u32le | pool:u8 | output_pool:u8 (≠ pool) | txid[32] | …
```

Spend proofs and signatures are checked against `pool`'s bundle (its anchor and nullifiers),
outputs are opened in `output_pool`'s bundle with that pool's note-encryption domain. The
signature covers both pool bytes, so a receipt can't be moved between bundles.

## Batches

```
batch := "ZRCB" | version:u8 = 1 | count:u16le | { len:u32le | receipt }*
text  := "zrcptb1" || base64url_nopad(batch)
```

Every receipt in a batch carries `batch:<id> <i>/<n>` as the first line of `msg`, which its
signature covers. A verifier checks that all ids match, `n` equals the count, and each
position `1..n` appears exactly once, then verifies each receipt on its own. Spend
authorities are not linked across receipts: each proof uses a fresh `rk`, so a batch does
not reveal that the payments came from one wallet.

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

## Message conventions

`msg` is free text, signed by every spend. These lines have a meaning to verifiers; any other
text is shown as is.

| line | meaning | checked by |
|---|---|---|
| `challenge:<hex>` | answers a proof request; binds the receipt to one invoice so it can't be reused | proof requests (`challenge_mismatch`) |
| `batch:<id> <i>/<n>` | the receipt's place in a batch (first line) | batch verification |
| `refund-to:<address>` | where the payer wants refunds sent; only the spender can have written it | refunds API |
| `public-note:<text>` | an opt-in note for a campaign's public page | campaigns |
| `tex-deposit:<tex>` + `second-tx:<txid>` | this transaction is the first step of a ZIP 320 payment to that TEX address, and `<txid>` the second | deposit verification (below) |

## Validity levels

ZIP 311 leaves "validity levels" open. Verifiers here report each property separately:
`spend_authority` (proven, with the number of actions), `outputs` (opened), `sender_address`
(proven or not disclosed), `challenge` (matched, mismatch, present or none), `confirmations`
and `finality` (final at 10 confirmations, the reorg limit lightwalletd clients assume). The
overall verdict is `valid` when final and `valid_provisional` before.

## Exchange deposits (ZIP 320)

A shielded payment to a TEX address takes two transactions: `tx1` spends shielded notes to an
ephemeral transparent address, `tx2` spends that output to the TEX's P2PKH. A deposit receipt is
an ordinary receipt for `tx1` (usually with no disclosed shielded outputs) whose message carries
the `tex-deposit:`/`second-tx:` lines. The verifier additionally checks that every input of `tx2`
spends an output of `tx1`, and sums `tx2`'s outputs to the TEX's P2PKH hash. The receipt then
proves that the holder of `tx1`'s spend authority made the deposit, which links their shielded
funds to it: it should only be shown to the exchange.

## Sign in with Zcash

The address proof above, without a transaction. The wallet makes a fresh `alpha`, an address
proof for `A` under `rk = SpendAuthSig.RandomizePublic(alpha, ak)`, and a `SpendAuthSig` by
`rsk` over

```
personalization = "ZcashSignIn\0" || I2LEOSP_32(coinType)
digest = BLAKE2b-256(personalization, "Receipts sign-in v1" || len32 || domain || len32 || nonce
                     || issued_at:u64le || rk || A || rho || rseed || nf || cv_net || cmx || proof)
text   = "zsig1" || base64url_nopad("ZSIG" | 1 | coinType:u32le | len16 domain | len16 nonce
                     | issued_at:u64le | rk | A | rho | rseed | nf | cv_net | cmx | len32 proof | sig)
```

A verifier issues a single-use nonce bound to its domain, checks the signature, the domain, the
nonce and the proof, then spends the nonce. A sign-in made for another domain or replayed fails.

## Attestations

For people who need a fact about a payment rather than the payment, a verifier that checked a
receipt can sign an SD-JWT (Ed25519) stating a lower bound on the amount, a day the payment was
on or before, the network and finality. The txid, the exact amount, the exact time, the request
id and the label are selectively disclosable claims. This is the server's word, so it is only as
trustworthy as the server; the receipt remains the trustless proof.

## Differences from the Sapling text, and open points

- **Sender address (optional).** Sapling ZIP 311 can prove a payment address with a ZIP 304
  proof. The Orchard version here is a second action proof under the **same** `alpha`, so it
  has the same `rk` as the spend disclosure. It spends a fresh 1-zatoshi note addressed to
  the claimed address `A`, and reveals that note's `rho` and `rseed`. The verifier recomputes
  the note commitment and the root of a one-leaf tree holding it, and uses that root as the
  anchor. Because the value is non-zero, the circuit enforces the anchor, so the proof shows
  that `A = (d, [ivk] g_d)` for the `ak` behind `rk`, and therefore that the spender controls
  `A`. The address proof's fields are covered by the receipt signature (encoding version 2
  adds them per spend). Without it, as with Sapling, a disclosure proves "the holder of this
  spend authority paid", not "address X paid".
- **Transparent inputs** (BIP 322) are out of scope, as they are still `TODO` in ZIP 311. The
  ZIP 320 deposit above proves a transparent hop that follows a shielded spend, not a
  transparent input itself.
- **Witness availability.** The sender needs the spent note's Merkle path at the
  transaction's anchor. `receipts create` first uses the wallet's checkpoints. If they have
  been pruned, it rebuilds the path from public chain data: the pool's tree frontier just
  before the note's block (`GetTreeState`), then every note commitment from that block
  onwards (`GetBlockRange`, compact blocks), until the root equals the transaction's anchor.
  Nothing needs to be cached at send time, which is ZIP 311's requirement. `--from-chain`
  forces this path.
- **Precomputed parameters.** Verifiers load the circuit's commitment parameters (k = 11,
  131 KB) from bytes shipped with the code instead of deriving them by hashing to the curve.
  They are deterministic and a test checks them byte for byte against a fresh derivation. This
  cuts the verifier's one-time setup from 7.7 s to 2.9 s in the browser (2.0 s to 0.8 s natively).
  It needs a one-function patch to orchard (`VerifyingKey::build_with_params`, `vendor/orchard`).
- **Circuit choice.** The disclosure proof always uses the post-NU6.3 circuit, including for
  pre-NU6.3 Orchard transactions. It is a new statement about an old note and is never
  verified by consensus, so it should use the secure circuit.

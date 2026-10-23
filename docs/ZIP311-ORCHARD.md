# ZIP 311 for Orchard and Ironwood: normative text

```
Title:    Payment Disclosures for Orchard and Ironwood
Status:   Draft text for ZIP 311's "Add support for Orchard" TODO (not submitted)
Requires: ZIP 311 (Payment Disclosures), ZIP 244 / ZIP 229, ZIP 212, protocol spec §4.20 and §5.4
Scope:    output disclosure and spend authority (format versions 1-3). The optional extensions
          (address proofs, source of funds, memo-withheld outputs, incoming receipts, batches,
          sign-in, payment requests, proof of funds) are in SPEC.md and are not normative here.
```

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in BCP 14 (RFC 2119,
RFC 8174). Implementations: `crates/receipts-core` (Rust) and `spec-verifier/` (Python,
written from this text and SPEC.md; it checks everything but the Halo 2 proof).
Test vectors: `conformance/vectors.json`.

## Terminology

- *Pool*: Orchard (`0`) or Ironwood (`1`). Ironwood uses the Orchard protocol, circuit and keys
  with note-plaintext lead byte `0x03`.
- *Payment bundle*: the transaction's bundle of the disclosure's spend pool. *Output bundle*: the
  bundle of its output pool (the same bundle unless the receipt is cross-pool, version 3).
- `coinType`: the SLIP-44 coin type, 133 on mainnet and 1 on testnet and regtest.
- `ValueCommit`, `PRF^ockOrchard`, `SpendAuthSig`, `DiversifyHash`: as in the protocol specification.

## Encoding

```
unsigned := "ZRCT" | version:u8 | coinType:u32le | pool:u8 | [outputPool:u8 if version = 3]
            | txid[32] | msgLen:u16le | msg
            | nOutputs:u8 | { index:u32le | ock[32] }^nOutputs
            | nSpends:u8  | { index:u32le | cvNet[32] | rk[32] | cmx[32] | proofLen:u32le | proof
                            | [addrFlag:u8 = 0 if version ∈ {2, 3}] }^nSpends
receipt  := unsigned | { spendAuthSig[64] }^nSpends
text     := "zip311r1" || base64url without padding (RFC 4648 §5) of receipt
```

`txid` is in internal byte order (the reverse of the hex block explorers show). `version` MUST
be the lowest that can carry the contents: 3 if `outputPool ≠ pool`, else 1 (versions 2, 4 and 5
carry the SPEC.md extensions).

A decoder MUST refuse a receipt that:
1. does not start with `ZRCT`, has an unknown version, or a version that is not the lowest for
   its contents;
2. has `pool` or `outputPool` other than 0 or 1, or `outputPool = pool` in version 3;
3. has `proofLen > 65,536`, an `addrFlag` other than 0 (1 introduces an address proof, an
   extension in SPEC.md: a verifier that doesn't implement it, including its fixed `cv_net` rule,
   MUST refuse such receipts), fewer bytes than its lengths
   declare, or any byte after the last signature;
4. does not re-encode to exactly its own bytes. Every receipt therefore has one encoding, and the
   signatures cover exactly those bytes.

The text form MUST be canonical base64url: a decoder MUST refuse padding, characters outside the
URL-safe alphabet, and non-zero trailing bits.

## Signing digest

```
personalization := "ZIP311Signed" || I2LEOSP_32(coinType)        (16 bytes)
digest          := BLAKE2b-256(personalization, unsigned)
```

## Creating a receipt (sender)

For each output to disclose, at index `j` of the output bundle, created with outgoing viewing key
`ovk`: `ock_j := PRF^ockOrchard_ovk(cv_net_j, cmx_j, ephemeralKey_j)` (§4.20.2).

For each spend to disclose, at index `i` of the payment bundle, spending note `n` with spending key
`sk` (`ask`, `ak`) and Merkle path `path` to the payment bundle's anchor `rt`:

1. Build an Orchard Action whose spend is `n` with `path` against `rt` (so its nullifier is the
   transaction's `nf_i`) and whose output is a zero-value dummy note with `rho = nf_i`.
2. Sample fresh `alpha` and `rcv`. `rk := SpendAuthSig.RandomizePublic(alpha, ak)`,
   `cvNet := ValueCommit_rcv(v(n) - 0)`, `cmx` := the dummy note's `x(cm)`.
3. Prove the Action statement under the post-NU6.3 Orchard circuit, whatever the payment's height
   (earlier circuit versions MUST NOT be used: the pre-NU6.2 circuit is unsound), with public
   inputs `(rt, cvNet, nf_i, rk, cmx, enableSpends = 1, enableOutputs = 1, enableCrossAddress = 1)`
   (SPEC.md writes the last flag as `disableCrossAddress = 0`; it is the same input).
4. After all spends are proven and `unsigned` is encoded, sign `digest` with
   `rsk := SpendAuthSig.RandomizePrivate(alpha, ask)`, one signature per spend, in spend order.

`msg` MAY carry a verifier's challenge as the line `challenge:<hex>`. A receipt MUST disclose at
least one spend. It MAY disclose zero outputs.

## Verifying a receipt (anyone)

Inputs: the receipt; the transaction `T` with id `txid*`, fetched or supplied; the expected network.

1. Decode the receipt (all rules above). Check `txid = txid*`, that `T`'s txid as computed by
   ZIP 244 (or ZIP 229 for v6) is `txid*`, and that `coinType` is the expected network's.
2. Let `B` be `T`'s bundle of `pool` and `B'` its bundle of `outputPool` (or `B`). Both MUST exist.
3. `nSpends ≥ 1`, and the number of signatures MUST equal `nSpends`.
4. Every spend and output index MUST be within its bundle's action count, and no index MAY
   appear twice among the spends or among the outputs.
5. For each spend `(i, cvNet, rk, cmx, proof)` with signature `σ`:
   1. `rk`, `cvNet` and `cmx` MUST be canonical encodings (`rk` and `cvNet` of Pallas points,
      `cmx` of a Pallas base field element), and `rk` MUST NOT be the identity.
   2. `SpendAuthSig.Validate(rk, digest, σ)` MUST hold.
   3. The proof MUST verify for the post-NU6.3 Action circuit with public inputs
      `(rt(B), cvNet, nf(B.actions[i]), rk, cmx, 1, 1, 1)`. The verifier MUST take the anchor and
      the nullifier from `T`, never from the receipt.
6. For each output `(j, ock)`: run Orchard output recovery with `ock` on `B'.actions[j]`
   (§4.20.3, the `ock` path, with the pool's lead byte and ZIP 212 rules). It MUST succeed, and
   the recomputed note commitment MUST equal `cmx(B'.actions[j])`. Report the address
   `(d, pk_d)`, value and memo.
7. The receipt is valid for `T`. Whether `T` was mined, and how deep, is established separately
   from the chain (a verifier SHOULD report the source it used and the confirmations), and a
   verifier that issued a challenge MUST check that `msg` carries it.

## Signing domains

Every signed format in this repository has its own BLAKE2b personalization (12 bytes, then
`coinType` as 4 bytes little-endian), so no signature made for one can verify as another. The
tags are this project's, not registered names; `ZIP321Signed` signs payment requests and is not
defined by ZIP 321.

| Format | Tag | Signed by |
|---|---|---|
| Receipt (`zip311r1`) | `ZIP311Signed` | the spend's randomized key `rk` |
| Incoming receipt (`zrcin1`) | `ZIP311Incomg` | a fresh `rk` of the recipient |
| Sign in with Zcash (`zsig1`) | `ZcashSignIn\0` | a fresh `rk` |
| Payment request (`zreq1`) | `ZIP321Signed` | a fresh `rk` of the payee |
| Proof of funds (`zrsv1`) | `ZcashReserve` | a fresh `rk` per note |

`receipts-core/tests/properties.rs::all_signing_domains_are_distinct` checks the five are distinct.

## Rationale

- *Same anchor, same nullifier.* As ZIP 311 notes for Sapling, re-proving against the
  transaction's own anchor costs nothing in privacy: the original spend already fixed the note's
  anonymity set. Taking `rt` and `nf` from `T` binds the proof to the payment.
- *Fresh `alpha` and `rcv`.* `rk` and `cvNet` are unlinkable to the transaction's, so the receipt
  reveals no more about the spent note than the transaction did.
- *Both flags enabled.* The spend-authority argument does not depend on the output half; the
  dummy output keeps the action identical to one an unmodified wallet builder produces.
  Spends-only proofs (which also force `v_new = 0`) are an equally sound choice; see
  SPEC-AMBIGUITIES.md, A15.
- *One digest for all spends.* Every signature covers every byte of `unsigned`, so receipts
  can't be merged, split or edited (non-malleability).
- *Canonical encoding, base64url text.* One receipt, one encoding. Bech32m's 90-character
  checksum range doesn't cover a 5 KB receipt, and a receipt that is corrupted fails its
  signature check anyway.

## Security considerations

- A receipt is a bearer proof: anyone holding it can show it. Interactive use needs a challenge.
- The sender chooses the outputs to disclose; a change output discloses like any other. A
  verifier binds a receipt to a payee by checking the recipient it expects.
- Inclusion rests on the chain source. A verifier SHOULD fetch by block (or from its own node)
  so the server does not learn the txid, and MAY cross-check a second server.
- A signer that holds `ask` apart from the prover (a hardware wallet) MUST be given the unsigned
  receipt and each spend's `alpha`, MUST compute `digest` itself with the `ZIP311Signed`
  personalization, MUST check each spend's `rk = SpendAuthSig.RandomizePublic(alpha, ak)`, and
  SHOULD display the txid, the disclosed outputs and `msg` before signing. It MUST NOT sign a
  digest supplied by the host: that could be a transaction's sighash, and the signature would
  authorize a real spend. `receipts_core::sign_prepared` is a reference signer that does these
  checks.
- Spend authority is proven for the signer's spend authorizing key. In a transaction several
  parties built (a PCZT), it is whoever holds that `ask` and knew each `ock`.

## Test vectors

`conformance/vectors.json`: 278 cases from real Orchard, Ironwood and cross-pool receipts, each
with the answer a correct verifier gives. `spec-verifier` additionally reports, for each proof, the
public inputs it must verify against.

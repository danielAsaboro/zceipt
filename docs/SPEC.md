# Receipts: an Orchard and Ironwood instantiation of ZIP 311

ZIP 311 ("Zcash Payment Disclosures", Draft) defines how the sender of a shielded
transaction proves what they paid without handing over a viewing key. It specifies Sapling
and leaves Orchard as `TODO`. This document describes the Orchard instantiation that this
repository implements. It applies unchanged to Ironwood (NU6.3), which uses the Orchard
protocol with version-3 note plaintexts.

The normative core (encoding, creation and every verification rule, with MUST/SHOULD) is in
[ZIP311-ORCHARD.md](ZIP311-ORCHARD.md). This document explains it and specifies the extensions.

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
text     := "zip311r1" || base64url_nopad(receipt)
```

Version 2 (some spend proves a sender address) appends to every spend, after its proof:

```
addr_flag:u8 (0 or 1) | if 1: address[43] (d[11] | pk_d[32]) | rho[32] | rseed[32] | nf[32]
                              | cv_net[32] (must be ValueCommit_0(1)) | cmx[32] | proof_len:u32le | proof
```

Every `proof_len` is at most 65,536. The version is determined by the contents (5 if any output
is opened without its memo, else 4 if any spend has a source proof, else 3 if the outputs are in another pool, else 2 if any spend has an
address proof, else 1); any other
version byte for the same contents is rejected, as is a flag other than 0 or 1, and anything
after the signatures.

A receipt with one spend and one output is about 5.2 KB (7 KB as text). That is small enough
for a URL fragment, which browsers never send to a server.

## Cross-pool receipts (version 3)

After NU6.3, a wallet spending Orchard notes pays into Ironwood outputs: the spends are in the
transaction's Orchard bundle and the payment in its Ironwood bundle. Version 3 adds the outputs'
pool right after the spends' pool and always carries the per-spend address flag:

```
unsigned := "ZRCT" | version:u8 = 3 | coin_type:u32le | pool:u8 | output_pool:u8 (≠ pool) | txid[32] | …
```

Decoding is strict: the per-spend address flag is exactly 0 or 1, a version-2 receipt must carry
at least one address proof, and a receipt is accepted only if re-encoding it reproduces its bytes,
so every receipt has a single encoding and its signature covers those exact bytes.

Spend proofs and signatures are checked against `pool`'s bundle (its anchor and nullifiers),
outputs are opened in `output_pool`'s bundle with that pool's note-encryption domain. The
signature covers both pool bytes, so a receipt can't be moved between bundles.

## Source of funds (version 4)

A sender can also prove **where the money came from**: for a disclosed spend at action `i`, that
the spent note was created by output `k` of an earlier transaction `S`. This answers the
question exchanges and compliance desks ask of shielded deposits ("source of funds",
zcash/zcash#3828), with one link instead of a viewing key. If `S` was the sender shielding an
exchange withdrawal, its transparent inputs are public, so the verifier sees the deposit's
funds trace to that withdrawal, and nothing else about the wallet.

The proof is a third Action proof, under the **same** `rk` as the spend disclosure:

1. Spend the same note `n` (so the same nullifier `nf_i`), but against the root of a one-leaf
   tree whose only leaf is `cmx_k`, the source output's commitment. Orchard nullifiers do not
   depend on the note's tree position (`nf = Extract([PRF_nk(ρ) + ψ] K + cm)`), so this is a
   valid spend statement for `n` exactly when `Extract(cm(n)) = cmx_k`.
2. The circuit only enforces the anchor when the spent value is non-zero, so the verifier fixes
   `cv_net` itself, with a zero trapdoor, and never takes it from the prover:
   - value hidden: `cv_net = ValueCommit_0(1)`; the proof's output (to a throwaway address,
     `ρ = nf_i`) carries `v − 1`. This shows `v ≥ 1` and nothing more about `v`.
   - value revealed: `cv_net = ValueCommit_0(v)`; the proof's output carries 0 and is opened
     (`address`, `rseed`), so the verifier recomputes its `cmx` and knows the spent note
     carried exactly `v`.

The verifier reads `cmx_k` from `S` itself (fetched by txid and checked mined, before the
payment), rebuilds the one-leaf anchor, and checks the proof against
`(anchor, cv_net, nf_i, rk, cmx_out, enableSpends = 1, enableOutputs = 1)`, with `nf_i` taken
from the payment transaction. A verifier that does not have `S` refuses the receipt rather than
ignoring the claim.

Encoding: version 4 always carries the outputs' pool byte (equal to the spends' pool when the
outputs are in the same pool) and replaces the per-spend address flag by a flags byte:

```
flags:u8 (bit 0: address proof, bit 1: source proof; other bits 0)
  | if bit 0: address proof (as in version 2)
  | if bit 1: txid_S[32] | index_k:u32le | value_flag:u8 (0 or 1)
              | if 0: cmx_out[32]
              | if 1: value:u64le (≥ 1) | out_address[43] | out_rseed[32]
              | proof_len:u32le | proof
```

Version 4 is used exactly when some spend carries a source proof; a revealed value of zero, a
value flag other than 0 or 1, or a flags byte above 3 is rejected. The signature covers every
field, so a source claim can't be added, removed or edited. A source proof made for one receipt
does not verify in another (it is bound to that receipt's fresh `rk`).

What it reveals: the link `S:k → T:i` and, if chosen, the note's value; through `S`'s public
transparent inputs, whoever funded `S` in the clear. A wallet that keeps no copy of `S` uses the
note's own commitment and asks no server for `S`; verifiers fetch `S` by txid.

## Outputs without their memo (version 5)

ZIP 311 leaves per-field disclosure open (zcash/zcash#2631). The `ock` of an output opens
everything, memo included. A sender can instead disclose an output by the opening of its note
commitment **without** `rseed`:

```
opened := index:u32le | address[43] (d | pk_d) | value:u64le | psi[32] | rcm[32]
```

The verifier takes `ρ = nf` of that action from the transaction and checks
`Extract(NoteCommit_rcm(g_d, pk_d, v, ρ, ψ)) = cmx`. Binding of `NoteCommit` fixes the recipient
and value. `esk = ToScalar(PRF^expand_rseed([4] ‖ ρ))` derives from `rseed`, which stays
secret, so nothing in the receipt opens the ciphertext and the memo stays encrypted.
(`ψ` and `rcm` also derive from `rseed`, but PRF^expand outputs for different domain bytes are
independent.) The verifier does not learn that the recipient can decrypt the note, only what
it commits to; a sender who wants that shown discloses the `ock` instead.

Version 5 is version 4's layout plus, right after the outputs, `n_opened:u8 (≥ 1) | opened*`.
It is used exactly when at least one output is opened; an index appears once across both lists.
The signature covers the openings, so the recipient and value can't be edited.

## Incoming receipts (`zrcin1`)

A sender's receipt proves "I paid". An incoming receipt is the recipient's half: "I was paid
this, at this address", for an accountant, a tax office or a lender, without an incoming
viewing key (which would show every payment to the wallet).

```
incoming := "ZRCI" | version:u8 = 1 | coin_type:u32le | pool:u8 | txid[32] | msg_len:u16le | msg
            | n:u8 | { index:u32le | esk[32] }* | rk[32] | address proof (as in v2) | sig[64]
text     := "zrcin1" || base64url_nopad(incoming)
digest   := BLAKE2b-256("ZIP311Incomg" || coinType_LE32, everything before sig)
```

- Each output is opened with the recipient's `pk_d` (from the proven address) and the disclosed
  `esk`, by the second half of §4.20.3 ("Decryption using an Outgoing Viewing Key"): `epk = [esk] g_d`,
  `K = KDF([esk] pk_d, epk)`, decrypt, re-derive `esk` from `rseed` (ZIP 212), check `cmx`. So the
  value and memo are those committed on chain to that address. `esk` opens that output only.
- The address proof is the same construction as a sender receipt's (one-leaf tree, value fixed by
  `ValueCommit_0(1)`): `rk`'s spend authority controls the address. The sender also knows `esk`
  (its OVK recovers it) but cannot prove the recipient's address, so only the recipient can make
  one. Every output must be to the proven address.
- No nullifier is revealed, so the verifier can't tell when the notes are spent.
- Decoding is strict (re-encoding must give the same bytes).

## Signed payment requests (`zreq1`)

ZIP 321 links say what to pay but not who asks (zcash/zips#611, #977). A signed request:

```
request := "ZREQ" | version:u8 = 1 | coin_type:u32le
           | domain | memo | code      (each u16le length + UTF-8)
           | amount:u64le (> 0) | expires_at:u64le (Unix seconds)
           | rk[32] | address proof for the payee (as in v2) | sig[64]
text    := "zreq1" || base64url_nopad(request)
digest  := BLAKE2b-256("ZIP321Signed" || coinType_LE32, everything before sig)
```

The address proof shows `rk`'s spend authority controls the payee address; the signature by `rk`
covers every field. The domain is a lowercase host (with an optional port), the memo at most 512
bytes, the code 6 to 64 hex characters. A wallet:

1. checks the signature, the address proof, the network and `now <= expires_at`;
2. fetches `https://<domain>/.well-known/zcash-receipts.json` (`{"payees": ["u1…"]}`, no
   redirects; plain http only for localhost) and requires a listed unified address with the
   payee's Orchard receiver. An attacker who swaps in their own address must sign with their own
   key, and the shop's domain doesn't list it;
3. pays `amount` to the payee with `memo`, and makes a receipt that signs `challenge:<code>`.

## Proof of funds (`zrsv1`)

"I hold at least X in unspent shielded notes", without a viewing key.

```
proof := "ZRSV" | version:u8 = 1 | coin_type:u32le | pool:u8 | height:u32le | anchor[32]
         | msg_len:u16le | msg | n:u8 | { nf[32] | value:u64le | rk[32] | out_address[43]
         | out_rseed[32] | proof_len:u32le | proof }* | sig[64] * n
text  := "zrsv1" || base64url_nopad(proof)
digest := BLAKE2b-256("ZcashReserve" || coinType_LE32, everything before the signatures)
```

For each note: an Action proof spending it against `anchor`, with public inputs
`(anchor, ValueCommit_0(value), nf, rk, cmx_out)`, where the verifier fixes the value commitment
(value ≥ 1, so the anchor is enforced) and recomputes `cmx_out` from the opened zero-value output
(`rho = nf`), so the note holds exactly `value`. Each note's `rk` signs the digest.

The verifier (1) reads the pool's tree root after block `height` from the chain and requires it
to equal `anchor`, so the notes existed then; (2) checks every proof and signature, with distinct
nullifiers; (3) downloads every nullifier the pool has published from its activation (NU6.3 for
Ironwood, NU5 for Orchard) to the tip and requires none to be one of the proof's: the notes are
unspent as of the tip. Downloading every block's nullifiers, as a wallet sync does, tells the
server nothing about which notes are checked; the nullifiers are cached keyed to a block hash, so
the next check only scans new blocks.

The verifier learns the values and the nullifiers, and so can see when these notes are spent
later. That is inherent to proving them unspent (Monero's reserve proofs reveal key images for
the same reason). Nothing else is revealed: no address, no other notes.

**Version 2: values hidden.** The holder can show the total and not each note's value:

```
proof := "ZRSV" | version:u8 = 2 | coin_type:u32le | pool:u8 | height:u32le | anchor[32]
         | msg_len:u16le | msg | total:u64le | rcv_sum[32] | n:u8 | { nf[32] | cv[32] | rk[32]
         | out_address[43] | out_rseed[32] | proof_len:u32le | proof }* | sig[64] * n
```

Each note's proof uses the holder's own value commitment `cv_i = ValueCommit_rcv_i(v_i)` as
`cv_net` (the opened output still carries 0, so `cv_i` commits to the note's whole value). The
verifier checks every proof and signature as in version 1, with `cv_i` as given, then requires
`sum cv_i = ValueCommit_rcv_sum(total)`. A note of value 0 skips the circuit's anchor check and
could be made up, but adds nothing to the total. The verifier learns the total and the
nullifiers. `receipts reserve --hide-values`; `roundtrip.rs::proof_of_funds_can_hide_each_value_and_show_only_the_total`;
the independent spec verifier checks the sum (`tests/test_testnet.py`).

## Screened-set proofs (`zip311s1`)

A separate proof, sent with a receipt, that the note spent by one of its spends is among a
published list of note commitments (for example the shield outputs an exchange has screened),
without saying which:

```
proof := "ZRCS" | version:u8 = 2 | coin_type:u32le | pool:u8 | txid[32] | index:u32le
         | floor:u64le | set_root[32] | cmx[32] | proof_len:u32le | proof
text  := "zip311s1" || base64url_nopad(proof)
```

The list's commitments, in order, are the leaves of an Orchard-shaped tree of depth 32 (empty
leaves and roots as in the commitment tree); `set_root` is its root. The proof is an Action proof
with public inputs `(set_root, ValueCommit_0(floor), nf, rk, cmx)`, where `nf` is the nullifier
action `index` of the receipt's transaction published and `rk` is that spend's key in the
receipt. The verifier computes the root from the list it trusts (never from the proof), fixes the
value commitment from `floor` (at least 1; the hidden output carries `v - floor`, so the note
held at least `floor` and the anchor is enforced), and requires a proof for every spend the
receipt proves. The sum of the floors is how much of the spent value is shown to have come from
the list (`create --screened-amount`), without any note's value.

What it shows: each note the payer's spends used is one of the list's notes, holding at least its
floor. What it doesn't: which one, its value, or anything about inputs other parties added to the
transaction. The independent spec verifier recomputes the root and the public inputs
(`tests/test_testnet.py`). `receipts screened-list`, `create --screened-set`, `verify --screened-set`;
`src/screened.rs`; `roundtrip.rs::screened_set_proof_shows_membership_not_which_member`; the
regtest run proves and refuses one.

## Batches

```
batch := "ZRCB" | version:u8 = 1 | count:u16le | { len:u32le | receipt }*
text  := "zip311b1" || base64url_nopad(batch)
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
  anchor. The circuit only enforces the anchor when the spent value is non-zero, so the
  verifier must know the value: as ZIP 304 does for Sapling, the proof uses `rcv = 0` and the
  verifier requires `cv_net = ValueCommit_0(1) = [1] V` (it never uses a `cv_net` chosen by the
  prover). With that, the proof shows that `A = (d, [ivk] g_d)` for the `ak` behind `rk`, and
  therefore that the spender controls `A`. (Taking `cv_net` from the prover let anyone claim
  any address by witnessing a zero-value note; see `CLAIM.md`.) The address proof's fields are
  covered by the receipt signature (encoding version 2 adds them per spend). Without it, as with
  Sapling, a disclosure proves "the holder of this spend authority paid", not "address X paid".
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

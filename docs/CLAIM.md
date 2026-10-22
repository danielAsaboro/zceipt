# What a receipt proves, and what it reveals

This is the one claim Receipts makes, stated precisely, with the argument for it and the limits of
it. Everything else in the repository (API, SDKs, pages) is a way to deliver or check this claim.

Sources: ZIP 311 (draft, `zips/zip-0311.rst` at zcash/zips `7b9e678`), ZIP 304, ZIP 229, ZIP 244,
and the protocol specification (`protocol/protocol.tex`, last changed `18d642d`, 2026-07-22).
Sections are named as in the specification.

## The claim

Let `T` be a transaction with identifier `txid`, and `R` a receipt that a verifier accepts for
`T` on network `coinType`. Then, except with negligible probability:

1. **Spend authority.** For every spend `(i, cv, rk, cmx, π, σ)` in `R`, whoever produced `σ`
   knows a spend authorizing key `ask` whose `ak = [ask] G` owns the note spent by action `i` of
   the receipt's pool bundle in `T` (the note whose nullifier is `nf_i`, as published in `T`).
2. **The disclosed outputs.** For every output `(j, ock)` in `R`, action `j` of the outputs' pool
   bundle in `T` carries a note to the address `(d, pk_d)` with value `v` and memo `m` that the
   verifier reports, and the holder of the incoming viewing key for that address can decrypt it.
3. **Binding.** The signers of every spend signed exactly these bytes: the network, both pool
   bytes, `txid`, the message `msg` (e.g. a verifier's challenge), every disclosed output and
   every spend disclosure. No-one without one of those `ask` values can produce a different
   receipt that a verifier accepts, by editing, merging or truncating receipts they hold.
4. **Sender address (optional).** For every spend that carries an address proof for `A`, the same
   `ask` (same `rk`) also controls `A`: `A = (d, [ivk] g_d)` for an `ivk` derived from that `ak`.
5. **Outputs without memo (optional).** For every opened output `j`, action `j` of the outputs'
   bundle carries a note to `(d, pk_d)` with value `v` (no claim about the memo or about who can
   decrypt it).
6. **Source of funds (optional).** For every spend that carries a source proof naming output `k`
   of transaction `S`, the note spent by action `i` of `T` is the note whose commitment `S`
   published at output `k`; if the proof reveals a value `v`, that note carried exactly `v`.

An **incoming receipt** (`zrcin1`, docs/SPEC.md) makes a separate claim: for each disclosed
output `j` of `T`, a note of the reported value and memo was committed to address `A`, and the
signer's spend authority controls `A` (the address-proof argument (4) below, under a fresh `rk`).
`tests/roundtrip.rs::only_the_recipient_can_prove_receipt` shows the sender, who knows every
`esk`, can't make one, and that validly signed wrong contents are refused.

It does **not** claim:

- that `T` was mined: the verifier must establish that separately. The chain verifier fetches it
  from a lightwalletd server and counts confirmations, so "mined" rests on that server's word
  (`receipts verify --cross-check <second server>` asks a second one); offline verification says
  it did not check;
- that a disclosed output went to someone other than the payer: the sender chooses which outputs
  to disclose, and change or a payment to itself discloses like any other output. What binds a
  receipt to a payee is the verifier's own check of the recipient (`expect_address`, "was it paid
  to you?", a proof request), and a batch total is the sum of the outputs its senders disclosed;
- that the signer *created* the disclosed outputs: the receipt shows that the spend-authority
  holder knew each output's `ock`. In a transaction built by one wallet (every wallet today) that
  is the payer; in a transaction assembled by several parties (a PCZT with several signers) it is
  whoever knew the `ock`;
- anything about the presenter: a receipt is a bearer proof. Anyone holding it can show it. A
  verifier who needs to know the receipt was made for them issues a challenge, which the signer
  puts in `msg` (`challenge:<hex>`);
- anything about transparent inputs (ZIP 311 leaves BIP 322 inputs as TODO; so do we).

## What a verifier learns, and what it doesn't

| A verifier learns | A verifier does not learn |
|---|---|
| `txid`, and so the whole public transaction | the sender's addresses, viewing keys, balance, or other transactions |
| for each disclosed output: recipient address, value, memo, `rseed` | anything about undisclosed outputs (each `ock` opens one output) |
| which actions' spends the signer authorized, by index | the values of those spent notes (`cv` is a hiding commitment with a fresh `rcv`) |
| the message `msg` | a link between this receipt's `rk` and the transaction's `rk`, or another receipt's (fresh `α`) |
| `A`, if and only if the signer chose to prove it | when the recipient later spends a disclosed note (see below) |
| with a source proof: which earlier output created each proven spend's note (and its value, if chosen) | anything about other notes of the wallet, or where *those* came from |

Knowing a disclosed note's plaintext does not let the verifier recognise its later spend: Orchard
nullifiers are `Extract([PRF_nk(ρ) + ψ] K + cm)` ("Computing ρ values and Nullifiers"), and the
specification requires nullifiers to be unlinkable to their notes even for an adversary who holds
the incoming viewing key or created the notes. `nk` stays with the recipient.

The chain server the verifier asks for `T` learns `txid` (or, with the `h=` hint, only the block);
`docs/ASSURANCE.md` records what was on the wire.

## The argument

The verifier takes `nf_i` (and the anchor `rt`) from `T`, never from the receipt, and checks the
Halo 2 proof `π` for the Action Statement (Orchard) with public inputs
`(rt, cv, nf_i, rk, cmx, enableSpends = 1, enableOutputs = 1)` under the post-NU6.3 circuit, and
`σ` as a `SpendAuthSig^Orchard` (RedPallas) by `rk` over
`BLAKE2b-256("ZIP311Signed" ‖ coinType, unsigned receipt)`.

**Spend authority (1).** By knowledge soundness of Halo 2 there is an extractable witness. The
statement fixes `rk = ak + [α] G`, `ivk = Commit^ivk_rivk(ak, nk)`, `pk_d = [ivk] g_d`,
`cm = NoteCommit(g_d, pk_d, v, ρ, ψ)` and `nf_i = DeriveNullifier_nk(ρ, ψ, cm)`. When `v ≠ 0`
it also fixes a Merkle path from `cm` to `rt`; when `v = 0` it does not (`v_old · (root − anchor)
= 0`, `vendor/orchard/src/circuit.rs:359`). The claim does not rest on that path: `nf_i` was
published by `T` for the note that `T` spent, with that note's `(nk*, ρ*, ψ*, cm*)`. A witness
with a different tuple and the same `nf_i` is a solution of
`[PRF_nk(ρ) + ψ] K + cm = ±P(nf_i)` with `cm = H(…) + [rcm] R`, a representation of a target
point in the independent bases `K` and `R` (both from `GroupHash^P`, "Group Hash into Pallas and Vesta"). Finding one is as
hard as discrete logarithms on Pallas; it is the "no two notes with distinct commitments but the
same nullifier" security requirement on nullifier derivation. So the extracted `(ak, nk, rivk)` are the owner's, the
signature under `rk` then needs `ask + α` (`SpendAuthSig` must be SURK-CMA secure, "Spend
Authorization Signature"), and the signer knows `ask`. Two consequences:

- substituting the anchor gains nothing. This matters for version 6 transactions, whose
  `txid` no longer commits to the anchors (ZIP 229 moved them to the authorizing data), so a raw
  transaction handed to an offline verifier can carry any anchor without changing its `txid`;
- dummy spends (value-0 notes to throwaway keys) can't be claimed by anyone, because nobody keeps
  their keys.

**Outputs (2).** Recovery with `ock` (§4.20.3, "Decryption using an Outgoing Viewing Key") decrypts `outCiphertext` to `(pk_d, esk)`, derives
the shared secret, decrypts `encCiphertext`, re-derives `esk` from `rseed` and checks it, re-derives
`rcm` and `ψ`, and requires `Extract(NoteCommit(g_d, pk_d, v, ρ, ψ)) = cmx_j` from `T` and
`[esk] g_d = epk_j`. Binding of `NoteCommit` makes `(d, pk_d, v, ρ, ψ)` the note committed on chain;
the `epk` and `esk` checks make the ciphertext the one the recipient's `ivk` opens. The memo is
authenticated by the AEAD under that key. For an Ironwood output the lead byte is `0x03` and
`rcm` is the ZIP 2005 derivation of "Sending Notes (Orchard)" (see `SPEC-AMBIGUITIES.md`, A9).

**Binding (3).** The signature covers the canonical encoding; decoding is strict (one encoding
per receipt). Proof bytes are inside the signed message, so re-randomizing a Halo 2 proof (which
anyone can do) breaks every signature, as ZIP 304 does for Groth16. Changing any other field
needs a new signature by every spend's `rsk`.

**Address proofs (4).** A second Action proof under the same `rk` spends a note of value 1 to `A`
with revealed `(ρ', rseed')`, against the root of a one-leaf tree holding that note, which the
verifier recomputes. The anchor check only binds the note when its value is non-zero, so the
verifier must know the value. It fixes `cv = ValueCommit_0(1)` (`rcv = 0`), as ZIP 304 fixes
`cv = ValueCommit_0(1)` for Sapling; then `v_old − v_new = 1` with both range-checked forces
`v_old ≥ 1`, the path is enforced, `cm` is the verifier's note to `A`, and `pk_d = [ivk] g_d` with
`ivk` from the same `ak`.

Until 2026-10-15 this repository took `cv` from the prover. A prover could then witness a
value-0 note to their own address, skip the anchor check, and "prove" any address `A`, and sign
in as anyone. `tests/roundtrip.rs::claiming_someone_elses_sender_address_is_refused` and
`::sign_in_as_someone_elses_address_is_refused` construct both forgeries; they were accepted
before the fix and are refused now. A forgery that keeps its own `cv` is also refused by the spec
verifier on its own (rule "cv_net is not ValueCommit_0(1)"); one that writes the expected `cv`
fails the Halo 2 check, which the spec verifier does not run, and the two verifiers agree on the
public inputs that check uses.

**Source of funds (6).** A third Action proof under the same `rk` uses the anchor the verifier
builds from `cmx_k`, read from `S`: the root of a one-leaf tree. As for (1), the extracted note has
nullifier `nf_i`, so it is the note `T` spent (unique nullifiers). The verifier fixes `cv` with a
zero trapdoor, `ValueCommit_0(1)` or `ValueCommit_0(v)`, so `v_old ≥ 1` and the circuit enforces
the Merkle path: `Extract(cm) = cmx_k`, unless the prover finds a Sinsemilla collision giving
the same root from another leaf or position. Orchard nullifiers do not depend on the position,
so position 0 of a fresh tree is a sound stand-in for the note's real position. With a revealed
value, the proof's output is opened with value 0 (the verifier recomputes `cmx_out`), so
`v_old − 0 = v`. `tests/roundtrip.rs::a_zero_value_note_cannot_claim_any_source` builds the
forgery the fixed `cv` prevents: the owner of a zero-value note, witnessing it against any
output's tree, satisfies the circuit with their own `cv` (checked), and is refused with every
`cv` the verifier allows. `::source_claims_are_bound_by_the_signature_and_the_proof` re-signs
lies about the value (lower and higher), relabelled proofs and borrowed proofs; all are refused.

## Assumptions

- Discrete logarithms are hard on Pallas, and `GroupHash^P` outputs have no known relations.
- Halo 2 (IPA over Pasta) is knowledge-sound, and the Orchard circuit implements the Action Statement (Orchard).
- RedPallas is SURK-CMA secure (secure under re-randomized keys); BLAKE2b is collision resistant.
- ChaCha20-Poly1305 is a secure AEAD; `KDF^Orchard` and `KA^Orchard` meet their requirements.
- The verifier obtains `T` by its `txid` and checks it was mined (outside the receipt).

## How each part is checked

`docs/TRACEABILITY.md` maps every requirement to the code and the test that checks it, in both
verifiers. `docs/ASSURANCE.md` lists the evidence that does not come from us: published test
vectors, the chain, a second implementation, mutation testing, fuzzing, Miri, and a recording of
exactly what the chain server receives.

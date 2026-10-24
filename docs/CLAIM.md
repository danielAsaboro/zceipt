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
4. **Sender address (optional).** For every spend that carries an address proof for `A`,
   whoever could sign under that spend's `rk` also controls `A`: `A = (d, [ivk] g_d)` for an
   `ivk` derived from some `ak'` with `rk = ak' + [alpha'] G`. The two proofs share `rk`, not
   `ak`: the spender's wallet makes both with one key, but a holder of the randomized signing
   key `rsk` (never shared by the reference signer, which takes `ask` and `alpha`) could attach
   a proof for an address of its own. So read it as "the receipt's signer controls `A`", which
   is what a payer who wants to be identified needs, not as a link between `A` and the spent note.
5. **Outputs without memo (optional).** For every opened output `j`, action `j` of the outputs'
   bundle carries a note to `(d, pk_d)` with value `v` (no claim about the memo or about who can
   decrypt it).
6. **Source of funds (optional).** For every spend that carries a source proof naming output `k`
   of transaction `S`, the note spent by action `i` of `T` is the note whose commitment `S`
   published at output `k`; if the proof reveals a value `v`, that note carried exactly `v`.
7. **Screened set (optional, a separate `zip311s1` proof).** For a list `L` of note commitments
   whose tree root the verifier computes itself, the note spent by action `i` of `T` (the one
   whose nullifier the action published, under the receipt's `rk`) is one of `L`'s notes and held
   at least the proof's `floor`. Which one, and its value, are not revealed: the proof's public
   inputs are the root, `ValueCommit_0(floor)` fixed by the verifier, the nullifier, `rk` and a fresh output commitment. `src/screened.rs`;
   `roundtrip.rs::screened_set_proof_shows_membership_not_which_member`. It covers the spends the
   receipt proves (the payer's own), not inputs other parties added to the transaction, and shows
   only a lower bound (the floor) on each such note's value.
8. **Same payer (optional, a separate `zip311k1` proof).** For the receipts it names (by signing
   digest, in order), whoever made the proof knows `alpha_i - alpha_0` for every spend's `rk`
   relative to the first, so every `rk` is `ak + [alpha]G` for one `ak`, or for keys whose
   relation the maker knows (keys pooled by their holders). The key and every other payment stay
   hidden. `src/link.rs`; `roundtrip.rs::same_payer_proof_links_one_key_and_nothing_else`, and
   the spec verifier checks the testnet batch's proof independently.
9. **Income (a separate `zip311i1` proof).** For every listed output `(txid, index)`, the holder of
   the proof's one `rk` owns the note that output created and it holds at least the item's floor,
   so together at least the sum of the floors. Each item is an Action proof against the root of a
   one-leaf tree holding the output's `cmx` (read from the chain by the verifier), with
   `cv_net = ValueCommit_0(floor)` fixed by the verifier: the circuit's 64-bit range checks on the
   note's value and on the hidden output's `v - floor` give `v >= floor`, and `floor >= 1` makes
   it check the anchor. One SpendAuthSig by `rk` covers every item. Revealed: the outputs, each
   note's nullifier, the floors. `src/income.rs`; `roundtrip.rs::proof_of_income_shows_a_total_not_the_amounts`.
10. **Key set (a separate `zip311m1` proof).** For a published set of keys `K_1..K_n`, every
   spend's `rk` is `K_j + [alpha]G` for some `j` whose `alpha` the prover knows (a one-of-many
   Schnorr proof: special soundness extracts `alpha` for at least one `j`, and the simulated
   branches make every `j` look alike). So the signer holds one of the keys, or knows its relation
   to one. `src/keyset.rs`; `roundtrip.rs::key_set_proof_names_the_set_not_the_key`, and the spec
   verifier checks `conformance/keyset.json`.
11. **Claim (a separate `zip311t1` proof, a local circuit).** The claimant owns a note holding at
   least `floor` in the tree at `anchor`, and `tag = Poseidon(nk, domain)` for that note's `nk`.
   The circuit is the Orchard Action circuit (`orchard::circuit::claim`) with the same `nk` cell
   feeding both `ivk = CommitIvk(ak, nk, rivk)`, which the note's address must match, and the tag
   hash, plus two public inputs (`domain`, `tag`). So every claim one key makes in one domain
   carries one tag, whichever note it uses (every address and both scopes of an account share
   `nk`), and finding a second tag for a key would need a CommitIvk collision. Against a chain
   snapshot, the claim reveals the note's nullifier and the verifier checks it wasn't published
   up to the snapshot block: the tree keeps spent notes, so without that a balance could claim
   from each key it passed through. Tags in different domains are unrelated values (Poseidon as a
   PRF keyed by `nk`). `src/claim.rs`; `roundtrip.rs::claims_are_one_per_key_per_domain`, and the
   regtest e2e claims twice from one wallet. A payer tag is the same proof on a note a payment
   spent (its nullifier one of the payment's, its anchor the payment's), so different tags mean
   different paying keys; `roundtrip.rs::payer_tags_tell_wallets_apart`.
12. **One verifier (a `zip311d1` receipt).** Claims (1) to (3) for the holder of the verifier key
   `V` only: each signature is a one-of-two Schnorr proof (`rk`'s discrete log, or `V`'s), so
   special soundness gives the verifier, who knows it didn't use its own `y`, the spend key's
   authorization; to anyone else the proof is one the verifier could have simulated
   (`designated::simulate`). `roundtrip.rs::designated_receipts_convince_only_their_verifier`.

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

## The argument (proof sketch)

The verifier takes `nf_i` (and the anchor `rt`) from `T`, never from the receipt, and checks the
Halo 2 proof `π` for the Action Statement (Orchard) with public inputs
`(rt, cv, nf_i, rk, cmx, enableSpends = 1, enableOutputs = 1, enableCrossAddress = 1)` under the post-NU6.3 circuit, and
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
- dummy spends (value-0 notes to throwaway keys) can't be claimed by an honest wallet, which
  doesn't keep their keys. A transaction builder that keeps a dummy's key, and disclosed outputs
  with its own `ovk`, could make a receipt for that dummy: it proves control of a spend that moved
  no value. So spend authority shows the signer took part in building the transaction, not how
  much it paid in; a verifier who needs the latter asks for `--prove-source --reveal-source-value`,
  which fixes each spent note's value (a dummy has none to show).

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

**Same payer (8).** Each link is a Schnorr proof for `D_i = rk_i - rk_0` with base `G`, made
non-interactive by hashing the whole statement (every `rk`, the receipts' digests, `msg`) with
the commitments. By special soundness, a prover who answers two challenges for the same `R_i`
yields `delta_i` with `D_i = [delta_i]G`, so in the random-oracle model a valid proof means the
prover knows every `delta_i`. If `rk_0 = [x_0]G` and `rk_i = [x_i]G` for different holders' keys,
`delta_i = x_i - x_0`, and knowing it without both secrets would solve a discrete log. It is
zero knowledge for the same reason a Schnorr signature is: `(R_i, s_i)` can be simulated from
`D_i` alone, so it reveals the `rk` relation it states and nothing about `ak`.
`roundtrip.rs::same_payer_proof_links_one_key_and_nothing_else` checks that another wallet's
receipt can't be linked, that a proof can't be moved, reordered or bent, and that a simulated
proof without the `alpha`s fails; `::spend_auth_base_is_the_orchard_generator` checks `G`.

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

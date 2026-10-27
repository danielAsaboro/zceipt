# Technical note

ZIP 311 defines a payment disclosure for Zcash and leaves its spend-authority proof as `TODO` for
Orchard. Zceipt fills that in for Orchard and Ironwood, then extends it: a receipt proves
one payment, and a small set of further proofs state relationships between payments, wallets and
keys without revealing the wallet's history.

This note says what each piece is, why it is needed, and what it costs. Status and evidence for
every piece are in [docs-site/status.mdx](docs-site/status.mdx); exact claims and arguments are in
[docs/CLAIM.md](docs/CLAIM.md).

## 1. Spend authority

**Problem.** Output disclosure (an outgoing viewing key's `ock`, or a note opening) can be produced
by anyone who saw the payment. It cannot tell the payer from anyone else, so it cannot answer a
dispute or a held deposit.

**Construction.** For each spend, a fresh Halo 2 proof of the stock Orchard Action circuit for the
anchor and nullifier the transaction published, under a re-randomized `rk = ak + [alpha]G`, and
a RedPallas signature by `rk` over the whole receipt. The verifier takes anchor and nullifier from
the transaction, never from the receipt. Only the full viewing key is needed to make the proofs;
the spend key signs afterwards and can stay offline.

**Why it holds.** Knowledge soundness of Halo 2 gives a witness for the published nullifier. A
different witness with the same nullifier would break discrete logarithms on Pallas, so the
extracted `(ak, nk, rivk)` are the owner's, and a valid signature needs `ask + alpha`.

**Cost.** About 4.9 KB per disclosed spend. No new circuit, no new setup. Real testnet and regtest
evidence; 278 conformance vectors; a second verifier written from the protocol spec.

**One self-found forgery.** The optional address proof took its value commitment from the prover,
so a zero-value note could forge any address. The verifier now fixes `cv = ValueCommit_0(1)`, as
ZIP 304 does. The forged artifacts are kept as must-fail vectors.

## 2. Relationships between payments

Everything below states one relationship. Each is a separate object, bound to what it covers.

| Relationship | Mechanism | New circuit |
|---|---|---|
| One key made all of these payments | Schnorr proof of `rk_i - rk_0 = [delta_i]G` | No |
| Signed by one of a published set | One-of-many Schnorr over the set | No |
| Issued by a delegate under a policy | Signed certificate; Schnorr links to the certificate's `rk` | No |
| Authorized under a t-of-n FROST key | Schnorr proof of `alpha` for `rk - C_0` | No |
| Received at least X across payments | Action proof against a one-leaf tree per output; value commitment fixed to the floor | No |
| Funded by a vetted set | Action proof against the set's tree | No |
| One claim per wallet; distinct payers | `tag = Poseidon(nk, domain)` inside a forked Action circuit | **Yes** |
| Two tags are accounts of one wallet | ZIP 32 child derivation with BLAKE2b inside a Halo 2 circuit | **Yes** |
| Convincing to one verifier only | OR-Schnorr in place of the spend signature | No |

## 3. Claim and payer tags

**Problem.** A grant round or airdrop must count wallets, not payments. A donor who splits a gift
into ten payments, or claims from each key a balance moved through, must count once.

**Construction.** `vendor/orchard/src/circuit/claim.rs` forks the Action circuit. The same `nk`
cell feeds `ivk = CommitIvk(ak, nk, rivk)`, which the note's address must match, and a Poseidon
hash that outputs `tag = Poseidon(nk, domain)`. Public inputs add `domain` and `tag`. The
Action constraints are reused as they are (`Circuit::synthesize_inner`).

**Why a tag is unique.** Every address and both scopes of an account share `nk`. A second tag for
one key needs a `CommitIvk` collision. Tags in different domains are unrelated (Poseidon keyed by
`nk`).

**Chain claims reveal the nullifier.** The tree keeps spent notes. The verifier checks the
nullifier was not published up to the snapshot block, or a balance could claim from every key it
passed through.

**Payer tags** are the same proof on a note a payment spent, so different tags mean different
paying keys.

**Risk.** This is the largest attack surface in the project: a soundness bug in the fork would
let a wallet claim twice or forge a tag. The base receipt does not depend on it.

## 4. Sibling accounts

**Problem.** Payer tags are per account. A donor with two accounts of one wallet gets two tags.

**Construction.** `crates/zceipt-kce` proves, for public `domain`, `tag_1`, `tag_2`, that there is
a hidden parent `(sk_par, c_par)` and two indices whose ZIP 32 hardened children have the `nk`s
behind the tags. BLAKE2b runs inside the circuit (four compressions), so the circuit is `k = 17`
and a proof takes about 72 seconds.

**Risk.** The BLAKE2b gadget is `eryxcoop/blake2b_halo2`, ported to `zcash/halo2`. Its authors say it
is not audited and neither is the port. A test checks the in-circuit derivation equals `orchard`'s.

## 5. Delegation

**Problem.** A wallet, back office or agent should be able to answer "prove you paid" without
holding the spend key.

**Construction.** The spend key signs a certificate under `rk_c` for a session key `S`, a maximum
per receipt, a last block and optional payees. The delegate holds the viewing key and the session
secret. For each spend it proves `rk_i - rk_c = [alpha_i - alpha_c]G` (the same `ak`) and signs the
receipt with `S`. The verifier checks the certificate, links, signature and policy against what
the receipt discloses.

**Limit.** Every receipt under one certificate carries it, so those receipts are linkable to each
other. The delegate can't spend, but it can decline to answer.

## 6. Threshold keys

A treasury whose key is split with FROST makes receipts like any wallet; the signature is an
ordinary `SpendAuthSig` and shows no signer set. A policy proof adds that the receipt was
authorized under the published t-of-n key, using the VSS commitment `C_0..C_{t-1}` with `C_0 = ak`.
Tested with the Zcash Foundation's FROST; not run on a chain.

## 7. What this does not do

- It does not prove the transaction is mined (a lightwalletd server's word, or two servers').
- It does not prove a disclosed output went to someone other than the payer.
- A receipt is a bearer proof; freshness needs a challenge.
- Sapling and transparent spends are out of scope.
- Nothing here has been run on mainnet, and the two circuits above are unreviewed.

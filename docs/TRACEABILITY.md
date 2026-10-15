# Traceability: every requirement, where it is implemented, what checks it

Two verifiers implement each verification rule: the Rust one (`crates/receipts-core`, used by the
CLI, API and WebAssembly page) and the spec verifier (`spec-verifier/specverify`, Python, written
from the specifications without reading the Rust verification code). The spec verifier checks
everything except Halo 2 proofs, and reports the exact public inputs each proof must be checked
against; `tests/test_differential.py` requires those to equal the Rust verifier's.

Abbreviations: `core` = `crates/receipts-core/src`, `rt` = `crates/receipts-core/tests/roundtrip.rs`,
`prop` = `crates/receipts-core/tests/properties.rs`, `conf` = `crates/receipts-cli/tests/conformance.rs`,
`sv` = `spec-verifier/specverify`, `svt` = `spec-verifier/tests`, corpus = the signed adversarial
cases in `svt/corpus.json` (written by `rt::differential_corpus`, each re-signed after the change).

## ZIP 311 requirements

| Requirement | Rust | Spec verifier | Checked by |
|---|---|---|---|
| Disclose zero or more outputs | `core/lib.rs::create_cross`, `verify_cross` | `sv/verify.py::verify_bundles` | corpus `resigned/no-outputs` (both accept); `examples/testnet/deposit-receipt.txt` |
| Only a sender can create one | Action proof for the spent note + `SpendAuthSig` by `rk` | signature (proof: public inputs only) | `rt::only_the_spender_can_create`; corpus `signed-by-someone-else` |
| Non-malleable | strict canonical decoding `core/encoding.rs::Receipt::from_bytes`; signature over all bytes | `sv/receipt.py::decode` (from `SPEC.md`) | `prop::encoding_is_a_bijection`, `::only_canonical_encodings_decode`, `::the_signing_digest_covers_every_field`; `rt::every_byte_matters`; corpus `flip/*`; 223 conformance vectors in both |
| Can be tied to a challenge | `msg` is signed; `challenge:<hex>` checked by proof requests | `msg` is in the signed bytes | corpus `resigned/new-message`; `receipts-server/tests/api.rs::real_receipt_replay_is_refused` |
| Optionally prove the sender's address | `core/lib.rs::address_proof`, `verify_address_proof` | `sv/verify.py::check_address_proof` | `rt::address_proof_roundtrip_and_rejections`, `::claiming_someone_elses_sender_address_is_refused`; corpus `honest/with-address`, `forged-address/*` |
| No ephemeral data kept from sending | Merkle path rebuilt from chain data | n/a | `receipts-chain/src/chain.rs::rebuild_witness`; `receipts create --from-chain` on testnet (`ASSURANCE.md`) |
| No new trusted setup | Halo 2; shipped parameters equal a fresh derivation | n/a | `rt::params_match_derivation` |

## Creating a disclosure (ZIP 311, "Creating a payment disclosure")

| Step | Rust | Checked by |
|---|---|---|
| At least one spend tuple | `create_cross` returns `NoSpends` | verification side: `rt::tampering_is_rejected` (spends stripped → `NoSpends`); creation side has no separate test |
| Spend proof for the note spent in `tx` at the same anchor | `create_cross`: `WrongNullifier`, `WrongAnchor` checks, `Circuit::from_action_context`, `Instance::from_parts(bundle.anchor(), …)` | `rt::*_roundtrip`; real receipts in `examples/` |
| Address proof with the same `α` and `rk` | `address_proof(…, alpha, rk, …)`, `rcv = 0`, `cv_net = address_proof_cv_net()` | `rt::address_proof_roundtrip_and_rejections` |
| `rsk = RandomizePrivate(α, ask)` | `SpendAuthorizingKey::randomize` | `rt::*_roundtrip` (signature verifies under `rk`) |
| `coinType` is 4-byte LE, index form; digest `BLAKE2b-256("ZIP311Signed" ‖ coinType, unsigned)` | `core/lib.rs::signing_personal`, `signing_digest` | `prop::receipts_and_sign_ins_are_domain_separated`; spec verifier recomputes it (`sv/verify.py::signing_digest`) and the signatures verify |
| `spendAuthSig = Sign(rsk, digest)` | `rsk.sign` | both verifiers |

## Verifying a disclosure (ZIP 311, "Verifying a payment disclosure")

| Step | Rust | Spec verifier | Checked by |
|---|---|---|---|
| `pd.txid = tx.txid()` | `receipts-chain/src/chain.rs::verify_offline` (zcash_primitives txid), `verify_cross` (`TxidMismatch`) | `sv/tx.py::txid`, ZIP 244 + ZIP 229 written out | `svt/test_vectors.py` (10 ZIP 244 vectors); the real testnet v6 transaction `571de6e4…` recomputes; conformance `cross/regtest-receipt-testnet-tx` |
| Indices in range | `check_indices` (`IndexOutOfRange`) | `verify_bundles` | corpus `resigned/output-index-out-of-range` |
| Indices unique | `check_indices` (`DuplicateIndex`) | `verify_bundles` | corpus `resigned/duplicate-output` |
| At least one spend | `verify_cross` (`NoSpends`) | `verify_bundles` | conformance vectors |
| Digest over the unsigned encoding | `signing_digest` | `signing_digest` over the decoded unsigned bytes | every valid vector verifies in both |
| `SpendAuthSig.Verify(rk, digest, σ)` | `reddsa` via `orchard::primitives::redpallas` | `sv/orchard.py::redpallas_verify` (RedDSA.Validate, canonical `R`, `S < r`) | corpus `signed-by-someone-else`, `flip/*` |
| Address proof | `verify_address_proof`: recompute note, one-leaf root, fixed `cv_net`, Halo 2 | `check_address_proof`: same except Halo 2; public inputs compared | `rt::*_refused`; corpus `forged-address/prover-cv` (both reject on `cv_net`), `forged-address/fixed-cv` (Rust rejects the proof; identical public inputs) |
| Spend proof with `rt`, `nf` from `tx`, `cv`, `rk` from `pd` (Orchard: also `cmx`, flags) | `Instance::from_parts(*bundle.anchor(), cv_net, *action.nullifier(), rk, cmx, Flags::ENABLED)`, `Proof::verify` | public inputs reported, compared | corpus `resigned/proof-from-another-receipt`, `cv-from-another-receipt`, `spend-index-of-another-action`, `wrong-pool-bundle` |
| Recover each output with `(height, ock)` (§4.20.3) | `zcash_note_encryption::try_output_recovery_with_ock` with `OrchardDomain`/`IronwoodDomain` | `sv/notes.py::recover_with_ock` (every step of §4.20.3, `Derive_rcm` for `0x03`) | `svt/test_vectors.py` (10 zcash-test-vectors note-encryption cases, wrong key, wrong pool); corpus `resigned/wrong-ock`, `ock-for-another-output`; testnet receipt opens to 0.01 TAZ |

## Orchard and Ironwood additions (not in ZIP 311's Sapling text)

| Rule | Rust | Spec verifier | Checked by |
|---|---|---|---|
| `rk` is not the zero point | `Instance::from_parts` returns `None` (`Malformed`) | `decode_point` refuses zero | corpus `resigned/rk-identity` |
| `cv_net` is a point, `cmx` a canonical field element | `ValueCommitment::from_bytes`, `ExtractedNoteCommitment::from_bytes` | `decode_point`, `_canonical_base` | corpus `resigned/cv-not-a-point`, `non-canonical-cmx` |
| Lead byte follows the pool (`0x02` Orchard, `0x03` Ironwood) | `OrchardDomain` / `IronwoodDomain` | `LEAD_BYTE[pool]` | `svt/test_vectors.py` (wrong pool refused) |
| Cross-pool (v3): spends in `pool`'s bundle, outputs in `output_pool`'s | `verify_tx_bundles` | `verify_bundles` (`out_pool`) | conformance `regtest-crosspool/*` |
| Network | `CoinTypeMismatch` | coin type check | corpus `resigned/mainnet-receipt-on-testnet` |
| Address proof `cv_net = ValueCommit_0(1)` | `verify_address_proof` | `check_address_proof` | `rt::*_refused`; corpus `forged-address/prover-cv` |
| Sign in with Zcash: domain, nonce, network, signature, address proof | `core/signin.rs::verify_sign_in` | `sv/verify.py::verify_sign_in` | `rt::sign_in_roundtrip_and_replay`, `::sign_in_as_someone_elses_address_is_refused`; conformance `sign-in/*` |
| Source proof (v4): anchor is the one-leaf root of the source output's `cmx`, read from the source transaction | `core/lib.rs::verify_source_proof`, `source_proof_anchor` | `sv/verify.py::check_source_proof` | `rt::a_source_must_be_the_output_that_created_the_note`; corpus `resigned/source-other-output` |
| Source proof `cv_net` fixed by the verifier: `ValueCommit_0(1)` hidden, `ValueCommit_0(v)` revealed, never 0 | `source_proof_cv_net` | `source_cv_net` | `rt::a_zero_value_note_cannot_claim_any_source`; corpus `resigned/source-value-lower`, `-higher` |
| Revealed value is exact: the proof's output is opened with value 0, `rho = nf` | `source_output_cmx` | `check_source_proof` (revealed branch) | `rt::source_claims_are_bound_by_the_signature_and_the_proof`; corpus `resigned/source-hidden-relabelled-as-1` |
| Same `rk` as the spend disclosure (no borrowed proofs) | `verify_cross` passes the spend's `rk` | `pi["rk"] = s.rk` | corpus `resigned/source-proof-from-another-receipt` |
| The source is a different, earlier transaction the verifier has; otherwise refused | `SourceLookup` returning `None` gives `SourceUnavailable`; `chain.rs` refuses later heights and the payment itself | `verify_bundles` (`source transaction output is not available`); heights checked by the caller | `conf::source_of_funds_offline`; conformance `*-source*/no-source-tx`, `/source-after-payment`; corpus `resigned/source-unknown-tx`, `/source-is-the-payment` |
| v4 canonical: flags ≤ 3, value flag 0 or 1, revealed value ≥ 1, v4 only with a source | `encoding.rs` | `sv/receipt.py::decode` | `prop::encoding_is_a_bijection`, `::only_canonical_encodings_decode` |

## Primitives in the spec verifier, against published vectors

| Primitive (protocol section) | `sv` | Vectors (zcash-test-vectors, independent Python reference) |
|---|---|---|
| Pallas, `abst_P`, `repr_P` ("Pallas and Vesta") | `pallas.py` | all below |
| Simplified SWU, isogeny, `GroupHash^P` ("Group Hash into Pallas and Vesta") | `pallas.py` | `orchard_map_to_curve` (13), `orchard_group_hash` (11), `orchard_generators` |
| Sinsemilla hash and commit | `orchard.py` | `orchard_sinsemilla` (11) |
| `MerkleCRH^Orchard`, empty roots, paths | `orchard.py` | `orchard_empty_roots` (33), `orchard_merkle_tree` |
| `NoteCommit^Orchard`, `DiversifyHash`, `ToScalar`/`ToBase`, `PRF^expand` | `orchard.py` | `orchard_key_components` (10) |
| `KDF^Orchard`, `Sym` (ChaCha20-Poly1305), recovery with `ock` | `orchard.py`, `aead.py`, `notes.py` | `orchard_note_encryption` (10); RFC 8439 §2.8.2 |
| v5 txid (ZIP 244) | `tx.py` | `zip_0244` (10) |
| v6 txid (ZIP 229) | `tx.py` | the real testnet transaction (no published v6 vectors yet) |
| NU6.3 `Derive_rcm` for `0x03` | `orchard.py::derive_rcm` | the real testnet Ironwood output; corpus (Rust and spec verifier agree on every opened output and address-proof anchor) |

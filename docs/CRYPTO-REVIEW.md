# Review of the cryptographic core

A focused review of `crates/receipts-core` (and the places the server compares secrets), done
2026-10-15. Each invariant names the test that checks it. Property tests run thousands of random
cases with a fixed seed (`crates/receipts-core/tests/properties.rs`), so failures reproduce.

## Invariants

| # | Invariant | Why it holds | Checked by |
|---|---|---|---|
| 1 | Only the holder of the spent note's spending key can make a receipt | Each spend disclosure is an Orchard action proof (same anchor and nullifier as on chain) under a key `rk = ak + [alpha]G` that the receipt signs with; making it needs `ask` | `roundtrip.rs::only_the_spender_can_create` |
| 2 | Non-malleable | One `SpendAuthSig` per spend over `BLAKE2b-256(personal, encode(unsigned))`; decoding is strict and canonical (address flags exactly 0/1, no flagless v2, re-encoding must reproduce the input), so a receipt has exactly one encoding | `roundtrip.rs::every_byte_matters`, `::encodings_are_canonical`; `properties.rs::encoding_is_a_bijection` (3,000 random receipts, every version relabelling), `::only_canonical_encodings_decode` (4,000 randomly mutated encodings: whatever decodes is its own canonical encoding) |
| 3 | The signature covers every field | The digest is over the full canonical encoding: coin type, both pool bytes, txid, message, every output index and `ock`, every spend's index, `cv_net`, `rk`, `cmx`, proof and address proof | `properties.rs::the_signing_digest_covers_every_field` (1,500 random receipts; one change to each field, including proof bytes and every address-proof field) |
| 4 | Domain separation between networks and protocols | Personalization `"ZIP311Signed" ‖ coinType` for receipts, `"ZcashSignIn\0" ‖ coinType` for sign-ins; the sign-in message also starts with `"Receipts sign-in v1"`. A mainnet receipt can't verify on testnet, and no receipt signature is a sign-in signature | `properties.rs::receipts_and_sign_ins_are_domain_separated` (the receipt digest is the ZIP311Signed hash for its network; the personalizations differ); `roundtrip.rs::sign_in_roundtrip_and_replay` (a sign-in for another network, domain or nonce is refused) |
| 5 | Bound to one transaction and pool | `txid` and the pool bytes are signed; proofs are checked against that bundle's anchor and nullifiers; v3 names both pools | `roundtrip.rs::tampering_is_rejected`; conformance vectors `cross/*` |
| 6 | Challenge binding | `challenge:<hex>` is part of the signed message; servers compare it with the request's challenge, and one payment output settles one request | `api.rs::real_receipt_replay_is_refused`, `::one_payment_settles_one_request`, `::concurrent_submissions_settle_once` |
| 7 | Unlinkability of the disclosure | Fresh `alpha`, `rcv` and dummy output per proof: `rk`, `cv_net`, `cmx` differ from the on-chain action's and between receipts | `roundtrip.rs::disclosures_are_unlinkable_to_the_action_and_to_each_other` |
| 8 | Address proofs bind to the same signer | The address proof uses the same `alpha` (hence the same `rk`) and spends a 1-zatoshi note to the address under a one-leaf tree whose root is recomputed by the verifier, and the verifier fixes `cv_net = ValueCommit_0(1)` so the circuit enforces that anchor. **This review originally missed the last part:** with `cv_net` taken from the prover, a zero-value witness note skipped the anchor check and any address could be claimed (found 2026-10-15 from ZIP 304 and the circuit; see `CLAIM.md`) | `roundtrip.rs::address_proof_roundtrip_and_rejections`, `::claiming_someone_elses_sender_address_is_refused`, `::sign_in_as_someone_elses_address_is_refused` |
| 9 | Shipped parameters are the real ones | The precomputed commitment parameters equal a fresh derivation byte for byte | `roundtrip.rs::params_match_derivation` |
| 10 | Decoders never panic | Bounds on proof lengths; every read is length-checked | `conformance.rs::decoders_never_panic` (20,000 random and mutated inputs) |

## Comparisons of secrets

| Where | Secret | Comparison |
|---|---|---|
| Webhook signatures (server, Rust, JS, Python, Go SDKs) | HMAC-SHA256 | Constant time: `ct_eq`, `Mac::verify_slice`, `safeEqual`, `hmac.compare_digest`, `hmac.Equal` |
| Hosted pay-page client secret | random 96-bit token | **Was** `==`; now constant time (`receipts-server/src/lib.rs::ct_eq`) |
| RedPallas, Halo 2 | n/a | Verification of public data; no secret-dependent branches in our code |
| API keys | 192-bit random | Looked up by SQLite primary key. A remote timing attack on a B-tree lookup of a 192-bit random key isn't practical; hashing keys at rest would remove it but changes how keys are shown at startup (not done) |

## Error paths

- Verification errors name the action index and the check that failed. Everything they mention
  is already in the receipt or the transaction, both of which the verifier holds.
- Secrets never appear in errors or logs: the tripwire refuses viewing keys, spending keys, seed
  phrases and age keys (also inside JSON escapes) without echoing them
  (`api.rs::pasted_viewing_keys_are_refused_and_never_echoed`, `::second_qa_pass_regressions`).
- The wallet code reads the mnemonic into memory only to derive keys, wrapped in `secrecy`, and
  never writes it anywhere (`crates/receipts-wallet/src/lib.rs::decrypt_seed`).

## Residual notes

- The receipt's `height` (for offline checks) selects the consensus branch for parsing and is
  reported, not proven.
- An attestation is the issuing server's signature; verifiers must name the issuer they trust
  (`verifyAttestation(…, { issuer })`).
- RedPallas and Halo 2 come from the `orchard` and `reddsa` crates (with one local patch that only
  loads precomputed parameters); this review covers how Receipts uses them, not the crates.

# Threat model: who learns what

Receipts exists so that proving one shielded payment doesn't hand anyone a viewing key. This
document lists, for every flow, what each party can learn, and points at the test or code that
backs each claim. "Learns" means can find out from what Receipts gives them; it says nothing about
what they knew already (a shop knows its own address, for instance).

**Parties**

| Party | Who |
|---|---|
| Payer | Sends the payment, makes the receipt in their own wallet |
| Shop | Asked for the payment; receives the receipt (or anyone the payer shows it to) |
| Receipts server | `receipts serve`, if the shop uses the API rather than verifying locally |
| lightwalletd | The chain server a verifier fetches the transaction from |
| Onlooker | Anyone watching the chain or the network, without the receipt |

Tests are `crate/tests/file.rs::name` or `packages/…/test/file.js` "name".

## 1. Making a receipt

The payer's wallet (`receipts create`, `receipts pay`) builds a fresh Halo 2 proof for each
spent note and signs the receipt. Everything runs locally against the wallet database; the only
network traffic is fetching public chain data.

| Claim | Backed by |
|---|---|
| Only the holder of the spending key can make a receipt for a spend | `receipts-core/tests/roundtrip.rs::only_the_spender_can_create` |
| The proof re-randomizes `rk`, `cv_net` and the dummy output, so the disclosure can't be matched to the on-chain action's keys, and two receipts for the same spend share nothing | `roundtrip.rs::disclosures_are_unlinkable_to_the_action_and_to_each_other`; `receipts-core/src/lib.rs` (`create_cross`: fresh `alpha`, `rcv`, dummy note) |
| Rebuilding a pruned Merkle path uses only public data (tree state and compact blocks), never the wallet's keys | `receipts-chain/src/chain.rs::rebuild_witness` |
| lightwalletd sees the wallet fetching blocks and, without the `h=` hint, one transaction id | `receipts-chain/src/chain.rs::fetch_mined_tx` |

## 2. What the receipt itself reveals

| Revealed to whoever holds the receipt | Not revealed | Backed by |
|---|---|---|
| The transaction id, its block | The payer's address (unless they chose `--prove-address`) | `roundtrip.rs::roundtrip`, `::address_proof_roundtrip_and_rejections` |
| Each disclosed output: recipient, amount, memo | The payer's balance, other notes, other transactions | `lib.rs::recover_with_ock` (one `ock` per disclosed output, nothing else) |
| That the receipt's signer had spend authority over the spent note(s) | Which note in the tree was spent, or its value | `lib.rs::verify_cross` (proof against the bundle's anchor and nullifier only) |
| The signed message (challenge, refund address, public note, deposit lines) | Undisclosed outputs (change, other recipients) | `roundtrip.rs::tampering_is_rejected`, `::every_byte_matters` |

A receipt can't be edited (every byte is signed, and decoding is canonical:
`roundtrip.rs::encodings_are_canonical`), forged by someone without the key, or moved to another
transaction or pool (`roundtrip.rs::tampering_is_rejected`; v3 binds both pools, `docs/SPEC.md`).

## 3. Sharing a receipt link

The receipt sits in the URL `#fragment`, which browsers never send to a server.

| Party | Learns | Backed by |
|---|---|---|
| The page's host | Nothing about the receipt (the fragment isn't in the HTTP request) | `web/app.js` (reads `location.hash` only); the page makes no request containing it |
| Referrer leaks | None: pages send `Referrer-Policy: no-referrer` | `receipts-server/tests/api.rs::hardening_public_limits_headers_and_live_webhook_hosts` |
| Onlooker | Nothing; receipts never touch the chain | (no transaction is made) |

## 4. Verifying in the browser (or with the npm package)

| Party | Learns | Backed by |
|---|---|---|
| Shop | What the receipt reveals (section 2) | `packages/zcash-receipts/test/conformance.test.js` |
| lightwalletd, link with `h=` | That someone fetched block *h* and every shielded transaction in it, not which one was checked. The hiding is only as good as the block is busy: with one shielded transaction it hides nothing, so the page reports the count | `packages/zcash-receipts/test/testnet.test.js` "block-level fetch hides which transaction was checked"; `grpc.js::fetchTransactionPrivately` |
| lightwalletd, no `h=` | The transaction id checked (the page says so) | `web/app.js::localBadge` |
| lightwalletd, offline mode | Nothing (the verifier is given the raw transaction) | `receipts-cli/tests/conformance.rs::conformance_vectors` (all offline) |
| Receipts server | Nothing: verification runs in WebAssembly on the device | `crates/receipts-wasm` (no network calls) |

## 5. Verifying through the Receipts API

The shop sends the receipt to its own Receipts server (`POST /v1/verify`, a proof request).

| Party | Learns | Backed by |
|---|---|---|
| Receipts server | Everything the receipt reveals (section 2); it stores it with the request | `receipts-server/src/requests.rs::accept_receipt` |
| Receipts server | Never a viewing key, spending key, seed phrase or age key: requests containing one are refused and not stored or echoed | `api.rs::pasted_viewing_keys_are_refused_and_never_echoed`, `::second_qa_pass_regressions` (JSON-escaped keys); `receipts-core/src/tripwire.rs` |
| lightwalletd | The transaction id (the server fetches it) | `receipts-server/src/verify.rs::verify_parsed` |
| Another shop | Can't reuse the receipt: it signs this request's challenge, and one payment settles one request | `api.rs::real_receipt_replay_is_refused`, `::one_payment_settles_one_request`, `::concurrent_submissions_settle_once` |

## 6. Hosted pay pages and campaigns

| Party | Learns | Backed by |
|---|---|---|
| Anyone without the client secret | Nothing about a request | `api.rs::hosted_pay_page_needs_the_client_secret` |
| Visitors to a campaign page | Only the contribution count and a rounded total, after at least *k* contributions, refreshed in batches; opted-in public notes | `api.rs::campaigns_publish_aggregates_only`, `::campaign_numbers_update_in_batches` |
| Onlooker timing payments against page updates | Can't match a contribution to a transaction by watching the total change (batched, rounded) | same |

## 7. Refunds

| Party | Learns | Backed by |
|---|---|---|
| Shop | The refund address the payer signed into the receipt, and nothing else about the payer | `api.rs::refunds_go_to_the_signed_address_and_need_proof` |
| Payer | The shop's refund receipt: that the shop paid it back | same; `scripts/e2e-regtest.sh` (cross-pool refund) |
| Phishing ("send my refund elsewhere") | Can't redirect: only the payer could have signed the address | `lib.rs::signing_digest` covers the message |

## 8. Attestations

| Party | Learns | Backed by |
|---|---|---|
| Accountant / auditor | A lower bound on the amount (net of refunds), a day, the network, finality, and whether it was a sandbox payment; nothing else unless the holder reveals it claim by claim | `api.rs::attestations_state_minimal_facts_and_disclose_selectively`, `::attestations_subtract_refunds`; `packages/zcash-receipts/test/attestation.test.js` |
| Which hidden claims exist | Not revealed: digests are padded with decoys | `receipts-server/src/attestations.rs` (padding to 8) |
| Forger | Can't make one that verifies against the issuer you name | `attestation.test.js` (refuses a token from another issuer) |
| Trust | The attestation is the server's word; the receipt is the trustless proof | `docs/guides/attestations.md` |

## 9. Sign in with Zcash

| Party | Learns | Backed by |
|---|---|---|
| The site | That the user controls the address they chose, for this domain and nonce, once | `api.rs::sign_in_with_zcash`; `roundtrip.rs::sign_in_roundtrip_and_replay` |
| Another site (phishing, replay) | Can't reuse the proof: it signs the domain and a single-use nonce | same |
| Onlooker | Nothing; no transaction is made | (no transaction) |

## 10. Exchange deposits (ZIP 320)

| Party | Learns | Backed by |
|---|---|---|
| Exchange | That the receipt's signer made this two-step deposit: this **links** the payer's shielded funds to the deposit, and every verifier says so | `receipts-cli/tests/conformance.rs::tex_deposit_offline`; `receipts-core/src/deposit.rs::WARNING` |
| Onlooker | What ZIP 320 already makes public (two transparent hops); the receipt is not on chain | ZIP 320 |

## 11. Webhooks and the 402 gate

| Party | Learns | Backed by |
|---|---|---|
| Shop backend | Signed events about its own requests | `api.rs::webhooks_are_signed_and_delivered` |
| An internal network behind the server | Not reachable from live webhooks: public HTTPS hosts only, checked again after DNS at send time, no redirects | `api.rs::hardening_public_limits_headers_and_live_webhook_hosts`, `::second_qa_pass_regressions`; `receipts-server/src/webhooks.rs::pinned_public_client` |
| A caller who didn't pay | Can't pass the gate with someone else's paid request (bound to session and route) or exhaust the shop's key | `packages/zcash-receipts/test/middleware.test.js` |

## Out of scope

- A compromised wallet or device (it holds the spending key).
- A Receipts server operator reading what shops send it: run your own, or verify in the browser.
- Network-level correlation of the verifier's IP by lightwalletd (use the `h=` hint, Tor, or offline mode).
- Transparent inputs (BIP 322): ZIP 311 leaves them `TODO` too.

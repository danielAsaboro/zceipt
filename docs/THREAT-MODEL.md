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
| lightwalletd sees the wallet fetching blocks and, without the `h=` hint, one transaction id. `receipts pay` waits for its payment to be mined by syncing the wallet (whole blocks), not by asking for the txid, and hands the shop the receipt with its block hint | `receipts-chain/src/chain.rs::fetch_mined_tx`; `receipts-wallet::mined_height_in_wallet` |

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
| The page's host | Nothing about the receipt (the fragment isn't in the HTTP request), and nothing about a proof request: its code, payee, minimum and label are in the fragment too (`#request=…`; links made before Oct 22 used the query string, which the host's logs see) | `web/app.js` (reads `location.hash` only); `receipts-wallet::parse_request_link` tests (fragment form) |
| Referrer leaks | None: pages send `Referrer-Policy: no-referrer` | `receipts-server/tests/api.rs::hardening_public_limits_headers_and_live_webhook_hosts` |
| Onlooker | Nothing; receipts never touch the chain | (no transaction is made) |

## 4. Verifying in the browser (or with the npm package)

| Party | Learns | Backed by |
|---|---|---|
| Shop | What the receipt reveals (section 2) | `packages/zcash-receipts/test/conformance.test.js` |
| lightwalletd, link with `h=` | That someone fetched block *h* and the run of up to 64 of its transactions that could carry a receipt (shielded, not the coinbase), the same run every time, not which one was checked. The hiding is only as good as the block is busy: measured over 1,000 recent blocks in an Oct 22 review, a receipt shares its block with 4.6 candidates on average on mainnet and is alone 10% of the time (testnet: 1.7, alone 53%). When the block has fewer than 8 candidates, the verifier also fetches the other blocks of its aligned run of 4 (fixed by the height, not centred on it) and their candidates, so the server learns the run, not the block; the remaining leak is that the payment's block is one of the run's quiet ones. Below 4 candidates the page and CLI say the server can narrow it down. A hostile server can list made-up or repeated txids around ours, or answer them all with one real transaction; it then learns which one was real. Every verifier counts a decoy only once, only if its bytes hash to the txid asked for, and only if the server places it in that block, so those tricks don't inflate the count. The block placement is still the server's word: against a server that lies about heights the count is an upper bound | `packages/zcash-receipts/test/testnet.test.js` "block-level fetch hides which transaction was checked"; `grpc.js::fetchTransactionPrivately` |
| lightwalletd, no `h=` | The transaction id checked (the page says so) | `web/app.js::localBadge` |
| lightwalletd, offline mode | Nothing (the verifier is given the raw transaction) | `receipts-cli/tests/conformance.rs::conformance_vectors` (all offline) |
| Receipts server | Nothing: verification runs in WebAssembly on the device | `crates/receipts-wasm` (no network calls) |

## 5. Verifying through the Receipts API

The shop sends the receipt to its own Receipts server (`POST /v1/verify`, a proof request).

| Party | Learns | Backed by |
|---|---|---|
| Receipts server | Everything the receipt reveals (section 2); it stores it with the request | `receipts-server/src/requests.rs::accept_receipt` |
| Receipts server | Never a viewing key, spending key, seed phrase or age key: requests containing one are refused and not stored or echoed | `api.rs::pasted_viewing_keys_are_refused_and_never_echoed`, `::second_qa_pass_regressions` (JSON-escaped keys); `receipts-core/src/tripwire.rs` |
| lightwalletd | With a link's `h=` (which `receipts pay` sends), the block, as in section 4; without it, the transaction id. Finality is then watched by block (`chain::tx_in_block`), not by txid | `receipts-server/src/verify.rs::verify_parsed_hinted`, `clocks.rs` |
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
| The site | That the user controls an address, for this domain and nonce, once. By default the address is derived from the domain, so each site sees its own address and two sites can't link a user by it | `api.rs::sign_in_with_zcash`; `roundtrip.rs::sign_in_roundtrip_and_replay`; `receipts-wallet::sign_in` |
| Another site (phishing, replay) | Can't reuse the proof: it signs the domain and a single-use nonce | same |
| A phishing site relaying a real site's challenge | Could get the user to sign in to the real site, if the user signs for the domain the phisher names: the CLI takes `--domain` from the user, so a wallet must show the domain it signs for and match it to where the user is. The per-domain address is derived from the normalized domain (lower case, no trailing dot or `:443`) | `receipts-wallet::sign_in` |
| Someone who knows your address | Can't sign in as you: the address proof's value commitment is fixed to `ValueCommit_0(1)`, so the circuit enforces that the proven note is yours (before 2026-10-15 it was not, and this was possible) | `roundtrip.rs::sign_in_as_someone_elses_address_is_refused`; conformance `sign-in/pre-fix` |
| Onlooker | Nothing; no transaction is made | (no transaction) |

## 10. Exchange deposits (ZIP 320)

| Party | Learns | Backed by |
|---|---|---|
| Exchange | That the receipt's signer made this two-step deposit: this **links** the payer's shielded funds to the deposit, and every verifier says so | `receipts-cli/tests/conformance.rs::tex_deposit_offline`; `receipts-core/src/deposit.rs::WARNING` |
| Onlooker | What ZIP 320 already makes public (two transparent hops); the receipt is not on chain | ZIP 320 |

## 11. Source of funds (`--prove-source`)

| Party | Learns | Backed by |
|---|---|---|
| Verifier (an exchange, say) | For each proven spend: the earlier transaction and output that created the spent note, and its value only with `--reveal-source-value`. Through that transaction's public transparent inputs, who funded it in the clear (the sender's own shielding of a withdrawal, typically). This **links** the payment to that earlier transaction, and every verifier says so | `roundtrip.rs::ironwood_source_roundtrip`, `::orchard_source_roundtrip`; `scripts/e2e-regtest.sh` (exchange withdrawal, shielding, deposit) |
| Verifier | Not: other notes of the wallet, where they came from, the sender's address or balance; a hidden value stays hidden (the proof's output and value commitment carry nothing the verifier can open) | `roundtrip.rs::source_proofs_stay_unlinkable`; `lib.rs::source_proof` |
| Verifier | Can't be fooled: a source must be the very output that created the note (`::a_source_must_be_the_output_that_created_the_note`), a revealed value must be exact (`::source_claims_are_bound_by_the_signature_and_the_proof`), and a zero-value note can't claim any source (`::a_zero_value_note_cannot_claim_any_source`); the spec verifier agrees on every case (`spec-verifier/tests/test_differential.py`) | as named |
| lightwalletd (verifier side) | The source transaction ids, fetched by txid (the payment itself can still use the `h=` block hint) | `receipts-chain/src/chain.rs::fetch_sources` |
| lightwalletd (wallet side) | Nothing new: the wallet reads the source from its own records, or uses the note's own commitment, without a request | `receipts-wallet/src/lib.rs::create_receipt` |

## 11b. Memo withheld (`--withhold-memo`)

| Party | Learns | Backed by |
|---|---|---|
| Verifier | The recipient and amount of each such output, from its note-commitment opening | `roundtrip.rs::ironwood_memo_withheld_roundtrip` |
| Verifier | Not the memo: the receipt holds no `ock` and not `rseed` (from which `esk`, and so the memo key, derive) | same test (asserts both); [SPEC.md](SPEC.md#outputs-without-their-memo-version-5) |

## 11c. Incoming receipts (`receipts received`)

| Party | Learns | Backed by |
|---|---|---|
| Verifier (an accountant, say) | The receiving address (proven controlled by the presenter), and the value and memo of each chosen output of one transaction | `roundtrip.rs::ironwood_incoming_roundtrip`; `examples/testnet/incoming` |
| Verifier | Not: other payments to the wallet, its balance, or when it spends these notes (no nullifier in the receipt) | same test (asserts the nullifier is absent) |
| The payer | Can't make one for the recipient: it knows `esk` but can't prove the address | `roundtrip.rs::only_the_recipient_can_prove_receipt` |
| The presenter | Can make one for a payment to itself: an incoming receipt proves a note reached an address the presenter controls, not that a third party paid it. For income, also ask for the payer's receipt | by design |

## 11d. Signed payment requests (`receipts request`, `receipts pay 'zreq1…'`)

| Party | Can / learns | Backed by |
|---|---|---|
| Someone who edits the request in transit (clipboard malware, a chat, an invoice) | Can't change the address, amount, memo, code, domain or expiry without the payee's key | `roundtrip.rs::signed_payment_requests`; `scripts/e2e-regtest.sh` ("an edited request is refused") |
| An attacker who signs its own request for the shop's domain | Refused: the domain's `/.well-known/zcash-receipts.json` doesn't list its address | same; e2e "a request for an address the domain doesn't list is refused" |
| The shop's domain | Learns that a wallet fetched its payee list (no wallet data is sent) | `receipts-cli/src/main.rs::domain_lists` |

## 11e. Proof of funds (`receipts reserve`)

| Party | Learns | Backed by |
|---|---|---|
| Verifier | The total and each note's value; the notes' nullifiers. That is forward linkability: whoever holds the proof sees the transaction that later spends those notes. It is how "unspent" is checked; move the notes to a fresh address after using a proof if that matters | `roundtrip.rs::proof_of_funds`; `examples/testnet/reserve` |
| Verifier | Not: the holder's address, other notes, history | same |
| lightwalletd (verifier side) | Only that the verifier downloaded the pool's blocks (all of them since activation), not which nullifiers it looks for | `receipts-chain/src/chain.rs::published_nullifiers` |
| Colluding holders | Each note is proven under its own fresh `rk`, so the proof shows the notes are unspent and were known to their holders, not that one person holds them all: several holders can pool notes into one proof, or answer a challenge for someone else. Use it to show funds exist, not who owns them | by design |
| Holder after spending | Can't keep using the proof: once a nullifier is on chain, verification fails | `scripts/e2e-regtest.sh` ("after the saver spends, the same proof is refused") |

## 11e1. Signing elsewhere (`zip311u1` prepared receipts)

The prepared file carries each spend's randomizer `alpha`. With the finished receipt, `alpha` gives
`ak = rk - [alpha] G`, the wallet's stable spend-validating key, which would link every receipt
it signs. So the file must go only from the proving machine to the signer: the CLI writes it
readable only by its owner and deletes it once signed, and a hardware signer must not export it.

## 11e2. Screened-set proofs (`zip311s1`)

| Party | Learns | Backed by |
|---|---|---|
| Whoever published the list | That each proven spend's note is one of the list's outputs and held at least its floor. The hiding set is the list's outputs that could hold that much: a short list, or a floor equal to a note's whole value (which the publisher may know), can narrow it to one. The CLI warns under 16 outputs; keep floors below the values when you can | `src/screened.rs`; `roundtrip.rs::screened_set_proof_shows_membership_not_which_member` |
| A verifier | The same, for the spends the receipt proves; nothing about other parties' inputs | CLAIM.md item 7 |

## 11f. Deposit desks (`source_of_funds` requests)

| Party | Learns | Backed by |
|---|---|---|
| Exchange | For each deposit: the source transactions of the spent notes and the transparent addresses and amounts that funded them, as with a transparent deposit; nothing else about the customer's wallet | `receipts-server/src/deposits.rs::evaluate`; e2e "deposit desk" |
| Anyone with the pay link | That the request requires a source and how many addresses are screened, never the list | `api.rs::deposit_desk_policy` |
| Customer | Whether the deposit was credited or held, and why (via the shop); a rejected deposit is refunded to the address they signed | e2e "the desk rejected it and refunds to the address the payer signed" |

## 12. Webhooks and the 402 gate

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

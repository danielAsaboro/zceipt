# Audit rerun with the Pashov method and Trail of Bits skills (2026-10-27)

Method: `pashov/skills` is Solidity-only, so its method (parallel specialist attackers, a four-gate
false-positive check, confidence threshold 75, read-only auditors) was adapted to this repo, with the
Trail of Bits skills (rust-review, spec-to-code, variant-analysis, differential-review, zeroize,
constant-time, supply-chain) as method files. No dedicated Zcash or Halo 2 audit skill exists on
GitHub. Eight read-only hunters ran against the working tree that includes the fixes from
`AUDIT-HOSTILE.md`; I re-checked the items marked *verified* by hand. Raw reports are per hunter in
the session scratchpad. `cargo audit`: one advisory (RUSTSEC-2026-0387, `crypto-bigint` via
`age`/`p256`) judged not reachable (the wallet uses an X25519 age identity); two unmaintained crates
not in the runtime path.

Result: no break of the circuits, the BLAKE2b gadget, any Schnorr/CDS/OR proof, the decoders (13,750
mutants through Rust and Python decoders, 0 disagreements) or the trailing-byte fix.

## Findings, merged and ranked

| # | Sev | Where | What | Status |
|---|---|---|---|---|
| R-1 | HIGH (regression, *verified*) | `packages/zceipt/index.js`, `pkg/zceipt_wasm.js` | JS imports `verify_policy_pinned`; the tracked wasm `pkg` doesn't export it, so the module fails to load and `zceipt serve` ships an inconsistent bundle. None of the wasm-side fixes ship until `scripts/build-web.sh` is rerun and `pkg/` committed. | fixed (wasm and web bundle rebuilt; index.js loads; JS tests pass) |
| R-2 | HIGH | `docs/pay.html:59` | `zceipt pay '${location.href}'` is HTML-escaped but not shell-quoted; a `'` in a link fragment injects shell commands when the payer pastes the copied command. `web/app.js:1051` quotes correctly. | fixed (shell-quoted) |
| R-3 | MEDIUM (*verified*) | `crates/zceipt-server/src/requests.rs:448-455` | The in-transaction source-of-funds recheck only handles `Err`, but `deposits::evaluate` reports a coverage failure as `Ok({status:"review"})`, so the recheck never fires and two parallel deposits from one source can both clear. | fixed (recount decides held) |
| R-4 | MEDIUM | `web/app.js:442`, `:807`, `web/make.js:11` | `request=` fragment value goes into `innerHTML` unescaped: markup injection and a forged "satisfied" box (CSP blocks scripts), and the value is copied into the message the payer signs. | fixed (code validated, escaped) |
| R-5 | MEDIUM | `crates/zceipt-server/src/lib.rs:110-146` | Unauthenticated `POST /v1/public/*/<id>/*` creates a rate bucket per made-up id; ~10k ids a minute fill the map and new API keys then get 429. A request id alone also burns that payer's 20 attempts a minute. | fixed (API keys evict public buckets) |
| R-6 | MEDIUM | CLI verify (`main.rs`) | The new flag table covers income, delegated/designated, siblings, claim only. Still ignored silently: `--key-set`, `--policy-commitment`, `--cross-check` on batches; `--cross-check`, `--key-set` on incoming; `--min-payers`/`--list` on ordinary receipts; `--cross-check` on list claims; `--network` on siblings; `--raw-tx` on several arms. | fixed (table covers batch, incoming, receipt, list claims, income-only flags) |
| R-7 | MEDIUM | server `Body`, JS/Go/MCP clients | Only `CreateRequest` has `deny_unknown_fields`. `POST /v1/verify` with a misspelt `chalenge` or `expectAddress` returns valid with no check; a mistyped attestation `valid_for_days` issues a non-expiring token. | fixed (deny_unknown_fields on every request body) |
| R-8 | MEDIUM | `main.rs:2353-2360` | The CLI policy line still uses unpinned `policy::verify` and prints the prover's holder count as "t-of-n"; the H-3 fix covered only wasm/JS. | fixed (CLI says "claims" unless pinned; holders not presented as pinned) |
| R-9 | MEDIUM | `webhooks.rs:67-82` | The worker awaits up to 200 deliveries of 10 s each per pass; a test key can point endpoints at blackholes and delay live-mode deliveries. | mitigated (live deliveries sent first; a pass still waits up to 10 s) |
| R-10 | LOW-MED | `lib.rs:368-374`, creating POSTs | Idempotency stores and replays 409/422 "retry later" errors for 24 h; `create_endpoint`, `resend_event` and four other creating POSTs ignore `Idempotency-Key`. | open |
| R-11 | LOW | chain/deposit | TEX verdict uses only tx1's confirmations (P-1); `published_nullifiers` cache rewritten with smaller `upto` still holds later nullifiers (false "spent", CH-2); batch with challenge skips the public-demo check (CH-3); `created_height` fire-and-forget leaves requests stuck at 409 (CH-4); source-fetch outage becomes a stored 422 (CH-5); refund settlement lacks a freshness check (CH-6). | open |
| R-12 | LOW | clients | Live-key https guard bypassed by `http://localhost:80@evil.example` in Go/Python/JS/Rust; Python `quote(id)` keeps `/`; JS `verifyBatch`/`verifyIncoming` skip the numeric check on `minZatoshis`; web `min=` NaN skips the check. | open |
| R-13 | LOW | misc | CLI says "same spend key (proven)" for link proofs (really "keys one party controls"); tripwire WIF heuristic falsely refuses ~0.075% of random 6.7 KB receipts (~4% of 50-receipt batches); anonymous campaign submits create a rejected-event row each, never pruned; `build_with_params` and `Proof::add_to_batch` public and unpinned/unpatched; secrets not zeroized (`Session`, `PreparedReceipt` alphas, seed copies); nullifier cache has a predictable tmp name and unkeyed digest (local writer); `.dockerignore` and release workflow hygiene; stale `SPEC.md:642` "about 60 lines". | open |
| R-14 | LOW (tests) | tests | `verify_refuses_expect_address_on_a_proof_of_income` uses an address that fails parsing first and passes without the fix; `check_vk` and trailing-byte tests cover one path each; the new circuit pins and `check-vendor-patch.sh` run in no CI (`vendor/orchard` is not a workspace member, the sibling pin is `#[ignore]`). | open |

Leads not proven: single-server trust for height/finality/delegation expiry (`second = None` in the
server claims endpoint), sign-in and keyset CPU cost (`spends x keys` scalar mults before the receipt
is checked), `sign_prepared` signs `ock`s a hardware signer cannot display.


## Status of the lows (local commit)

Fixed: R-12 (live-key https guard now exact in Rust, JS, Python, Go with a Go test; Python `quote(safe="")`;
JS `verifyBatch`/`verifyIncoming` numeric check; web `min=` not a number is no request), R-13 (link-proof
wording, tripwire WIF now requires a valid Base58Check checksum), R-14 (circuit pins, vendor-patch check and
vendored claim tests run in CI job `circuits`; a stale attestation test fixed). Open: idempotency replay of
retryable errors and missing keys on some POSTs (R-10), the chain-trust lows (R-11), secrets zeroization,
nullifier-cache file hardening, `.dockerignore`/release workflow hygiene, `build_with_params`/`add_to_batch`
visibility.

Second batch of lows (same local branch): idempotency now covers webhook-endpoint creation and never replays
"not yet" errors (R-10); nullifier cache never shrinks its line and uses an unpredictable temp name, private
files are opened with O_NOFOLLOW, `.dockerignore` extended (R-11/R-13); batch + challenge refuses the public demo
key and a source-fetch outage is a retryable 502 (R-11); `Session` secrets and `PreparedReceipt` randomizers are
wiped on drop (best effort); `build_with_params` renamed `build_with_unchecked_params` with a warning (R-13).
Still open: TEX second-hop confirmations and `created_height` retry (R-11), refund freshness, release workflow
action pinning/permissions, base image digest pinning.

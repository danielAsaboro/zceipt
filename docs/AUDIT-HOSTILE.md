# Hostile audit of zecathon-receipts

Audited 2026-10-26 at `d845ac5` (branch main). Nothing pushed or committed; no tracked file
changed, this report is the only addition (build output went to the ignored `target/`).
Method: read the code, not the comments; diffed the vendored Orchard against crates.io 0.16.0;
re-ran the project's own tests; wrote and ran proofs of concept on the real testnet proofs in
`examples/testnet/proofs`. Testnet only.

What I ran:

| Run | Result |
|---|---|
| `cargo test --release -p zceipt-core --features "orchard-ext extensions"` | all pass (47 roundtrip tests in 90 s, FROST, parameter-derivation, properties) |
| `scripts/test-vendored-orchard.sh` (claim circuit witness-mutation test) | passes in 37 s; needs the network and re-resolves dependencies (see M-2) |
| `python3 -m unittest discover -s spec-verifier/tests` | 30 pass; 278 conformance vectors and 232 corpus cases agree |
| PoC: trailing bytes on real testnet claim and payer-tag proofs | accepted (H-2) |
| PoC: `zceipt verify` on a real list claim with a wrong challenge, address and memo | `VALID`, exit 0 (H-1) |
| PoC: certificate signed "under" the identity key | passes `Certificate::check()` (M-1) |
| `cargo mutants` on the Fiat-Shamir and delegation verifiers | 54 mutants, 6 missed (last section) |

Not done: libFuzzer (nothing new to fuzz that the project's seven targets don't cover; see gaps),
a machine proof of the BLAKE2b gadget, anything on mainnet.

---

## EXECUTIVE SUMMARY

This is auditable, unusually so. The cryptographic core is small, the claims are written down with
the test that backs each one, and the authors keep finding their own bugs (the zero-value-note
anchor skip, the claim/payer-tag domain collision, identity session keys). I tried to break the
forked claim circuit, the sibling circuit and its ported BLAKE2b gadget, every Fiat-Shamir
transcript, the canonical decoders and the verification dispatch. **I found no soundness break:
no CRITICAL.** The fresh-proof spend authority, the verifier-fixed `cv_net` that forces the anchor
check, `rho = nf` on the throwaway output, the floor of at least 1, the two domain
personalizations and the one `nk` cell feeding both `CommitIvk` and the tag all hold up when traced
through the circuit. I read every gate the BLAKE2b gadget uses and found nothing under-constrained.

The weak points are at the seams, not in the mathematics. First, `zceipt verify` picks its code
path by substring, and the path it picks silently drops flags it doesn't implement: a valid list
claim, proof of income or sibling proof passes `--expect-address` (list claims and sibling proofs
also `--challenge` and `--memo-contains`) and verifies with exit code 0 (H-1, reproduced). Second, Halo 2 proofs accept trailing bytes,
so "one receipt has one encoding" is false for every artifact whose proof bytes are not under a
signature (H-2, reproduced). Third, the policy and key-set proofs return a threshold and a key
set that the prover chose, and the browser verifier prints them as a verified fact (H-3). Around
those: no pinned verifying key or circuit fingerprint for the two new circuits, a vendored patch
file that no longer reproduces the vendored tree, a runtime-trusted parameter blob, a verify API
that accepts any `VerifyingKey` including the insecure pre-NU6.2 one, and a second verifier that
covers none of the claim, payer-tag or sibling formats.

Risk: low for protocol soundness as far as a human read can establish, medium for anyone
integrating it through the CLI, wasm or web page without reading `docs/`. I would trust the
receipt core for the claims in `CLAIM.md` items 1 to 3 and 12. I would not trust the claim and
sibling circuits with anything valuable until someone outside the project reviews them and the
verifying keys are pinned; the authors say the same ("not covered", KNOWN-EXPLOITS). Nothing here
needs a redesign. Most fixes are a day each.

---

## CRITICAL

None found. What I tried and why each failed:

| Attack | Why it fails |
|---|---|
| Claim a payment I only observed (receipt, claim, tag, income, reserve) | Every proof needs `ak`, `nk`, `rivk` of the spent note's address plus the note opening; observers and previous senders know none. A zero-value note skips the anchor but its nullifier must still equal the on-chain one, which needs a preimage of the nullifier derivation. |
| Zero-value note to skip the anchor | Every place that matters fixes `cv_net` on the verifier side from a floor of at least 1 (`lib.rs:698`, `lib.rs:710-713`, `screened.rs:88-90`, `claim.rs:209`, `income.rs:207`). `floor == 0` fails at decode and again when the instance is built. |
| Second tag for one key | `nk` is a single assigned cell used by `CommitIvk`, nullifier derivation and the tag hash (`circuit.rs:605`, `claim.rs:82-88`). A second tag needs a `CommitIvk` collision. |
| Claim vs payer-tag confusion | Domain hashed under different personalizations chosen by the verifier's entry point (`claim.rs:97-104`, `claim.rs:340-351`); a claim presented as a tag fails in the circuit, not in a check I could bypass. |
| Non-canonical tag, anchor, `rk`, `cmx`, nullifier | `from_repr` / `from_bytes` reject values at or above the modulus (`claim.rs:204-210`). |
| Identity `rk` | `Instance::from_parts` rejects it (`circuit.rs:1259`); `income::verify` re-checks (`income.rs:260`). |
| Forge a policy / key-set / link / delegation proof without the discrete log | Schnorr / CDS transcripts hash the digest, every key, every commitment and the context (checked line by line); no missing public input. |
| Break the sibling statement | Needs BLAKE2b preimages or a gadget bug; none found. |

---

## HIGH

### H-1 `zceipt verify` routes by substring and silently ignores flags (reproduced)

Locations: `crates/zceipt-cli/src/main.rs:1854-2245` (the `Cmd::Verify` arms),
`main.rs:899-911` (`count_receipts`), `main.rs:1231-1276` (`check_verify_flags`).

`run()` picks a verification arm with `read_arg_text(&receipt)?.contains(PREFIX)`, in this order:
income (1857), delegated (1962), designated (1984), siblings (2009), claim (2031), reserve
(2129/2132), incoming (2166/2178), generic receipt (2245). Each arm destructures only the flags it
implements and drops the rest without a word. The reserve arm bails on `--expect-address`
(2129); the others don't:

| Arm | Silently ignored |
|---|---|
| income (1857) | `--expect-address`, `--memo-contains`, `--screened-*`, `--cross-check`; `--min` is reused as the income total |
| list claim (2036-2064) | `--expect-address`, `--challenge`, `--memo-contains` |
| payer tag (2066-2085) | `--expect-address`, `--challenge` |
| siblings (2009) | everything |

`count_receipts` (899) counts six prefixes and not `zip311a1`, `d1`, `w1`, `p1`, `m1`, `s1`, `k1`,
so an input holding a receipt and a delegated receipt is routed by arm order, not by what the user
asked for.

PoC (real testnet list claim, nothing to do with this address or challenge):

```
$ zceipt verify @examples/testnet/proofs/listclaim.txt --list examples/testnet/proofs/list.txt \
    --domain list-airdrop --min 0.00000001 --expect-address "$(cat examples/testnet/merchant.ua)" \
    --challenge deadbeef --memo-contains "Invoice 42"
VALID list claim ...
exit=0
```

The income arm behaves the same against the live testnet (`zceipt verify
@examples/testnet/proofs/income.txt --expect-address "$(cat examples/testnet/merchant.ua)"
--memo-contains "Invoice 42"` prints `VALID proof of income`; neither flag is consulted).

Exploit: a script that gates on `zceipt verify "$input" --expect-address "$ME" --min 5
--challenge "$C"` (exit code, or `--json` `"valid": true`) accepts any valid income proof, list
claim or sibling proof the payer chooses to send. The API server is not affected (`verify.rs:133`
accepts three kinds and refuses mixtures).

Fix: tokenise the input once; require exactly one top-level artifact; give each kind an explicit
allowed-flag set and fail on any other flag that was set (the reserve arm at 2129 is the pattern).
Default deny.

### H-2 Halo 2 proofs accept trailing bytes, so unsigned proof blobs have many valid encodings (reproduced)

Locations: stock `Proof::verify` in `vendor/orchard/src/circuit.rs` (unchanged),
`vendor/orchard/src/circuit/claim.rs:152-159`, `crates/zceipt-kce/src/lib.rs:368-390`.

`plonk::verify_proof` reads what it needs from the transcript and never checks the reader is
empty. On the real testnet proofs, `claim::__check_proof_only_for_tests` returned `Ok(())` after
appending four bytes to the claim's proof and one byte to a payer tag's proof.

End to end on the shipped CLI: `examples/testnet/batch-same-payer.txt` is a real aggregated batch
(9,536-byte aggregate proof). Appending `de ad be ef` to that proof and fixing its length field
gives a different text that `zceipt verify` prints as `VALID batch 34e5eb3407cee395 ... one
aggregated proof, 9540 bytes`, with the same three payments and total.

Where it matters: the proof bytes are not under a signature in the aggregate proof of a `zip311b1`
version-2 batch, in `zip311w1` sibling proofs and in `zip311s1` screened proofs. Anyone can append
bytes and obtain a second, valid, different text for the same statement; hash-keyed dedup,
caching and "this exact artifact" references break. In signed artifacts only the signer can pad
(up to the 64 KiB cap), which contradicts `encoding.rs:19-24` ("a receipt has exactly one
encoding") and CRYPTO-REVIEW invariant 2 in letter, not in security. The project's byte-flip
sweeps (`testnet_adversarial.rs:98-121`) never append, so they cannot see it.

Fix: after `verify_proof`, require the reader is exhausted (verify from a cursor and check its
position). Do it in the vendored `Proof::verify`, in `ClaimKeys::verify` and in `kce`'s two
`verify` functions. Add an "append one byte" case to the sweeps.

### H-3 Policy and key-set results are prover assertions, shown as verified (documented, but the surfaces overstate)

Locations: `policy.rs:166-187`, `keyset.rs:179-209`, `crates/zceipt-wasm/src/lib.rs:550-555`,
`web/app.js:331`, `packages/zceipt/index.js:144`.

`policy::verify` checks only that `rk = C_0 + [alpha]G` for an `alpha` the prover knows.
`C_1..C_{t-1}`, `t` and `holders` appear only in the transcript. A single-key payer can publish
`(ak, X, Y)` with `holders = 5` and get `Ok((3, 5))`; the repo's own test proves it
(`tests/frost.rs:159-166`, `faked`). The core function returns that pair as if it were a result,
the wasm function returns `{threshold, holders, key}`, and the web page prints "A 3-of-5 key:
authorized under the shared key ..." with no caveat (the key-set line next to it, `app.js:330`,
does carry one). The JS `verifyReceipt` has a `keySet` pin option and no policy pin option.
`--policy-commitment` pins the commitment but never `holders` (KNOWN-EXPLOITS, "left as known
limits").

Fix: make the expected commitment (and `holders`) a required argument of `policy::verify` and
return nothing the caller didn't pin; in the wasm, JS and web surfaces drop the "t-of-n" wording
unless a pin was given and say "unpinned" otherwise; add a policy pin option to the JS API.

---

## MEDIUM

### M-1 Delegation: policy is a separate call, covers only disclosed outputs, and has no issuance bound

- `verify_delegated_tx_bundles` (`lib.rs:1220-1241`) returns `Ok` without applying the policy; the
  caller must call `delegated::check_policy` (`delegated.rs:335-344`) with a block height it
  trusts. The in-repo callers do (`chain.rs:727`, `wasm lib.rs:344`); a third-party Rust caller
  that reads "verify" as complete accepts an expired or over-limit certificate.
- `check_policy` sums and checks only the outputs the delegate chose to disclose. A payment with a
  hidden 1000 ZEC output and a disclosed 3 ZEC output satisfies `max_zats = 5`. The module doc says
  "the most a receipt may show", which is accurate, but the CLI line says "at most N ZEC"
  (`main.rs:1977`).
- The certificate has `until_height` and no `from_height` or issuance time. A delegate holding the
  viewing key can attest any past payment of the wallet up to `until_height`, including ones made
  before the delegation, indefinitely. No revocation.
- The mined height comes from the chain server (CLI) or the page (wasm); a lying server defeats
  `until_height`.
- `Certificate::check` (`delegated.rs:125-130`) accepts `rk_c` equal to the identity: reddsa
  accepts the identity key, so a signature `(R = sG, s)` verifies for any message. PoC: a
  certificate with `max_zats = u64::MAX`, no payees, `rk = [0;32]` and such a signature returns
  `Ok(())`. It does not give a forged delegated receipt (the links then need the discrete log of
  each spend's `rk`), but the Python verifier rejects it and Rust accepts it, and the certificate
  alone looks authentic.
- `check_policy` and `batch` totals use unchecked `u64` sums (`delegated.rs:336`,
  `verify.rs:455`); bounded by consensus on a real chain, a panic in debug builds elsewhere.

Fix: fold the policy into one `verify_delegated(...)` that takes the height and refuses without
it; add `not_before` and a certificate id; reject identity `rk_c` in `Certificate::check`; use
`checked_add`.

### M-2 The two new circuits are not pinned, and the vendor patch no longer reproduces the vendor tree

- No verifying-key digest or circuit fingerprint exists for the claim circuit (both modes) or the
  sibling circuit. Upstream Orchard ships `circuit/fingerprint` for the stock circuit; nothing
  equivalent covers `claim.rs` or `kce`. A constraint change anywhere in the dependency graph
  silently produces a different verifying key, two verifiers can diverge, and reviewers cannot
  pin what they reviewed.
- `vendor/orchard-0.16.0-zceipt.patch` is stale. Applying it to pristine 0.16.0 gives a
  `claim.rs` of 154 lines; the vendored file has 293 (the `__empty_for_tests` helper and the
  whole witness-mutation test were added in `91b5442` and `40db91e` and the patch was not
  regenerated). Circuit code is identical; `vendor/README.md`'s "diff -ru ... shows exactly the
  patch above" is false for that file.
- `scripts/test-vendored-orchard.sh` is the only way to run the claim soundness test. It copies the
  tree out of the workspace, needs the network, and cargo re-resolves dependencies instead of
  honoring the lockfile ("Updating winnow ...", "Adding addchain ..."), so the evidence floats.

Fix: a test that hashes `vk.transcript_repr()` for claim (public / private) and sibling against a
constant; a CI step that applies the patch to a pristine crate and diffs against `vendor/orchard`;
make the claim test runnable inside the workspace with the lockfile.

### M-3 The k = 11 commitment parameters are trusted at runtime

`lib.rs:1407-1412` loads `orchard-params-k11.bin` with `include_bytes!` and falls back to
derivation only on a read error. The match with a fresh derivation is checked by one unit test
(`params_match_derivation`, which passes). The k = 17 sibling parameters, by contrast, are
digest-checked on every load (`kce lib.rs:324-332`). Trapdoored generators would let a forger
prove false statements for every receipt. Add the same `PARAMS_DIGEST` check at load.

### M-4 Verify entry points accept any `VerifyingKey`, including the insecure circuit

`verify`, `verify_tx_bundles*`, `verify_aggregate`, `income::verify`, `reserve::verify_reserve`,
`screened::verify` and the address-proof verifiers take a caller-built `VerifyingKey`. Orchard
exposes `InsecurePreNu6_2` ("the variable-base scalar-multiplication base is not anchored").
`RECEIPT_CIRCUIT` is forced everywhere the library builds keys, but nothing refuses a key of
another version. Assert `vk.circuit_version() == RECEIPT_CIRCUIT` in every entry point.

### M-5 Docs and comments that understate or overstate

- `Cargo.toml:40-42`: "~60-line patch ... No circuit change." The patch is 331 lines and adds a
  circuit. `docs/CRYPTO-REVIEW.md:48`: "one local patch that only loads precomputed parameters."
  `vendor/README.md` describes the fork correctly apart from the points below; these two are
  stale and would mislead a reviewer.
- `vendor/README.md` lists `DiversifiedTransmissionKey::from_bytes` as made public; the patch makes
  `EphemeralSecretKey::from_bytes` public (`keys.rs` hunk) and leaves the other alone.
- `docs/SPEC.md:406`: "One claim per wallet." The tag depends on `nk`, which differs per ZIP 32
  account, so it is one claim per account key. `claim.rs:18` states it correctly.
- `docs/KNOWN-EXPLOITS.md:32`: "all nonces, randomizers and codes come from the OS generator." The
  CLI uses `rand::random` for a batch id and a payment-request code (`main.rs:1689`,
  `main.rs:2593`), which is a userspace CSPRNG; fine, but not what the sentence says.

### M-6 The second verifier covers less than the first, and differs where it overlaps

`spec-verifier` has no claim, payer-tag or sibling decoder, and the conformance directory holds a
single positive vector each for policy, key set, delegated, designated, and none for claims, tags,
siblings, income, link or screened. Where both exist (found by reading):

- Python `verify_policy` decodes only `C_0`; a proof with off-curve or identity `C_1..C_{t-1}` is
  accepted. Rust rejects it (`policy.rs:171-175`).
- Python `verify_keyset` rejects identity keys and has no cap on the key count; Rust accepts identity
  keys and caps at 1024 (`keyset.rs:33`, `101`).
- Python rejects `rk_c = identity` in a delegation certificate; Rust accepts it (M-1).
- Python `verify_income` has no proof-length cap; Rust caps at 1 MiB (`income.rs:42`).

Two verifiers that disagree on edge cases are worse than one for a contest claim of independence.

### M-7 `verify_aggregated` in the wasm skips the batch completeness check

`wasm lib.rs:264-281` verifies each receipt and the aggregate proof but never calls `check_batch`
(positions, one id, no output disclosed twice). The JS wrapper calls `open_batch` first
(`index.js:265`), the server calls `check_batch` (`verify.rs:415`), but the exported wasm function is
public. Call it inside.

### M-8 Claim endpoints do CPU-bound work on the async workers, and two of three paths take no permit

`crates/zceipt-server/src/lib.rs:503-573`. The list-claim branch (516-535) rebuilds a Sinsemilla
Merkle tree from the caller's list (`set_root`, up to 1 MiB of body, about 15,000 leaves, tens of
thousands of hashes) and verifies a Halo 2 proof inline in the async handler: no
`spawn_blocking`, no `verify_slots` permit. The payer-tag branch (536-553) is the same. The chain
claim branch takes a permit (565) but still verifies inline. Receipts use both
(`verify.rs:250-251`). The first claim of each mode also builds a proving key (seconds) inside
`get_or_init` (`claim.rs:61-65`). At the default 300 requests a minute per key, and with a test key
printed at startup, one caller can keep every tokio worker busy and stall health checks and every
other request. Authenticated, so MEDIUM. Fix: `spawn_blocking` plus the permit on all three
branches, and build the claim keys in `warm_up`.

---

## LOW / INFO

- `unconstrained.rs:353` checks public rows `0..11`. The claim circuit has 12 (`INSTANCE_ROWS = 10`
  plus domain and tag, `claim.rs:34-36`); row 11, the tag, is never asserted by the detector, and
  the comment omits the cross-address row. The tag is constrained (`claim.rs:89`) and the mutation
  test refuses a changed tag, so this is a hole in the evidence, not in the circuit.
- The FROST negative test (`tests/frost.rs:122-123`) passes on any panic, not on a specific refusal.
- `PaymentRequest::from_bytes` accepts an upper-case hex `code` (`valid_fields`); `sign_request`
  lowercases. The challenge comparison only matches lower case, so such a request can never be
  answered; harmless.
- `ffi describe_prepared` shows only counts of outputs and spends, not recipients or amounts
  (they sit behind `ock`s); a signer UI built on it cannot show what it is authorizing.
- Poseidon(`nk`, `domain`) is now an unmasked PRF on verifier-chosen input; Orchard's nullifier
  PRF only exposes it blinded by `psi`. No attack known; it is a stronger use of the assumption.
- `Receipt::from_text` and the other `from_text` functions `trim()` the text, so a receipt has more
  than one text form (whitespace). Binary is canonical.
- The generic verify arm prints the policy and key-set lines only in non-JSON mode
  (`main.rs:2329-2338`); `--json` drops them, so a script cannot tell a policy was checked.
- Hidden `__*_for_tests` functions are `pub` in release builds (documented).

---

## CIRCUIT AUDIT DEEP DIVE

### Fork surface

`diff -ru` of `vendor/orchard/src` against crates.io 0.16.0 shows: three accessors made public
(`address.rs`, `keys.rs`, `note.rs`), `VerifyingKey::build_with_params` / `params_bytes`, one new
module `circuit/claim.rs`, and three hunks in `circuit.rs`: (1) `Circuit::synthesize` now calls a
new `synthesize_inner(.., expose_nf)`; (2) `nk_out = nk.clone()` taken from the same assigned cell
that feeds `CommitIvk` and `DeriveNullifier`; (3) `constrain_instance(nf_old, NF_OLD)` made
conditional (`circuit.rs:694`). Nothing else changed. The stock Action circuit and its key are
unchanged.

### `claim.rs`, constraint by constraint

| Constraint | Source | Verdict |
|---|---|---|
| Note in tree at `anchor`, enforced iff `v_old != 0` | stock Merkle gate | Sound because the verifier fixes `cv_net = [floor]V`, `floor >= 1` |
| `cv_net = [v_old - v_new]V + [rcv]R`, 64-bit magnitude and sign | stock | With public `cv_net = [floor]V` and independent `V`, `R`: `rcv = 0` and `v_old - v_new = floor` as integers, so `v_old >= floor` |
| `rk = ak + [alpha]G` | stock | Sound; sign of `ak` is not constrained but `CommitIvk` uses only its x, and the signer holds `±ask` |
| Address from `ivk = CommitIvk(ak, nk, rivk)` | stock, `circuit.rs:731-739` | One `nk` cell for ivk (moved into `commit_ivk`), nullifier (`nk.clone()`) and tag (`nk_out`, `:605`) |
| Nullifier derived, `rho_new = nf_old` | stock, `circuit.rs:820` | Still derived and still in the new note's commitment, so in hidden mode the nullifier is private but determined by public `cmx` |
| `nf_old` public iff `expose_nf` | patch | Two verifying keys; instance row 3 zeroed by the verifier (`claim.rs:110-112`) and unconstrained by design |
| `domain` witnessed, equal to instance row 10 | `claim.rs:85-86` | Bound; `domain_field` is verifier-computed |
| `tag = Poseidon(nk, domain)` equal to instance row 11 | `claim.rs:87-89` | `ConstantLength<2>`, `P128Pow5T3`, same chip as the nullifier PRF |
| Cross-address check | `claim.rs:83` | Called; flag fixed to `ENABLED` by the verifier |
| Circuit version | `claim.rs:49-51` | `new` refuses anything but `PostNu6_3` |

Instance layout: rows 0-9 are the stock ten (anchor, cv x, cv y, nf, rk x, rk y, cmx, enable
spend, enable output, disable cross address), row 10 domain, row 11 tag; 12 rows in both modes.
The verifier builds every row (`claim.rs:106-116`); the claimant supplies none. Completeness:
honest provers succeed (real testnet claims verify). I found no unconstrained value and no missing
equality; the project's own detector and the 21-way witness mutation test (re-run, passes) agree.

### BLAKE2b gadget (`zceipt-kce/src/blake2b_halo2`)

Read in full against RFC 7693 and the ZIP 32 derivation.

| Piece | Check |
|---|---|
| Initial state | `IV0 ^ 0x01010000 ^ (keylen << 8) ^ outlen` (`blake2b_chip.rs:104`); words 6, 7 xor the little-endian personalization halves (`:733-738`), assigned as constants |
| Rounds | 12 rounds, `SIGMA` rows 10 and 11 equal rows 0 and 1, `ABCD` column then diagonal order, `G` with rotations 32, 24, 16, 63 |
| Counter and final flag | `t` is a build-time constant (`utils.rs:31-44`); `v12 = t ^ IV4`, `v13 = IV5`, `v14` negated only in the last block (`:229-241`) |
| Add mod 2^64 | `r - x - y + carry * 2^64 = 0`, carry boolean, result range-checked by `q_range` and decomposed: unique for 64-bit operands |
| XOR | per-limb 3-column lookup into the 2^16-row table; operand rows decomposed, result row decomposed |
| Rotation 32, 24, 16 | result limbs are copy-constrained to the input limbs in rotated columns, `q_decompose` on the result row |
| Rotation 63 | `(2x - r)(2x - r - (2^64-1)) = 0` with `r` range-checked: exactly one solution; field larger than 2^65 asserted at configure |
| Negate | `(2^64-1) - v - not_v = 0` on a range-checked input |
| Message words | 128 padded bytes: real bytes copy-constrained and range-checked, padding cells `constrain_equal` to the zero constant (`utils.rs:101-120`) |
| Row-reuse optimization | "previous row" assumptions hold at all call sites in `mix` and the final xor |
| Output | 64 bytes; the circuit takes `[..32]` for `sk` and all 64 for `nk` |

Unverified: that no combination of the shared columns lets a lookup row alias another region's
cells. `Pow5Chip` and the blake2b chip share `advice[1..4]` (`kce lib.rs:101-104`); their selectors
are disjoint and the layouter keeps regions apart, so I found no interaction. The authors say the
gadget is unaudited and the port is too (`vendor/README.md`); I agree that is the right label.
`unconstrained.rs` parses `Debug` output with regular expressions and can only flag cells no gate
mentions; it cannot see a gate that mentions a cell without pinning it. Treat "0 unconstrained
cells" as necessary, not sufficient.

### Sibling circuit

Statement: public `(domain, tag1, tag2)`; private `(sk_par, c_par, i1, i2)`;
`sk_j = BLAKE2b-512("Zcash_ExpandSeed", c_par || 0x81 || sk_par || i_j)[..32]`,
`nk_j = ToBase(BLAKE2b-512("Zcash_ExpandSeed", sk_j || 0x07))`, `tag_j = Poseidon(nk_j, domain)`.
`ToBase` accumulates 64 constrained bytes most-significant first (`lib.rs:107-118`, `200-221`),
which is the reduction mod p. The indices are free witnesses, so the proof does not say the
accounts are hardened; it does not need to, because the tags are bound to real keys by BLAKE2b
preimage resistance. `verify` requires `tag1 != tag2` (`lib.rs:311`), which also forces distinct
indices. Matches orchard's own derivation (`against_orchard` test). Witness region rows do not
overlap. Parameters are digest-checked.

---

## ADVERSARIAL CASES TRACED

| # | Case | Result |
|---|---|---|
| 1 | Claim by observer | Rejected by the Action proof (`conformance proof-only/claimed-by-observer`). Residual: in a multi-party transaction the receipt shows "someone who knew an input key and the `ock`". |
| 2 | Edited receipt | Signature over the full canonical encoding plus re-encode check (`encoding.rs:316`, `lib.rs:1313`). |
| 3 | Replayed challenge | Bound in `msg`; enforced by the generic CLI arm and the API (`requests.rs:364`); **not enforced** by the list-claim and payer-tag CLI arms (H-1). |
| 4 | Link reorder | Digests are compared pairwise in order (`link.rs:202-206`) and the challenge hashes `rk`s in order; reordering fails. |
| 5 | Cross-domain link | Coin type compared (`link.rs:199`); mainnet 133 vs testnet 1. Regtest shares testnet's coin type by design. |
| 6 | FROST single share | The verifier only checks a SpendAuthSig; one share cannot produce one. The repo's negative test is a `catch_unwind`. |
| 7 | Policy for wrong receipt | Digest in the head of the transcript (`policy.rs:168`). |
| 8 | Delegation expired or out of scope | Refused only if the caller invokes `check_policy` (M-1). |
| 9 | Forked circuit bypass | Witness mutation test passes; see deep dive. |
| 10 | Source proof for a fake tx | Lookup returns `None`, receipt refused (`lib.rs:1332`, `chain.rs` `fetch_sources`). |
| 11 | Income floor 0 or above note value | Floor 0 fails decode and instance build; floor above value makes the hidden output negative, refused by the range check. |
| 12 | Sibling false positive | Needs a BLAKE2b break or gadget bug; none found. |
| 13 | Canonicality bypass | No bypass in signed artifacts; proof tails in unsigned ones (H-2). |
| 14 | Version confusion | Decoder re-encodes and compares; v2 without address proof, v4 without source, v5 without opened output all rejected (`encoding.rs:310-327`, Python `receipt.py:170-175`). |

---

## ENCODING AND CANONICALITY VERDICT

| Format | Verdict | Specifics |
|---|---|---|
| `zip311r1` v1-v5 | Pass | Strict reader, flags 0/1 (v4/v5: 0-3), version fixed by contents, re-encode equality. The signer can pad proofs to 64 KiB (H-2). |
| `zip311u1` | Pass | Scalars canonical. |
| `zip311b1` v1 | Pass | Size 1-256, per-receipt canonical, one form (proofs all present or all absent). |
| `zip311b1` v2 | **Fail** | Aggregate proof bytes unsigned, tail accepted (H-2). |
| `zip311k1` | Pass | `nr` 1-64, scalars canonical, identity `R` refused. |
| `zip311p1` | Pass (encoding) | Semantics are prover-chosen (H-3). |
| `zip311m1` | Pass | Scalars canonical; semantics as H-3. |
| `zip311i1` | Pass | Floor > 0, items 1-256, proof 1 MiB cap; signature covers proof. |
| `zip311t1` | Pass | Tag, anchor, `rk`, `cmx`, nullifier canonical; floor > 0; proof tail possible but tag is the dedup key. |
| `zip311a1`, `zip311g1` | Pass | Fixed layout, zero signatures required. |
| `zip311d1` | Pass | |
| `zip311s1` | **Fail** | Proof unsigned, tail accepted. |
| `zip311w1` | **Fail** | Proof unsigned, tail accepted. |
| `zsig1`, `zreq1`, `zrcin1`, `zrsv1` | Pass | `zreq1` allows an upper-case `code` (LOW). |
| coin type | Pass | In every digest personalization and compared on every verify path. |

---

## SPEC-VERIFIER PARITY

Present in Python: receipts v1-v5, batches (v1, v2), link, policy, key set, designated, delegated,
income, screened, reserve, sign-in, incoming, request. **Absent: claims, payer tags, siblings.**

Rust accepts, Python rejects: an identity key in a key set; an identity `rk_c` in a certificate.
Python accepts, Rust rejects: policy proofs with invalid or identity `C_1..C_{t-1}`; key sets over
1024 keys; income proofs with proofs over 1 MiB.
Python's delegated verifier returns the certificate's policy for the caller to check (as Rust's
core does, M-1) and does not itself reject an over-limit or expired one.

---

## TEST COVERAGE GAPS

- No conformance vector for claims, payer tags, siblings, income, link, screened or reserve; one
  positive vector each for policy, key set, delegated, designated, none negative.
- No "append a byte" case anywhere; the sweeps only flip (H-2).
- Fuzz targets: decoders and one soundness target (`mutate_proofs`). No target for the verifiers
  on structurally valid inputs (policy, key set, delegated, link with random points), and no
  Rust-versus-Python differential target.
- Mutation testing in ASSURANCE.md covers `lib.rs`, `encoding.rs`, `signin.rs` only; none of
  `link`, `policy`, `keyset`, `delegated`, `designated`, `income`, `claim`. My run on the first
  four is in the MUTATION RUN section at the end of this file.
- No test pins a verifying key for the claim or sibling circuits (M-2).
- No test that the CLI refuses a flag its chosen arm ignores (H-1).
- No test that `verify_*` refuses a `VerifyingKey` of another circuit version (M-4).
- The unconstrained-cell detector's coverage test stops at row 10 (LOW).
- `scripts/test-vendored-orchard.sh` is not hermetic.

---

## TOP 3 FIXES

1. **H-1**: make `zceipt verify` fail closed. One artifact, one allowed-flag set, error on any
   flag the chosen path doesn't implement. It is the only finding that turns a valid-but-irrelevant
   artifact into an accepted payment check.
2. **M-2 plus H-2**: pin the circuits and make proofs canonical. VK digests for claim (both
   modes) and sibling, regenerate and CI-check the vendor patch, runtime digest for the k = 11
   parameters, reject trailing bytes in every `verify`. This is what lets an outside reviewer say
   "I reviewed exactly this" and what makes "one encoding" true.
3. **H-3 plus M-1**: make unforgeable what the API returns. Policy and key-set verification take
   the pin as an argument; delegated verification takes the height and applies the policy; none
   of the web or wasm surfaces print a threshold, key set or limit the verifier did not pin.

---

## FINAL VERDICT

Not yet "undisputed winner" material, but close, and the gap is not where a cryptographer would
look first. A sharp reviewer will read the circuit diff, the claim circuit and the gadget, find
them tight, and then run `zceipt verify` with a flag the arm ignores, or notice that
`vendor/README.md`, `Cargo.toml` and `CRYPTO-REVIEW.md` each describe the fork differently from the
tree, or point at the "3-of-5 key" line the page prints on the prover's say-so. Those are an hour
or a day each. The remaining risk is the one the authors name themselves: the claim and sibling
circuits and the ported gadget have never been looked at by anyone outside the project, and a
human read, including mine, is not a proof. Fix the three items above, pin the keys, commit the
regenerated patch, and the submission's weakest points become its documented ones.

---

## MUTATION RUN (zceipt-core tests only: `roundtrip` filtered to same_payer, key_set, designated, delegated, plus `frost`)

54 mutants of `link::verify`, the `link`/`policy`/`keyset` challenges, `policy::verify`,
`keyset::verify`, `check_policy`, `check_authorization`, `Certificate::check`, `check_proofs`:
27 caught, 21 unviable, **6 missed**.

| Missed mutant | What no core test checks |
|---|---|
| `delegated.rs:126` `Certificate::check` -> `Ok(())` | A certificate with a bad spend-key signature (a delegate raising its own limits and re-signing with its session key) |
| `delegated.rs:255` `||` -> `&&` (two operators) | Receipt/link count mismatch, empty spends, coin-type mismatch are not tested one by one |
| `delegated.rs:337` `>` -> `>=` (two operators) | The exact boundary of `max_zats` and `until_height` |
| `designated.rs:134` `||` -> `&&` | Proof count mismatch / empty spends in a designated receipt |

Scope caveat: only `zceipt-core`'s tests were run against each mutant. The CLI crate's
`testnet_adversarial.rs` (delegation cases) may kill some of these. A partial earlier run was
stopped when too slow; this one ran to completion.

---

## FIX STATUS (working tree, uncommitted; all workspace tests pass in release mode)

| Finding | Status |
|---|---|
| H-1 | Fixed. `check_verify_flags` refuses any flag the chosen artifact kind ignores; list-claim honors `--challenge`; payer tags refuse it; `count_receipts` counts `a1`, `d1`, `w1`. Tests `verify_refuses_*` in `crates/zceipt-cli/tests/cli.rs`. |
| H-2 | Fixed in the vendored `Proof::verify`, `ClaimKeys::verify` and both `kce` verifiers (trailing bytes refused). Re-ran the padded aggregated batch: refused; original still `VALID`. Test `a_proof_with_trailing_bytes_is_refused`. |
| H-3 | Fixed. `policy::verify_pinned`, wasm `verify_policy_pinned`, JS `options.policy`; unpinned results are named `claimed_*` with `pinned: false`; the web page says the split is the prover's claim. `holders` is now pinnable. |
| M-1 | Identity `rk_c` refused; `check_policy` uses checked sums; boundary tests added. **Not changed:** the certificate still has no `not_before` or revocation (a wire-format change), and the policy still covers only disclosed outputs; both are documented limits. |
| M-2 | Claim (both modes) and sibling verifying keys pinned by fingerprint tests (the sibling one is `#[ignore]`, run after any circuit change); patch regenerated and `scripts/check-vendor-patch.sh` proves it reproduces `vendor/orchard/src`. The vendored test script still needs the network. |
| M-3 | The shipped k=11 blob is used only if its BLAKE2b-256 matches the pinned digest. |
| M-4 | `check_vk` in `verify_cross`, `verify_aggregate`, address proofs, income, reserve, screened (`Error::WrongCircuit`). Test added. |
| M-5 | Fixed: `Cargo.toml`, `CRYPTO-REVIEW.md`, `SPEC.md`, `KNOWN-EXPLOITS.md`, `vendor/README.md`. |
| M-6 | Python: all `C_j` validated, key-set cap 1024 and identity keys allowed, income proof cap 1 MiB. **Not done:** Python decoders for claims, payer tags, siblings, and more conformance vectors. |
| M-7 | `verify_aggregated` calls `check_batch`. |
| M-8 | List and payer-tag claim checks take a verify slot; Halo 2 checks run in `spawn_blocking` (also the chain-claim path). |
| LOW | Detector range now `0..12`. **Not changed:** FROST negative test, `describe_prepared`, unchecked sums over chain-bounded values, text `trim()`. The web build (`web/zceipt`) and wasm `pkg` need `scripts/build-web.sh` to pick up the JS/wasm changes. |
| Mutation misses | Cert identity and `max_zats` / `until_height` boundaries now tested; the `check_authorization` and `check_proofs` condition mutants are still untested individually. |

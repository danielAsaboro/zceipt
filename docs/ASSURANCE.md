# Assurance: evidence that doesn't come from us

`CLAIM.md` states what a receipt proves. This page lists the checks whose verdict is not ours:
the chain, published test vectors, a second implementation, mutation testing, fuzzing, Miri, and
a byte-for-byte record of what the chain server receives. Each entry says how to re-run it.
All of it ran on 2026-10-15 on Zcash testnet; nothing here touches mainnet.

## 1. The chain accepts every disclosed transaction

Every example receipt is for a transaction mined on the public testnet, fetched by `txid` from
`testnet.zec.rocks` and verified (`docs/evidence/testnet-verify.txt`):

| Receipt | Transaction | Height | Opens to |
|---|---|---|---|
| `receipt.txt` | `571de6e4…` | 4,500,997 | 0.01 TAZ, "Invoice 42: two coffees" |
| `receipt-with-sender-address.txt` (re-made after the fix) | `db7c3c5e…` | 4,501,025 | 0.005 TAZ, sender address proven |
| `receipt-with-refund-address.txt` | `de9ef067…` | 4,502,724 | 0.003 TAZ |
| `refund-receipt.txt` | `deede14f…` | 4,502,726 | 0.001 TAZ |
| `deposit-receipt.txt` (ZIP 320) | `cfb97544…` | 4,502,928 | spend authority only |
| `batch.txt` (3 payments) | `571de6e4…`, `db7c3c5e…`, `08caa945…` | | each proven |
| `pre-fix/receipt-with-sender-address.txt` | `db7c3c5e…` | | **refused**: made before the address-proof fix |

```bash
receipts verify @examples/testnet/receipt.txt
```

## 2. A second implementation agrees

`spec-verifier` (Python, standard library, written from `protocol.tex`, ZIP 229/244 and
`SPEC.md`) re-derives every primitive and checks everything except the Halo 2 proofs:

- against the Zcash test vectors: map-to-curve 13/13, group hash 11/11, Sinsemilla 11/11, empty
  roots 33/33, Merkle paths, generators, note commitments 10/10, OVK recovery 10/10, ZIP 244 txids
  10/10; ChaCha20-Poly1305 against RFC 8439;
- on the real testnet transactions: it recomputes each v6 txid from the raw bytes (so the server
  that served them need not be trusted) and opens every disclosed Ironwood output;
- against the Rust verifier: 270/270 shared conformance vectors, and 232/232 signed adversarial
  receipts (each altered receipt re-signed by the spender, so only the check under test can
  catch it). The 9 that the Rust verifier rejects only on a Halo 2 proof get exactly the public
  inputs the Rust verifier used.

```bash
python3 -m unittest discover -s spec-verifier/tests
```

## 3. Mutation testing

`cargo mutants` changed the core's code 178 ways (`lib.rs`, `encoding.rs`, `signin.rs`) and ran
the core's tests against each. The first run: 126 caught, 32 unviable (don't compile), **20
missed**. Every missed mutant was a missing test, not dead code:

| Missed | What was untested | Test added |
|---|---|---|
| address proof `rho` fixed to a constant (2) | two address proofs for one address must not be linkable | `rt::address_proof_roundtrip_and_rejections` (distinct `rho`, `nf`, `cmx`, `rk`) |
| `address_proof_anchor` (3) | the anchor equals a one-leaf tree root computed independently | same |
| proof-length cap, batch size bounds (7) | exact boundaries: 65,536-byte proofs decode, 65,537 don't; batches of 1 and 256 decode, 0 and 257 don't | `tests/encoding_ub.rs::length_limits_are_exact` |
| `check_batch` position and id checks (2) | position 0, positions above `n`, mixed ids | `::batch_positions_are_checked` |
| sign-in digest, sign-in proof cap (4) | the public digest is the signed one; the cap is exact | `::sign_in_digest_and_limits` |
| `display_txid` (2) | explorer byte order | `::txids_display_as_explorers_show_them` |

Looking at the length fields also showed that `create` would encode a message over 65,535 bytes
or more than 255 outputs with a wrapped length; it now refuses (`Error::TooLarge`), with tests at
the exact limits. A clean full run afterwards (189 mutants, since the new checks add some):
**157 caught, 32 unviable, 0 missed, 0 timeouts**. (An intermediate re-run that let parallel jobs
share one build directory gave unreliable results and is not counted.)

```bash
cargo mutants -p receipts-core -f crates/receipts-core/src/lib.rs -f crates/receipts-core/src/encoding.rs -f crates/receipts-core/src/signin.rs
```

Source proofs (format v4, 2026-10-16): 67 mutants of the new code (`source_*`, `output_cmx`,
`verify_cross`, the v4 encoder and decoder). First run: 49 caught, 12 unviable, **6 missed**:
`source_proof_cmx` was only exercised by the differential corpus (now the verifier itself goes
through it, so every source test covers it); the source proof's length cap had no exact-limit
test (added to `tests/encoding_ub.rs::length_limits_are_exact`); and `|` → `^` on the v4 flags
byte, an equivalent mutant (the two bits are disjoint). Re-run of the affected functions: 30
mutants, 29 caught, 1 unviable, 0 missed.

## 4. Fuzzing

`cargo fuzz` (libFuzzer, AddressSanitizer) on every decoder for 15 minutes each, seeded with the
real receipts. Besides "never panics", each target asserts that whatever decodes re-encodes to the
same bytes, so the signed encoding is unique:

| Target | Executions | Result |
|---|---|---|
| `decode_receipt` (bytes) | 11,359,725 | no crash, no non-canonical decode |
| `decode_batch` | 8,761,198 | same |
| `decode_sign_in` | 12,374,327 | same |
| `decode_text` (`zrcpt1`, `zrcptb1`, `zsig1`) | 10,092,364 | same |

```bash
cd crates/receipts-core && cargo +nightly fuzz run decode_receipt -- -max_total_time=900
```

Source proofs (2026-10-16): the receipt decoder, seeded also with the four real v4 receipts
(testnet and regtest source proofs), ran 12.7 million inputs in 10 minutes with no crash and no
re-encoding mismatch.

## 5. Miri

The decoders, encoders, batch checks and RedPallas signature verification run under Miri
(`tests/encoding_ub.rs`) with no undefined behaviour reported. Halo 2 proving and verifying are
too slow for Miri and are not covered; the receipts crates contain no `unsafe` code.

```bash
cargo +nightly miri test -p receipts-core --test encoding_ub
```

## 6. What the chain server sees

`scripts/wire/wire.py` sits between the CLI and `testnet.zec.rocks:443`: the CLI speaks plaintext
HTTP/2 to `127.0.0.1`, the recorder speaks TLS to the server, and every byte is kept and decoded
(HTTP/2 frames, HPACK headers, gRPC messages). A packet capture of the TLS link would show only
the sizes and timing below; this shows the content too. Decoded records are in
`docs/evidence/wire-*.json`.

| Action | Requests the server received | Bytes sent |
|---|---|---|
| `receipts verify @examples/testnet/receipt.txt` | one `GetTransaction` whose only field is the 32-byte txid | 254 |
| `receipts create --from-chain` (before) | `GetTreeState(4,500,983)`, `GetBlockRange(4,500,984 → 4,500,997)`: the block the spent note was created in | 320 |
| `receipts create --from-chain` (now) | `GetTreeState(4,499,999)`, `GetBlockRange(4,500,000 → 4,500,997)`: only the 1,000-block window | 320 |

So verification reveals which transaction is being checked (the page's `h=` hint narrows that to
a block), and nothing from the receipt: no message, key, amount or address. The second row was a
real leak, found by this recording: rebuilding a pruned witness told the server where the
sender's spent note was created. It now asks from the start of the 1,000-block window instead
(about 0.5 MB more to download).

```bash
python3 scripts/wire/wire.py proxy 19067 testnet.zec.rocks:443 /tmp/wire &
receipts verify @examples/testnet/receipt.txt --server 127.0.0.1:19067
python3 scripts/wire/wire.py decode /tmp/wire
```

## 7. A fresh clone works

`git clone` of this branch into an empty directory, with a new target directory:

- `python3 -m unittest discover -s spec-verifier/tests`: 14 tests pass, including the zcash-test-vectors
  (copied into the repo) and all real testnet receipts offline;
- `cargo install --locked --path crates/receipts-cli` built in 1 min 47 s (crates already in the
  local cargo cache), then `receipts verify @examples/testnet/receipt.txt` and the sender-address
  receipt verify against testnet, offline verification prints that mining was not checked, and
  `receipts demo --no-wait` runs the whole tour (exit 0).

The full workspace suite (`cargo test --workspace`) passes; so does the npm verifier on the 270
conformance vectors (`node --test packages/zcash-receipts/test/conformance.test.js`).

## What this found

| Finding | Found by | Fixed in |
|---|---|---|
| Sender-address proofs and Sign in with Zcash were forgeable (zero-value witness skips the anchor check; the verifier took `cv` from the prover) | reading ZIP 304's rationale against the Action circuit's `v_old · (root − anchor)` gate | `CLAIM.md`; `rt::claiming_someone_elses_sender_address_is_refused` |
| Offline verification displayed the supplied height as the mined block | the precise claim (a receipt doesn't prove mining) | `chain_checked`, page note |
| Witness rebuild revealed the spent note's block to the server | the wire recording | `witness_window_start` |
| `create` could encode a too-long message or too many outputs with a wrapped length | mutation testing (length fields) | `Error::TooLarge` |
| Length limits, batch positions, address-proof anchor and unlinkability had no direct tests | mutation testing | `tests/encoding_ub.rs`, `rt::address_proof_roundtrip_and_rejections` |
| §4.20.3 of the protocol spec can't open Ironwood outputs as written | writing the spec verifier | `SPEC-AMBIGUITIES.md` A9 |
| Our `SPEC.md` omitted the address-proof layout and limits | writing the spec verifier | `SPEC.md` |

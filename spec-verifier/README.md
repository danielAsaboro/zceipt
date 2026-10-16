# spec-verifier: a second, independent receipt verifier

A ZIP 311 receipt verifier for Orchard and Ironwood written in Python from the specifications,
sharing no code or libraries with the Rust verifier: standard library only, every primitive
reimplemented from `protocol.tex` (Pallas, hash-to-curve, Sinsemilla, NoteCommit, MerkleCRH,
RedPallas, ChaCha20-Poly1305, note recovery with an `ock`) and the v5/v6 transaction format and
txid from ZIP 244 and ZIP 229. The receipt format comes from `docs/SPEC.md`.

```bash
python3 -m unittest discover -s spec-verifier/tests      # about 15 s
cd spec-verifier && python3 -m specverify ../examples/testnet/receipt.txt ../examples/testnet/tx.hex
```

## What it checks

Everything a receipt claims except the Halo 2 proofs: it parses the raw transaction and
recomputes its txid; decodes the receipt strictly; checks indices, the network, every
spend-authorization signature, every disclosed output (all of §4.20.3, with the NU6.3 `rcm` for
Ironwood), every address proof's note, one-leaf anchor and fixed value commitment, and every
source proof's anchor (rebuilt from the source transaction's output), fixed value commitment and
opened output (format v4; the caller supplies the source transactions and checks their heights). For each
proof it reports the exact public inputs the proof must verify against. It does not reimplement
the Halo 2 verifier for the Orchard circuit; a receipt it accepts is "valid if the proofs verify
against these public inputs".

## Why it is evidence

| Check | Result |
|---|---|
| Primitives against zcash-test-vectors (the protocol designers' own Python reference, independent of librustzcash) | map-to-curve 13/13, group hash 11/11, Sinsemilla 11/11, empty roots 33/33, Merkle paths, generators, note commitments 10/10, note recovery 10/10, ZIP 244 txids 10/10 |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 |
| v6 txid and Ironwood note recovery | the real testnet transaction `571de6e4…` recomputes, and its output opens to 0.01 TAZ, "Invoice 42: two coffees" |
| Real testnet source-of-funds receipts (`examples/testnet/source`) | both decode as v4, name `2a2bd721…` action 0, the revealed one shows 0.125 TAZ; refused without the source transaction |
| Shared conformance vectors (`conformance/vectors.json`) | 251/251 agree with the Rust verifier |
| Signed adversarial corpus (`tests/corpus.json`, from the Rust test `differential_corpus`) | 232/232 agree; the 9 the Rust verifier rejects only on a Halo 2 proof get identical public inputs here |

The zcash-test-vectors files used are copied unmodified into `tests/zcash-test-vectors` (MIT; see
`SOURCE` there for the commit). Regenerate the corpus with
`DIFF_CORPUS=spec-verifier/tests/corpus.json cargo test -p receipts-core --test roundtrip differential_corpus`.

Independence is in the sources, language and code paths, not the authorship: it was written by
the same team (an AI agent) that wrote the Rust verifier, working from `protocol.tex`, the ZIPs
and `docs/SPEC.md`. Writing it found a gap in our own `SPEC.md` (A14), an inconsistency in the protocol
specification (A9) and a case ZIP 229 leaves unstated (A13); see `docs/SPEC-AMBIGUITIES.md`.

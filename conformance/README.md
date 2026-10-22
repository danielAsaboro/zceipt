# Conformance vectors

`vectors.json` holds 270 cases (230 receipts, 19 incoming receipts, 21 sign-ins; 12 of them
valid) built from real receipts (an Orchard payment, an Ironwood payment and a cross-pool
Orchard-to-Ironwood payment on regtest, source-of-funds receipts, and Ironwood payments on
testnet), a real testnet incoming receipt and a real testnet "Sign in with Zcash". Each case says what any correct verifier must answer:

- valid receipts, with the amounts and memos they must open to;
- the same receipts with one character changed in 24 places (header, message, outputs, proof,
  signature), truncated, extended, mis-prefixed, or checked against the wrong transaction;
- a valid sign-in, and the same sign-in for another domain, another nonce, or altered.

Every valid receipt also carries `known_answers`, computed by the independent spec verifier
(`spec-verifier/`, written from the protocol specification): the signing digest, each spend's
proof public inputs (anchor, `cv_net`, nullifier, `rk`, `cmx`, flags) and each opened output's
raw recipient and value, so a new implementation can compare intermediate values, not only the
final yes or no. The Rust test checks the digest and `cv_net` against them.

Both verifiers in this repository run every vector: the Rust one
(`cargo test -p receipts-cli --test conformance`) and the WebAssembly/npm one
(`node --test packages/zcash-receipts/test/conformance.test.js`). A third-party verifier is
conformant when it agrees with `expect.valid` on all of them. Everything is offline: each
receipt vector carries its raw transaction and height.

The Rust run also includes a small fuzz pass: 20,000 random and mutated inputs through every
decoder (`zip311r1`, `zip311b1`, `zsig1`), which must reject without panicking.

Regenerate with `python3 scripts/gen-conformance.py` after changing an example.

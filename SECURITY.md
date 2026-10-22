# Security

The disclosure construction (a fresh Orchard action proof plus a spend-authorization signature,
[docs/ZIP311-ORCHARD.md](docs/ZIP311-ORCHARD.md)) has been reviewed only by its author so far
([docs/CRYPTO-REVIEW.md](docs/CRYPTO-REVIEW.md)); that review found and fixed one forgery in the
address proofs, and the forged artifacts are kept as must-fail vectors. Treat it as unaudited.

Please report a vulnerability privately (GitHub's "Report a vulnerability" on this repository) rather
than in a public issue: what is affected, how to reproduce it, and its impact. A forgery (a
receipt any verifier here accepts for a payment the presenter's key did not authorize) or a
leak of anything a receipt is meant to withhold is in scope for all of `receipts-core`,
`receipts-chain`, the CLI, the server, the browser verifier and the SDKs.

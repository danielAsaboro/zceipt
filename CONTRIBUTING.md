# Contributing

- **Run the checks** before sending a change: `cargo test --workspace --release`,
  `cargo clippy --workspace --release -- -D warnings`, `./scripts/check-stock-orchard.sh`,
  `python3 -m unittest discover -s spec-verifier/tests`, and `node --test test/*.test.js` in
  `packages/zceipt`. `./scripts/e2e-regtest.sh` replays the whole flow on a private chain.
- **Changing zceipt-core** (encoding, creation or verification): update
  [docs/ZIP311-ORCHARD.md](docs/ZIP311-ORCHARD.md) or [docs/SPEC.md](docs/SPEC.md), the Python
  spec verifier if the rule is one it checks, and regenerate `conformance/vectors.json`
  (`python3 scripts/gen-conformance.py`) and the browser build (`./scripts/build-web.sh`).
- **A new verification rule** comes with a must-fail test or vector that the old code accepts.
- **Privacy:** never log, store or echo a receipt's contents, a key or a mnemonic; anything sent
  to a chain server is listed in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- Licence: contributions are under MIT OR Apache-2.0, like the rest of the repository.

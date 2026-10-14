# SDKs

| | install / path | client | webhook helper |
|---|---|---|---|
| TypeScript / JS | `packages/zcash-receipts` (`zcash-receipts/client`) | `new Receipts(key, { baseUrl })` | `webhooks.constructEvent` |
| Python 3.9+ | `packages/receipts-python` (stdlib only) | `Receipts(key, base_url=…)` | `construct_event` |
| Rust | `crates/receipts-client` | `Client::new(key).base_url(…)` | `webhooks::construct_event` |
| Browser (no server) | `zcash-receipts` | `verifyReceipt(link, opts)` (WASM) | n/a |
| Any page | `<zcash-receipt receipt="…">` | web component | n/a |
| Rust, in-process | `crates/receipts-core` | `receipts_core::verify` | n/a |

All three API clients share the same design:
- typed errors that carry `code` and `param`;
- an automatic `Idempotency-Key` on every POST;
- retries on network errors, 429 and 5xx;
- cursor pagination (`each()` in JS and Python).

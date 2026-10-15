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

## Server integrations

- Node: `zcash-receipts/middleware` (Express and fetch-style servers: Next.js, Hono, Bun, Deno).
- Python: `zcash_receipts.web` (FastAPI, Django, Flask).

Both give an HTTP 402 receipt gate and a signed-webhook handler; see the
[HTTP 402 guide](guides/http-402.md).

## CLI for payers

`receipts pay '<the shop's pay link>' -w <wallet> -i <key.age>` shows what it will pay, asks,
pays from a zcash-devtool wallet, waits for the block and hands the receipt back.

## Go

`packages/receipts-go` (standard library only): `receipts.New(key)`, one method per operation
(`CreateRequest`, `Verify`, `CreateRefund`, …), typed `*receipts.Error`, and
`receipts.ConstructEvent` for webhooks. See its README.

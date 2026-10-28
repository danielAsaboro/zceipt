# Privacy audit (2026-10-28)

Question asked: what does each path tell a server, a log or a third party that the user didn't
choose to disclose? Method: every page of the built site and the live zceipt.xyz loaded in
headless Chrome with all requests recorded (landing, docs incl. search and the ask box, verifier
with each sample, the browser receipt maker); server, SDK and CLI code read for logs, URLs,
stored columns and error text; the tree and full git history searched for keys, seeds, age
identities and mainnet addresses.

## Fixed

| # | Where | Leak | Fix |
|---|---|---|---|
| P-1 | `site-src/index.html`, `stage.js` | The landing loaded Three.js from cdn.jsdelivr.net: every visitor's IP and visit time went to a third party. | Three.js 0.170.0 (npm tarball) served from `/vendor/three/`. |
| P-2 | `scripts/build-site.sh` | No site-wide policy stopped a later edit (or the Mintlify export) from loading a script, font or image off-site. | `content-security-policy` on every path: scripts, styles, fonts, images and workers from the site only. |
| P-3 | `crates/zceipt-server/src/requests.rs` | A campaign's public tally refreshed after any new contribution, so two reads around one contribution gave its amount (to 0.001 ZEC) and tied it to its public note. | Once published, the tally moves only in steps of at least k contributions. Test `campaign_tally_moves_in_steps_of_k`. |
| P-4 | npm, Python, Go and Rust SDKs | `public.getRequest` put the hosted page's client secret in the URL (`?secret=`), where proxies and access logs keep it. | Sent as the `Zceipt-Client-Secret` header, as the hosted page and CLI already did. Live tests pass in all four. |

## Checked, no leak

- Verifier and maker with a block hint (`&h=`): the chain server sees the aligned run of 4 blocks and
  every shielded transaction in the payment's window, in random order; never the txid alone. Without
  a hint, and for source-of-funds and TEX second-step fetches, the page says the server saw those ids.
- Docs (Mintlify export): no request leaves zceipt.xyz on load, on search or from the ask box.
- Server: no access log, no client IP read or stored; secrets pasted by mistake are refused, never
  echoed or stored; rejection events keep only the error.
- Repo and history: no seed, age identity or real mainnet address. Public on purpose: the testnet
  demo wallet's key (`examples/testnet/demo`) and the testnet merchant receiver re-encoded as a
  mainnet address for a "wrong network" vector.

## Inherent, documented

A light client tells its lightwalletd the block ranges it scans (the maker: birthday to the
payment's 1,000-block window, and each spent note's window), and its IP. Use your own lightwalletd
(Settings on the verifier, `--server` on the CLI) or Tor to avoid that.

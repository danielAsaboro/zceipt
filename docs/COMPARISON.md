# Zceipt next to viewing-key payment processors

Zcash payment processors detect payments by holding a viewing key for the merchant's wallet or
account. That works, and it is the only option ZIP 311's absence left them. Zceipt takes the
other route ZIP 311 describes: the payer proves one payment, and nobody holds a standing key.
The two are complementary; a processor could accept receipts too.

Sources are each project's own repository and docs, read on 2026-10-15. Points marked
*inferred* come from reading the code where the docs are silent.

## Side by side

| | CipherPay | BTCPay Server, Zcash plugin | ZGo | **Zceipt** |
|---|---|---|---|---|
| What the shop's system holds | The merchant submits a UFVK; the server keeps the Orchard incoming viewing key, encrypted at rest ([README][cp-readme], [`merchants/mod.rs`][cp-merchants]) | The merchant's UFVK, in the wallet daemon's config ([plugin][btcpay], [zcash-walletd][walletd]) | A Sapling FVK or UFVK in the service's database ([backend][zgo]) | **Nothing.** The shop gets one receipt per payment |
| What that reveals, for as long as it's held | Amount and memo of every incoming Orchard payment to the account ([ZIP 316][zip316]) | Incoming notes, and when they are spent; a UFVK can also recover outgoing details ([ZIP 316][zip316]; *inferred* for walletd) | Incoming amounts and memos; outgoing with a FVK (*inferred*) | Only the outputs the payer disclosed in that one transaction, plus proof the payer authorized it ([threat model](THREAT-MODEL.md)) |
| Where it lives | cipherpay.app (hosted) or self-hosted | The merchant's BTCPay server; one wallet shared by every store on it | zgo.cash (hosted; code is open) | The shop verifies in the browser, or on its own server |
| Matching payment to order | A diversified Orchard address per invoice; memo codes as a legacy fallback | A diversified address per invoice | Memo `ZGo Order::<id>` plus exact amount | The receipt signs the order's challenge; one payment settles one request |
| Customer can prove a payment in a dispute | No (the processor's records are the evidence) | No | No | **Yes:** the receipt, verifiable by anyone, offline if needed |
| Refunds | The merchant marks an invoice refunded and may record a txid; funds sent by hand ([`invoice_routes.rs`][cp-invoice]) | No ZEC payout handler in the plugin (*inferred*) | None found | To an address the payer signed into the receipt; the shop's own receipt proves the refund ([guide](guides/refunds.md)) |
| Pools | Orchard in current code (README also says Sapling) | Sapling, Orchard, unified addresses | Sapling, Orchard via UFVK | Orchard, Ironwood, and Orchard-to-Ironwood ([spec](SPEC.md)) |

## What a viewing key gives away

ZIP 316 describes an incoming viewing key as giving access "only to view incoming payments", and a
full viewing key "all transactions to and from the address" ([ZIP 316][zip316]). ZIP 310 adds
that decrypting with it reveals memo contents ([ZIP 310][zip310]). The key covers every
diversified address of the account and stays valid until the wallet is abandoned: a database
leak at a processor exposes the payment history of every merchant it serves, past and future.

A receipt is scoped the other way round: one transaction, the outputs the payer chose, nothing
about the payer's address or balance, and it can't be turned into a key for anything else.

## Where viewing keys still fit

A merchant who wants automatic detection of every incoming payment, with no action from the
customer, needs something that watches the chain; that is what these processors do well, and the
CipherPay design limits exposure by keeping only an incoming key and recommending a dedicated
store wallet ([SPEC][cp-spec]). Zceipt needs the payer's wallet to make the receipt (or
`zceipt pay` to do it in one step). The two combine: detect with a dedicated store wallet, and
use receipts wherever proof has to leave that system (disputes, refunds, audits, exchanges,
donors), so no viewing key ever has to.

[cp-readme]: https://github.com/atmospherelabs-dev/cipherpay-api/blob/main/README.md
[cp-merchants]: https://github.com/atmospherelabs-dev/cipherpay-api/blob/main/src/merchants/mod.rs
[cp-invoice]: https://github.com/atmospherelabs-dev/cipherpay-api/blob/main/src/api/invoice_routes.rs
[cp-spec]: https://github.com/atmospherelabs-dev/cipherpay-api/blob/main/SPEC.md
[btcpay]: https://github.com/btcpay-zcash/btcpayserver-zcash-plugin
[walletd]: https://github.com/hhanh00/zcash-walletd
[zgo]: https://code.vergara.tech/Vergara_Tech/zgo-backend
[zip316]: https://zips.z.cash/zip-0316
[zip310]: https://zips.z.cash/zip-0310

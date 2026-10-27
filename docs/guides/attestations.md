# Attestations: prove a business fact, not the payment

A receipt shows everything about one payment: the transaction, the exact amount, the memo. An
accountant, an auditor or a grant committee usually needs much less: "at least 1 ZEC was paid
for invoice 42 by the end of the quarter". An attestation states exactly that and nothing else.

Try it in the sandbox: create a request and pay it with a fixture, then attest.

```bash
ID=$(curl -s localhost:8723/v1/requests -H "authorization: Bearer $ZCEIPT_KEY" \
  -d '{"payee":"utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa","amount_zatoshis":1000000}' | jq -r .id)
curl -s localhost:8723/v1/requests/$ID/receipts -H "authorization: Bearer $ZCEIPT_KEY" -d '{"receipt":"zip311_test_valid"}' >/dev/null
curl -s -X POST localhost:8723/v1/requests/$ID/attestations \
  -H "authorization: Bearer $ZCEIPT_KEY" -d '{"at_least_zatoshis":500000,"before":"2026-12-31"}'
```

The response has a `presentation` to hand over. It is an SD-JWT (the IETF selective-disclosure
JWT format), signed with Ed25519 by your Zceipt server, stating only:

| claim | example |
|---|---|
| `paid_at_least_zatoshis` | a floor you choose, never more than was paid (`attestation_overclaims` otherwise); by default what was paid rounded down to 0.01 ZEC, so the exact amount stays hidden |
| `paid_on_or_before` | a day you choose, never earlier than the payment's day |
| `network`, `final` | testnet or mainnet, and whether the payment has 10 confirmations |
| `livemode`, `sandbox` | whether a live key issued it, and whether it was paid with a sandbox fixture rather than a real transaction |
| `net_of_refunds` | always true: refunds already paid back are subtracted before the floor is checked |

The transaction id, the exact amount, the exact time, the request id and the label are in the
token only as salted hashes. The response's `disclosures` is an object with one string per hidden
claim (`disclosures.label`, `disclosures.txid`, …); append
any of them (`presentation + disclosure + "~"`) to reveal that claim alone, now or later, and the
signature still checks. Nothing can be revealed that wasn't signed.

Verify without an account, in a browser or Node:

```js
import { verifyAttestation } from "zceipt";
// Name the server you trust: anyone can sign a token and host keys of their own.
const facts = await verifyAttestation(presentation, { issuer: "https://zceipt.example" });
facts.paid_at_least_zatoshis, facts.paid_on_or_before, facts.revealed.label
```

or with the API (`POST /v1/attestations/verify`). The public keys are at `/.well-known/jwks.json`.

An attestation is the server's word about a receipt it verified, so trust it as much as you trust
that server. For a claim nobody has to trust, share the receipt itself.

The token always carries eight hidden-claim digests (real ones plus decoys), so it doesn't reveal
which claims exist. A request whose payment a reorg dropped can't be attested
(`payment_unconfirmed`) until it is mined again.

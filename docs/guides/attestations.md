# Attestations: prove a business fact, not the payment

A receipt shows everything about one payment: the transaction, the exact amount, the memo. An
accountant, an auditor or a grant committee usually needs much less: "at least 1 ZEC was paid
for invoice 42 by the end of the quarter". An attestation states exactly that and nothing else.

```bash
curl -s -X POST localhost:8723/v1/requests/$ID/attestations \
  -H "authorization: Bearer $RECEIPTS_API_KEY" -d '{"at_least_zatoshis":100000000,"before":"2026-12-31"}'
```

The response has a `presentation` to hand over. It is an SD-JWT (the IETF selective-disclosure
JWT format), signed with Ed25519 by your Receipts server, stating only:

| claim | example |
|---|---|
| `paid_at_least_zatoshis` | a floor you choose, never more than was paid (`attestation_overclaims` otherwise) |
| `paid_on_or_before` | a day you choose, never earlier than the payment's day |
| `network`, `final` | testnet or mainnet, and whether the payment has 10 confirmations |
| `net_of_refunds` | always true: refunds already paid back are subtracted before the floor is checked |

The transaction id, the exact amount, the exact time, the request id and the label are in the
token only as salted hashes. The response's `disclosures` holds one string per hidden claim; append
any of them (`presentation + disclosure + "~"`) to reveal that claim alone, now or later, and the
signature still checks. Nothing can be revealed that wasn't signed.

Verify without an account, in a browser or Node:

```js
import { verifyAttestation } from "zcash-receipts";
const facts = await verifyAttestation(presentation); // fetches <iss>/.well-known/jwks.json
facts.paid_at_least_zatoshis, facts.paid_on_or_before, facts.revealed.label
```

or with the API (`POST /v1/attestations/verify`). The public keys are at `/.well-known/jwks.json`.

An attestation is the server's word about a receipt it verified, so trust it as much as you trust
that server. For a claim nobody has to trust, share the receipt itself.

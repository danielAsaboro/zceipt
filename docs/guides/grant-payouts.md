# Recipe: prove a whole payout round with one link

```bash
receipts create -w treasury -i key.age --txid <a> --txid <b> --txid <c> -m "Grant round 3"
```

The batch link verifies every payment and fails if any one is dropped, added or reordered.
The verifier page and `POST /v1/verify` both show totals per recipient. The treasury's
address and balance stay private.

# zcash-receipts (Python)

Client for the Receipts API. Standard library only, Python 3.9+.

```python
from zcash_receipts import Receipts, VerificationError, construct_event

receipts = Receipts("rcpt_test_…", base_url="http://127.0.0.1:8723")
req = receipts.requests.create(payee="utest1…", amount_zatoshis=1_000_000, label="Order #42",
                               metadata={"order_id": "42"})
print(req["payment_uri"])   # zcash:utest1…?amount=0.01&memo=…
print(req["receipt_link"])  # give this to the payer: receipts create … --request '<link>'

done = receipts.requests.submit_receipt(req["id"], receipt=receipt_text)  # or VerificationError

# In your webhook handler (raw body!):
event = construct_event(request.body, request.headers["Receipts-Signature"], WHSEC)
if event["type"] == "request.fulfilled":
    mark_paid(event["data"]["object"]["metadata"]["order_id"])
```

Errors are typed (`AuthenticationError`, `InvalidRequestError`, `VerificationError`, `ApiError`,
`ConnectionError`) and carry `.code`, `.param` and `.status`. Retries and idempotency keys are
automatic.

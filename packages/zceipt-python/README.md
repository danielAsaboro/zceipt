# zceipt (Python)

Client for the Zceipt API. Standard library only, Python 3.9+.

```bash
python3 -m venv .venv && .venv/bin/pip install ./packages/zceipt-python
```

```python
from zceipt import Zceipt, VerificationError, construct_event

receipts = Zceipt("rcpt_test_…", base_url="http://127.0.0.1:8723")
req = receipts.requests.create(payee="utest1…", amount_zatoshis=1_000_000, label="Order #42",
                               metadata={"order_id": "42"})
print(req["payment_uri"])   # zcash:utest1…?amount=0.01&memo=…
print(req["receipt_link"])  # give this to the payer: zceipt create … --request '<link>'

done = receipts.requests.submit_receipt(req["id"], receipt=receipt_text)  # or VerificationError

# In your webhook handler (raw body!):
event = construct_event(request.body, request.headers["Zceipt-Signature"], WHSEC)
if event["type"] == "request.fulfilled":
    mark_paid(event["data"]["object"]["metadata"]["order_id"])
```

Errors are typed (`AuthenticationError`, `InvalidRequestError`, `VerificationError`, `ApiError`,
`ConnectionError`) and carry `.code`, `.param` and `.status`. Retries and idempotency keys are
automatic.

## Web frameworks

`zceipt.web.check_gate(...)` puts any FastAPI, Django or Flask route behind
"prove you paid" (HTTP 402), and `handle_webhook(...)` verifies and dispatches webhooks.
See [docs/guides/http-402.md](../../docs/guides/http-402.md).

## Tests

`ZCEIPT_URL=http://127.0.0.1:8723 ZCEIPT_KEY=rcpt_test_… ` then run the test command. Without them, the API tests are skipped and only the offline tests run.

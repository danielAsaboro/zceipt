# Go SDK for Receipts

Standard library only. Covers all 31 API operations (checked by `scripts/sdk-parity.py`, and
`go test` calls every one against a running server when `RECEIPTS_URL` and a test `RECEIPTS_KEY`
are set).

```go
c := receipts.New(os.Getenv("RECEIPTS_KEY"))
req, err := c.CreateRequest(ctx, receipts.M{"payee": shopUA, "amount_zatoshis": 1_000_000})
v, err := c.Verify(ctx, receipts.M{"receipt": "zip311_test_valid"})
var apiErr *receipts.Error
if errors.As(err, &apiErr) && apiErr.Code == "challenge_mismatch" { … }

// Webhooks: verify the signature on the raw body.
ev, err := receipts.ConstructEvent(body, r.Header.Get("Receipts-Signature"), whsec, 5*time.Minute)
```

Tests: `go test ./...` (offline: webhook signatures; with a server: every operation).

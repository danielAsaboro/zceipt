# Go SDK for Zceipt

Standard library only. Covers all 31 API operations (checked by `scripts/sdk-parity.py`, and
`go test` calls every one against a running server when `ZCEIPT_URL` and a test `ZCEIPT_KEY`
are set).

```go
c := zceipt.New(os.Getenv("ZCEIPT_KEY"))
req, err := c.CreateRequest(ctx, zceipt.M{"payee": shopUA, "amount_zatoshis": 1_000_000})
v, err := c.Verify(ctx, zceipt.M{"receipt": "zip311_test_valid"})
var apiErr *zceipt.Error
if errors.As(err, &apiErr) && apiErr.Code == "challenge_mismatch" { … }

// Webhooks: verify the signature on the raw body.
ev, err := zceipt.ConstructEvent(body, r.Header.Get("Zceipt-Signature"), whsec, 5*time.Minute)
```

Tests: `go test ./...` (offline: webhook signatures; with a server: every operation).

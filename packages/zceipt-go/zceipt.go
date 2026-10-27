// Package zceipt is a Go client for the Zceipt API: ZIP 311 payment receipts for Zcash
// (Orchard and Ironwood). Standard library only.
//
//	c := zceipt.New(os.Getenv("ZCEIPT_KEY"))
//	req, _ := c.CreateRequest(ctx, zceipt.M{"payee": shopUA, "amount_zatoshis": 1_000_000})
//	v, err := c.Verify(ctx, zceipt.M{"receipt": "zip311r1…"})
//
// Responses are decoded into map[string]any (type M), mirroring the JSON documented in
// docs/openapi.yaml. Errors are *Error with the API's stable Code.
package zceipt

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// M is a JSON object.
type M = map[string]any

// Client talks to one Zceipt server with one API key.
type Client struct {
	Key        string
	BaseURL    string
	MaxRetries int
	HTTP       *http.Client
}

// New returns a client for key. BaseURL defaults to $ZCEIPT_URL or http://127.0.0.1:8723.
func New(key string) *Client {
	base := os.Getenv("ZCEIPT_URL")
	if base == "" {
		base = "http://127.0.0.1:8723"
	}
	return &Client{Key: key, BaseURL: strings.TrimRight(base, "/"), MaxRetries: 2, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Error is an API error. Branch on Code, never on Message.
type Error struct {
	Status  int
	Type    string
	Code    string
	Message string
	Param   string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

func randomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) do(ctx context.Context, method, path string, body any) (M, error) {
	raw, err := c.raw(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	out := M{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Client) raw(ctx context.Context, method, path string, body any) ([]byte, error) {
	var payload []byte
	idem := ""
	if method == http.MethodPost {
		if body == nil {
			body = M{}
		}
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
		idem = randomKey()
	}
	// sleep waits for d or until ctx is done.
	sleep := func(d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(c.Key, "rcpt_live_") && !strings.HasPrefix(strings.ToLower(c.BaseURL), "https://") && !isLoopbackURL(c.BaseURL) {
			return nil, fmt.Errorf("zceipt: a live API key must be sent over https")
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Key)
		req.Header.Set("User-Agent", "zceipt-go/0.1")
		if idem != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", idem)
		}
		res, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() == nil && attempt < c.MaxRetries {
				if err := sleep(time.Duration(500<<attempt) * time.Millisecond); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return data, nil
		}
		if (res.StatusCode == 429 || res.StatusCode >= 500) && attempt < c.MaxRetries {
			wait := time.Duration(500<<attempt) * time.Millisecond
			if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 && s <= 60 {
				wait = time.Duration(s) * time.Second
			}
			if err := sleep(wait); err != nil {
				return nil, err
			}
			continue
		}
		var e struct {
			Error struct{ Type, Code, Message, Param string } `json:"error"`
		}
		if json.Unmarshal(data, &e) != nil || e.Error.Code == "" {
			// Not the API's error shape (a proxy, say): keep the body as the message.
			msg := strings.TrimSpace(string(data))
			if len(msg) > 300 {
				msg = msg[:300]
			}
			return nil, &Error{Status: res.StatusCode, Type: "api_error", Code: "http_" + strconv.Itoa(res.StatusCode), Message: msg}
		}
		return nil, &Error{Status: res.StatusCode, Type: e.Error.Type, Code: e.Error.Code, Message: e.Error.Message, Param: e.Error.Param}
	}
}

func esc(s string) string { return url.PathEscape(s) }

func query(p M) string {
	if len(p) == 0 {
		return ""
	}
	q := url.Values{}
	for k, v := range p {
		q.Set(k, fmt.Sprint(v))
	}
	return "?" + q.Encode()
}

// Verification
func (c *Client) Verify(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/verify", p)
}
func (c *Client) CheckPaymentLink(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/payment_links/check", p)
}

// Proof requests
func (c *Client) CreateRequest(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/requests", p)
}
func (c *Client) ListRequests(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "GET", "/v1/requests"+query(p), nil)
}
func (c *Client) GetRequest(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "GET", "/v1/requests/"+esc(id), nil)
}
func (c *Client) SubmitReceipt(ctx context.Context, id, receipt string) (M, error) {
	return c.do(ctx, "POST", "/v1/requests/"+esc(id)+"/receipts", M{"receipt": receipt})
}

// ReviewDeposit accepts or rejects a deposit held for review (deposit desks); decision is
// "accept" or "reject".
func (c *Client) ReviewDeposit(ctx context.Context, id, decision, note string) (M, error) {
	b := M{"decision": decision}
	if note != "" {
		b["note"] = note
	}
	return c.do(ctx, "POST", "/v1/requests/"+esc(id)+"/review", b)
}

// RequestQR returns the request's ZIP-321 payment URI as an SVG QR code.
func (c *Client) RequestQR(ctx context.Context, id string) (string, error) {
	b, err := c.raw(ctx, "GET", "/v1/requests/"+esc(id)+"/qr.svg", nil)
	return string(b), err
}

// Hosted pages (no API key needed; a per-request client secret)
func (c *Client) PublicGetRequest(ctx context.Context, id, secret string) (M, error) {
	return c.do(ctx, "GET", "/v1/public/requests/"+esc(id)+"?secret="+url.QueryEscape(secret), nil)
}
func (c *Client) PublicSubmitReceipt(ctx context.Context, id, receipt, clientSecret string) (M, error) {
	return c.do(ctx, "POST", "/v1/public/requests/"+esc(id)+"/receipts", M{"receipt": receipt, "client_secret": clientSecret})
}
func (c *Client) PublicCampaign(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "GET", "/v1/public/campaigns/"+esc(id), nil)
}

// Refunds
func (c *Client) CreateRefund(ctx context.Context, requestID string, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/requests/"+esc(requestID)+"/refunds", p)
}
func (c *Client) GetRefund(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "GET", "/v1/refunds/"+esc(id), nil)
}
func (c *Client) SubmitRefundReceipt(ctx context.Context, id, receipt string) (M, error) {
	return c.do(ctx, "POST", "/v1/refunds/"+esc(id)+"/receipts", M{"receipt": receipt})
}

// Attestations
func (c *Client) CreateAttestation(ctx context.Context, requestID string, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/requests/"+esc(requestID)+"/attestations", p)
}
func (c *Client) VerifyAttestation(ctx context.Context, attestation string) (M, error) {
	return c.do(ctx, "POST", "/v1/attestations/verify", M{"attestation": attestation})
}
func (c *Client) JWKS(ctx context.Context) (M, error) {
	return c.do(ctx, "GET", "/.well-known/jwks.json", nil)
}

// Sign in with Zcash
func (c *Client) CreateSignInChallenge(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/sign_in/challenges", p)
}
func (c *Client) VerifySignIn(ctx context.Context, signIn string) (M, error) {
	return c.do(ctx, "POST", "/v1/sign_in/verify", M{"sign_in": signIn})
}

// Claims and payer tags: p is {"claim", "domain", "height" (claims only)}.
func (c *Client) VerifyClaim(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/claims/verify", p)
}

// Sandbox test clocks
func (c *Client) CreateTestClock(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/test_clocks", p)
}
func (c *Client) GetTestClock(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "GET", "/v1/test_clocks/"+esc(id), nil)
}
func (c *Client) AdvanceTestClock(ctx context.Context, id string, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/test_clocks/"+esc(id)+"/advance", p)
}
func (c *Client) ReorgTestClock(ctx context.Context, id string, depth int) (M, error) {
	return c.do(ctx, "POST", "/v1/test_clocks/"+esc(id)+"/reorg", M{"depth": depth})
}

// Webhooks and events
func (c *Client) CreateWebhookEndpoint(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "POST", "/v1/webhook_endpoints", p)
}
func (c *Client) ListWebhookEndpoints(ctx context.Context) (M, error) {
	return c.do(ctx, "GET", "/v1/webhook_endpoints", nil)
}
func (c *Client) DeleteWebhookEndpoint(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "DELETE", "/v1/webhook_endpoints/"+esc(id), nil)
}
func (c *Client) ListEvents(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "GET", "/v1/events"+query(p), nil)
}
func (c *Client) ResendEvent(ctx context.Context, id string) (M, error) {
	return c.do(ctx, "POST", "/v1/events/"+esc(id)+"/resend", nil)
}
func (c *Client) ListDeliveries(ctx context.Context, p M) (M, error) {
	return c.do(ctx, "GET", "/v1/deliveries"+query(p), nil)
}

// Meta
func (c *Client) Health(ctx context.Context) (M, error) { return c.do(ctx, "GET", "/v1/health", nil) }
func (c *Client) ListErrors(ctx context.Context) (M, error) {
	return c.do(ctx, "GET", "/v1/errors", nil)
}
func (c *Client) SandboxFixtures(ctx context.Context) (M, error) {
	return c.do(ctx, "GET", "/v1/sandbox/fixtures", nil)
}

// Sign computes a Zceipt-Signature header for rawBody at unix time t.
func Sign(rawBody, secret string, t int64) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d.%s", t, rawBody)
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(m.Sum(nil)))
}

// ConstructEvent verifies a webhook's Zceipt-Signature header (within tolerance) and returns
// the event. Use the raw request body, not a re-encoded one.
func ConstructEvent(rawBody []byte, header, secret string, tolerance time.Duration) (M, error) {
	if secret == "" {
		return nil, fmt.Errorf("zceipt: an empty webhook secret verifies nothing")
	}
	var t int64
	var v1 string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			t, _ = strconv.ParseInt(v, 10, 64)
		case "v1":
			v1 = v
		}
	}
	if t == 0 || v1 == "" {
		return nil, fmt.Errorf("missing or malformed Zceipt-Signature header")
	}
	want := Sign(string(rawBody), secret, t)
	if !hmac.Equal([]byte(want[strings.Index(want, "v1=")+3:]), []byte(v1)) {
		return nil, fmt.Errorf("signature mismatch")
	}
	if d := time.Since(time.Unix(t, 0)); d > tolerance || d < -tolerance {
		return nil, fmt.Errorf("signature timestamp outside tolerance")
	}
	ev := M{}
	return ev, json.Unmarshal(rawBody, &ev)
}

// isLoopbackURL reports whether url is plain http to this computer.
func isLoopbackURL(url string) bool {
	u := strings.ToLower(url)
	for _, p := range []string{"http://127.0.0.1", "http://localhost", "http://[::1]"} {
		if strings.HasPrefix(u, p) {
			rest := u[len(p):]
			if i := strings.IndexAny(rest, "/?#"); i >= 0 {
				rest = rest[:i]
			}
			// Nothing, or a numeric port: a "@" or any other text makes it another host.
			if rest == "" {
				return true
			}
			if rest[0] != ':' || len(rest) == 1 {
				return false
			}
			for _, c := range rest[1:] {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}

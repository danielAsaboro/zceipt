package receipts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignatures(t *testing.T) {
	body := []byte(`{"id":"evt_1","type":"request.fulfilled"}`)
	now := time.Now().Unix()
	ev, err := ConstructEvent(body, Sign(string(body), "whsec_x", now), "whsec_x", 5*time.Minute)
	if err != nil || ev["id"] != "evt_1" {
		t.Fatal(err, ev)
	}
	if _, err := ConstructEvent([]byte(`{}`), Sign(string(body), "whsec_x", now), "whsec_x", 5*time.Minute); err == nil {
		t.Fatal("tampered body accepted")
	}
	if _, err := ConstructEvent(body, Sign(string(body), "whsec_x", now-3600), "whsec_x", 5*time.Minute); err == nil {
		t.Fatal("stale signature accepted")
	}
}

const payee = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa"

// Calls every API operation through this SDK and checks the list against conformance/sdk-parity.json.
func TestEveryOperation(t *testing.T) {
	key := os.Getenv("RECEIPTS_KEY")
	if key == "" || os.Getenv("RECEIPTS_URL") == "" {
		t.Skip("needs RECEIPTS_URL and RECEIPTS_KEY")
	}
	c, ctx, done := New(key), context.Background(), map[string]bool{}
	must := func(op string) func(M, error) M {
		return func(v M, err error) M {
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			done[op] = true
			return v
		}
	}
	s := func(v M, k string) string { return v[k].(string) }
	must("health")(c.Health(ctx))
	must("listErrors")(c.ListErrors(ctx))
	must("listSandboxFixtures")(c.SandboxFixtures(ctx))
	must("verify")(c.Verify(ctx, M{"receipt": "zrcpt_test_valid"}))
	must("checkPaymentLink")(c.CheckPaymentLink(ctx, M{"uri": "zcash:" + payee + "?amount=0.01"}))
	clock := must("createTestClock")(c.CreateTestClock(ctx, M{}))
	must("getTestClock")(c.GetTestClock(ctx, s(clock, "id")))
	req := must("createRequest")(c.CreateRequest(ctx, M{"payee": payee, "amount_zatoshis": 1_000_000, "test_clock": s(clock, "id")}))
	id := s(req, "id")
	must("getRequest")(c.GetRequest(ctx, id))
	must("listRequests")(c.ListRequests(ctx, M{"limit": 2}))
	svg, err := c.RequestQR(ctx, id)
	if err != nil || !strings.Contains(svg, "<svg") {
		t.Fatal("qr", err)
	}
	done["requestQr"] = true
	must("publicGetRequest")(c.PublicGetRequest(ctx, id, s(req, "client_secret")))
	must("publicSubmitReceipt")(c.PublicSubmitReceipt(ctx, id, "zrcpt_test_refund_to", s(req, "client_secret")))
	must("advanceTestClock")(c.AdvanceTestClock(ctx, s(clock, "id"), M{"blocks": 9}))
	must("reorgTestClock")(c.ReorgTestClock(ctx, s(clock, "id"), 1))
	rf := must("createRefund")(c.CreateRefund(ctx, id, M{"amount_zatoshis": 1000}))
	must("getRefund")(c.GetRefund(ctx, s(rf, "id")))
	must("submitRefundReceipt")(c.SubmitRefundReceipt(ctx, s(rf, "id"), "zrcpt_test_valid"))
	other, _ := c.CreateRequest(ctx, M{"payee": payee, "amount_zatoshis": 1_000_000})
	must("submitReceipt")(c.SubmitReceipt(ctx, s(other, "id"), "zrcpt_test_valid"))
	att := must("createAttestation")(c.CreateAttestation(ctx, s(other, "id"), M{}))
	must("verifyAttestation")(c.VerifyAttestation(ctx, s(att, "presentation")))
	must("jwks")(c.JWKS(ctx))
	camp, _ := c.CreateRequest(ctx, M{"payee": payee, "kind": "campaign"})
	must("publicCampaign")(c.PublicCampaign(ctx, s(camp, "id")))
	must("createSignInChallenge")(c.CreateSignInChallenge(ctx, M{"domain": "parity.test"}))
	var apiErr *Error
	if _, err := c.VerifySignIn(ctx, "zsig1AAAA"); !errors.As(err, &apiErr) || apiErr.Code != "sign_in_malformed" {
		t.Fatal("verifySignIn", err)
	}
	done["verifySignIn"] = true
	ep := must("createWebhookEndpoint")(c.CreateWebhookEndpoint(ctx, M{"url": "http://127.0.0.1:9/parity"}))
	must("listWebhookEndpoints")(c.ListWebhookEndpoints(ctx))
	must("deleteWebhookEndpoint")(c.DeleteWebhookEndpoint(ctx, s(ep, "id")))
	evs := must("listEvents")(c.ListEvents(ctx, M{"limit": 1}))
	must("resendEvent")(c.ResendEvent(ctx, evs["data"].([]any)[0].(map[string]any)["id"].(string)))
	must("listDeliveries")(c.ListDeliveries(ctx, M{"limit": 1}))

	raw, _ := os.ReadFile("../../conformance/sdk-parity.json")
	var table map[string]any
	_ = json.Unmarshal(raw, &table)
	for op := range table {
		if !strings.HasPrefix(op, "_") && !done[op] {
			t.Errorf("operation %s not exercised", op)
		}
	}
}

func TestRetriesRespectTheContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "20")
		w.WriteHeader(503)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()
	c := New("rcpt_test_x")
	c.BaseURL = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Health(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("expected a prompt deadline error, got %v after %v", err, time.Since(start))
	}
	c.MaxRetries = 0
	_, err = c.Health(context.Background())
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "http_503" || apiErr.Message != "upstream down" {
		t.Fatalf("non-JSON error body lost: %#v", err)
	}
}

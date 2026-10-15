// The 402 gate and webhook handler against a running `receipts serve` (RECEIPTS_URL, RECEIPTS_KEY),
// plus offline webhook checks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Receipts, webhooks } from "../client.js";
import { receiptGate, webhookHandler, checkGate } from "../middleware.js";

const URL_ = process.env.RECEIPTS_URL, KEY = process.env.RECEIPTS_KEY;
const PAYEE = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

test("webhook handler: signed events dispatch, forged ones get 400", async () => {
  const secret = "whsec_test";
  const body = JSON.stringify({ id: "evt_1", type: "request.fulfilled", data: { object: {} } });
  const seen = [];
  const ok = await webhookHandler.fetch(new Request("http://x", { method: "POST", body, headers: { "receipts-signature": await webhooks.sign(body, secret) } }), { secret, on: { "request.fulfilled": (e) => seen.push(e.id) } });
  assert.equal(ok.status, 200);
  assert.deepEqual(seen, ["evt_1"]);
  const bad = await webhookHandler.fetch(new Request("http://x", { method: "POST", body, headers: { "receipts-signature": "t=1,v1=00" } }), { secret });
  assert.equal(bad.status, 400);
});

test("402 gate: pay, prove, get through; bound to its caller", { skip: !URL_ || !KEY }, async () => {
  const receipts = new Receipts(KEY, { baseUrl: URL_ });
  const opts = { receipts, payee: PAYEE, amountZatoshis: 1_000_000, label: "report.pdf", bindTo: "alice" };
  const first = await receiptGate.fetch(new Request("http://shop/report.pdf"), opts);
  assert.equal(first.status, 402);
  const body = await first.json();
  assert.match(body.payment_uri, /^zcash:/);
  // Not paid yet: still 402 with the same request.
  const again = await receiptGate.fetch(new Request("http://shop/report.pdf", { headers: { "receipt-request": body.request } }), opts);
  assert.equal(again.status, 402);
  assert.equal((await again.json()).request, body.request);
  await receipts.requests.submitReceipt(body.request, { receipt: "zrcpt_test_valid" });
  assert.equal(await receiptGate.fetch(new Request("http://shop/report.pdf", { headers: { "receipt-request": body.request } }), opts), null);
  // Someone else presenting alice's paid request id doesn't get in.
  const mallory = await checkGate({ ...opts, bindTo: "mallory", requestId: body.request });
  assert.equal(mallory.allow, false);
  // Express adapter.
  let status, json, nexted = false;
  const res = { set() {}, status(s) { status = s; return this; }, json(j) { json = j; } };
  await receiptGate.express(opts)({ headers: {} }, res, () => (nexted = true));
  assert.equal(status, 402);
  await receiptGate.express(opts)({ headers: { "receipt-request": body.request } }, res, () => (nexted = true));
  assert.equal(nexted, true);
});

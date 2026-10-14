// API client tests against a running `receipts serve` (set RECEIPTS_URL and RECEIPTS_KEY),
// plus offline webhook-signature tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Receipts, VerificationError, AuthenticationError, InvalidRequestError, webhooks, WebhookSignatureError } from "../client.js";

const URL_ = process.env.RECEIPTS_URL, KEY = process.env.RECEIPTS_KEY;
const live = !(URL_ && KEY);
const ex = (p) => new URL(`../../../examples/${p}`, import.meta.url);

test("webhook signatures: valid, tampered, stale", async () => {
  const body = JSON.stringify({ id: "evt_1", type: "request.fulfilled", data: { object: {} } });
  const header = await webhooks.sign(body, "whsec_test");
  assert.equal((await webhooks.constructEvent(body, header, "whsec_test")).id, "evt_1");
  await assert.rejects(webhooks.constructEvent(body + " ", header, "whsec_test"), WebhookSignatureError);
  const old = await webhooks.sign(body, "whsec_test", Math.floor(Date.now() / 1000) - 3600);
  await assert.rejects(webhooks.constructEvent(body, old, "whsec_test"), /tolerance/);
});

test("API: auth error is typed", { skip: live }, async () => {
  await assert.rejects(new Receipts("rcpt_test_nope", { baseUrl: URL_ }).requests.list(), AuthenticationError);
});

test("API: create, retrieve, list, idempotent replay", { skip: live }, async () => {
  const r = new Receipts(KEY, { baseUrl: URL_ });
  const payee = (await readFile(ex("testnet/merchant.ua"), "utf8")).trim();
  const a = await r.requests.create({ payee, amount_zatoshis: 1_000_000, label: "SDK test" }, { idempotencyKey: "sdk-test-1" });
  const b = await r.requests.create({ payee, amount_zatoshis: 1_000_000, label: "SDK test" }, { idempotencyKey: "sdk-test-1" });
  assert.equal(a.id, b.id);
  assert.match(a.payment_uri, /^zcash:utest1/);
  assert.equal((await r.requests.retrieve(a.id)).status, "open");
  const page = await r.requests.list({ limit: 1 });
  assert.equal(page.data.length, 1);
  await assert.rejects(r.requests.create({ payee: "u1notanaddress" }), (e) => e instanceof InvalidRequestError && e.param === "payee");
});

test("API: verify succeeds, wrong challenge is a VerificationError with a code", { skip: live }, async () => {
  const r = new Receipts(KEY, { baseUrl: URL_ });
  const receipt = await readFile(ex("testnet/receipt.txt"), "utf8");
  const v = await r.verify({ receipt });
  assert.equal(v.mined_height, 4500997);
  await assert.rejects(r.verify({ receipt, challenge: "00112233aabbccdd" }), (e) => e instanceof VerificationError && e.code === "challenge_mismatch");
});

test("refunds and sign-in route to the right endpoints", async () => {
  const { Receipts } = await import("../client.js");
  const calls = [];
  const fetch = async (url, init) => { calls.push([init.method, url, init.body]); return new Response(JSON.stringify({ ok: true }), { status: 200 }); };
  const r = new Receipts("rcpt_test_x", { baseUrl: "http://api", fetch });
  await r.refunds.create("preq_1", { amount_zatoshis: 5 });
  await r.refunds.submitReceipt("rf_1", { receipt: "zrcpt_test_valid" });
  await r.signIn.createChallenge({ domain: "a.example" });
  await r.signIn.verify("zsig1abc");
  assert.deepEqual(calls.map((c) => c[1]), ["http://api/v1/requests/preq_1/refunds", "http://api/v1/refunds/rf_1/receipts", "http://api/v1/sign_in/challenges", "http://api/v1/sign_in/verify"]);
  assert.equal(JSON.parse(calls[3][2]).sign_in, "zsig1abc");
});

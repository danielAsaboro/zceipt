// Calls every API operation through this SDK against a running server (sandbox), and checks the
// list against conformance/sdk-parity.json. Needs RECEIPTS_URL and a test RECEIPTS_KEY.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Receipts } from "../client.js";

const URL_ = process.env.RECEIPTS_URL, KEY = process.env.RECEIPTS_KEY;
const PAYEE = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

test("every API operation works through the JS SDK", { skip: !URL_ || !KEY }, async () => {
  const table = JSON.parse(await readFile(new URL("../../../conformance/sdk-parity.json", import.meta.url), "utf8"));
  const r = new Receipts(KEY, { baseUrl: URL_ });
  const done = new Set();
  const call = async (op, p) => { const v = await p; done.add(op); return v; };
  await call("health", r.health());
  await call("listErrors", r.errors.list());
  await call("listSandboxFixtures", r.sandbox.fixtures());
  await call("verify", r.verify("zrcpt_test_valid"));
  await call("checkPaymentLink", r.paymentLinks.check(`zcash:${PAYEE}?amount=0.01`));
  const clock = await call("createTestClock", r.testClocks.create());
  await call("getTestClock", r.testClocks.retrieve(clock.id));
  const req = await call("createRequest", r.requests.create({ payee: PAYEE, amount_zatoshis: 1_000_000, test_clock: clock.id }));
  await call("getRequest", r.requests.retrieve(req.id));
  await call("listRequests", r.requests.list({ limit: 2 }));
  assert.match(await call("requestQr", r.requests.qr(req.id)), /<svg/);
  await call("publicGetRequest", r.public.getRequest(req.id, req.client_secret));
  await call("publicSubmitReceipt", r.public.submitReceipt(req.id, { receipt: "zrcpt_test_refund_to", client_secret: req.client_secret }));
  await call("advanceTestClock", r.testClocks.advance(clock.id, { blocks: 9 }));
  await call("reorgTestClock", r.testClocks.reorg(clock.id, { depth: 1 }));
  const rf = await call("createRefund", r.refunds.create(req.id, { amount_zatoshis: 1000 }));
  await call("getRefund", r.refunds.retrieve(rf.id));
  await call("submitRefundReceipt", r.refunds.submitReceipt(rf.id, { receipt: "zrcpt_test_valid" }));
  const other = await r.requests.create({ payee: PAYEE, amount_zatoshis: 1_000_000 });
  await call("submitReceipt", r.requests.submitReceipt(other.id, { receipt: "zrcpt_test_valid" }));
  const att = await call("createAttestation", r.attestations.create(other.id));
  await call("verifyAttestation", r.attestations.verify(att.presentation));
  await call("jwks", r.attestations.jwks());
  const camp = await r.requests.create({ payee: PAYEE, kind: "campaign" });
  await call("publicCampaign", r.public.campaign(camp.id));
  const ch = await call("createSignInChallenge", r.signIn.createChallenge({ domain: "parity.test" }));
  await call("verifySignIn", r.signIn.verify("zsig1AAAA").catch((e) => assert.equal(e.code ?? e.body?.error?.code, "sign_in_malformed")));
  void ch;
  const ep = await call("createWebhookEndpoint", r.webhookEndpoints.create({ url: "http://127.0.0.1:9/parity" }));
  await call("listWebhookEndpoints", r.webhookEndpoints.list());
  await call("deleteWebhookEndpoint", r.webhookEndpoints.del(ep.id));
  const ev = await call("listEvents", r.events.list({ limit: 1 }));
  await call("resendEvent", r.events.resend(ev.data[0].id));
  await call("listDeliveries", r.deliveries.list({ limit: 1 }));
  const missing = Object.keys(table).filter((k) => !k.startsWith("_") && !done.has(k));
  assert.deepEqual(missing, [], "operations not exercised");
});

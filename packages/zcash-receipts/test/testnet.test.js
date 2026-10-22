// Verifies the committed testnet receipt against the live testnet (network test), and
// the committed regtest receipt fully offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { verifyReceipt, inspectReceipt, verifyIncoming } from "../index.js";

const ex = (p) => new URL(`../../../examples/${p}`, import.meta.url);

test("regtest receipt verifies offline against the raw transaction", async () => {
  const receipt = await readFile(ex("regtest/receipt.txt"), "utf8");
  const rawTx = await readFile(ex("regtest/tx.hex"), "utf8");
  const merchant = (await readFile(ex("regtest/merchant.ua"), "utf8")).trim();
  const v = await verifyReceipt(receipt, { rawTx, height: 222, regtest: true, expectAddress: merchant, minZatoshis: 42_000_000 });
  assert.equal(v.valid, true);
  assert.equal(v.outputs[0].memo, "Invoice 42: two coffees");
  assert.equal(v.paidToExpected, 42_000_000);
});

test("edited receipt is rejected", async () => {
  const receipt = (await readFile(ex("regtest/receipt.txt"), "utf8")).trim();
  const rawTx = await readFile(ex("regtest/tx.hex"), "utf8");
  // Flip one character in the middle of the proof.
  const i = 4000;
  const bad = receipt.slice(0, i) + (receipt[i] === "A" ? "B" : "A") + receipt.slice(i + 1);
  await assert.rejects(verifyReceipt(bad, { rawTx, height: 222, regtest: true }));
});

test("testnet request answer verifies against the live chain", { skip: !!process.env.OFFLINE }, async () => {
  const link = await readFile(ex("testnet/request-answer-link.txt"), "utf8");
  const s = await inspectReceipt(link);
  assert.equal(s.network, "testnet");
  const merchant = (await readFile(ex("testnet/merchant.ua"), "utf8")).trim();
  const v = await verifyReceipt(link, { expectAddress: merchant, minZatoshis: 1_000_000, challenge: "e1e14a5d182a" });
  assert.equal(v.mined_height, 4500997);
  await assert.rejects(verifyReceipt(link, { challenge: "000000000000" }), /challenge/);
});

test("testnet batch of three payments verifies", { skip: !!process.env.OFFLINE }, async () => {
  const { verifyBatch } = await import("../index.js");
  const text = await readFile(ex("testnet/batch.txt"), "utf8");
  const b = await verifyBatch(text);
  assert.equal(b.results.length, 3);
  assert.equal(Object.values(b.totals).reduce((s, z) => s + z, 0), 2_200_000);
});

test("Sign in with Zcash verifies locally, only for its domain and nonce", async () => {
  const { verifySignIn } = await import("../index.js");
  const s = await readFile(ex("testnet/sign-in.txt"), "utf8");
  const r = await verifySignIn(s, { domain: "kemis-coffee.test", nonce: "example-nonce-0001" });
  assert.equal(r.network, "testnet");
  assert.match(r.address, /^utest1/);
  await assert.rejects(verifySignIn(s, { domain: "evil.example", nonce: "example-nonce-0001" }));
  await assert.rejects(verifySignIn(s, { domain: "kemis-coffee.test", nonce: "another" }));
});

test("block hints are read from links", async () => {
  const { heightHint } = await import("../index.js");
  assert.equal(heightHint("https://x/#zip311r1abc&h=4500997"), 4500997);
  assert.equal(heightHint("zip311r1abc"), null);
  assert.equal(heightHint("https://x/?request=ab#zip311r1abc&h=12"), 12);
});

test("block-level fetch hides which transaction was checked", { skip: !!process.env.OFFLINE }, async () => {
  const receipt = (await readFile(ex("testnet/receipt.txt"), "utf8")).trim();
  const v = await verifyReceipt(`${receipt}&h=4500997`);
  assert.equal(v.valid, true);
  assert.equal(v.fetch.mode, "block");
  assert.ok(v.fetch.anonymity_set > 1, JSON.stringify(v.fetch));
  await assert.rejects(verifyReceipt(`${receipt}&h=4500996`), /not in block/);
});

test("payment links are linted", async () => {
  const { checkPaymentLink } = await import("../index.js");
  const ua = (await readFile(ex("testnet/merchant.ua"), "utf8")).trim();
  const ok = await checkPaymentLink(`zcash:${ua}?amount=0.01&memo=SW52b2ljZSA0Mg`, { network: "testnet" });
  assert.equal(ok.ok, true);
  assert.equal(ok.payments[0].memo, "Invoice 42");
  const bad = await checkPaymentLink(`zcash:${ua}?amount=0.01`, { network: "mainnet" });
  assert.equal(bad.ok, false);
  assert.ok(bad.findings.some((f) => f.code === "network_mismatch"));
});

test("source-of-funds receipts verify offline with their source transaction, and not without it", async () => {
  const rawTx = await readFile(ex("testnet/source/tx.hex"), "utf8");
  const src = await readFile(ex("testnet/source/source-tx.hex"), "utf8");
  for (const [name, value] of [["receipt-source-hidden", null], ["receipt-source-value", 12_500_000]]) {
    const receipt = await readFile(ex(`testnet/source/${name}.txt`), "utf8");
    const v = await verifyReceipt(receipt, { rawTx, height: 4500997, sourceTxs: [{ rawTx: src, height: 4500984 }] });
    assert.equal(v.sources.length, 1, name);
    assert.match(v.sources[0].source_txid, /^2a2bd721/, name);
    assert.equal(v.sources[0].zatoshis, value, name);
    await assert.rejects(verifyReceipt(receipt, { rawTx, height: 4500997, sourceTxs: [] }), /not available/, name);
    // A source mined after the payment can't be its source.
    await assert.rejects(verifyReceipt(receipt, { rawTx, height: 4500997, sourceTxs: [{ rawTx: src, height: 4500998 }] }), /not available/, name);
  }
});

test("incoming receipt (the recipient proves it was paid) verifies offline", async () => {
  const receipt = await readFile(ex("testnet/incoming/receipt.txt"), "utf8");
  const rawTx = await readFile(ex("testnet/incoming/tx.hex"), "utf8");
  const merchant = (await readFile(ex("testnet/merchant.ua"), "utf8")).trim();
  const v = await verifyIncoming(receipt, { rawTx, height: 4500997, expectAddress: merchant });
  assert.equal(v.kind, "incoming");
  assert.equal(v.outputs[0].zatoshis, 1_000_000);
  assert.equal(v.outputs[0].memo, "Invoice 42: two coffees");
  const i = receipt.indexOf("zrcin1") + 2000;
  const bad = receipt.slice(0, i) + (receipt[i] === "A" ? "B" : "A") + receipt.slice(i + 1);
  await assert.rejects(verifyIncoming(bad, { rawTx, height: 4500997 }));
});

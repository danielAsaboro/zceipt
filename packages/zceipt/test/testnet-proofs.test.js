// The proofs made on the Zcash public testnet (examples/testnet/proofs), checked offline with the
// raw transactions, the way a browser checks them, and the attacks on them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { verifyDesignated, verifyDelegated, verifyPayerTag } from "../index.js";

const read = async (f) => (await readFile(new URL(`../../../examples/testnet/proofs/${f}`, import.meta.url), "utf8")).trim();
const at = async (n, height) => ({ rawTx: await read(`tx${n}.hex`), height });
const A = await at("A", 4539401);
const B = await at("B", 4539426);
const C = await at("C", 4539407);

test("payer tags: one wallet's two payments share a tag, another account's differs", async () => {
  const tag = async (n, p) => (await verifyPayerTag(await read(`tag${n}.txt`), { domain: "round-testnet", ...p })).tag;
  const [a, b, c] = [await tag("A", A), await tag("B", B), await tag("C", C)];
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("a payer tag is refused for another round, another payment, or with an edit", async () => {
  const t = await read("tagA.txt");
  await assert.rejects(verifyPayerTag(t, { domain: "round-other", ...A }));
  await assert.rejects(verifyPayerTag(t, { domain: "round-testnet", ...C }));
  const i = 3000;
  await assert.rejects(verifyPayerTag(t.slice(0, i) + (t[i] === "A" ? "B" : "A") + t.slice(i + 1), { domain: "round-testnet", ...A }));
});

test("a receipt for one verifier convinces that verifier and no one else", async () => {
  const d = await read("dv.txt");
  const v = await verifyDesignated(d, await read("shop.key"), A);
  assert.equal(v.designated, true);
  assert.equal(v.outputs[0].zatoshis ?? v.outputs[0].value, 200000);
  await assert.rejects(verifyDesignated(d, await read("other.key"), A), /another verifier/);
  await assert.rejects(verifyDesignated(d, await read("shop.key"), C));
});

test("a delegated receipt keeps to its policy", async () => {
  const g = await verifyDelegated(await read("dg.txt"), A);
  assert.equal(g.delegation.max_zatoshis, 50000000);
  for (const f of ["dg2.txt", "dg-expired.txt", "dg-wrong-payee.txt"]) await assert.rejects(verifyDelegated(await read(f), A), undefined, f);
  await assert.rejects(verifyDelegated(await read("dg.txt"), C));
});

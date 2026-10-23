// Runs the shared conformance vectors (conformance/vectors.json) through this package.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { verifyReceipt, verifySignIn, verifyIncoming, challengeIn } from "../index.js";

const { vectors } = JSON.parse(await readFile(new URL("../../../conformance/vectors.json", import.meta.url), "utf8"));

async function run(v) {
  try {
    if (v.type === "receipt") {
      const sourceTxs = v.source_txs ? v.source_txs.map((t) => ({ rawTx: t.raw_tx, height: t.height })) : undefined;
      const r = await verifyReceipt(v.receipt, { rawTx: v.raw_tx, height: v.height, regtest: v.regtest, sourceTxs });
      return { valid: r.valid === true, r };
    }
    if (v.type === "expectation") {
      // "Was I paid": verifyReceipt with the expectation must succeed exactly when it is satisfied.
      const r = await verifyReceipt(v.receipt, { rawTx: v.raw_tx, height: v.height, regtest: v.regtest });
      let satisfied = true;
      try {
        await verifyReceipt(v.receipt, { rawTx: v.raw_tx, height: v.height, regtest: v.regtest, expectAddress: v.expect_address, minZatoshis: v.min_zatoshis });
      } catch {
        satisfied = false;
      }
      return { valid: r.valid === true, r: { ...r, satisfied } };
    }
    if (v.type === "incoming") {
      const r = await verifyIncoming(v.receipt, { rawTx: v.raw_tx, height: v.height, regtest: v.regtest });
      return { valid: r.valid === true, r };
    }
    const r = await verifySignIn(v.sign_in, { domain: v.domain, nonce: v.nonce });
    return { valid: true, r };
  } catch (e) {
    return { valid: false, e };
  }
}

test(`conformance: ${vectors.length} vectors`, async () => {
  for (const v of vectors) {
    const got = await run(v);
    assert.equal(got.valid, v.expect.valid, `${v.name}: expected valid=${v.expect.valid}, got ${got.e?.message ?? "valid"}`);
    if (v.expect.outputs) {
      assert.deepEqual(got.r.outputs.map((o) => ({ zatoshis: o.zatoshis, memo: o.memo })), v.expect.outputs, v.name);
    }
    if (v.expect.network) assert.equal(got.r.network, v.expect.network, v.name);
    if (v.expect.satisfied != null) assert.equal(got.r.satisfied, v.expect.satisfied, v.name);
    if (v.expect.sources) assert.deepEqual(got.r.sources.map((s) => ({ zatoshis: s.zatoshis })), v.expect.sources, v.name);
  }
});

test("the challenge rule matches conformance/challenge.json", async () => {
  const { cases } = JSON.parse(await readFile(new URL("../../../conformance/challenge.json", import.meta.url), "utf8"));
  for (const c of cases) assert.equal(challengeIn(c.message), c.challenge, JSON.stringify(c.message));
});

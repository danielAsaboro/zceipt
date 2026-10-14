// Runs the shared conformance vectors (conformance/vectors.json) through this package.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { verifyReceipt, verifySignIn } from "../index.js";

const { vectors } = JSON.parse(await readFile(new URL("../../../conformance/vectors.json", import.meta.url), "utf8"));

async function run(v) {
  try {
    if (v.type === "receipt") {
      const r = await verifyReceipt(v.receipt, { rawTx: v.raw_tx, height: v.height, regtest: v.regtest });
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
  }
});

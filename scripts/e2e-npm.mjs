// The npm package checks what the CLI made in the regtest end to end, offline (raw transactions
// given): node scripts/e2e-npm.mjs <dir> <T1 hex> <T1 height> <DEP hex> <DEP height>
import { readFile } from "node:fs/promises";
import { verifyDesignated, verifyDelegated, verifyPayerTag } from "../packages/zcash-receipts/index.js";

const [dir, t1, h1, dep, hd] = process.argv.slice(2);
const read = (f) => readFile(`${dir}/${f}`, "utf8");
const out = [];
const d = await verifyDesignated(await read("dv.txt"), (await read("shop.key")).trim(), { rawTx: t1, height: +h1, regtest: true });
out.push(`designated ${d.designated && d.outputs.length > 0}`);
await verifyDesignated(await read("dv.txt"), (await read("other.key")).trim(), { rawTx: t1, height: +h1, regtest: true }).then(
  () => out.push("other-key accepted"),
  (e) => out.push(`other-key refused ${/another verifier/.test(e.message)}`),
);
const g = await verifyDelegated(await read("dg.txt"), { rawTx: t1, height: +h1, regtest: true });
out.push(`delegated ${g.delegation.max_zatoshis === 50000000}`);
await verifyDelegated(await read("dg2.txt"), { rawTx: t1, height: +h1, regtest: true }).then(() => out.push("over-limit accepted"), () => out.push("over-limit refused true"));
const t = await verifyPayerTag(await read("tag-DEP.txt"), { domain: "round-e2e", rawTx: dep, height: +hd });
out.push(`payer-tag ${t.tag === JSON.parse(await read("tag-DEP.json")).tag}`);
console.log(out.join("\n"));

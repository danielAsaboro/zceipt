// The npm package checks what the CLI made on the testnet (scripts/e2e-testnet.sh), offline (the
// raw transaction given): node scripts/e2e-npm-testnet.mjs <dir> <payment A hex> <its block height>
import { readFile } from "node:fs/promises";
import { verifyDesignated, verifyDelegated, verifyPayerTag } from "../packages/zceipt/index.js";

const [dir, tx, height] = process.argv.slice(2);
const read = (f) => readFile(`${dir}/${f}`, "utf8");
const at = { rawTx: tx, height: +height };
const out = [];
const d = await verifyDesignated(await read("dv.txt"), (await read("shop.key")).trim(), at);
out.push(`designated ${d.designated && d.outputs.length > 0}`);
await verifyDesignated(await read("dv.txt"), (await read("other.key")).trim(), at).then(
  () => out.push("other-key accepted"),
  (e) => out.push(`other-key refused ${/another verifier/.test(e.message)}`),
);
const g = await verifyDelegated(await read("dg.txt"), at);
out.push(`delegated ${g.delegation.max_zatoshis === 50000000}`);
await verifyDelegated(await read("over-limit.txt"), at).then(() => out.push("over-limit accepted"), () => out.push("over-limit refused true"));
const t = await verifyPayerTag(await read("tag-A.txt"), { domain: "round-e2e", ...at });
out.push(`payer-tag ${t.tag === JSON.parse(await read("tag-A.json")).tag}`);
console.log(out.join("\n"));

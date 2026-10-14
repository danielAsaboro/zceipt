// zcash-receipts: verify ZIP 311 payment receipts for Zcash Orchard and Ironwood.
//
//   import { verifyReceipt } from "zcash-receipts";
//   const r = await verifyReceipt("https://…#zrcpt1…", { expectAddress: "u1…" });
//   r.valid, r.outputs[0].zatoshis, r.outputs[0].memo, r.message
//
// Everything runs locally (Rust compiled to WebAssembly). The only network request fetches
// the public transaction from a lightwalletd grpc-web server, which you can override or skip
// entirely by passing the raw transaction.

import init, { initSync, inspect, verify, orchard_receiver_hex } from "./pkg/receipts_wasm.js";
import { DEFAULT_ENDPOINTS, fetchTransaction, hexToBytes } from "./grpc.js";

export { DEFAULT_ENDPOINTS, fetchTransaction };

let ready;
async function load() {
  if (!ready) {
    ready = (async () => {
      if (typeof window === "undefined" && typeof process !== "undefined" && process.versions?.node) {
        const { readFile } = await import("node:fs/promises");
        initSync({ module: await readFile(new URL("./pkg/receipts_wasm_bg.wasm", import.meta.url)) });
      } else {
        await init();
      }
    })();
  }
  return ready;
}

/** Extracts the `zrcpt1…` receipt from a link, a fragment or bare text. */
export function extractReceipt(input) {
  const s = decodeURIComponent(String(input).trim());
  const i = s.indexOf("zrcpt1");
  if (i < 0) throw new Error("no zrcpt1 receipt found");
  return s.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
}

/** Decodes a receipt without verifying it: `{ network, pool, txid, message, outputs, spends, bytes }`. */
export async function inspectReceipt(input) {
  await load();
  return JSON.parse(inspect(extractReceipt(input)));
}

/** The Orchard receiver of a unified address, hex. Two addresses match if these match. */
export async function orchardReceiver(ua) {
  await load();
  return orchard_receiver_hex(ua);
}

/**
 * Verifies a receipt against the chain.
 *
 * options:
 *   endpoint       grpc-web lightwalletd URL (default: ChainSafe for the receipt's network)
 *   rawTx, height  verify against these instead of fetching (Uint8Array or hex, number)
 *   regtest        the receipt is from a local regtest chain
 *   expectAddress  fail unless an output paid this unified address
 *   minZatoshis    fail unless that address received at least this much
 *   challenge      fail unless the receipt signs `challenge:<code>`
 *
 * Resolves to `{ valid: true, network, pool, txid, mined_height, message, proven_spend_actions,
 * outputs: [{ action, recipient, zatoshis, memo }], paidToExpected }` or throws with the reason.
 */
export async function verifyReceipt(input, options = {}) {
  await load();
  const receipt = extractReceipt(input);
  const summary = JSON.parse(inspect(receipt));
  let raw = options.rawTx, height = options.height;
  if (raw == null) {
    const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
    if (!endpoint) throw new Error(`no lightwalletd endpoint for ${summary.network}`);
    ({ raw, height } = await fetchTransaction(endpoint, summary.txid));
  } else if (typeof raw === "string") {
    raw = hexToBytes(raw.trim());
  }
  const v = JSON.parse(verify(receipt, raw, Number(height), !!options.regtest));
  if (options.challenge != null) {
    const m = /(?:^|\n)challenge:([0-9a-f]{6,64})(?:\n|$)/.exec(v.message || "");
    if (!m || m[1] !== String(options.challenge)) throw new Error("the receipt does not sign the expected challenge");
  }
  if (options.expectAddress) {
    const want = orchard_receiver_hex(options.expectAddress);
    const paid = v.outputs.filter((o) => orchard_receiver_hex(o.recipient) === want).reduce((s, o) => s + o.zatoshis, 0);
    if (paid === 0) throw new Error("no disclosed output paid the expected address");
    if (options.minZatoshis != null && paid < options.minZatoshis) throw new Error(`paid ${paid} zatoshis, less than ${options.minZatoshis}`);
    v.paidToExpected = paid;
  }
  return v;
}

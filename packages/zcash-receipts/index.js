// zcash-receipts: verify ZIP 311 payment receipts for Zcash Orchard and Ironwood.
//
//   import { verifyReceipt } from "zcash-receipts";
//   const r = await verifyReceipt("https://…#zrcpt1…", { expectAddress: "u1…" });
//   r.valid, r.outputs[0].zatoshis, r.outputs[0].memo, r.message
//
// Everything runs locally (Rust compiled to WebAssembly). The only network request fetches
// the public transaction from a lightwalletd grpc-web server, which you can override or skip
// entirely by passing the raw transaction.

import init, { initSync, inspect, verify, orchard_receiver_hex, open_batch, secret_kind, verify_sign_in, check_payment_uri } from "./pkg/receipts_wasm.js";
import { DEFAULT_ENDPOINTS, fetchTransaction, fetchTransactionPrivately, heightHint, hexToBytes } from "./grpc.js";

export { DEFAULT_ENDPOINTS, fetchTransaction, fetchTransactionPrivately, heightHint };

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

/** The kind of secret (viewing key, spending key, seed phrase) in `text`, or null. Never echo it. */
export async function detectSecret(text) {
  await load();
  return secret_kind(String(text)) || null;
}

/** Extracts a `zrcptb1…` batch from a link, a fragment or bare text, or returns null. */
export function extractBatch(input) {
  const s = decodeURIComponent(String(input).trim());
  const i = s.indexOf("zrcptb1");
  return i < 0 ? null : s.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
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
  const leak = secret_kind(String(input));
  if (leak) throw new Error(`refusing: input contains what looks like a ${leak}; never share it`);
  const receipt = extractReceipt(input);
  const summary = JSON.parse(inspect(receipt));
  let raw = options.rawTx, height = options.height;
  let fetchInfo = { mode: "offline", server: null, sees: "nothing: you supplied the transaction" };
  if (raw == null) {
    const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
    if (!endpoint) throw new Error(`no lightwalletd endpoint for ${summary.network}`);
    const hint = options.height ?? heightHint(input);
    if (hint && options.privateFetch !== false) {
      const r = await fetchTransactionPrivately(endpoint, summary.txid, hint, { maxSet: options.maxAnonymitySet });
      ({ raw, height } = r);
      fetchInfo = { mode: "block", server: endpoint, anonymity_set: r.anonymitySet, sees: `block ${hint} and ${r.anonymitySet} of its ${r.blockTxs} shielded transactions, not which one you checked` };
    } else {
      ({ raw, height } = await fetchTransaction(endpoint, summary.txid));
      fetchInfo = { mode: "txid", server: endpoint, sees: "the transaction id you checked (add the h= hint or pass rawTx to avoid this)" };
    }
  } else if (typeof raw === "string") {
    raw = hexToBytes(raw.trim());
  }
  const v = JSON.parse(verify(receipt, raw, Number(height), !!options.regtest));
  v.local = true;
  v.fetch = fetchInfo;
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

/**
 * Verifies a batch link (`zrcptb1…`): checks it is complete and consistent (every receipt signs
 * `batch:<id> <i>/<n>`), then verifies each receipt against the chain.
 * Resolves to `{ id, results: [verifyReceipt result, …], totals: { recipient: zatoshis } }`.
 * Options are passed to each `verifyReceipt` call, except `rawTx`/`height`.
 */
export async function verifyBatch(input, options = {}) {
  await load();
  const text = extractBatch(input);
  if (!text) throw new Error("no zrcptb1 batch found");
  const { id, receipts } = JSON.parse(open_batch(text));
  const { rawTx, height, expectAddress, minZatoshis, ...rest } = options;
  const results = [];
  for (const r of receipts) results.push(await verifyReceipt(r, rest));
  const totals = {};
  for (const v of results) for (const o of v.outputs) totals[o.recipient] = (totals[o.recipient] || 0) + o.zatoshis;
  return { id, results, totals };
}

/** Extracts a `zsig1…` sign-in from a link, a fragment or bare text, or returns null. */
export function extractSignIn(input) {
  const s = decodeURIComponent(String(input).trim());
  const i = s.indexOf("zsig1");
  return i < 0 ? null : s.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
}

/**
 * Sign in with Zcash, verified locally: checks that a `zsig1…` proves control of a shielded
 * address for your `domain` and the one-time `nonce` you issued. Resolves to
 * `{ address, network, issued_at }` or throws. Keep nonces single-use and short-lived.
 */
export async function verifySignIn(input, { domain, nonce }) {
  if (!domain || !nonce) throw new Error("verifySignIn needs { domain, nonce }");
  const s = extractSignIn(input);
  if (!s) throw new Error("no zsig1 sign-in found");
  await load();
  return JSON.parse(verify_sign_in(s, String(domain), String(nonce)));
}

/**
 * Lints a ZIP-321 payment link before you print it or turn it into a QR code. Resolves to
 * `{ ok, payments, total_zatoshis, qr: { version, modules }, findings: [{ level, code, message }] }`.
 * Pass `{ network: "mainnet" }` to make a wrong-network address an error.
 */
export async function checkPaymentLink(uri, { network } = {}) {
  await load();
  return JSON.parse(check_payment_uri(String(uri), network ? String(network) : ""));
}

const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const b64urlEncode = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * Verifies a payment-fact attestation (an SD-JWT from `POST /v1/requests/{id}/attestations`)
 * locally with WebCrypto. `jwks` is the issuer's `/.well-known/jwks.json` (an object, or a URL to
 * fetch; default: `<iss>/.well-known/jwks.json`). Resolves to the signed claims, with any
 * revealed hidden claims under `revealed`. Throws if anything doesn't check out.
 */
export async function verifyAttestation(presentation, { jwks } = {}) {
  const [jwt, ...disclosures] = String(presentation).trim().split("~");
  const [h, p, s] = jwt.split(".");
  if (!s) throw new Error("not a JWT");
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  if (header.alg !== "EdDSA") throw new Error("unsupported alg");
  let set = jwks;
  if (!set || typeof set === "string") set = await (await fetch(set || `${String(claims.iss).replace(/\/$/, "")}/.well-known/jwks.json`)).json();
  const jwk = (set.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown key id");
  const key = await crypto.subtle.importKey("raw", b64urlDecode(jwk.x), { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw new Error("signature does not verify");
  const revealed = {};
  for (const d of disclosures.filter(Boolean)) {
    const digest = b64urlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(d)));
    if (!(claims._sd || []).includes(digest)) throw new Error("a disclosure is not part of this attestation");
    const [, name, value] = JSON.parse(new TextDecoder().decode(b64urlDecode(d)));
    if (name in revealed) throw new Error("duplicate disclosure");
    revealed[name] = value;
  }
  delete claims._sd;
  delete claims._sd_alg;
  return { ...claims, revealed };
}

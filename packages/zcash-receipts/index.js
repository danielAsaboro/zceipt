// zcash-receipts: verify ZIP 311 payment receipts for Zcash Orchard and Ironwood.
//
//   import { verifyReceipt } from "zcash-receipts";
//   const r = await verifyReceipt("https://…#zip311r1…", { expectAddress: "u1…" });
//   r.valid, r.outputs[0].zatoshis, r.outputs[0].memo, r.message
//
// Everything runs locally (Rust compiled to WebAssembly). The only network requests go to one
// lightwalletd grpc-web server (the transaction, or its block's list and transactions with an
// h= hint), which you can override or skip entirely by passing the raw transaction.

import init, { initSync, inspect, verify, orchard_receiver_hex, address_network, open_batch, secret_kind, verify_sign_in, check_payment_uri, check_tex_deposit, source_txids, transparent_output, verify_incoming, inspect_incoming, txid_of, verify_same_payer, verify_screened, verify_aggregated, verify_keyset, key_set_keys, verify_policy, inspect_income, verify_income } from "./pkg/receipts_wasm.js";
import { DEFAULT_ENDPOINTS, fetchTransaction, fetchTransactionPrivately, heightHint, hexToBytes } from "./grpc.js";

export { DEFAULT_ENDPOINTS, fetchTransaction, fetchTransactionPrivately, heightHint };

// Links can carry other text with a stray "%" (`&note=50%off`): never let that stop a check.
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

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

// The txid check for block-level fetches (see fetchTransactionPrivately).
const txidOf = (network) => (raw, height) => txid_of(raw, height, network === "mainnet" ? 133 : 1);

/** The kind of secret (viewing key, spending key, seed phrase) in `text`, or null. Never echo it. */
export async function detectSecret(text) {
  await load();
  return secret_kind(String(text)) || null;
}

/** Extracts a `zip311b1…` batch from a link, a fragment or bare text, or returns null. */
export function extractBatch(input) {
  const s = safeDecode(String(input).trim());
  const i = s.indexOf("zip311b1");
  return i < 0 ? null : s.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
}

/** Extracts the `zip311r1…` receipt from a link, a fragment or bare text. */
export function extractReceipt(input) {
  const s = safeDecode(String(input).trim());
  const i = s.indexOf("zip311r1");
  if (i < 0) throw new Error("no zip311r1 receipt found");
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
 *   sourceTxs      for receipts that prove where the money came from: `[{ rawTx, height }]`
 *                  for each source transaction, instead of fetching them by txid
 *
 * Resolves to `{ valid: true, network, pool, txid, mined_height, message, proven_spend_actions,
 * outputs: [{ action, recipient, zatoshis, memo }], paidToExpected }` or throws with the reason.
 * `screened: { proofs, set, minZatoshis? }` also checks screened-set proofs (`zip311s1…`) against
 * the exchange's published list, and adds `screened: { root, size, covered_zatoshis }`.
 * `public_demo: true` marks the public demo wallet's payment: anyone can sign those, so a
 * receipt for it never answers a challenge.
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
      const r = await fetchTransactionPrivately(endpoint, summary.txid, hint, { maxSet: options.maxAnonymitySet, txidOf: txidOf(summary.network) });
      ({ raw, height } = r);
      const where = r.blocks && r.blocks.length > 1 ? `blocks ${r.blocks[0]} to ${r.blocks[r.blocks.length - 1]}` : `block ${hint}`;
      fetchInfo = { mode: "block", server: endpoint, anonymity_set: r.anonymitySet, blocks: r.blocks, sees: `${where} and ${r.anonymitySet} of ${r.blocks && r.blocks.length > 1 ? "their" : "its"} transactions that could carry a receipt (each checked to exist there), not which one you checked` };
    } else {
      ({ raw, height } = await fetchTransaction(endpoint, summary.txid));
      fetchInfo = { mode: "txid", server: endpoint, sees: "the transaction id you checked (add the h= hint or pass rawTx to avoid this)" };
    }
  } else if (typeof raw === "string") {
    raw = hexToBytes(raw.trim());
  }
  // Source proofs: the receipt names earlier transactions its spent notes came from.
  const needed = JSON.parse(source_txids(receipt));
  let sources;
  if (needed.length) {
    let list = options.sourceTxs;
    if (list == null) {
      const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
      // Fetched by txid: the server learns which source transactions you checked.
      list = await Promise.all(needed.map((id) => fetchTransaction(endpoint, id)));
      fetchInfo.sources = `the source transaction id(s) ${needed.join(", ")}`;
    }
    sources = JSON.stringify(list.map((t) => ({ raw: typeof (t.rawTx ?? t.raw) === "string" ? (t.rawTx ?? t.raw) : bytesToHex(t.rawTx ?? t.raw), height: Number(t.height) })));
  }
  const v = JSON.parse(verify(receipt, raw, Number(height), !!options.regtest, sources));
  // A key-set proof on the link (`m=zip311m1…`): signed under one of a published set of keys.
  // `keySet: [hex…]` requires it to be over exactly that set.
  const ks = (safeDecode(String(input)).match(/zip311m1[A-Za-z0-9_-]+/) || [])[0];
  if (ks) {
    verify_keyset(ks, receipt);
    v.keySet = JSON.parse(key_set_keys(ks));
    if (options.keySet && [...options.keySet].map((k) => k.toLowerCase()).sort().join() !== [...v.keySet].sort().join()) throw new Error("the key-set proof is over other keys than the published set");
  } else if (options.keySet) throw new Error("the receipt carries no key-set proof");
  // A policy proof (`p=zip311p1…`): signed under a published t-of-n key.
  const pol = (safeDecode(String(input)).match(/zip311p1[A-Za-z0-9_-]+/) || [])[0];
  if (pol) v.policy = JSON.parse(verify_policy(pol, receipt));
  // `screened: { proofs, set }`: the money came from one of an exchange's screened outputs
  // (`set`, its published list), which one hidden. Each spend the receipt proves needs a proof.
  if (options.screened) {
    v.screened = JSON.parse(verify_screened(receipt, raw, Number(height), String(options.screened.proofs), String(options.screened.set)));
    if (options.screened.minZatoshis != null && v.screened.covered_zatoshis < options.screened.minZatoshis) {
      throw new Error(`the screened-set proof shows ${v.screened.covered_zatoshis} zatoshis from the list, less than ${options.screened.minZatoshis}`);
    }
  }
  // Who funded each source transaction in the clear (its transparent inputs' previous outputs).
  if (v.sources && options.sourceFunding !== false && options.sourceTxs == null) {
    const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
    const coin = summary.network === "mainnet" ? 133 : 1;
    for (const s of v.sources) {
      for (const i of s.transparent_inputs.slice(0, 16)) {
        try {
          const prev = await fetchTransaction(endpoint, i.prevout_txid);
          Object.assign(i, JSON.parse(transparent_output(prev.raw, Number(prev.height), i.prevout_index, coin, !!options.regtest)));
        } catch { /* leave the outpoint as it is */ }
      }
    }
  }
  v.local = true;
  v.fetch = fetchInfo;
  // Exchange deposit (ZIP 320 TEX two-step): also check the second transaction.
  const second = /(?:^|\n)second-tx:([0-9a-f]{64})(?:\n|$)/.exec(v.message || "");
  if (second && /(?:^|\n)tex-deposit:/.test(v.message)) {
    let tx2 = options.secondRawTx != null ? { raw: typeof options.secondRawTx === "string" ? hexToBytes(options.secondRawTx.trim()) : options.secondRawTx, height: options.secondHeight ?? height } : null;
    if (!tx2) {
      const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
      // Usually mined in the same block as the first step: fetch that block, else by txid.
      tx2 = await fetchTransactionPrivately(endpoint, second[1], Number(height)).catch(() => fetchTransaction(endpoint, second[1]));
    }
    v.deposit = JSON.parse(check_tex_deposit(receipt, raw, Number(height), tx2.raw, Number(tx2.height), !!options.regtest));
  }
  if (options.challenge != null) {
    if (v.public_demo) throw new Error("this receipt is from the public demo wallet, whose key anyone has: it can't answer a challenge");
    if (challengeIn(v.message) !== String(options.challenge)) throw new Error("the receipt does not sign the expected challenge");
  }
  if (options.minZatoshis != null && !options.expectAddress) throw new Error("minZatoshis needs expectAddress: the minimum is checked against what that address received");
  if (options.expectAddress) {
    const paid = paidTo([v], options.expectAddress);
    if (paid === 0) throw new Error("no disclosed output paid the expected address");
    if (options.minZatoshis != null && paid < options.minZatoshis) throw new Error(`paid ${paid} zatoshis, less than ${options.minZatoshis}`);
    v.paidToExpected = paid;
  }
  return v;
}

// What verified receipts paid `ua`, by Orchard receiver. The address must be on the payments'
// network (receiver bytes carry none), and outputs disclosed without their memo don't count:
// they don't show the payee can receive the note.
// The challenge a receipt signs: the first line starting "challenge:", if its value is 6 to 64
// lowercase hex digits (the API reads it the same way; lines end at \n or \r\n).
export function challengeIn(message) {
  const line = String(message || "").split("\n").map((l) => l.replace(/\r$/, "")).find((l) => l.startsWith("challenge:"));
  const c = line ? line.slice("challenge:".length) : "";
  return /^[0-9a-f]{6,64}$/.test(c) ? c : null;
}

// Testnet and regtest share a coin type, so only mainnet versus the test networks is checked.
const sameNet = (a, b) => (a === "mainnet") === (b === "mainnet");

function paidTo(results, ua) {
  const network = results[0].network;
  if (!sameNet(address_network(ua), network)) throw new Error(`the expected address is a ${address_network(ua)} address, but the payment is on ${network}`);
  const want = orchard_receiver_hex(ua);
  return results.flatMap((v) => v.outputs).filter((o) => !o.memo_withheld && orchard_receiver_hex(o.recipient) === want).reduce((s, o) => s + o.zatoshis, 0);
}

/**
 * Verifies an incoming receipt (`zrcin1…`): the RECIPIENT proves it was paid, for an accountant or
 * a lender, without a viewing key. Options as for `verifyReceipt` (endpoint, rawTx, height,
 * regtest, expectAddress). Resolves to `{ valid, kind: "incoming", recipient, outputs, … }`.
 */
export async function verifyIncoming(input, options = {}) {
  await load();
  const s = safeDecode(String(input).trim());
  const i = s.indexOf("zrcin1");
  if (i < 0) throw new Error("no zrcin1 incoming receipt found");
  const text = s.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
  const summary = JSON.parse(inspect_incoming(text));
  let raw = options.rawTx, height = options.height;
  if (raw == null) {
    const endpoint = options.endpoint || DEFAULT_ENDPOINTS[summary.network];
    const hint = options.height ?? heightHint(input);
    ({ raw, height } = hint ? await fetchTransactionPrivately(endpoint, summary.txid, hint, { txidOf: txidOf(summary.network) }) : await fetchTransaction(endpoint, summary.txid));
  } else if (typeof raw === "string") {
    raw = hexToBytes(raw.trim());
  }
  const v = JSON.parse(verify_incoming(text, raw, Number(height), !!options.regtest));
  if (options.expectAddress) {
    if (!sameNet(address_network(options.expectAddress), v.network)) throw new Error(`the expected address is a ${address_network(options.expectAddress)} address, but the payment is on ${v.network}`);
    if (orchard_receiver_hex(v.recipient) !== orchard_receiver_hex(options.expectAddress)) throw new Error("the receipt proves a different receiving address");
  }
  if (options.minZatoshis != null) {
    const total = v.outputs.reduce((s, o) => s + o.zatoshis, 0);
    if (total < options.minZatoshis) throw new Error(`received ${total} zatoshis, less than ${options.minZatoshis}`);
  }
  return v;
}

/**
 * Verifies a batch link (`zip311b1…`): checks it is complete and consistent (every receipt signs
 * `batch:<id> <i>/<n>`), then verifies each receipt against the chain.
 * Resolves to `{ id, results: [verifyReceipt result, …], totals: { recipient: zatoshis } }`.
 * Options are passed to each `verifyReceipt` call, except `rawTx`/`height`.
 */
function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export async function verifyBatch(input, options = {}) {
  await load();
  const text = extractBatch(input);
  if (!text) throw new Error("no zip311b1 batch found");
  const { id, receipts, aggregated } = JSON.parse(open_batch(text));
  const { rawTx, height, expectAddress, minZatoshis, challenge, ...rest } = options;
  const results = [];
  // Fetches overlap; each proof is checked as its transaction arrives.
  // The link's block hints (`&h=a,b,c`, one per receipt): fetch each payment by block, not txid.
  const m = /[#?&]h=(\d{1,9}(?:,\d{1,9})*)(?:&|$)/.exec(safeDecode(String(input)));
  const hints = m ? m[1].split(",").map(Number) : [];
  const useHints = hints.length === receipts.length;
  if (aggregated) {
    // One proof for every spend: fetch every transaction, then check the receipts and the proof together.
    const txs = await Promise.all(receipts.map(async (r, i) => {
      const s = JSON.parse(inspect(r));
      const endpoint = rest.endpoint || DEFAULT_ENDPOINTS[s.network];
      const t = useHints
        ? await fetchTransactionPrivately(endpoint, s.txid, hints[i], { txidOf: (raw, h) => txid_of(raw, h, s.network === "mainnet" ? 133 : 1) })
        : await fetchTransaction(endpoint, s.txid);
      return { raw: Array.from(t.raw, (b) => b.toString(16).padStart(2, "0")).join(""), height: t.height };
    }));
    results.push(...JSON.parse(verify_aggregated(text, JSON.stringify(txs), !!rest.regtest)));
  } else {
    results.push(...(await Promise.all(receipts.map((r, i) => verifyReceipt(useHints ? `${r}&h=${hints[i]}` : r, rest)))));
  }
  const totals = {};
  for (const v of results) for (const o of v.outputs) totals[o.recipient] = (totals[o.recipient] || 0) + o.zatoshis;
  const out = { id, results, totals };
  // One request answered by several payments: every receipt signs its challenge.
  if (challenge != null) {
    if (results.some((v) => v.public_demo)) throw new Error("a payment in the batch is from the public demo wallet, whose key anyone has: it can't answer a challenge");
    if (!results.every((v) => challengeIn(v.message) === String(challenge))) throw new Error("not every payment in the batch signs the expected challenge");
  }
  // A same-payer proof with the batch (`k=zip311k1…`): every payment signed by one key.
  const link = (safeDecode(String(input)).match(/zip311k1[A-Za-z0-9_-]+/) || [])[0];
  if (link) out.onePayer = { spends: verify_same_payer(link, text) };
  if (expectAddress) {
    out.paidToExpected = paidTo(results, expectAddress);
    if (out.paidToExpected === 0) throw new Error("no disclosed output in the batch paid the expected address");
    if (minZatoshis != null && out.paidToExpected < minZatoshis) throw new Error(`the batch paid ${out.paidToExpected} zatoshis, less than ${minZatoshis}`);
  } else if (minZatoshis != null) {
    throw new Error("minZatoshis needs expectAddress");
  }
  return out;
}

/**
 * Verifies a proof of income (`zip311i1…`): the wallet behind it received at least
 * `at_least_zatoshis` across `payments` separate payments, no payment's amount shown. Fetches
 * each payment among its block's transactions. Options: `endpoint`, `minZatoshis`, `minPayments`,
 * `challenge`.
 */
export async function verifyIncome(input, options = {}) {
  await load();
  const text = (safeDecode(String(input)).match(/zip311i1[A-Za-z0-9_-]+/) || [])[0];
  if (!text) throw new Error("no zip311i1 proof of income found");
  const info = JSON.parse(inspect_income(text));
  if (options.challenge != null && challengeIn(info.message) !== String(options.challenge)) throw new Error("the proof doesn't sign the expected challenge");
  const endpoint = options.endpoint || DEFAULT_ENDPOINTS[info.network];
  const txs = await Promise.all(info.items.map(async (it) => {
    const t = await fetchTransactionPrivately(endpoint, it.txid, it.height, { txidOf: (raw, h) => txid_of(raw, h, info.network === "mainnet" ? 133 : 1) });
    return { raw: Array.from(t.raw, (b) => b.toString(16).padStart(2, "0")).join(""), height: t.height };
  }));
  const v = JSON.parse(verify_income(text, JSON.stringify(txs)));
  if (options.minZatoshis != null && v.at_least_zatoshis < options.minZatoshis) throw new Error(`the proof shows ${v.at_least_zatoshis} zatoshis, less than ${options.minZatoshis}`);
  if (options.minPayments != null && v.payments < options.minPayments) throw new Error(`the proof counts ${v.payments} payments, fewer than ${options.minPayments}`);
  return { valid: true, kind: "income", network: info.network, ...v };
}

/** Extracts a `zsig1…` sign-in from a link, a fragment or bare text, or returns null. */
export function extractSignIn(input) {
  const s = safeDecode(String(input).trim());
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
 * locally with WebCrypto. You must say whom you trust: `issuer` (the Receipts server's base URL;
 * its keys are fetched from `<issuer>/.well-known/jwks.json` and the token's `iss` must match)
 * or `jwks` (that key set, as an object or URL). A token naming some other issuer is refused,
 * since anyone can sign a token and host keys. Resolves to the signed claims, with any revealed
 * hidden claims under `revealed`. Throws if anything doesn't check out, and for test-mode or
 * sandbox attestations unless `allowTest` is set.
 */
export async function verifyAttestation(presentation, { issuer, jwks, allowTest = false } = {}) {
  if (!issuer && !jwks) throw new Error("verifyAttestation needs { issuer } or { jwks }: the server you trust");
  const [jwt, ...disclosures] = String(presentation).trim().split("~");
  const [h, p, s] = jwt.split(".");
  if (!s) throw new Error("not a JWT");
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  if (header.alg !== "EdDSA") throw new Error("unsupported alg");
  const norm = (u) => String(u).replace(/\/+$/, "");
  if (issuer && norm(claims.iss) !== norm(issuer)) throw new Error(`issued by ${claims.iss}, not ${issuer}`);
  let set = jwks;
  if (!set || typeof set === "string") set = await (await fetch(set || `${norm(issuer)}/.well-known/jwks.json`)).json();
  const jwk = (set.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown key id");
  const key = await crypto.subtle.importKey("raw", b64urlDecode(jwk.x), { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw new Error("signature does not verify");
  const revealed = Object.create(null);
  for (const d of disclosures.filter(Boolean)) {
    const digest = b64urlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(d)));
    if (!(claims._sd || []).includes(digest)) throw new Error("a disclosure is not part of this attestation");
    const [, name, value] = JSON.parse(new TextDecoder().decode(b64urlDecode(d)));
    if (Object.prototype.hasOwnProperty.call(revealed, name)) throw new Error("duplicate disclosure");
    revealed[name] = value;
  }
  // Test-mode and sandbox attestations are signed with the same key as live ones; the signed
  // claims say which they are, so refuse them unless the caller asks for test facts.
  if (!allowTest && (claims.livemode === false || claims.sandbox === true)) {
    throw new Error("test-mode attestation (issued with a test key or paid with a sandbox fixture); pass { allowTest: true } to accept it");
  }
  delete claims._sd;
  delete claims._sd_alg;
  return { ...claims, revealed: { ...revealed } };
}

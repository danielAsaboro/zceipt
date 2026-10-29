// Zceipt verifier page. The receipt lives in the URL fragment (#zip311r1…), which browsers
// never send to any server. The page talks to one lightwalletd server of the viewer's choice
// (the block's transaction list and the transactions themselves), and nothing else.

// grpc-web servers that allow browser (CORS) requests, tried in order. Settings overrides them.
const ENDPOINT_LISTS = {
  mainnet: ["https://zcash-mainnet.chainsafe.dev"],
  testnet: ["https://zcash-testnet.chainsafe.dev"],
};
const ENDPOINTS = Object.fromEntries(Object.entries(ENDPOINT_LISTS).map(([k, v]) => [k, v[0]]));

// Links can carry other text with a stray "%" (`&note=50%off`): never let that stop a check.
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

const $ = (s) => document.querySelector(s);
const worker = new Worker("./worker.js", { type: "module" });
let seq = 0;
const pending = new Map();
worker.onmessage = (e) => {
  const { id, ok, result, error } = e.data;
  const p = pending.get(id);
  pending.delete(id);
  ok ? p.resolve(result) : p.reject(new Error(error));
};
const call = (op, args = {}) =>
  new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });

// Start building the verifying key in the worker as soon as the page opens (about 8s, once).
// Quick calls (decoding, address checks) run on this thread so they never wait behind it.
const warmStart = performance.now();
const warmed = call("warm")
  .then(() => {
    const el = document.querySelector("#warm");
    // Ready in the background; the verify step says how long the first check took.
    if (el) el.dataset.state = "ready";
  })
  .catch(() => {});
import { fetchTipHeight, fetchTransactionPrivately, heightHint } from "./zceipt/grpc.js";
import { parseRequestLink } from "./zceipt/index.js";
import { SAMPLE_REAL, SAMPLE_EDITED, SAMPLE_OBSERVER, SAMPLE_HEIGHT, SAMPLE_BATCH, SAMPLE_BATCH_HEIGHTS, SAMPLE_TX, SAMPLE_SOURCE, SAMPLE_MERCHANT, DEMO_PREPARED, DEMO_KEY, DEMO_HEIGHT, SAMPLE_SCREENED, SAMPLE_SCREENED_PROOF, SAMPLE_SCREENED_SET } from "./samples.js";
import initLocal, { inspect as inspectLocal, orchard_receiver_hex, address_network, open_batch, secret_kind, check_payment_uri, check_tex_deposit, source_txids, transparent_output, inspect_incoming, verify_payment_request, txid_of, sign_prepared_text, claimed_outputs, qr_svg, verify_same_payer, verify_screened, verify_keyset, verify_policy } from "./zceipt/pkg/zceipt_wasm.js";
const local = initLocal();
// Block-level fetches check each transaction the server sends hashes to the txid asked for.
const txidOf = (network) => (raw, height) => txid_of(raw, height, network === "mainnet" ? 133 : 1);
const quick = async (op, args) => {
  await local;
  if (op === "inspect") return JSON.parse(inspectLocal(args.receipt));
  if (op === "receiver") return orchard_receiver_hex(args.ua);
  // An expected address must be on the payment's network: receiver bytes carry no network.
  if (op === "receiverOn") {
    const n = address_network(args.ua);
    if ((n === "mainnet") !== (args.network === "mainnet")) throw new Error(`that is a ${n} address, but this payment is on ${args.network}`);
    return orchard_receiver_hex(args.ua);
  }
  if (op === "batch") return JSON.parse(open_batch(args.batch));
};

// ---------- grpc-web: CompactTxStreamer.GetTransaction ----------
function hexToBytes(h) {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}
function displayTxidToInternal(t) {
  return hexToBytes(t).reverse();
}
function readVarint(buf, pos) {
  let result = 0n, shift = 0n;
  for (;;) {
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7n;
  }
  return [result, pos];
}
async function fetchRawTx(endpoint, displayTxid) {
  const hash = displayTxidToInternal(displayTxid);
  const msg = new Uint8Array(2 + 32);
  msg[0] = 0x1a; msg[1] = 0x20; msg.set(hash, 2); // TxFilter.hash = field 3
  const frame = new Uint8Array(5 + msg.length);
  frame[0] = 0;
  new DataView(frame.buffer).setUint32(1, msg.length);
  frame.set(msg, 5);
  const res = await fetch(`${endpoint.replace(/\/$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction`, {
    method: "POST",
    headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" },
    body: frame,
  });
  if (!res.ok) throw new Error(`lightwalletd answered HTTP ${res.status}`);
  const status = res.headers.get("grpc-status");
  if (status && status !== "0") throw new Error(safeDecode(res.headers.get("grpc-message") || `grpc-status ${status}`));
  const body = new Uint8Array(await res.arrayBuffer());
  let pos = 0, data = null, height = 0n, trailer = "";
  while (pos + 5 <= body.length) {
    const flag = body[pos];
    const len = new DataView(body.buffer, body.byteOffset + pos + 1, 4).getUint32(0);
    const chunk = body.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (flag & 0x80) { trailer += new TextDecoder().decode(chunk); continue; }
    let p = 0;
    while (p < chunk.length) {
      const [key, p2] = readVarint(chunk, p); p = p2;
      const field = Number(key >> 3n), wire = Number(key & 7n);
      if (wire === 2) {
        const [l, p3] = readVarint(chunk, p); p = p3;
        const v = chunk.subarray(p, p + Number(l)); p += Number(l);
        if (field === 1) data = v;
      } else if (wire === 0) {
        const [v, p3] = readVarint(chunk, p); p = p3;
        if (field === 2) height = v;
      } else throw new Error("unexpected protobuf wire type");
    }
  }
  const m = trailer.match(/grpc-status:\s*(\d+)/);
  if (m && m[1] !== "0") {
    const why = (trailer.match(/grpc-message:\s*(.*)/) || [])[1] || "";
    throw new Error(`lightwalletd: ${safeDecode(why.trim()) || "status " + m[1]}`);
  }
  if (!data) throw new Error("lightwalletd returned no transaction");
  return { raw: data, height: Number(height) };
}

const regtest = () => $("#regtest").checked;
// A local regtest chain is a developer's setup: the switch shows only when the page is opened
// with ?regtest, and only the viewer ticks it. A link must not point the verifier at another
// chain by itself.
if (new URLSearchParams(location.search).has("regtest")) $("#regtestRow").hidden = false;

// ---------- proof requests ("prove it's you") ----------
// A verifier creates a request: a random challenge plus the payee and minimum amount they
// expect. The payer's receipt must sign `challenge:<code>`, so a receipt someone else made
// (or an old one) can't be replayed. Requests are remembered only in this browser, so the
// checks compare against what *you* asked for, not against whatever the returned link says.
const REQ_KEY = "zceipt.requests.v1";
const loadRequests = () => { try { return JSON.parse(localStorage.getItem(REQ_KEY) || "{}"); } catch { return {}; } };
const USED_KEY = "receipts.usedPayments";
const loadUsed = () => { try { return JSON.parse(localStorage.getItem(USED_KEY) || "{}"); } catch { return {}; } };
const saveUsed = (txid, code) => { try { localStorage.setItem(USED_KEY, JSON.stringify({ ...loadUsed(), [txid]: code })); } catch {} };
const saveRequest = (code, r) => { try { const all = loadRequests(); all[code] = r; localStorage.setItem(REQ_KEY, JSON.stringify(all)); } catch {} };
const newCode = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
// The request in this link, or null (see parseRequestLink: the code, a whole-zatoshi minimum
// and an address-shaped payee, or nothing).
const requestFromUrl = () => parseRequestLink(location.hash, location.search);
// The challenge a receipt signs: the first line starting "challenge:", if its value is 6 to 64
// lowercase hex digits (the API reads it the same way; lines end at \n or \r\n).
function challengeIn(message) {
  const line = String(message || "").split("\n").map((l) => l.replace(/\r$/, "")).find((l) => l.startsWith("challenge:"));
  const c = line ? line.slice("challenge:".length) : "";
  return /^[0-9a-f]{6,64}$/.test(c) ? c : null;
}

// ---------- UI ----------
// "block 4,500,997", or "blocks 4,500,996 to 4,500,999" when a quiet block's run of 4 joined the cover.
const blockRange = (f) => (f.blocks && f.blocks.length > 1 ? `blocks ${f.blocks[0].toLocaleString()} to ${f.blocks[f.blocks.length - 1].toLocaleString()}` : `block ${f.block.toLocaleString()}`);
// The tab title carries the verdict of whatever card is showing (and any later change to it,
// such as PAID TO YOU).
new MutationObserver(() => {
  const stamp = $("#result").hidden ? "" : $("#result .stamp")?.textContent.trim();
  document.title = stamp ? `${stamp} · Zceipt` : "Zceipt · prove one Zcash payment";
}).observe($("#result"), { attributes: true, attributeFilter: ["hidden"], childList: true, subtree: true, characterData: true });
// The placeholder shows only while there is no result.
new MutationObserver(() => { $("#empty").hidden = !$("#result").hidden; }).observe($("#result"), { attributes: true, attributeFilter: ["hidden"] });
// Blocks on top of a payment before it counts as settled (the CLI and API use the same number).
const FINAL = 10;
const confirmations = (v) => (fetchMode && fetchMode.tip && v.mined_height ? Math.max(0, fetchMode.tip - v.mined_height + 1) : null);
// Each check bumps this; an earlier check still in flight then stops touching the page, so a
// new link can't be overwritten by the old one's late result.
let runGen = 0;
// What the showing card has checked (see paintStamp).
let verdict = {};
const steps = ["decode", "fetch", "verify"];
function setStep(name, state, text) {
  const el = document.querySelector(`[data-step="${name}"]`);
  el.dataset.state = state;
  if (text !== undefined) el.querySelector(".detail").textContent = text;
}
function resetSteps() {
  for (const s of steps) setStep(s, "idle", "");
}
const short = (s, n = 10) => (s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);
const zec = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");

// Shows the result panel; on a phone it moves above the form and scrolls into view, so a link
// opens straight onto the payment.
function revealResult() {
  $("#result").hidden = false;
  document.body.classList.add("has-result");
  $("#result").focus({ preventScroll: true });
  if (window.matchMedia("(max-width: 860px)").matches) $("#right")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Three different failures, said differently: the link is incomplete or isn't a receipt; the
// chain couldn't be reached; the receipt was altered or forged.
// An empty box says what it needs, in the browser's own bubble, until it is typed in.
function need(sel, what) {
  const el = $(sel);
  el.setCustomValidity(what);
  el.reportValidity();
  el.addEventListener("input", () => el.setCustomValidity(""), { once: true });
  el.focus();
}

function showError(msg, kind = "notice", claimed = []) {
  revealResult();
  const head = { forged: "NOT VALID", unreadable: "NOT A RECEIPT", network: "COULD NOT CHECK", notice: "NOT VALID", other: "OTHER FORMAT", secret: "DON'T SHARE THAT", unproven: "NOT PROVEN BY THE PAYER" }[kind];
  const plain = {
    forged: "This receipt was changed after it was made, or it was never made by the wallet that paid. Don't rely on it.",
    unreadable: "The link may be cut off (some apps shorten long links), or what was pasted isn't a receipt. Ask for the whole link, or the receipt as a file.",
    network: "The receipt wasn't checked: the chain server couldn't be reached or doesn't have the transaction yet. Try again in a minute, or pick another server in Settings.",
    notice: "",
    other: "",
    secret: "",
    unproven: "The payment above is on chain, but this receipt doesn't prove the payer made it: it was sent by someone who only saw the payment, or changed before it was signed. Don't rely on it as proof of who paid.",
  }[kind];
  $("#result").innerHTML = `
    <div class="ticket invalid" data-kind="${kind}">
      <div class="stamp ${kind === "network" || kind === "other" || kind === "secret" ? "warn" : "bad"}">${head}</div>
      ${claimed.map((o) => `<div class="line"><span class="k">CLAIMS</span><span class="v"><span class="amount">${zec(o.zatoshis)} <small>${UNIT}</small></span> to <span class="mono addr" title="${escapeHtml(o.recipient)}">${escapeHtml(short(o.recipient, 12))}</span>${o.memo ? ` · “${escapeHtml(o.memo)}”` : ""}</span></div>`).join("")}
      ${plain ? `<p class="why">${escapeHtml(plain)}</p><p class="fine">Detail: ${escapeHtml(msg)}</p>` : `<p class="why">${escapeHtml(msg)}</p>`}
      ${kind === "other" || kind === "secret" ? "" : `<p class="fine">A receipt is only valid if the sender's proof, signature and the on-chain transaction all agree.</p>`}
    </div>`;
}
// A refusal in words first; the technical reason stays in the card's detail line.
function plainFailure(m) {
  if (/signature|proof/i.test(m)) return "changed after it was made, or not made by the wallet that paid";
  return m;
}
// Address errors in words a shop owner can act on.
function friendlyAddressError(e, input = "") {
  const m = String(e && e.message ? e.message : e);
  if (/Bech32|not a unified address|checksum|invalid/i.test(m) && /^u(test|regtest)?1/.test(input)) return "That address has a typo or is cut off. Copy it again from your wallet.";
  if (/Bech32|not a unified address|checksum|invalid/i.test(m)) return "That doesn't look like a Zcash shielded address (it should start with u1…, or utest1… on testnet). Copy it again from your wallet.";
  if (/no Orchard receiver/i.test(m)) return "That address has no shielded (Orchard) part, so a receipt can't be checked against it. Use your wallet's unified address.";
  return m;
}

// Also shows control characters and bidi overrides as \u{..}, so text a sender chose (a memo,
// a message) can't reorder or hide what the page prints.
function escapeHtml(s) {
  return String(s)
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u{${c.charCodeAt(0).toString(16)}}`)
    .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function localBadge() {
  const f = fetchMode || {};
  const sees =
    f.mode === "offline" ? "No server was contacted: you supplied the transaction."
    : f.mode === "offline-sample" ? "No server answered, so nothing about this check reached one."
    : f.mode === "block" ? (f.set < 4
      ? `${escapeHtml(f.host)} saw a request for ${blockRange(f)}, which ${f.blocks && f.blocks.length > 1 ? "have" : "has"} only ${f.set} transaction${f.set === 1 ? "" : "s"} that could carry a receipt, so it can narrow the one you checked down to ${f.set === 1 ? "it" : "those"}.`
      : `${escapeHtml(f.host)} saw a request for ${blockRange(f)} and the ${f.set} transactions in ${f.blocks && f.blocks.length > 1 ? "them" : "it"} that could carry a receipt, not which one you checked.`)
    : f.mode === "batch-blocks" ? `${escapeHtml(f.host)} saw requests for ${f.blocks.length} block${f.blocks.length > 1 ? "s" : ""} (${f.set} transactions in all), not which transactions are in the batch. It can tell the requests came from one visitor at one time.`
    : f.mode === "batch-txids" ? `${escapeHtml(f.host)} saw the ids of all ${f.n} transactions you checked, together, so it can tell they belong to one batch. Links with <code>h=</code> block hints avoid this.`
    : `${escapeHtml(f.host || "The server")} saw which transaction you checked. Links with an <code>h=</code> block hint avoid this.`;
  const second = f.second ? " The deposit's second step (a public transparent transaction) was fetched by its id." : "";
  const sources = f.sources ? ` The source transaction${f.sources > 1 ? "s" : ""} the sender named (and the outputs that funded ${f.sources > 1 ? "them" : "it"}) were fetched by id, so the server saw those ids.` : "";
  return `<div class="local" data-mode="${f.mode || "txid"}"><strong>Verified on this device.</strong> The receipt never left your browser; the proof was checked here in WebAssembly. ${sees}${second}${sources} The receipt has been removed from this tab's address bar so browser history and sync don't keep it.</div>`;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// The currency on the result being shown: testnet coins are TAZ, not ZEC.
let UNIT = "ZEC";
const unitFor = (network) => (network === "mainnet" ? "ZEC" : "TAZ");

function render(v, net) {
  UNIT = unitFor(v.network);
  const rows = v.outputs
    .map(
      (o) => `
      <div class="line paid">
        <span class="k">PAID</span>
        <span class="v amount">${zec(o.zatoshis)} <small>${UNIT}</small></span>
      </div>
      <div class="line"><span class="k">TO</span><span class="v mono addr" title="${o.recipient}">${short(o.recipient, 14)}</span></div>
      ${o.memo ? `<div class="line"><span class="k">MEMO</span><span class="v memo">“${escapeHtml(o.memo)}”</span></div>` : o.memo_withheld ? `<div class="line"><span class="k">MEMO</span><span class="v"><small>withheld by the sender (the receipt can't open it)</small></span></div>` : ""}
      <div class="dash"></div>`
    )
    .join("");
  revealResult();
  $("#result").innerHTML = `
    <div class="ticket">
      <div class="head">
        <div class="brand">RECEIPT</div>
        <div class="sub">Zcash · ${v.network} · ${v.pool} pool</div>
      </div>
      <div class="dash"></div>
      ${rows}
      <div class="line"><span class="k">TX</span><span class="v mono" title="${v.txid}">${short(v.txid, 8)}</span></div>
      ${fetchMode && fetchMode.mode === "offline-sample"
        ? `<div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()} <small>(published with the sample, not checked)</small></span></div>
      <p class="fine">Checked offline: no chain server answered, so this sample was checked against its published transaction (testnet ${short(v.txid, 6)}). The proof and signature are real; that the transaction is in the chain was not checked this time.</p>`
        : fetchMode && fetchMode.mode === "offline"
        ? `<div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()} <small>(as you gave it, not checked)</small></span></div>
      <p class="fine">Offline check: this receipt matches the transaction you pasted. Whether that transaction was mined was not checked; fetch it from a server to confirm.</p>`
        : `<div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()}${confirmations(v) != null ? ` <small>(${confirmations(v).toLocaleString()} confirmation${confirmations(v) === 1 ? "" : "s"}${confirmations(v) < FINAL ? ", not final yet" : ""})</small>` : ` <small>(confirmations unknown: the server didn't say its tip)</small>`}</span></div>${fetchMode && fetchMode.time ? `<div class="line"><span class="k">DATE</span><span class="v">${new Date(fetchMode.time * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</span></div>` : ""}`}
      ${(v.sender_addresses || []).map((s) => `<div class="line"><span class="k">FROM</span><span class="v mono addr" title="${s}">${short(s, 14)} <small>(the signer controls it)</small></span></div>`).join("")}
      ${(v.sources || []).map((s) => `<div class="line"><span class="k">FUNDS</span><span class="v">${s.zatoshis != null ? `${zec(s.zatoshis)} ${UNIT} note ` : "spent note "}from <span class="mono" title="${s.source_txid}">${short(s.source_txid, 6)}</span> output ${s.source_action} <small>(block ${s.source_height.toLocaleString()}, proven)</small></span></div>
      ${s.transparent_inputs.map((i) => `<div class="line"><span class="k"></span><span class="v"><small>${i.address ? `funded in the clear: ${zec(i.zatoshis)} ${UNIT} from <span class="mono" title="${i.address}">${short(i.address, 8)}</span>` : `spent transparent output ${short(i.prevout_txid, 6)}:${i.prevout_index}`}</small></span></div>`).join("")}
      ${s.transparent_inputs.length ? "" : `<div class="line"><span class="k"></span><span class="v"><small>that transaction was itself funded from shielded notes (not shown)</small></span></div>`}`).join("")}
      ${v.message ? `<div class="line"><span class="k">MESSAGE</span><span class="v text">${escapeHtml(v.deposit ? v.message.split("\n").filter((l) => !/^(tex-deposit|second-tx):/.test(l)).join("\n") : v.message)}</span></div>` : ""}
      ${v.deposit ? `<div class="dash"></div>
      <div class="line paid"><span class="k">DEPOSIT</span><span class="v amount">${zec(v.deposit.deposit_zatoshis)} <small>${UNIT}</small></span></div>
      <div class="line"><span class="k">EXCHANGE</span><span class="v mono addr" title="${v.deposit.tex_address}">${short(v.deposit.tex_address, 14)}</span></div>
      <div class="line"><span class="k">VIA</span><span class="v mono">${short(v.deposit.first_tx, 6)} → ${short(v.deposit.second_tx, 6)}</span></div>
      <div class="local" data-mode="txid"><strong>Exchange deposit (ZIP 320).</strong> The sender proved they made this two-step deposit to the exchange's TEX address. ${escapeHtml(v.deposit.warning)}</div>` : ""}
      <div class="dash"></div>
      ${fetchMode && fetchMode.mode === "offline" ? `<div class="stamp warn">MATCHES THE PASTED TRANSACTION</div>` : confirmations(v) == null ? `<div class="stamp warn">VERIFIED · CONFIRMATIONS UNKNOWN</div>` : confirmations(v) < FINAL ? `<div class="stamp warn">VERIFIED · NOT FINAL YET</div>` : `<div class="stamp warn">VERIFIED · RECIPIENT NOT CHECKED</div>`}
      <ul class="facts">
        <li>Signed with the key that spent the money in this payment (a zero-knowledge proof and a signature over this receipt).</li>
        ${v.keySetSize ? `<li><strong>One of ${v.keySetSize} published keys:</strong> signed under one of the keys this link's proof lists, not saying which. Compare them with the set the payer's organization publishes.</li>` : ""}
        ${v.policy ? `<li><strong>Signed under the key ${escapeHtml(v.policy.key.slice(0, 16))}…</strong>, which the proof calls a ${v.policy.claimed_threshold}-of-${v.policy.claimed_holders} key. That split is the prover's claim, not checked: compare the key and the split with the treasury's published commitment.</li>` : ""}
        ${v.outputs.length ? `<li>The amount, recipient and memo above were opened from ${fetchMode && fetchMode.mode === "offline" ? "the transaction you pasted" : "the transaction on chain"}.</li>` : ""}
        ${(v.sources || []).length ? `<li>The sender proved where the spent money came from (FUNDS above): only that link, read from the chain.</li>` : ""}
        ${(v.sender_addresses || []).length || (v.sources || []).length ? `${(v.sender_addresses || []).length ? `<li>Whoever signed this receipt also controls the FROM address above.</li>` : ""}<li><strong>Not revealed:</strong> the sender's balance or any other transaction.</li>` : `<li><strong>Not revealed:</strong> the sender's address, balance, or any other transaction.</li>`}
        ${challengeIn(v.message) && challengeIn(v.message) === requestFromUrl()?.code
          ? `<li><strong>Made for one request:</strong> it answers the request in this link, so it was made for you only if you created that request.</li>`
          : `<li id="reuseWarn"><strong>Check before relying on it:</strong> the sender chose which outputs to show, and anyone holding this receipt can show it. Check the recipient below is you, or ask for a receipt that answers your own request.</li>`}
      </ul>
      ${localBadge()}
      <div id="reqChecks"></div>
      <div id="screenedOut"></div>
      <details class="screened"><summary>Check where the money came from</summary>
        <label for="screenedSet">The exchange's screened list (note commitments, one per line)</label>
        <textarea id="screenedSet" spellcheck="false"></textarea>
        <label for="screenedProof">The payer's screened-set proof (zip311s1…)</label>
        <textarea id="screenedProof" spellcheck="false"></textarea>
        <button type="button" id="screenedBtn">Check</button>
      </details>
      <p class="fine"><button type="button" class="ghost" id="copyLink">Copy link</button> <button type="button" class="ghost" id="saveFile">Save as file</button> <button type="button" class="ghost" id="printBtn">Print or save as PDF</button></p>
      <div class="check">
        <label for="mine">Was it paid to you? Your address</label>
        <div class="row"><input id="mine" placeholder="${v.network === "mainnet" ? "u1…" : "utest1…"}" autocomplete="off" spellcheck="false"><button id="mineBtn">Check</button></div>
        <label class="fine"><input type="checkbox" id="rememberMine"> Remember on this device</label>
        <div id="mineOut" class="fine"></div>
      </div>
    </div>`;
  verdict = { v, paid: null, req: null };
  paintStamp();
  $("#screenedBtn").onclick = () => checkScreened($("#screenedProof").value, $("#screenedSet").value);
  if (pendingScreened) {
    const { proofs, set } = pendingScreened;
    pendingScreened = null;
    checkScreened(proofs, set);
  }
  renderRequestChecks(v);
  shareButtons(`receipt-${v.txid.slice(0, 12)}`);
  $("#mineBtn").onclick = async () => {
    const ua = $("#mine").value.trim();
    if (!ua) return need("#mine", "Paste your address.");
    if (secret_kind(ua)) {
      $("#mine").value = "";
      $("#mineOut").textContent = "That looks like a key or seed phrase, not an address. It was cleared and not stored or sent.";
      return;
    }
    try {
      const want = await quick("receiverOn", { ua, network: v.network });
      // Compare by Orchard receiver: a unified address can carry other receivers too. Outputs
      // disclosed without their memo don't show the note can be received, so they don't count.
      const got = await Promise.all(v.outputs.filter((o) => !o.memo_withheld).map((o) => quick("receiver", { ua: o.recipient })));
      const paid = got.includes(want);
      $("#mineOut").textContent = paid
        ? ua === SAMPLE_MERCHANT ? "Yes. You are viewing this as the sample's merchant, whose address this is." : "Yes. This payment went to that address (to its shielded part, which is what TO shows)."
        : "No. None of the disclosed outputs went to that address.";
      $("#mineOut").dataset.ok = paid;
      // Only if asked, and only an address this receipt paid: then the next receipt answers
      // "was I paid?" by itself.
      try { if ($("#rememberMine").checked && paid && !secret_kind(ua) && ua !== SAMPLE_MERCHANT) localStorage.setItem(MY_ADDRESS, ua); } catch { /* private mode */ }
      if (verdict.v === v) {
        verdict.paid = paid;
        paintStamp();
      }
    } catch (e) {
      $("#mineOut").textContent = friendlyAddressError(e, ua);
    }
  };
  $("#mine").onkeydown = (e) => { if (e.key === "Enter") $("#mineBtn").click(); };
  const saved = (() => { try { return localStorage.getItem(MY_ADDRESS) || ""; } catch { return ""; } })();
  $("#rememberMine").checked = !!saved;
  $("#rememberMine").onchange = (e) => { try { if (!e.target.checked) localStorage.removeItem(MY_ADDRESS); else if ($("#mine").value.trim()) localStorage.setItem(MY_ADDRESS, $("#mine").value.trim()); } catch { /* private mode */ } };
  // The real sample opens as the merchant it paid, so its first verdict answers "was I paid?".
  const as = sampleAs;
  sampleAs = null;
  if (saved || as) {
    $("#mine").value = saved || as;
    $("#mineBtn").click();
  }
}
const MY_ADDRESS = "receipts.myAddress";
// The transaction the showing card was checked against, for the screened-set check.
let lastCheck = null;
let pendingScreened = null;

// A screened-set proof: the spent note was one of the exchange's vetted outputs, which one hidden.
async function checkScreened(proofs, set) {
  const out = $("#screenedOut");
  if (!proofs.trim()) return need("#screenedProof", "Paste the payer's zip311s1… proof.");
  if (!set.trim()) return need("#screenedSet", "Paste the exchange's list.");
  try {
    await local;
    const s = JSON.parse(verify_screened(lastCheck.receiptText, lastCheck.raw, lastCheck.height, proofs, set));
    out.innerHTML = `<div class="reqbox" data-ok="true"><div class="reqhead">FUNDS FROM THE SCREENED LIST</div><ul><li data-ok="true">✓ Every spend of this payment used a note from the list of ${s.size} outputs, at least ${zec(s.covered_zatoshis)} ${UNIT} of it. Which output is not revealed.</li></ul></div>`;
  } catch (e) {
    out.innerHTML = `<div class="reqbox" data-ok="false"><div class="reqhead">NOT FROM THE SCREENED LIST</div><ul><li data-ok="false">✗ ${escapeHtml(e.message)}</li></ul></div>`;
  }
}
let sampleAs = null;

async function renderRequestChecks(v) {
  const fromUrl = requestFromUrl();
  const signed = challengeIn(v.message);
  // With no request in the link, only a request this browser made counts: the sender chose the
  // challenge, so it alone says nothing.
  if (!fromUrl && !(signed && loadRequests()[signed])) return;
  const code = fromUrl ? fromUrl.code : signed;
  const mine = loadRequests()[code];
  const req = mine || fromUrl;
  const rows = [];
  const row = (ok, text) => rows.push(`<li data-ok="${ok}">${ok ? "✓" : "✗"} ${escapeHtml(text)}</li>`);
  // A request made in this browser is the shop's own; one only in the link came with the receipt,
  // so the sender could have written it. Its checks still run, under a different heading.
  if (mine) row(true, `You created request ${code} in this browser${mine.label ? ` (“${mine.label}”)` : ""}`);
  else rows.push(`<li data-ok="info">ℹ Request ${escapeHtml(code)} wasn't made in this browser, so these checks compare the receipt with the request written in the link. Trust them only if you made that request.</li>`);
  row(signed === code, signed === code ? "The sender signed this request's challenge, so the receipt was made for this request" : "The receipt does not sign this request's challenge");
  if (req && req.to) {
    try {
      const want = await quick("receiverOn", { ua: req.to, network: v.network });
      const paid = [];
      for (const o of v.outputs) if (!o.memo_withheld && (await quick("receiver", { ua: o.recipient })) === want) paid.push(o.zatoshis);
      const total = paid.reduce((s, z) => s + z, 0);
      row(paid.length > 0, paid.length ? `Paid ${zec(total)} ${UNIT} to the requested address` : "Nothing was paid to the requested address");
      if (req.min) row(total >= req.min, `${total >= req.min ? "At least" : "Less than"} the requested ${zec(req.min)} ${UNIT}`);
    } catch (e) {
      row(false, `Could not check the payee: ${friendlyAddressError(e, req.to)}`);
    }
  }
  if (mine) ownRequestRows(row, mine, code, [{ v, time: fetchMode?.time }]);
  const ok = !rows.some((r) => r.includes('data-ok="false"'));
  if (ok && mine) saveUsed(v.txid, code);
  const head = !ok ? "REQUEST NOT SATISFIED" : mine ? "REQUEST SATISFIED" : "MATCHES THE REQUEST IN THIS LINK";
  $("#reqChecks").innerHTML = `<div class="reqbox" data-ok="${ok ? (mine ? "true" : "info") : "false"}"><div class="reqhead">${head}</div><ul>${rows.join("")}</ul></div>`;
  if (verdict.v === v) {
    verdict.req = { ok, mine: !!mine };
    paintStamp();
  }
}

// The checks only a request this browser made can carry, shared by the single and batch paths so
// neither fails open. An old payment can't answer a new request: each payment must be mined after
// the request was created, by block when the tip at creation is known, else by block time, with
// no slack; when neither is known the row fails, since "couldn't tell" must not read as paid for
// this request. And one payment answers one request: a payment that already answered another
// request in this browser fails here.
function ownRequestRows(row, mine, code, payments) {
  const one = payments.length === 1;
  const unknown = [], early = [];
  for (const { v, time } of payments) {
    const paidAt = time ? time * 1000 : confirmations(v) != null ? Date.now() - confirmations(v) * 75_000 : null;
    const fresh = mine.tip ? v.mined_height > mine.tip : paidAt != null && mine.created && paidAt >= Date.parse(mine.created);
    if (fresh) continue;
    (!mine.tip && paidAt == null ? unknown : early).push(v);
  }
  if (unknown.length) row(false, one ? "Couldn't tell when it was paid, so not that it was paid for this request" : `Couldn't tell when ${unknown.length === payments.length ? "the payments were" : `${unknown.length} of the ${payments.length} payments ${unknown.length === 1 ? "was" : "were"}`} made, so not that they were paid for this request`);
  else if (early.length) row(false, one ? `Paid in block ${early[0].mined_height.toLocaleString()}, before you created this request` : `A payment (block ${early[0].mined_height.toLocaleString()}) was made before you created this request`);
  else row(true, one ? "Paid after you created the request" : "Every payment was made after you created the request");
  const used = loadUsed();
  const prior = payments.map(({ v }) => used[v.txid]).find((p) => p && p !== code);
  if (prior) row(false, one ? `This payment already answered request ${prior} in this browser` : `A payment in this batch already answered request ${prior} in this browser`);
}

// The card's verdict, from everything checked so far. Green only for a request this browser
// made and the receipt meets in full, or a payment to the viewer's own address; never before
// the payment is final, and never for a transaction checked offline.
function paintStamp() {
  const stamp = $("#result .stamp");
  const v = verdict.v;
  if (!stamp || !v || (fetchMode && fetchMode.mode.startsWith("offline"))) return;
  // A tip the server didn't give is not ten confirmations: unknown counts as not final.
  const notFinal = confirmations(v) == null || confirmations(v) < FINAL;
  const r = verdict.req;
  // Your own "No" outranks a request written in the link.
  let text = verdict.paid === false ? "VALID · NOT TO YOUR ADDRESS" : r ? (!r.ok ? "VALID · REQUEST NOT MET" : r.mine ? "PAID AS REQUESTED" : "VERIFIED · MATCHES THE LINK'S REQUEST")
    : verdict.paid != null ? (verdict.paid ? "PAID TO YOU" : "VALID · NOT TO YOUR ADDRESS")
    : notFinal ? "VERIFIED" : "VERIFIED · RECIPIENT NOT CHECKED";
  let good = !notFinal && verdict.paid !== false && (r ? r.ok && r.mine : verdict.paid === true);
  // The public demo wallet's key is in this page: its receipts show how it works, not who paid.
  if (v.public_demo) {
    text = "VALID · DEMO WALLET (KEY IS PUBLIC)";
    good = false;
  }
  if (notFinal) text += confirmations(v) == null ? " · CONFIRMATIONS UNKNOWN" : " · NOT FINAL YET";
  stamp.textContent = text;
  stamp.className = good ? "stamp good" : "stamp warn";
  // Only a request this browser made rules out a receipt shown again: a payment to you could be
  // an old one.
  const warn = document.getElementById("reuseWarn");
  if (warn) {
    warn.hidden = !!(r && r.ok && r.mine);
    if (verdict.paid) warn.innerHTML = "<strong>Shown again?</strong> Anyone holding this receipt can show it. For an order, ask for a receipt that answers your own request.";
  }
}

// zreceipt (a separate project) also writes links as zip311r1 + base64url, but of JSON. Say so
// instead of failing with a decode error.
const ZRECEIPT_NOTE = "This is a zreceipt link (github.com/Cosmiq2025/zreceipt), a different format that discloses an output without proving who sent it. Open it with zreceipt's verifier.";

async function run(receiptText) {
  const gen = ++runGen;
  const ok = () => gen === runGen;
  $("#result").hidden = true;
  $("#progress").hidden = false;
  resetSteps();
  let summary;
  try {
    ok() && setStep("decode", "busy");
    summary = await quick("inspect", { receipt: receiptText });
    ok() && setStep("decode", "done", `${regtest() ? "regtest" : summary.network}, ${summary.pool} pool, ${(summary.bytes / 1024).toFixed(1)} KB`);
  } catch (e) {
    ok() && setStep("decode", "fail", e.message);
    return ok() && showError(e.message, "unreadable");
  }
  let tx;
  try {
    ok() && setStep("fetch", "busy");
    const manual = $("#rawTx").value.trim();
    if (manual) {
      tx = { raw: hexToBytes(manual), height: Number($("#rawHeight").value) };
      if (ok()) fetchMode = { mode: "offline" };
      ok() && setStep("fetch", "done", "using the transaction you pasted");
    } else {
      const custom = $("#endpoint").value.trim();
      const endpoints = custom ? [custom] : regtest() ? [location.origin] : ENDPOINT_LISTS[summary.network] || [];
      if (!endpoints.length) throw new Error(`no ${summary.network} server set; open Settings`);
      const hint = heightHint(location.hash);
      let lastError;
      for (const endpoint of endpoints) {
        try {
          if (hint) {
            // Fetch the payment among up to 64 shielded transactions of its block: the server learns
            // the block, not which transaction is checked.
            await local;
            tx = await fetchTransactionPrivately(endpoint, summary.txid, hint, { txidOf: txidOf(summary.network) });
            if (ok()) fetchMode = { mode: "block", host: new URL(endpoint).host, set: tx.anonymitySet, block: hint, blocks: tx.blocks, time: tx.blockTime };
            ok() && setStep("fetch", "done", `${blockRange(fetchMode)} (${tx.anonymitySet} that could carry a receipt) from ${new URL(endpoint).host}`);
          } else {
            tx = await fetchRawTx(endpoint, summary.txid);
            if (ok()) fetchMode = { mode: "txid", host: new URL(endpoint).host };
            ok() && setStep("fetch", "done", `${short(summary.txid, 6)} at block ${tx.height.toLocaleString()} from ${new URL(endpoint).host}`);
          }
          // Confirmations: how deep the payment is under this server's tip.
          try { const tip = await fetchTipHeight(endpoint); if (ok()) fetchMode.tip = tip; } catch { /* shown as confirmations unknown, never as final */ }
          break;
        } catch (e) {
          lastError = e;
        }
      }
      if (!tx) {
        // The samples carry their published transaction: check them offline rather than fail.
        if ([SAMPLE_REAL, SAMPLE_EDITED, SAMPLE_OBSERVER].includes(receiptText)) {
          tx = { raw: hexToBytes(SAMPLE_TX), height: SAMPLE_HEIGHT };
          if (ok()) fetchMode = { mode: "offline-sample" };
          ok() && setStep("fetch", "done", "no chain server answered; using the sample's published transaction");
        } else {
          throw lastError;
        }
      }
    }
  } catch (e) {
    ok() && setStep("fetch", "fail", e.message);
    return ok() && showError(`Could not fetch the transaction: ${e.message}`, "network");
  }
  try {
    ok() && setStep("verify", "busy", document.querySelector("#warm")?.dataset.state === "ready" ? "checking the Halo 2 proof and signature" : "preparing the verifier, then checking the proof and signature");
    const t0 = performance.now();
    // Source proofs: fetch the earlier transactions the sender says the money came from.
    await local;
    const needed = JSON.parse(source_txids(receiptText));
    // A budget, so a made-up receipt can't make this page fetch thousands of transactions.
    if (needed.length > 8) throw new Error(`the receipt names ${needed.length} source transactions; this page fetches at most 8`);
    let funding = 16;
    let sources;
    const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
    if (needed.length) {
      const stxs = await Promise.all(needed.map((id) => fetchRawTx(endpoint, id)));
      sources = JSON.stringify(stxs.map((t) => ({ raw: bytesToHex(t.raw), height: t.height })));
      if (ok() && fetchMode) fetchMode.sources = needed.length;
    }
    const v = await call("verify", { receipt: receiptText, rawTx: tx.raw, height: tx.height, regtest: regtest(), sources });
    // Who funded each source transaction in the clear: the outputs its transparent inputs spent.
    for (const s of v.sources || []) {
      for (const i of s.transparent_inputs.slice(0, 16)) {
        if (funding-- <= 0) break;
        try {
          const prev = await fetchRawTx(endpoint, i.prevout_txid);
          Object.assign(i, JSON.parse(transparent_output(prev.raw, prev.height, i.prevout_index, summary.network === "mainnet" ? 133 : 1, regtest())));
        } catch { /* show the outpoint only */ }
      }
    }
    ok() && setStep("verify", "done", `proof and signature valid (${((performance.now() - t0) / 1000).toFixed(1)}s)`);
    // Exchange deposit (ZIP 320): check the second step too.
    const second = /(?:^|\n)second-tx:([0-9a-f]{64})(?:\n|$)/.exec(v.message || "");
    if (second && /(?:^|\n)tex-deposit:/.test(v.message)) {
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
      let tx2;
      try {
        tx2 = await fetchRawTx(endpoint, second[1]);
      } catch (e) {
        // The receipt itself checked out: not finding its second step is the chain's answer, not a forgery.
        return ok() && showError(`The receipt's proof and signature are valid, but its second deposit step (${second[1].slice(0, 12)}…) couldn't be fetched: ${e.message}`, "network");
      }
      if (ok() && fetchMode) fetchMode.second = true;
      await local;
      v.deposit = JSON.parse(check_tex_deposit(receiptText, tx.raw, tx.height, tx2.raw, tx2.height, regtest()));
    }
    lastCheck = { receiptText, raw: tx.raw, height: tx.height };
    // A key-set proof (`m=zip311m1…`) or a policy proof (`p=zip311p1…`) on the link.
    const hashText = safeDecode(location.hash);
    const ks = (hashText.match(/zip311m1[A-Za-z0-9_-]+/) || [])[0];
    const pol = (hashText.match(/zip311p1[A-Za-z0-9_-]+/) || [])[0];
    await local;
    if (ks) v.keySetSize = verify_keyset(ks, receiptText);
    if (pol) v.policy = JSON.parse(verify_policy(pol, receiptText));
    if (ok()) {
      render(v, summary.network);
      hideReceiptFromUrl();
    }
  } catch (e) {
    ok() && setStep("verify", "fail", plainFailure(e.message));
    const unproven = /^not proven by the payer/.test(e.message);
    // What it claims is on chain, but not that the payer made the claim: shown as a claim.
    let claimed = [];
    if (unproven && tx) try { await local; claimed = JSON.parse(claimed_outputs(receiptText, tx.raw, tx.height, regtest())); } catch { /* the verdict alone */ }
    if (summary) UNIT = unitFor(regtest() ? "regtest" : summary.network);
    ok() && showError(e.message, unproven ? "unproven" : "forged", claimed);
  }
}

// Multi-hop source of funds: a receipt whose proven source is another receipt's transaction.
function provenanceHtml(results) {
  if (!results.some((v) => (v.sources || []).length)) return "";
  const byTx = new Map(results.map((v) => [v.txid, v]));
  const used = new Set(results.flatMap((v) => (v.sources || []).map((s) => s.source_txid)));
  const rows = [];
  const walk = (v, depth, seen) => {
    if (seen.has(v.txid)) return;
    seen.add(v.txid);
    for (const s of v.sources || []) {
      rows.push(`<div class="line"><span class="k">${depth ? "" : "FUNDS"}</span><span class="v" style="padding-left:${depth * 12}px"><small>${short(v.txid, 6)} spent a note${s.zatoshis != null ? ` of ${zec(s.zatoshis)} ${UNIT}` : ""} from ${short(s.source_txid, 6)}</small></span></div>`);
      const next = byTx.get(s.source_txid);
      if (next) walk(next, depth + 1, seen);
      else rows.push(`<div class="line"><span class="k"></span><span class="v" style="padding-left:${(depth + 1) * 12}px"><small>${s.transparent_inputs.length ? `funded in the clear by ${short(s.source_txid, 6)}'s transparent inputs` : `${short(s.source_txid, 6)} was funded from shielded notes not shown`}</small></span></div>`);
    }
  };
  const seen = new Set();
  for (const v of results.filter((v) => !used.has(v.txid))) walk(v, 0, seen);
  return `<div class="dash"></div>${rows.join("")}`;
}

async function runBatch(batchText) {
  const gen = ++runGen;
  const ok = () => gen === runGen;
  $("#result").hidden = true;
  $("#progress").hidden = false;
  resetSteps();
  let b;
  try {
    ok() && setStep("decode", "busy");
    b = await quick("batch", { batch: batchText });
    ok() && setStep("decode", "done", `batch ${b.id}: ${b.receipts.length} receipts, complete and in order`);
  } catch (e) {
    ok() && setStep("decode", "fail", e.message);
    return ok() && showError(`This batch is not valid: ${e.message}`);
  }
  const results = [];
  const txs = [];
  try {
    // With block hints (one per receipt), each transaction is fetched with others from its
    // block, so the server learns which blocks were looked at, not which transactions.
    const hints = batchHeightHints(location.hash);
    const useHints = hints && hints.length === b.receipts.length;
    ok() && setStep("fetch", "busy", `fetching ${b.receipts.length} transactions`);
    let host = "", set = 0, lastEndpoint = "";
    // Fetch in random order, all of them, before reporting any failure: the order and the point
    // where fetching stops would otherwise tell the server which block is which receipt.
    const order = [...b.receipts.keys()];
    for (let k = order.length - 1; k > 0; k--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (k + 1);
      [order[k], order[j]] = [order[j], order[k]];
    }
    const fetched = await Promise.allSettled(order.map(async (i) => {
      const r = b.receipts[i];
      const s = await quick("inspect", { receipt: r });
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[s.network]);
      host = new URL(endpoint).host;
      lastEndpoint = endpoint;
      const tx = useHints ? await fetchTransactionPrivately(endpoint, s.txid, hints[i], { txidOf: txidOf(s.network) }) : await fetchRawTx(endpoint, s.txid);
      set += tx.anonymitySet || 0;
      txs[i] = tx;
    }));
    const failed = fetched.find((f) => f.status === "rejected");
    if (failed) throw failed.reason;
    if (!ok()) return;
    fetchMode = useHints
      ? { mode: "batch-blocks", host, blocks: [...new Set(hints)], set }
      : { mode: "batch-txids", host, n: txs.length };
    // The tip, so a request's "paid after it was created" check can count blocks when the link
    // carries no block times.
    try { const tip = await fetchTipHeight(lastEndpoint); if (ok()) fetchMode.tip = tip; } catch { /* checked by block time, or not at all */ }
    ok() && setStep("fetch", "done", useHints ? `${txs.length} blocks' transactions fetched (${set} in all)` : `${txs.length} transactions fetched by id`);
    await local;
    // An aggregated batch: one proof for every spend, checked once with all the transactions.
    if (b.aggregated) {
      ok() && setStep("verify", "busy", `checking ${b.receipts.length} receipts and their one aggregated proof`);
      results.push(...(await call("aggregated", { batch: batchText, txs: JSON.stringify(txs.map((t) => ({ raw: bytesToHex(t.raw), height: t.height }))), regtest: regtest() })));
    }
    for (const [i, r] of (b.aggregated ? [] : b.receipts).entries()) {
      ok() && setStep("verify", "busy", `checking proof ${i + 1} of ${b.receipts.length}`);
      // Receipts that prove their source of funds need the source transactions too.
      const needed = JSON.parse(source_txids(r));
      let sources;
      if (needed.length) {
        const s = await quick("inspect", { receipt: r });
        const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[s.network]);
        const stxs = await Promise.all(needed.map((id) => fetchRawTx(endpoint, id)));
        sources = JSON.stringify(stxs.map((t) => ({ raw: bytesToHex(t.raw), height: t.height })));
        if (ok() && fetchMode) fetchMode.sources = (fetchMode.sources || 0) + needed.length;
      }
      results.push(await call("verify", { receipt: r, rawTx: txs[i].raw, height: txs[i].height, regtest: regtest(), sources }));
    }
    ok() && setStep("fetch", "done", `${results.length} transactions fetched`);
    ok() && setStep("verify", "done", b.aggregated ? `all ${results.length} signatures and the one aggregated proof valid` : `all ${results.length} proofs and signatures valid`);
  } catch (e) {
    ok() && setStep("verify", "fail", e.message);
    return ok() && showError(`Payment ${results.length + 1} of the batch failed: ${e.message}`);
  }
  // A same-payer proof with the batch (`k=zip311k1…`): one key signed every payment.
  const linkText = (safeDecode(location.hash).match(/zip311k1[A-Za-z0-9_-]+/) || [])[0];
  let onePayer = 0;
  if (linkText) {
    try {
      await local;
      onePayer = verify_same_payer(linkText, batchText);
    } catch (e) {
      return ok() && showError(e.message, "forged");
    }
  }
  if (!ok()) return;
  UNIT = unitFor(results[0].network);
  const lines = results.flatMap((v) => v.outputs.map((o) => ({ v, o })));
  // Outputs disclosed without their memo don't show the payee can receive the note: listed, not counted.
  const total = lines.filter((l) => !l.o.memo_withheld).reduce((s, l) => s + l.o.zatoshis, 0);
  const recipients = new Set(lines.map((l) => l.o.recipient)).size;
  const note = (results[0].message || "").split("\n").filter((l) => !l.startsWith("batch:")).join(" ");
  revealResult();
  $("#result").innerHTML = `
    <div class="ticket">
      <div class="head"><div class="brand">RECEIPT</div><div class="sub">Zcash · ${results[0].network} · ${results.length} payments</div></div>
      ${note ? `<div class="sub" style="text-align:center;margin-top:6px">${escapeHtml(note)}</div>` : ""}
      <div class="dash"></div>
      ${lines.map(({ v, o }) => `
        <div class="line"><span class="k">${zec(o.zatoshis)}</span><span class="v">${o.memo ? escapeHtml(o.memo) : `<span class="mono">${short(o.recipient, 10)}</span>`}<br><span class="mono" style="font-size:11px;color:var(--ink-2)">${short(o.recipient, 10)} · block ${v.mined_height.toLocaleString()}</span></span></div>`).join("")}
      <div class="dash"></div>
      <div class="line paid"><span class="k">TOTAL</span><span class="v amount">${zec(total)} <small>${UNIT}</small></span></div>
      <div class="line"><span class="k">TO</span><span class="v">${recipients} recipient${recipients === 1 ? "" : "s"}</span></div>
      ${onePayer ? `<div class="line"><span class="k">FROM</span><span class="v">one payer, proven</span></div>` : ""}
      ${provenanceHtml(results)}
      <div class="dash"></div>
      <div class="stamp warn">VERIFIED · RECIPIENTS NOT CHECKED</div>
      <ul class="facts">
        <li>Every payment was signed by the key that spent its money.</li>
        ${onePayer ? `<li><strong>One payer:</strong> every payment was signed with the same spend key (proven over ${onePayer} spends), and the key stays hidden.</li>` : ""}
        <li>This batch is complete: each receipt signs its place in it, so none of its payments were dropped or added, and none is counted twice. (It doesn't show the sender made no other payments.)</li>
        <li><strong>Not revealed:</strong> the treasury's address, balance, or any other transaction.</li>
      </ul>
    </div>
    ${localBadge()}
    <div id="reqChecks"></div>
    <p class="fine"><button type="button" class="ghost" id="copyLink">Copy link</button> <button type="button" class="ghost" id="saveFile">Save as file</button> <button type="button" class="ghost" id="printBtn">Print or save as PDF</button></p>
    <div class="check">
      <label for="mine">Were you paid in this batch? Your address</label>
      <div class="row"><input id="mine" placeholder="${results[0].network === "mainnet" ? "u1…" : "utest1…"}" autocomplete="off" spellcheck="false"><button id="mineBtn">Check</button></div>
      <div id="mineOut" class="fine"></div>
    </div>`;
  shareButtons(`batch-${results[0].txid.slice(0, 12)}`);
  batchRequestChecks(results, txs.map((t) => t && t.blockTime));
  hideReceiptFromUrl();
  $("#mineBtn").onclick = async () => {
    const ua = $("#mine").value.trim();
    if (!ua) return need("#mine", "Paste your address.");
    try {
      const want = await quick("receiverOn", { ua, network: results[0].network });
      let got = 0;
      for (const { o } of lines) if (!o.memo_withheld && (await quick("receiver", { ua: o.recipient })) === want) got += o.zatoshis;
      $("#mineOut").textContent = got ? `Yes: ${zec(got)} ${UNIT} of this batch went to that address.` : "No. None of this batch went to that address.";
      const stamp = $("#result .stamp");
      stamp.textContent = got ? "PAID TO YOU" : "VALID · NOT TO YOUR ADDRESS";
      stamp.className = got ? "stamp good" : "stamp warn";
    } catch (e) {
      $("#mineOut").textContent = friendlyAddressError(e, ua);
    }
  };
  $("#mine").onkeydown = (e) => { if (e.key === "Enter") $("#mineBtn").click(); };
}

// One request answered by several payments (invoices A and B): every receipt in the batch signs
// the request's challenge, and together they paid the requested address at least the amount.
async function batchRequestChecks(results, blockTimes = []) {
  const fromUrl = requestFromUrl();
  if (!fromUrl) return;
  const mine = loadRequests()[fromUrl.code];
  const req = mine || fromUrl;
  const rows = [];
  const row = (ok, text) => rows.push(`<li data-ok="${ok}">${ok ? "✓" : "✗"} ${escapeHtml(text)}</li>`);
  if (!mine) rows.push(`<li data-ok="info">ℹ Request ${escapeHtml(fromUrl.code)} wasn't made in this browser, so these checks compare the batch with the request written in the link. Trust them only if you made that request.</li>`);
  const signs = results.every((v) => challengeIn(v.message) === fromUrl.code);
  row(signs, signs ? `All ${results.length} payments sign this request's challenge` : "Not every payment signs this request's challenge");
  if (req.to) {
    try {
      const want = await quick("receiverOn", { ua: req.to, network: results[0].network });
      let total = 0;
      for (const v of results) for (const o of v.outputs) if (!o.memo_withheld && (await quick("receiver", { ua: o.recipient })) === want) total += o.zatoshis;
      row(total > 0, total ? `Paid ${zec(total)} ${UNIT} to the requested address in total` : "Nothing was paid to the requested address");
      if (req.min) row(total >= req.min, `${total >= req.min ? "At least" : "Less than"} the requested ${zec(req.min)} ${UNIT}`);
    } catch (e) {
      row(false, `Could not check the payee: ${friendlyAddressError(e, req.to)}`);
    }
  }
  if (mine) ownRequestRows(row, mine, fromUrl.code, results.map((v, i) => ({ v, time: blockTimes[i] })));
  if (results.some((v) => v.public_demo)) row(false, "A payment is from the public demo wallet, whose key anyone has");
  const ok = !rows.some((r) => r.includes('data-ok="false"'));
  if (ok && mine) for (const v of results) saveUsed(v.txid, fromUrl.code);
  $("#reqChecks").innerHTML = `<div class="reqbox" data-ok="${ok ? (mine ? "true" : "info") : "false"}"><div class="reqhead">${!ok ? "REQUEST NOT SATISFIED" : mine ? "REQUEST SATISFIED" : "MATCHES THE REQUEST IN THIS LINK"}</div><ul>${rows.join("")}</ul></div>`;
  const stamp = $("#result .stamp");
  if (stamp) {
    stamp.textContent = !ok ? "VALID · REQUEST NOT MET" : mine ? "PAID AS REQUESTED" : "VERIFIED · MATCHES THE LINK'S REQUEST";
    stamp.className = ok && mine ? "stamp good" : "stamp warn";
  }
}

// Once a card is up, the receipt leaves the address bar: browser history, synced history and
// bookmarks would otherwise keep the whole receipt. The full link stays here for Copy link, Save
// as file and Print. replaceState fires no hashchange, so nothing re-runs.
let shareLink = "";
function hideReceiptFromUrl() {
  if (!location.hash) return;
  shareLink = location.href;
  history.replaceState(null, "", location.pathname + location.search);
}

// Copy, save and print for the card showing: the link can be too long for some chat apps, and a
// file always carries it whole.
function shareButtons(name) {
  $("#printBtn").onclick = () => window.print();
  $("#copyLink").onclick = () =>
    navigator.clipboard.writeText(shareLink || location.href).then(
      () => { $("#copyLink").textContent = "Copied"; },
      () => { $("#copyLink").textContent = "Copy it from the address bar"; },
    );
  $("#saveFile").onclick = () => {
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([(shareLink || location.href) + "\n"], { type: "text/plain" })), download: `${name}.zip311.txt` });
    a.click();
    URL.revokeObjectURL(a.href);
  };
}

// ---------- incoming receipts (the recipient proves it was paid) ----------
function incomingFromHash() {
  const h = safeDecode(location.hash.slice(1));
  const i = h.indexOf("zrcin1");
  return i >= 0 ? h.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "") : "";
}

async function runIncoming(text) {
  const gen = ++runGen;
  const ok = () => gen === runGen;
  $("#result").hidden = true;
  $("#progress").hidden = false;
  resetSteps();
  let s;
  try {
    ok() && setStep("decode", "busy");
    await local;
    s = JSON.parse(inspect_incoming(text));
    ok() && setStep("decode", "done", `incoming receipt: ${regtest() ? "regtest" : s.network}, ${s.pool} pool, ${(s.bytes / 1024).toFixed(1)} KB`);
  } catch (e) {
    ok() && setStep("decode", "fail", e.message);
    return ok() && showError(e.message, "unreadable");
  }
  let tx;
  try {
    ok() && setStep("fetch", "busy");
    const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[s.network]);
    const hint = heightHint(location.hash);
    tx = hint ? await fetchTransactionPrivately(endpoint, s.txid, hint, { txidOf: txidOf(s.network) }) : await fetchRawTx(endpoint, s.txid);
    if (ok()) fetchMode = hint ? { mode: "block", host: new URL(endpoint).host, set: tx.anonymitySet, block: hint, blocks: tx.blocks } : { mode: "txid", host: new URL(endpoint).host };
    ok() && setStep("fetch", "done", `${short(s.txid, 6)} at block ${tx.height.toLocaleString()}`);
  } catch (e) {
    ok() && setStep("fetch", "fail", e.message);
    return ok() && showError(`Could not fetch the transaction: ${e.message}`, "network");
  }
  try {
    ok() && setStep("verify", "busy", "checking the recipient's address proof, signature and each output");
    const v = await call("incoming", { receipt: text, rawTx: tx.raw, height: tx.height, regtest: regtest() });
    ok() && setStep("verify", "done", "address proof, signature and outputs valid");
    if (!ok()) return;
    UNIT = unitFor(regtest() ? "regtest" : s.network);
    const rows = v.outputs.map((o) => `
      <div class="line paid"><span class="k">RECEIVED</span><span class="v amount">${zec(o.zatoshis)} <small>${UNIT}</small></span></div>
      ${o.memo ? `<div class="line"><span class="k">MEMO</span><span class="v memo">“${escapeHtml(o.memo)}”</span></div>` : ""}
      <div class="dash"></div>`).join("");
    revealResult();
    $("#result").innerHTML = `
      <div class="ticket">
        <div class="head"><div class="brand">INCOMING</div><div class="sub">Zcash · ${v.network} · ${v.pool} pool</div></div>
        <div class="dash"></div>
        ${rows}
        <div class="line"><span class="k">TO</span><span class="v mono addr" title="${v.recipient}">${short(v.recipient, 14)} <small>(proven)</small></span></div>
        <div class="line"><span class="k">TX</span><span class="v mono" title="${v.txid}">${short(v.txid, 8)}</span></div>
        <div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()}</span></div>
        ${v.message ? `<div class="line"><span class="k">MESSAGE</span><span class="v text">${escapeHtml(v.message)}</span></div>` : ""}
        <div class="dash"></div>
        <div class="stamp good">VERIFIED</div>
        <ul class="facts">
          <li>Whoever made this receipt controls the TO address (zero-knowledge proof + signature), and these payments reached it.</li>
          <li><strong>Not revealed:</strong> the recipient's balance, other payments, or when it spends these.</li>
        </ul>
        ${localBadge()}
        ${requestFromUrl() ? `<div class="reqbox" data-ok="false"><div class="reqhead">REQUEST NOT SATISFIED</div><ul><li data-ok="false">✗ This is an incoming receipt (the recipient proving it was paid). It doesn't answer a payment request: ask the payer for a receipt made with the request link.</li></ul></div>` : ""}
      </div>`;
    hideReceiptFromUrl();
  } catch (e) {
    ok() && setStep("verify", "fail", e.message);
    ok() && showError(e.message, "forged");
  }
}

function batchFromHash() {
  const h = safeDecode(location.hash.slice(1));
  const i = h.indexOf("zip311b1");
  return i >= 0 ? h.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "") : "";
}

/** A batch link's block hints (`&h=12,40,41`), one per receipt in order, or null. */
function batchHeightHints(input) {
  const m = /[#?&]h=(\d{1,9}(?:,\d{1,9})*)(?:&|$)/.exec(safeDecode(String(input)));
  return m ? m[1].split(",").map(Number) : null;
}

function receiptFromHash() {
  const h = safeDecode(location.hash.slice(1));
  if (h.includes("zip311b1")) return "";
  if (!h.includes("zip311r1") && h.includes("zrcpt1eyJ")) { showError(ZRECEIPT_NOTE, "other"); return ""; }
  const i = h.indexOf("zip311r1");
  return i >= 0 ? h.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "") : "";
}

// How the transaction was obtained, for the privacy badge.
let fetchMode = null;

for (const [id, text, hint] of [["#sampleReal", SAMPLE_REAL, SAMPLE_HEIGHT], ["#sampleEdited", SAMPLE_EDITED, SAMPLE_HEIGHT], ["#sampleObserver", SAMPLE_OBSERVER, SAMPLE_HEIGHT], ["#sampleBatch", SAMPLE_BATCH, SAMPLE_BATCH_HEIGHTS], ["#sampleSource", SAMPLE_SOURCE, SAMPLE_HEIGHT], ["#sampleScreened", SAMPLE_SCREENED, SAMPLE_HEIGHT]]) {
  const b = $(id);
  if (b) b.onclick = () => {
    sampleAs = id === "#sampleReal" ? SAMPLE_MERCHANT : null;
    pendingScreened = id === "#sampleScreened" ? { proofs: SAMPLE_SCREENED_PROOF, set: SAMPLE_SCREENED_SET } : null;
    const h = `${text}&h=${hint}`;
    if (safeDecode(location.hash.slice(1)) === h) (text.startsWith("zip311b1") ? runBatch(text) : run(text));
    else location.hash = h;
  };
}

// A real payment from a throwaway testnet wallet whose key is public (samples.js): its proofs
// were made once, and this signs them for the visitor's own message, here, then verifies it.
$("#ownBtn").onclick = async () => {
  const msg = $("#ownMsg").value.trim();
  if (!msg) return need("#ownMsg", "Write a message to sign.");
  await local;
  sampleAs = SAMPLE_MERCHANT;
  location.hash = `${sign_prepared_text(DEMO_PREPARED, DEMO_KEY, msg)}&h=${DEMO_HEIGHT}`;
};
$("#ownMsg").onkeydown = (e) => { if (e.key === "Enter") $("#ownBtn").click(); };

// A receipt saved as a file (`.zip311.txt`, the link inside) can be opened or dropped on the box.
$("#openFile").onclick = () => $("#fileIn").click();
$("#fileIn").onchange = async () => {
  const f = $("#fileIn").files?.[0];
  if (!f || f.size > 1_000_000) return;
  $("#paste").value = await f.text();
  $("#verifyBtn").click();
};
$("#paste").addEventListener("dragover", (e) => e.preventDefault());
$("#paste").addEventListener("drop", async (e) => {
  const f = e.dataTransfer?.files?.[0];
  if (!f) return;
  e.preventDefault();
  if (f.size > 1_000_000) return need("#paste", "That file is too big to be a receipt.");
  $("#paste").value = await f.text();
  $("#verifyBtn").click();
});

$("#verifyBtn").onclick = async () => {
  const t = $("#paste").value.trim();
  // A new attempt: clear the previous run's steps so they can't contradict this one.
  runGen++;
  resetSteps();
  $("#ignored").hidden = true;
  $("#progress").hidden = true;
  if (!t) return need("#paste", "Paste a receipt link, or open a file.");
  await local;
  const leak = secret_kind(t);
  if (leak) {
    $("#paste").value = "";
    return showError(`That looks like a ${leak}. Never paste it anywhere: it reveals your whole wallet. It was cleared and not sent. Paste only the zip311r1… receipt.`, "secret");
  }
  const ii = t.indexOf("zrcin1");
  if (ii >= 0) {
    const it = t.slice(ii).replace(/[^A-Za-z0-9_-].*$/s, "");
    const h = heightHint(t);
    history.replaceState(null, "", "#" + it + (h ? `&h=${h}` : ""));
    return runIncoming(it);
  }
  const bi = t.indexOf("zip311b1");
  if (bi >= 0) {
    const bt = t.slice(bi).replace(/[^A-Za-z0-9_-].*$/s, "");
    const hs = batchHeightHints(t);
    history.replaceState(null, "", "#" + bt + (hs ? `&h=${hs.join(",")}` : ""));
    return runBatch(bt);
  }
  const i = t.indexOf("zip311r1");
  if (i < 0 && /zrsv1|zip311s1/.test(t)) return showError(`That is a ${t.includes("zrsv1") ? "proof of funds" : "screened-set proof"}. This page checks payment receipts; check it with zceipt verify.`, "other");
  if (i < 0) return t.includes("zrcpt1eyJ") ? showError(ZRECEIPT_NOTE, "other") : showError("no zip311r1… receipt in what was pasted", "unreadable");
  const r = t.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
  const h = heightHint(t);
  history.replaceState(null, "", "#" + r + (h ? `&h=${h}` : ""));
  run(r);
};
// One check per link, on load as on every hash change: the first kind of artifact found wins
// (incoming receipt, then batch, then receipt) and the page says which other kind it ignored.
// Two checks running at once would overwrite each other's server choice, unit and card.
function checkFromHash() {
  const h = safeDecode(location.hash.slice(1));
  const it = incomingFromHash();
  const bt = it ? "" : batchFromHash();
  const r = it || bt ? "" : receiptFromHash();
  const ignored = [["zrcin1", "an incoming receipt"], ["zip311b1", "a batch"], ["zip311r1", "a receipt"]].filter(([tag]) => h.includes(tag)).map(([, name]) => name).slice(1);
  $("#ignored").hidden = !ignored.length;
  $("#ignored").textContent = ignored.length ? `This link also holds ${ignored.join(" and ")}, which was ignored: one link checks one thing.` : "";
  $("#paste").value = it || bt || r;
  if (it) return runIncoming(it);
  if (bt) return runBatch(bt);
  if (r) return run(r);
  showRequest();
}
window.addEventListener("hashchange", () => {
  // Whatever the new link holds replaces the old check entirely: box, steps and result.
  runGen++;
  resetSteps();
  $("#progress").hidden = true;
  $("#result").hidden = true;
  checkFromHash();
});

// A request link opened on its own: say what is being asked, and how to answer it.
// The command a payer runs to answer a request, from any wallet's seed phrase, with a copy button.
function answerCommand(link, to) {
  // Shell-quoted: a label with an apostrophe must not break the command.
  const quoted = `'${String(link).replace(/'/g, "'\\''")}'`;
  const cmd = `zceipt create --ufvk @viewing-key.txt --birthday <wallet birthday> --txid <txid> --request ${quoted} --unsigned r.txt && zceipt sign r.txt --seed-stdin`;
  const id = `cmd${Math.random().toString(36).slice(2, 8)}`;
  setTimeout(() => { const b = document.getElementById(id); if (b) b.onclick = () => navigator.clipboard.writeText(cmd).then(() => { b.textContent = "Copied"; }, () => { b.textContent = "Select and copy the command above"; }); });
  return `<div class="cli">${escapeHtml(cmd)}</div><p class="fine"><button type="button" class="ghost" id="${id}">Copy command</button></p>`;
}

let askedFor = requestFromUrl();
async function showRequest() {
  askedFor = requestFromUrl();
  if (!askedFor) return;
  const asked = askedFor;
  await local;
  if (askedFor !== asked) return; // the link changed while the verifier loaded
  // Only an address the verifier parses as a unified address reaches the pay link, the QR code
  // and the make page; the unit follows its network.
  let net = "";
  try { net = asked.to ? address_network(asked.to) : ""; } catch { asked.to = ""; }
  const answer = location.href;
  const payUri = `zcash:${asked.to}${asked.min ? `?amount=${zec(asked.min)}` : ""}`;
  const makeParams = new URLSearchParams();
  for (const [k, v] of Object.entries({ request: asked.code, to: asked.to, min: asked.min ? String(asked.min) : "", label: asked.label })) if (v) makeParams.set(k, v);
  $("#empty").innerHTML = `
    <div class="big">PAYMENT REQUEST</div>
    <p>You're asked to prove a payment${asked.min ? ` of at least <strong>${zec(asked.min)} ${unitFor(net || "testnet")}</strong>` : ""}${asked.to ? ` to <span class="mono" title="${escapeHtml(asked.to)}">${escapeHtml(short(asked.to, 10))}</span>` : ""}${asked.label ? ` (“${escapeHtml(asked.label)}”)` : ""}.</p>
    ${asked.to ? `<p><a class="paybtn" href="${escapeHtml(payUri)}">Pay in your wallet</a></p><div class="qr" id="payQr" aria-label="QR code of the payment link"></div>` : ""}
    <p><a class="paybtn" href="./make.html#${escapeHtml(makeParams.toString())}">Then make the receipt in your browser</a></p>
    <details class="more"><summary>Or in a terminal</summary>${answerCommand(answer, asked.to)}</details>`;
  if (asked.to) try { $("#payQr").innerHTML = qr_svg(payUri); } catch { /* the link stands without a QR code */ }
  // On a phone the request comes first, not below the form.
  document.body.classList.add("has-result");
}
checkFromHash();

// ---------- signed payment requests (zreq1) ----------
// What the signed request claims, checked here; the domain's payee list only on the viewer's
// click, since anyone can sign a request naming any domain, and the fetch tells that domain the
// viewer's address and the time.
async function checkSignedRequest(text) {
  const out = $("#linkOut");
  let r;
  try {
    await local;
    r = JSON.parse(verify_payment_request(text, Date.now() / 1000));
  } catch (e) {
    out.innerHTML = `<div class="reqbox" data-ok="false"><div class="reqhead">DO NOT PAY</div><ul><li>${escapeHtml(e.message)}</li></ul></div>`;
    return;
  }
  const paint = (listed) => {
    const domainLine = listed === true ? `<strong>${escapeHtml(r.domain)}</strong> lists this address.`
      : listed === false ? `<strong>Refuse it:</strong> ${escapeHtml(r.domain)} does not list this address.`
      : listed === "unreadable" ? `${escapeHtml(r.domain)}'s list couldn't be read from here. Open <a href="${escapeHtml(r.well_known)}" target="_blank" rel="noreferrer noopener">it</a> and confirm it contains this address before paying.`
      : `This is what the request claims. Only ${escapeHtml(r.domain)}'s own payee list ties the signing key to the shop.`;
    // Only the shop's own list ties the signing key to the shop: unread, it's unconfirmed.
    const state = listed === true ? "true" : listed === false ? "false" : "info";
    const head = { true: "SIGNED BY THE PAYEE", false: "DO NOT PAY", info: "SIGNED, SHOP NOT CONFIRMED" }[state];
    out.innerHTML = `<div class="reqbox" data-ok="${state}"><div class="reqhead">${head}</div><ul>
      <li>Pay ${zec(r.amount_zatoshis)} ${unitFor(r.network)} to <span class="mono">${escapeHtml(short(r.payee, 14))}</span> (${escapeHtml(r.network)})</li>
      ${r.memo ? `<li>Memo “${escapeHtml(r.memo)}”</li>` : ""}
      <li>Request ${escapeHtml(r.code)}, valid until ${new Date(r.expires_at * 1000).toLocaleString()}</li>
      <li>Nobody changed the address, amount or memo: ${listed === true ? "the payee's own key signed them" : "the key behind this address signed them"}.</li>
      <li>${domainLine}</li></ul>
      ${listed == null ? `<p class="fine"><button type="button" class="ghost" id="wellKnownBtn">Check the domain's payee list</button> ${escapeHtml(r.domain)} will see this request (your address and the time).</p>` : ""}</div>`;
    const btn = $("#wellKnownBtn");
    if (btn) btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "Checking";
      try {
        const doc = await fetch(r.well_known, { redirect: "error" }).then((x) => x.json());
        const want = orchard_receiver_hex(r.payee);
        paint((doc.payees || []).some((ua) => { try { return orchard_receiver_hex(ua) === want; } catch { return false; } }));
      } catch {
        paint("unreadable"); // the domain may not allow cross-origin reads
      }
    };
  };
  paint(null);
}

// ---------- check a payment link ----------
$("#linkBtn").onclick = async () => {
  await local;
  const uri = $("#linkIn").value.trim();
  if (!uri) return need("#linkIn", "Paste a zcash: payment link.");
  if (uri.includes("zreq1")) return checkSignedRequest(uri.slice(uri.indexOf("zreq1")).replace(/[^A-Za-z0-9_-].*$/s, ""));
  const v = JSON.parse(check_payment_uri(uri, regtest() ? "regtest" : ""));
  const pays = v.payments.map((p) =>
    `<li>${escapeHtml(p.network || "unknown network")} ${escapeHtml(p.address_kind)} address · ${p.amount_zatoshis != null ? `${zec(p.amount_zatoshis)} ${p.network === "mainnet" ? "ZEC" : "TAZ"}` : "no amount"}${p.memo ? ` · memo “${escapeHtml(p.memo)}”` : ""} · ${p.receipt_provable ? "provable with a receipt" : p.address_kind === "tex" ? "provable with a deposit receipt" : "<strong>not provable with a receipt</strong>"}</li>`).join("");
  // The parser's own wording ("Error { input: …, code: MapOpt }") means nothing to a shop owner.
  const say = (m) => (/Error \{|code: /.test(m) ? "This isn't a valid zcash: payment link. Check it for a typo, or copy it again from your wallet." : m);
  const finds = v.findings.map((f) => `<li data-level="${f.level}">${escapeHtml(say(f.message))}</li>`).join("");
  $("#linkOut").innerHTML = `<div class="verdict">${v.ok ? (v.findings.some((f) => f.level === "warning") ? "Works, with warnings" : "Looks good") : "Fix before printing"}</div>
    <ul>${pays}${v.qr ? `<li>As a QR code: version ${v.qr.version}, ${v.qr.modules}×${v.qr.modules} modules</li>` : ""}${finds}</ul>`;
};

// ---------- create a request ----------
$("#reqBtn").onclick = () => {
  const to = $("#reqTo").value.trim();
  // "0,05" is how much of the world writes 0.05.
  const amount = Number(($("#reqAmount").value || "0").trim().replace(",", "."));
  const label = $("#reqLabel").value.trim();
  if (!/^u(test|regtest)?1/.test(to)) { $("#reqOut").textContent = "Enter your unified address (u1…, or utest1… on testnet)."; return; }
  if (!Number.isFinite(amount) || amount < 0) return need("#reqAmount", "Enter an amount such as 0.05, or leave it empty.");
  const code = newCode();
  const min = Math.round(amount * 1e8);
  saveRequest(code, { to, min, label, created: new Date().toISOString() });
  // The tip now: a payment must be mined after it (an old payment can't answer a new request).
  (async () => {
    await local;
    const net = (() => { try { return address_network(to); } catch { return ""; } })();
    const endpoint = regtest() ? location.origin : $("#endpoint").value.trim() || ENDPOINTS[net];
    if (!endpoint) return;
    try { saveRequest(code, { ...loadRequests()[code], tip: await fetchTipHeight(endpoint) }); } catch { /* the time check stands in */ }
  })();
  const q = new URLSearchParams({ request: code, to });
  if (min) q.set("min", String(min));
  if (label) q.set("label", label);
  if (regtest()) q.set("regtest", "");
  // In the #fragment, like receipts: browsers never send it, so the page's host doesn't log the
  // payee, amount or label.
  const link = `${location.origin}${location.pathname}#${q}`;
  $("#reqOut").innerHTML = `
    <p class="hint">Send this to the person who paid you. Their receipt must answer challenge <code>${code}</code>.</p>
    <textarea readonly id="reqLink">${escapeHtml(link)}</textarea>
    <p class="fine"><button type="button" class="ghost" id="copyReq">Copy link</button></p>
    <div class="qr" id="reqQr" aria-label="QR code of the request link"></div>
    <p class="hint">They run:</p>
    ${answerCommand(link, to)}
    <p class="hint">and send back the link it prints. Opening it here checks the challenge, the payee and the amount.</p>`;
  local.then(() => { $("#reqQr").innerHTML = qr_svg(link); }).catch(() => {});
  $("#copyReq").onclick = () =>
    navigator.clipboard.writeText(link).then(
      () => { $("#copyReq").textContent = "Copied"; },
      () => { $("#reqLink").select(); $("#copyReq").textContent = "Selected: copy it"; },
    );
};

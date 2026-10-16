// Receipts verifier page. The receipt lives in the URL fragment (#zrcpt1…), which browsers
// never send to any server. The only network request is fetching the public transaction
// from a lightwalletd server of the viewer's choice.

const ENDPOINTS = {
  mainnet: "https://zcash-mainnet.chainsafe.dev",
  testnet: "https://zcash-testnet.chainsafe.dev",
};
const EXPLORER = {
  mainnet: (t) => `https://mainnet.zcashexplorer.app/transactions/${t}`,
  testnet: (t) => `https://testnet.zcashexplorer.app/transactions/${t}`,
};

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
    if (el) { el.dataset.state = "ready"; el.textContent = `Verifier ready (${((performance.now() - warmStart) / 1000).toFixed(1)}s, one time)`; }
  })
  .catch(() => {});
import { fetchTransactionPrivately, heightHint } from "./zcash-receipts/grpc.js";
import initLocal, { inspect as inspectLocal, orchard_receiver_hex, open_batch, secret_kind, check_payment_uri, check_tex_deposit, source_txids, transparent_output } from "./zcash-receipts/pkg/receipts_wasm.js";
const local = initLocal();
const quick = async (op, args) => {
  await local;
  if (op === "inspect") return JSON.parse(inspectLocal(args.receipt));
  if (op === "receiver") return orchard_receiver_hex(args.ua);
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
  if (status && status !== "0") throw new Error(decodeURIComponent(res.headers.get("grpc-message") || `grpc-status ${status}`));
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
    throw new Error(`lightwalletd: ${decodeURIComponent(why.trim()) || "status " + m[1]}`);
  }
  if (!data) throw new Error("lightwalletd returned no transaction");
  return { raw: data, height: Number(height) };
}

// A local regtest chain (see scripts/dev-server.mjs): set in Settings or with ?regtest.
const regtest = () => $("#regtest").checked;
if (new URLSearchParams(location.search).has("regtest")) $("#regtest").checked = true;

// ---------- proof requests ("prove it's you") ----------
// A verifier creates a request: a random challenge plus the payee and minimum amount they
// expect. The payer's receipt must sign `challenge:<code>`, so a receipt someone else made
// (or an old one) can't be replayed. Requests are remembered only in this browser, so the
// checks compare against what *you* asked for, not against whatever the returned link says.
const REQ_KEY = "receipts.requests.v1";
const loadRequests = () => { try { return JSON.parse(localStorage.getItem(REQ_KEY) || "{}"); } catch { return {}; } };
const saveRequest = (code, r) => { try { const all = loadRequests(); all[code] = r; localStorage.setItem(REQ_KEY, JSON.stringify(all)); } catch {} };
const newCode = () => Array.from(crypto.getRandomValues(new Uint8Array(6)), (b) => b.toString(16).padStart(2, "0")).join("");
function requestFromUrl() {
  const q = new URLSearchParams(location.search);
  const code = q.get("request");
  if (!code) return null;
  return { code, to: q.get("to") || "", min: Number(q.get("min") || 0), label: q.get("label") || "" };
}
function challengeIn(message) {
  const m = /(?:^|\n)challenge:([0-9a-f]{6,64})(?:\n|$)/.exec(message || "");
  return m ? m[1] : null;
}

// ---------- UI ----------
const steps = ["decode", "fetch", "verify"];
function setStep(name, state, text) {
  const el = document.querySelector(`[data-step="${name}"]`);
  el.dataset.state = state;
  if (text) el.querySelector(".detail").textContent = text;
}
function resetSteps() {
  for (const s of steps) setStep(s, "idle", "");
}
const short = (s, n = 10) => (s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);
const zec = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");

function showError(msg) {
  $("#result").hidden = false;
  $("#result").innerHTML = `
    <div class="ticket invalid">
      <div class="stamp bad">NOT VALID</div>
      <p class="why">${escapeHtml(msg)}</p>
      <p class="fine">A receipt is only valid if the sender's proof, signature and the on-chain transaction all agree.</p>
    </div>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function localBadge() {
  const f = fetchMode || {};
  const sees =
    f.mode === "offline" ? "No server was contacted: you supplied the transaction."
    : f.mode === "block" ? `${escapeHtml(f.host)} saw a request for block ${f.block.toLocaleString()} and its ${f.set} shielded transactions, not which one you checked.`
    : `${escapeHtml(f.host || "The server")} saw which transaction you checked. Links with an <code>h=</code> block hint avoid this.`;
  const second = f.second ? " The deposit's second step (a public transparent transaction) was fetched by its id." : "";
  const sources = f.sources ? ` The source transaction${f.sources > 1 ? "s" : ""} the sender named (and the outputs that funded ${f.sources > 1 ? "them" : "it"}) were fetched by id, so the server saw those ids.` : "";
  return `<div class="local" data-mode="${f.mode || "txid"}"><strong>Verified on this device.</strong> The receipt never left your browser; the proof was checked here in WebAssembly. ${sees}${second}${sources}</div>`;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function render(v, net) {
  const rows = v.outputs
    .map(
      (o) => `
      <div class="line paid">
        <span class="k">PAID</span>
        <span class="v amount">${zec(o.zatoshis)} <small>ZEC</small></span>
      </div>
      <div class="line"><span class="k">TO</span><span class="v mono addr" title="${o.recipient}">${short(o.recipient, 14)}</span></div>
      ${o.memo ? `<div class="line"><span class="k">MEMO</span><span class="v memo">“${escapeHtml(o.memo)}”</span></div>` : o.memo_withheld ? `<div class="line"><span class="k">MEMO</span><span class="v"><small>withheld by the sender (the receipt can't open it)</small></span></div>` : ""}
      <div class="dash"></div>`
    )
    .join("");
  $("#result").hidden = false;
  $("#result").innerHTML = `
    <div class="ticket">
      <div class="head">
        <div class="brand">RECEIPT</div>
        <div class="sub">Zcash · ${v.network} · ${v.pool} pool</div>
      </div>
      <div class="dash"></div>
      ${rows}
      <div class="line"><span class="k">TX</span>${EXPLORER[v.network] ? `<a class="v mono" target="_blank" rel="noreferrer noopener" href="${EXPLORER[v.network](v.txid)}">${short(v.txid, 8)}</a>` : `<span class="v mono" title="${v.txid}">${short(v.txid, 8)}</span>`}</div>
      ${fetchMode && fetchMode.mode === "offline"
        ? `<div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()} <small>(as you gave it, not checked)</small></span></div>
      <p class="fine">Offline check: this receipt matches the transaction you pasted. Whether that transaction was mined was not checked; fetch it from a server to confirm.</p>`
        : `<div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()}</span></div>`}
      ${(v.sender_addresses || []).map((s) => `<div class="line"><span class="k">FROM</span><span class="v mono addr" title="${s}">${short(s, 14)} <small>(proven)</small></span></div>`).join("")}
      ${(v.sources || []).map((s) => `<div class="line"><span class="k">FUNDS</span><span class="v">${s.zatoshis != null ? `${zec(s.zatoshis)} ZEC note ` : "spent note "}from <span class="mono" title="${s.source_txid}">${short(s.source_txid, 6)}</span> output ${s.source_action} <small>(block ${s.source_height.toLocaleString()}, proven)</small></span></div>
      ${s.transparent_inputs.map((i) => `<div class="line"><span class="k"></span><span class="v"><small>${i.address ? `funded in the clear: ${zec(i.zatoshis)} ZEC from <span class="mono" title="${i.address}">${short(i.address, 8)}</span>` : `spent transparent output ${short(i.prevout_txid, 6)}:${i.prevout_index}`}</small></span></div>`).join("")}
      ${s.transparent_inputs.length ? "" : `<div class="line"><span class="k"></span><span class="v"><small>that transaction was itself funded from shielded notes (not shown)</small></span></div>`}`).join("")}
      ${v.message ? `<div class="line"><span class="k">NOTE</span><span class="v">${escapeHtml(v.message.split("\n").filter((l) => !/^(tex-deposit|second-tx):/.test(l)).join("\n"))}</span></div>` : ""}
      ${v.deposit ? `<div class="dash"></div>
      <div class="line paid"><span class="k">DEPOSIT</span><span class="v amount">${zec(v.deposit.deposit_zatoshis)} <small>ZEC</small></span></div>
      <div class="line"><span class="k">EXCHANGE</span><span class="v mono addr" title="${v.deposit.tex_address}">${short(v.deposit.tex_address, 14)}</span></div>
      <div class="line"><span class="k">VIA</span><span class="v mono">${short(v.deposit.first_tx, 6)} → ${short(v.deposit.second_tx, 6)}</span></div>
      <div class="local" data-mode="txid"><strong>Exchange deposit (ZIP 320).</strong> The sender proved they made this two-step deposit to the exchange's TEX address. ${escapeHtml(v.deposit.warning)}</div>` : ""}
      <div class="dash"></div>
      <div class="stamp good">VERIFIED</div>
      <ul class="facts">
        <li>The sender proved they authorized this payment (zero-knowledge proof + signature over this receipt).</li>
        ${v.outputs.length ? `<li>The amount, recipient and memo above were opened from the transaction on chain.</li>` : ""}
        ${(v.sources || []).length ? `<li>The sender proved where the spent money came from (FUNDS above): only that link, read from the chain.</li>` : ""}
        ${(v.sender_addresses || []).length || (v.sources || []).length ? `${(v.sender_addresses || []).length ? `<li>The sender also proved they control the FROM address above.</li>` : ""}<li><strong>Not revealed:</strong> the sender's balance or any other transaction.</li>` : `<li><strong>Not revealed:</strong> the sender's address, balance, or any other transaction.</li>`}
      </ul>
      ${localBadge()}
      <div id="reqChecks"></div>
      <div class="check">
        <label for="mine">Was it paid to you? Paste your address</label>
        <div class="row"><input id="mine" placeholder="u1…" autocomplete="off" spellcheck="false"><button id="mineBtn">Check</button></div>
        <div id="mineOut" class="fine"></div>
      </div>
    </div>`;
  renderRequestChecks(v);
  $("#mineBtn").onclick = async () => {
    const ua = $("#mine").value.trim();
    if (!ua) return;
    try {
      const want = await quick("receiver", { ua });
      // Compare by Orchard receiver: a unified address can carry other receivers too.
      const got = await Promise.all(v.outputs.map((o) => quick("receiver", { ua: o.recipient })));
      $("#mineOut").textContent = got.includes(want) ? "Yes. This payment went to that address." : "No. None of the disclosed outputs went to that address.";
      $("#mineOut").dataset.ok = got.includes(want);
    } catch (e) {
      $("#mineOut").textContent = e.message;
    }
  };
}

async function renderRequestChecks(v) {
  const fromUrl = requestFromUrl();
  const signed = challengeIn(v.message);
  if (!fromUrl && !signed) return;
  const code = fromUrl ? fromUrl.code : signed;
  const mine = loadRequests()[code];
  const req = mine || fromUrl;
  const rows = [];
  const row = (ok, text) => rows.push(`<li data-ok="${ok}">${ok ? "✓" : "✗"} ${escapeHtml(text)}</li>`);
  row(!!mine, mine ? `You created request ${code} in this browser${mine.label ? ` (“${mine.label}”)` : ""}` : `Request ${code} was not created in this browser; checking against the link instead`);
  row(signed === code, signed === code ? "The sender signed your challenge, so this receipt was made for this request" : "The receipt does not sign this request's challenge");
  if (req && req.to) {
    try {
      const want = await quick("receiver", { ua: req.to });
      const paid = [];
      for (const o of v.outputs) if ((await quick("receiver", { ua: o.recipient })) === want) paid.push(o.zatoshis);
      const total = paid.reduce((s, z) => s + z, 0);
      row(paid.length > 0, paid.length ? `Paid ${zec(total)} ZEC to the requested address` : "Nothing was paid to the requested address");
      if (req.min) row(total >= req.min, `${total >= req.min ? "At least" : "Less than"} the requested ${zec(req.min)} ZEC`);
    } catch (e) {
      row(false, `Could not check the payee: ${e.message}`);
    }
  }
  const ok = !rows.some((r) => r.includes('data-ok="false"'));
  $("#reqChecks").innerHTML = `<div class="reqbox" data-ok="${ok}"><div class="reqhead">${ok ? "REQUEST SATISFIED" : "REQUEST NOT SATISFIED"}</div><ul>${rows.join("")}</ul></div>`;
}

async function run(receiptText) {
  $("#result").hidden = true;
  $("#progress").hidden = false;
  resetSteps();
  let summary;
  try {
    setStep("decode", "busy");
    summary = await quick("inspect", { receipt: receiptText });
    setStep("decode", "done", `${regtest() ? "regtest" : summary.network}, ${summary.pool} pool, ${(summary.bytes / 1024).toFixed(1)} KB`);
  } catch (e) {
    setStep("decode", "fail", e.message);
    return showError(`This is not a readable receipt: ${e.message}`);
  }
  let tx;
  try {
    setStep("fetch", "busy");
    const manual = $("#rawTx").value.trim();
    if (manual) {
      tx = { raw: hexToBytes(manual), height: Number($("#rawHeight").value) };
      fetchMode = { mode: "offline" };
      setStep("fetch", "done", "using the transaction you pasted");
    } else {
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
      if (!endpoint) throw new Error(`no ${summary.network} server set; open Settings`);
      const hint = heightHint(location.hash);
      if (hint) {
        // Fetch the whole block: the server learns the block, not which transaction is checked.
        tx = await fetchTransactionPrivately(endpoint, summary.txid, hint);
        fetchMode = { mode: "block", host: new URL(endpoint).host, set: tx.anonymitySet, block: hint };
        setStep("fetch", "done", `block ${hint.toLocaleString()} (${tx.anonymitySet} transactions) from ${new URL(endpoint).host}`);
      } else {
        tx = await fetchRawTx(endpoint, summary.txid);
        fetchMode = { mode: "txid", host: new URL(endpoint).host };
        setStep("fetch", "done", `${short(summary.txid, 6)} at block ${tx.height.toLocaleString()} from ${new URL(endpoint).host}`);
      }
    }
  } catch (e) {
    setStep("fetch", "fail", e.message);
    return showError(`Could not fetch the transaction: ${e.message}`);
  }
  try {
    setStep("verify", "busy", document.querySelector("#warm")?.dataset.state === "ready" ? "checking the Halo 2 proof and signature" : "preparing the verifier (one time), then checking the proof and signature");
    const t0 = performance.now();
    // Source proofs: fetch the earlier transactions the sender says the money came from.
    await local;
    const needed = JSON.parse(source_txids(receiptText));
    let sources;
    const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
    if (needed.length) {
      const stxs = await Promise.all(needed.map((id) => fetchRawTx(endpoint, id)));
      sources = JSON.stringify(stxs.map((t) => ({ raw: bytesToHex(t.raw), height: t.height })));
      if (fetchMode) fetchMode.sources = needed.length;
    }
    const v = await call("verify", { receipt: receiptText, rawTx: tx.raw, height: tx.height, regtest: regtest(), sources });
    // Who funded each source transaction in the clear: the outputs its transparent inputs spent.
    for (const s of v.sources || []) {
      for (const i of s.transparent_inputs.slice(0, 16)) {
        try {
          const prev = await fetchRawTx(endpoint, i.prevout_txid);
          Object.assign(i, JSON.parse(transparent_output(prev.raw, prev.height, i.prevout_index, summary.network === "mainnet" ? 133 : 1, regtest())));
        } catch { /* show the outpoint only */ }
      }
    }
    setStep("verify", "done", `proof and signature valid (${((performance.now() - t0) / 1000).toFixed(1)}s)`);
    // Exchange deposit (ZIP 320): check the second step too.
    const second = /(?:^|\n)second-tx:([0-9a-f]{64})(?:\n|$)/.exec(v.message || "");
    if (second && /(?:^|\n)tex-deposit:/.test(v.message)) {
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
      const tx2 = await fetchRawTx(endpoint, second[1]);
      if (fetchMode) fetchMode.second = true;
      await local;
      v.deposit = JSON.parse(check_tex_deposit(receiptText, tx.raw, tx.height, tx2.raw, tx2.height, regtest()));
    }
    render(v, summary.network);
  } catch (e) {
    setStep("verify", "fail", e.message);
    showError(e.message);
  }
}

async function runBatch(batchText) {
  $("#result").hidden = true;
  $("#progress").hidden = false;
  resetSteps();
  let b;
  try {
    setStep("decode", "busy");
    b = await quick("batch", { batch: batchText });
    setStep("decode", "done", `batch ${b.id}: ${b.receipts.length} receipts, complete and in order`);
  } catch (e) {
    setStep("decode", "fail", e.message);
    return showError(`This batch is not valid: ${e.message}`);
  }
  const results = [];
  try {
    // Fetch every transaction at once; proofs are then checked one by one in the worker.
    setStep("fetch", "busy", `fetching ${b.receipts.length} transactions`);
    const txs = await Promise.all(b.receipts.map(async (r) => {
      const s = await quick("inspect", { receipt: r });
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[s.network]);
      return fetchRawTx(endpoint, s.txid);
    }));
    setStep("fetch", "done", `${txs.length} transactions fetched`);
    for (const [i, r] of b.receipts.entries()) {
      setStep("verify", "busy", `checking proof ${i + 1} of ${b.receipts.length}`);
      results.push(await call("verify", { receipt: r, rawTx: txs[i].raw, height: txs[i].height, regtest: regtest() }));
    }
    setStep("fetch", "done", `${results.length} transactions fetched`);
    setStep("verify", "done", `all ${results.length} proofs and signatures valid`);
  } catch (e) {
    setStep("verify", "fail", e.message);
    return showError(`Payment ${results.length + 1} of the batch failed: ${e.message}`);
  }
  const lines = results.flatMap((v) => v.outputs.map((o) => ({ v, o })));
  const total = lines.reduce((s, l) => s + l.o.zatoshis, 0);
  const recipients = new Set(lines.map((l) => l.o.recipient)).size;
  const note = (results[0].message || "").split("\n").filter((l) => !l.startsWith("batch:")).join(" ");
  $("#result").hidden = false;
  $("#result").innerHTML = `
    <div class="ticket">
      <div class="head"><div class="brand">RECEIPT</div><div class="sub">Zcash · ${results[0].network} · ${results.length} payments</div></div>
      ${note ? `<div class="sub" style="text-align:center;margin-top:6px">${escapeHtml(note)}</div>` : ""}
      <div class="dash"></div>
      ${lines.map(({ v, o }) => `
        <div class="line"><span class="k">${zec(o.zatoshis)}</span><span class="v">${o.memo ? escapeHtml(o.memo) : `<span class="mono">${short(o.recipient, 10)}</span>`}<br><span class="mono" style="font-size:11px;color:var(--ink-2)">${short(o.recipient, 10)} · block ${v.mined_height.toLocaleString()}</span></span></div>`).join("")}
      <div class="dash"></div>
      <div class="line paid"><span class="k">TOTAL</span><span class="v amount">${zec(total)} <small>ZEC</small></span></div>
      <div class="line"><span class="k">TO</span><span class="v">${recipients} recipient${recipients === 1 ? "" : "s"}</span></div>
      <div class="dash"></div>
      <div class="stamp good">VERIFIED</div>
      <ul class="facts">
        <li>Every payment was proven by the wallet that sent it.</li>
        <li>The batch is complete: each receipt signs its place in it, so nothing was dropped or added.</li>
        <li><strong>Not revealed:</strong> the treasury's address, balance, or any other transaction.</li>
      </ul>
    </div>`;
}

function batchFromHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  const i = h.indexOf("zrcptb1");
  return i >= 0 ? h.slice(i) : "";
}

function receiptFromHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  if (h.includes("zrcptb1")) return "";
  const i = h.indexOf("zrcpt1");
  return i >= 0 ? h.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "") : "";
}

// How the transaction was obtained, for the privacy badge.
let fetchMode = null;

$("#verifyBtn").onclick = async () => {
  const t = $("#paste").value.trim();
  await local;
  const leak = secret_kind(t);
  if (leak) {
    $("#paste").value = "";
    return showError(`That looks like a ${leak}. Never paste it anywhere: it reveals your whole wallet. It was cleared and not sent. Paste only the zrcpt1… receipt.`);
  }
  const bi = t.indexOf("zrcptb1");
  if (bi >= 0) {
    const bt = t.slice(bi).replace(/[^A-Za-z0-9_-].*$/s, "");
    history.replaceState(null, "", "#" + bt);
    return runBatch(bt);
  }
  const i = t.indexOf("zrcpt1");
  if (i < 0) return showError("Paste a receipt that starts with zrcpt1, or a link containing one.");
  const r = t.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
  const h = heightHint(t);
  history.replaceState(null, "", "#" + r + (h ? `&h=${h}` : ""));
  run(r);
};
window.addEventListener("hashchange", () => {
  const bt = batchFromHash();
  if (bt) return runBatch(bt);
  const r = receiptFromHash();
  if (r) {
    $("#paste").value = r;
    run(r);
  }
});

const initialBatch = batchFromHash();
if (initialBatch) {
  $("#paste").value = initialBatch;
  runBatch(initialBatch);
}
const initial = receiptFromHash();
if (initial) {
  $("#paste").value = initial;
  run(initial);
}

// ---------- check a payment link ----------
$("#linkBtn").onclick = async () => {
  await local;
  const uri = $("#linkIn").value.trim();
  if (!uri) return;
  const v = JSON.parse(check_payment_uri(uri, regtest() ? "regtest" : ""));
  const pays = v.payments.map((p) =>
    `<li>${escapeHtml(p.network || "unknown network")} ${escapeHtml(p.address_kind)} address · ${p.amount_zatoshis != null ? zec(p.amount_zatoshis) + " ZEC" : "no amount"}${p.memo ? ` · memo “${escapeHtml(p.memo)}”` : ""} · ${p.receipt_provable ? "provable with a receipt" : p.address_kind === "tex" ? "provable with a deposit receipt" : "<strong>not provable with a receipt</strong>"}</li>`).join("");
  const finds = v.findings.map((f) => `<li data-level="${f.level}">${escapeHtml(f.message)}</li>`).join("");
  $("#linkOut").innerHTML = `<div class="verdict">${v.ok ? (v.findings.some((f) => f.level === "warning") ? "Works, with warnings" : "Looks good") : "Fix before printing"}</div>
    <ul>${pays}${v.qr ? `<li>QR version ${v.qr.version} (${v.qr.modules}×${v.qr.modules})</li>` : ""}${finds}</ul>`;
};

// ---------- create a request ----------
$("#reqBtn").onclick = () => {
  const to = $("#reqTo").value.trim();
  const amount = Number($("#reqAmount").value || 0);
  const label = $("#reqLabel").value.trim();
  if (!/^u(test|regtest)?1/.test(to)) { $("#reqOut").textContent = "Enter your unified address (u1…, or utest1… on testnet)."; return; }
  const code = newCode();
  const min = Math.round(amount * 1e8);
  saveRequest(code, { to, min, label, created: new Date().toISOString() });
  const q = new URLSearchParams({ request: code, to });
  if (min) q.set("min", String(min));
  if (label) q.set("label", label);
  if (regtest()) q.set("regtest", "");
  const link = `${location.origin}${location.pathname}?${q}`;
  $("#reqOut").innerHTML = `
    <p class="hint">Send this to the person who paid you. Their receipt must answer challenge <code>${code}</code>.</p>
    <textarea readonly id="reqLink">${escapeHtml(link)}</textarea>
    <p class="hint">They run:</p>
    <div class="cli">receipts create -w &lt;wallet&gt; -i &lt;key.age&gt; --txid &lt;txid&gt; --request '${escapeHtml(link)}'</div>
    <p class="hint">and send back the link it prints. Opening it here checks the challenge, the payee and the amount.</p>`;
};

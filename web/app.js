// Receipts verifier page. The receipt lives in the URL fragment (#zrcpt1…), which browsers
// never send to any server. The only network request is fetching the public transaction
// from a lightwalletd server of the viewer's choice.

const ENDPOINTS = {
  mainnet: "https://zcash-mainnet.chainsafe.dev",
  testnet: "",
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
call("warm").catch(() => {});
import initLocal, { inspect as inspectLocal, orchard_receiver_hex } from "./pkg/receipts_wasm.js";
const local = initLocal();
const quick = async (op, args) => {
  await local;
  if (op === "inspect") return JSON.parse(inspectLocal(args.receipt));
  if (op === "receiver") return orchard_receiver_hex(args.ua);
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

function render(v, net) {
  const rows = v.outputs
    .map(
      (o) => `
      <div class="line paid">
        <span class="k">PAID</span>
        <span class="v amount">${zec(o.zatoshis)} <small>ZEC</small></span>
      </div>
      <div class="line"><span class="k">TO</span><span class="v mono addr" title="${o.recipient}">${short(o.recipient, 14)}</span></div>
      ${o.memo ? `<div class="line"><span class="k">MEMO</span><span class="v memo">“${escapeHtml(o.memo)}”</span></div>` : ""}
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
      <div class="line"><span class="k">BLOCK</span><span class="v mono">${v.mined_height.toLocaleString()}</span></div>
      ${v.message ? `<div class="line"><span class="k">NOTE</span><span class="v">${escapeHtml(v.message)}</span></div>` : ""}
      <div class="dash"></div>
      <div class="stamp good">VERIFIED</div>
      <ul class="facts">
        <li>The sender proved they authorized this payment (zero-knowledge proof + signature over this receipt).</li>
        <li>The amount, recipient and memo above were opened from the transaction on chain.</li>
        <li><strong>Not revealed:</strong> the sender's address, balance, or any other transaction.</li>
      </ul>
      <div class="check">
        <label for="mine">Was it paid to you? Paste your address</label>
        <div class="row"><input id="mine" placeholder="u1…" autocomplete="off" spellcheck="false"><button id="mineBtn">Check</button></div>
        <div id="mineOut" class="fine"></div>
      </div>
    </div>`;
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
      setStep("fetch", "done", "using the transaction you pasted");
    } else {
      const endpoint = $("#endpoint").value.trim() || (regtest() ? location.origin : ENDPOINTS[summary.network]);
      if (!endpoint) throw new Error(`no ${summary.network} server set; open Settings`);
      tx = await fetchRawTx(endpoint, summary.txid);
      setStep("fetch", "done", `${short(summary.txid, 6)} at block ${tx.height.toLocaleString()} from ${new URL(endpoint).host}`);
    }
  } catch (e) {
    setStep("fetch", "fail", e.message);
    return showError(`Could not fetch the transaction: ${e.message}`);
  }
  try {
    setStep("verify", "busy", "checking the Halo 2 proof and signature (the first check also prepares the verifier, about 10s)");
    const t0 = performance.now();
    const v = await call("verify", { receipt: receiptText, rawTx: tx.raw, height: tx.height, regtest: regtest() });
    setStep("verify", "done", `proof and signature valid (${((performance.now() - t0) / 1000).toFixed(1)}s)`);
    render(v, summary.network);
  } catch (e) {
    setStep("verify", "fail", e.message);
    showError(e.message);
  }
}

function receiptFromHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  const i = h.indexOf("zrcpt1");
  return i >= 0 ? h.slice(i) : "";
}

$("#verifyBtn").onclick = () => {
  const t = $("#paste").value.trim();
  const i = t.indexOf("zrcpt1");
  if (i < 0) return showError("Paste a receipt that starts with zrcpt1, or a link containing one.");
  const r = t.slice(i).replace(/[^A-Za-z0-9_-].*$/s, "");
  history.replaceState(null, "", "#" + r);
  run(r);
};
window.addEventListener("hashchange", () => {
  const r = receiptFromHash();
  if (r) run(r);
});

const initial = receiptFromHash();
if (initial) {
  $("#paste").value = initial;
  run(initial);
}

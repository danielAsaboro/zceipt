#!/usr/bin/env node
// Kemi's Coffee: a complete shop integration of Receipts in ~200 lines, no dependencies.
//
//   RECEIPTS_KEY=rcpt_test_… SHOP_ADDRESS=utest1… node examples/shop/server.mjs
//   open http://localhost:4242
//
// Flow: the customer picks drinks → the shop creates a proof request (amount + order id) →
// the customer pays the ZIP-321 QR from any shielded wallet → they hand back a receipt
// (`receipts create --request <link>`, or paste it on the order page) → Receipts verifies it
// and sends a signed `request.fulfilled` webhook → the order is marked paid.
// The shop never holds a viewing key and never learns who the customer is.

import http from "node:http";
import { Receipts, webhooks, VerificationError } from "../../packages/zcash-receipts/client.js";

const PORT = Number(process.env.PORT || 4242);
const API = process.env.RECEIPTS_URL || "http://127.0.0.1:8723";
const SHOP_ADDRESS = process.env.SHOP_ADDRESS;
if (!process.env.RECEIPTS_KEY || !SHOP_ADDRESS) {
  console.error("Set RECEIPTS_KEY (rcpt_test_…) and SHOP_ADDRESS (your utest1… address).");
  process.exit(1);
}
const receipts = new Receipts(process.env.RECEIPTS_KEY, { baseUrl: API });

const MENU = [
  { id: "flat-white", name: "Flat white", zats: 500_000 },
  { id: "cold-brew", name: "Cold brew", zats: 400_000 },
  { id: "croissant", name: "Croissant", zats: 300_000 },
];
const orders = new Map(); // order id → { items, total, requestId, status, paidTx }
let whsec = "";

// Register this shop's webhook endpoint with the Receipts API.
const endpoint = await receipts.webhookEndpoints.create({ url: `http://127.0.0.1:${PORT}/webhooks/receipts`, events: ["request.fulfilled"] });
whsec = endpoint.secret;
process.on("SIGINT", async () => { await receipts.webhookEndpoints.del(endpoint.id).catch(() => {}); process.exit(0); });

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const zec = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Kemi's Coffee</title><style>
body{margin:0;background:#f6f1e7;color:#2a2118;font:16px/1.5 ui-sans-serif,system-ui,sans-serif}main{max-width:720px;margin:0 auto;padding:32px 18px}
h1{font-family:Georgia,serif;font-size:34px;margin:0 0 4px}.sub{color:#7a6a58;margin:0 0 22px}.card{background:#fff;border:1px solid #e6dccb;border-radius:14px;padding:18px 20px;margin:14px 0}
.item{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px dashed #e6dccb}.item:last-child{border:0}
button{background:#2a2118;color:#f6f1e7;border:0;border-radius:10px;padding:11px 16px;font:600 15px system-ui;cursor:pointer}input[type=number]{width:60px}
code,textarea{font:12px ui-monospace,Menlo,monospace}textarea{width:100%;min-height:90px}.paid{color:#1d6b45;font-weight:700}.wait{color:#9a6b00;font-weight:700}
.qr{width:220px;background:#fff;border:1px solid #e6dccb;border-radius:10px;padding:6px}.qr svg{width:100%;height:auto;display:block}.err{color:#a3271f}
.row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}</style></head><body><main><h1>Kemi's Coffee</h1><p class="sub">Pay privately with shielded Zcash (testnet). No accounts, no viewing keys.</p>${body}</main></body></html>`;

function readBody(req) {
  return new Promise((resolve) => { const c = []; req.on("data", (d) => c.push(d)); req.on("end", () => resolve(Buffer.concat(c))); });
}
const send = (res, status, html, type = "text/html; charset=utf-8") => { res.writeHead(status, { "content-type": type }); res.end(html); };
const redirect = (res, to) => { res.writeHead(303, { location: to }); res.end(); };

async function orderPage(id, error = "") {
  const o = orders.get(id);
  const r = await receipts.requests.retrieve(o.requestId);
  if (r.status === "fulfilled" && o.status !== "paid") { o.status = "paid"; o.paidTx = r.fulfillment.txid; }
  const qr = o.status === "paid" ? "" : await fetch(`${API}/v1/requests/${r.id}/qr.svg`, { headers: { authorization: `Bearer ${process.env.RECEIPTS_KEY}` } }).then((x) => x.text());
  return page(`Order ${id}`, `
    <div class="card"><b>Order ${esc(id)}</b> · ${o.items.map((i) => `${i.qty}× ${esc(i.name)}`).join(", ")} · <b>${zec(o.total)} ZEC</b>
      <div style="margin-top:8px">${o.status === "paid" ? `<span class="paid">PAID ✓</span> · tx <code>${esc(o.paidTx.slice(0, 16))}…</code> · we'll start brewing.` : `<span class="wait">Waiting for payment proof…</span>`}</div></div>
    ${o.status === "paid" ? "" : `
    <div class="card"><div class="row"><div class="qr">${qr}</div><div style="flex:1;min-width:240px">
      <p><b>1.</b> Scan with any shielded Zcash wallet, or pay <code>${esc(r.payment_uri)}</code></p>
      <p><b>2.</b> Prove it (your wallet stays private):</p><code>${esc(r.cli_command)}</code></div></div></div>
    <form class="card" method="post" action="/order/${esc(id)}/receipt"><b>3.</b> Paste the receipt link here
      <textarea name="receipt" placeholder="https://…#zip311r1…  (sandbox: zrcpt_test_valid)"></textarea>
      ${error ? `<p class="err">${esc(error)}</p>` : ""}<button>Confirm payment</button></form>
    <script>setInterval(async()=>{const s=await (await fetch('/order/${esc(id)}/status')).json(); if(s.status==='paid') location.reload();},3000)</script>`}`);
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "GET" && url.pathname === "/") {
      return send(res, 200, page("Menu", `<form class="card" method="post" action="/checkout">${MENU.map((m) => `
        <div class="item"><span>${esc(m.name)} · ${zec(m.zats)} ZEC</span><input type="number" name="${m.id}" min="0" max="9" value="${m.id === "flat-white" ? 2 : 0}"></div>`).join("")}
        <p><button>Pay with Zcash</button></p></form>`));
    }
    if (req.method === "POST" && url.pathname === "/checkout") {
      const form = new URLSearchParams((await readBody(req)).toString());
      const items = MENU.map((m) => ({ ...m, qty: Number(form.get(m.id) || 0) })).filter((i) => i.qty > 0);
      if (!items.length) return redirect(res, "/");
      const total = items.reduce((s, i) => s + i.qty * i.zats, 0);
      const id = "KC" + Math.random().toString(36).slice(2, 7).toUpperCase();
      const r = await receipts.requests.create(
        { payee: SHOP_ADDRESS, amount_zatoshis: total, label: `Kemi's Coffee order ${id}`, metadata: { order_id: id }, expires_in: 3600 },
        { idempotencyKey: `order-${id}` },
      );
      orders.set(id, { items, total, requestId: r.id, status: "awaiting_payment" });
      return redirect(res, `/order/${id}`);
    }
    const m = url.pathname.match(/^\/order\/([A-Z0-9]+)(\/receipt|\/status)?$/);
    if (m && orders.has(m[1])) {
      const id = m[1];
      if (req.method === "GET" && !m[2]) return send(res, 200, await orderPage(id));
      if (req.method === "GET" && m[2] === "/status") return send(res, 200, JSON.stringify({ status: orders.get(id).status }), "application/json");
      if (req.method === "POST" && m[2] === "/receipt") {
        const receipt = new URLSearchParams((await readBody(req)).toString()).get("receipt")?.trim();
        try {
          await receipts.requests.submitReceipt(orders.get(id).requestId, { receipt });
          return redirect(res, `/order/${id}`);
        } catch (e) {
          const msg = e instanceof VerificationError ? `Not accepted (${e.code}): ${e.message}` : e.message;
          return send(res, 422, await orderPage(id, msg));
        }
      }
    }
    if (req.method === "POST" && url.pathname === "/webhooks/receipts") {
      const raw = await readBody(req);
      let event;
      try { event = await webhooks.constructEvent(raw, req.headers["receipts-signature"], whsec); }
      catch (e) { return send(res, 400, "bad signature", "text/plain"); }
      if (event.type === "request.fulfilled") {
        const r = event.data.object;
        const o = orders.get(r.metadata.order_id);
        if (o && o.status !== "paid") {
          o.status = "paid";
          o.paidTx = r.fulfillment.txid;
          console.log(`order ${r.metadata.order_id} paid: ${zec(r.fulfillment.paid_zatoshis)} ZEC, tx ${r.fulfillment.txid}`);
        }
      }
      return send(res, 200, "ok", "text/plain");
    }
    send(res, 404, page("Not found", "<p>Not found.</p>"));
  } catch (e) {
    send(res, 500, page("Error", `<p class="err">${esc(e.message)}</p>`));
  }
}).listen(PORT, "127.0.0.1", () => console.log(`Kemi's Coffee on http://localhost:${PORT}  (Receipts API ${API})`));

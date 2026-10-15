#!/usr/bin/env node
// A paid API in 40 lines: HTTP 402 until the caller proves a shielded payment with a receipt.
//
//   RECEIPTS_KEY=rcpt_test_… SHOP_ADDRESS=utest1… node examples/paid-api/server.mjs
//   curl -i localhost:4343/report                       # 402 + payment_uri + receipt_link
//   …pay, then `receipts create … --request '<receipt_link>'` (sandbox: submit zrcpt_test_valid)…
//   curl -H 'Receipt-Request: preq_…' localhost:4343/report   # 200
//
// The API never sees the payer's wallet, and a paid request id only works for the caller it
// was issued to (here: the client's IP, for the demo; use a session or account id).

import http from "node:http";
import { Receipts } from "../../packages/zcash-receipts/client.js";
import { receiptGate, webhookHandler } from "../../packages/zcash-receipts/middleware.js";

const receipts = new Receipts(process.env.RECEIPTS_KEY, { baseUrl: process.env.RECEIPTS_URL || "http://127.0.0.1:8723" });
const gate = { receipts, payee: process.env.SHOP_ADDRESS, amountZatoshis: 100_000, label: "One report", bindTo: (req) => req.headers.get("x-forwarded-for") || "local" };
const PORT = Number(process.env.PORT || 4343);

http
  .createServer(async (req, res) => {
    const request = new Request(`http://localhost${req.url}`, { method: req.method, headers: req.headers });
    if (req.url === "/report") {
      const blocked = await receiptGate.fetch(request, gate);
      if (blocked) {
        res.writeHead(blocked.status, Object.fromEntries(blocked.headers));
        return res.end(await blocked.text());
      }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ report: "Q3 numbers", paid_with: request.headers.get("receipt-request") }));
    }
    res.writeHead(404).end();
  })
  .listen(PORT, () => console.log(`paid API on http://localhost:${PORT}/report`));

#!/usr/bin/env node
// A paid API in 40 lines: HTTP 402 until the caller proves a shielded payment with a receipt.
//
//   ZCEIPT_KEY=rcpt_test_… SHOP_ADDRESS=utest1… node examples/paid-api/server.mjs
//   curl -iL -c jar -b jar localhost:4343/report                  # 402 + payment_uri + receipt_link
//   …pay, then `zceipt pay '<hosted_url>'` (sandbox: submit zip311_test_valid)…
//   curl -b jar -H 'Receipt-Request: preq_…' localhost:4343/report  # 200
//
// The API never sees the payer's wallet, and a paid request id only works for the caller it
// was issued to: here a random session cookie the server sets (in a real app, your session or
// account id). Never bind to something the client sends, like X-Forwarded-For.

import http from "node:http";
import { Zceipt } from "../../packages/zceipt/client.js";
import { receiptGate, webhookHandler } from "../../packages/zceipt/middleware.js";

const receipts = new Zceipt(process.env.ZCEIPT_KEY, { baseUrl: process.env.ZCEIPT_URL || "http://127.0.0.1:8723" });
const session = (req) => /(?:^|;\s*)sid=([0-9a-f]{32})/.exec(req.headers.get("cookie") || "")?.[1];
const gate = { receipts, payee: process.env.SHOP_ADDRESS, amountZatoshis: 100_000, label: "One report", route: "/report", bindTo: session };
const PORT = Number(process.env.PORT || 4343);

http
  .createServer(async (req, res) => {
    const request = new Request(`http://localhost${req.url}`, { method: req.method, headers: req.headers });
    if (req.url === "/report") {
      if (!session(request)) {
        // First visit: give the caller a session, then gate it.
        res.setHeader("set-cookie", `sid=${crypto.randomUUID().replaceAll("-", "")}; HttpOnly; SameSite=Lax; Path=/`);
        res.writeHead(303, { location: "/report" });
        return res.end();
      }
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

// Drop-in server integrations: an HTTP 402 "prove you paid" gate and a webhook handler.
// Framework-agnostic cores, plus Express (Connect-style) and fetch-style (Next.js route
// handlers, Hono, Bun, Deno) adapters. No dependencies.
//
//   import express from "express";
//   import { Receipts } from "zcash-receipts/client";
//   import { receiptGate, webhookHandler } from "zcash-receipts/middleware";
//
//   const receipts = new Receipts(process.env.RECEIPTS_KEY);
//   app.get("/report.pdf", receiptGate.express({ receipts, payee: SHOP_UA, amountZatoshis: 1_000_000 }), sendReport);
//   app.post("/webhooks/receipts", express.raw({ type: "application/json" }),
//     webhookHandler.express({ secret: process.env.RECEIPTS_WHSEC, on: { "request.fulfilled": (e) => markPaid(e) } }));
//
// The gate: a request with no proof gets HTTP 402 Payment Required and a JSON body with a
// ZIP-321 `payment_uri` and a `receipt_link`. The client pays, answers the link with a receipt
// (`receipts create --request <receipt_link>`), and retries with `Receipt-Request: <id>`: the
// gate lets it through once that request is fulfilled. The server never sees a viewing key.

import { webhooks } from "./client.js";

const HEADER = "receipt-request";

/** Core gate: decide from a request id (or none) whether to let a caller through. */
// A fulfilled request id is a bearer token: whoever presents it gets through. Pass `bindTo`
// (a session or account id) to tie each request to the caller it was issued to.
export async function checkGate({ receipts, payee, amountZatoshis, label, requestId, expiresIn = 3600, requireFinal = false, bindTo }) {
  if (requestId) {
    let r;
    try {
      r = await receipts.requests.retrieve(requestId);
    } catch {
      r = null;
    }
    // Only a request this gate could have made counts: same payee, at least the amount.
    const bound = bindTo == null || r?.metadata?.gate_bind === String(bindTo);
    if (r && bound && r.payee === payee && (r.amount_zatoshis ?? 0) >= amountZatoshis) {
      if (r.status === "fulfilled" && (!requireFinal || r.final)) return { allow: true, request: r };
      if (r.status === "open" || r.status === "fulfilled") return { allow: false, status: 402, body: challengeBody(r, requireFinal && r.status === "fulfilled" ? "paid; waiting for 10 confirmations" : "waiting for the receipt") };
    }
  }
  const r = await receipts.requests.create({ payee, amount_zatoshis: amountZatoshis, label, expires_in: expiresIn, metadata: bindTo == null ? undefined : { gate_bind: String(bindTo) } });
  return { allow: false, status: 402, body: challengeBody(r, "payment required") };
}

function challengeBody(r, state) {
  return {
    error: { type: "payment_required", message: `Pay ${r.amount_zatoshis / 1e8} ZEC, answer the receipt link with a receipt, then retry with the header Receipt-Request: ${r.id}`, state },
    request: r.id,
    payment_uri: r.payment_uri,
    receipt_link: r.receipt_link,
    hosted_url: r.hosted_url,
    expires_at: r.expires_at,
    retry_with_header: { "Receipt-Request": r.id },
  };
}

export const receiptGate = {
  /** Express / Connect middleware. Sets `req.receiptRequest` when the caller is let through. */
  express(opts) {
    return async (req, res, next) => {
      try {
        const bindTo = typeof opts.bindTo === "function" ? opts.bindTo(req) : opts.bindTo;
        const g = await checkGate({ ...opts, bindTo, requestId: req.get?.(HEADER) ?? req.headers?.[HEADER] });
        if (g.allow) {
          req.receiptRequest = g.request;
          return next();
        }
        if (res.set) res.set("Link", `<${g.body.receipt_link}>; rel="payment"`);
        res.status(g.status).json(g.body);
      } catch (e) {
        next(e);
      }
    };
  },
  /** Fetch-style: returns a 402 `Response`, or `null` to let the request through. */
  async fetch(request, opts) {
    const bindTo = typeof opts.bindTo === "function" ? opts.bindTo(request) : opts.bindTo;
    const g = await checkGate({ ...opts, bindTo, requestId: request.headers.get(HEADER) });
    if (g.allow) return null;
    return new Response(JSON.stringify(g.body), { status: g.status, headers: { "content-type": "application/json", link: `<${g.body.receipt_link}>; rel="payment"` } });
  },
};

/** Core webhook check: verifies the signature and dispatches `on[type]` (or `on["*"]`). */
export async function handleWebhook({ secret, on = {}, toleranceSecs = 300 }, rawBody, signatureHeader) {
  const event = await webhooks.constructEvent(rawBody, signatureHeader, secret, { toleranceSecs });
  const fn = on[event.type] ?? on["*"];
  if (fn) await fn(event);
  return event;
}

export const webhookHandler = {
  /** Express handler; mount it after `express.raw({ type: "application/json" })`. */
  express(opts) {
    return async (req, res) => {
      const raw = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : typeof req.body === "string" ? req.body : null;
      if (raw == null) return res.status(500).send("mount express.raw({ type: 'application/json' }) before the webhook handler");
      try {
        await handleWebhook(opts, raw, req.get?.("receipts-signature") ?? req.headers["receipts-signature"]);
        res.status(200).send("ok");
      } catch (e) {
        res.status(400).send(String(e.message || e));
      }
    };
  },
  /** Fetch-style (Next.js `export async function POST(req)`): returns a `Response`. */
  async fetch(request, opts) {
    try {
      await handleWebhook(opts, await request.text(), request.headers.get("receipts-signature"));
      return new Response("ok");
    } catch (e) {
      return new Response(String(e.message || e), { status: 400 });
    }
  },
};

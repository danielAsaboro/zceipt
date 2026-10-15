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
// Each open-ended caller would otherwise mint a new proof request (an API call and a row) per
// hit. The gate reuses the open request it already issued to the same caller for the same
// route, and caps how many new ones it creates per minute in all (`maxNewPerMinute`).
const issued = new Map(); // `${bind}|${route}` -> { id, at }
let windowStart = 0, createdInWindow = 0;

// A fulfilled request id is a bearer token: whoever presents it gets through. Pass `bindTo`
// (a server-side session or account id, never a header the client sets) to tie it to one caller,
// `route` to tie it to one resource (default: the label), and `maxAgeSeconds` to make access
// expire. Refunds already paid back count against the price.
export async function checkGate({ receipts, payee, amountZatoshis, label, route, requestId, expiresIn = 3600, requireFinal = false, bindTo, maxAgeSeconds, maxNewPerMinute = 30 }) {
  const routeKey = String(route ?? label ?? "default");
  const bind = bindTo == null ? null : String(bindTo);
  if (requestId) {
    let r;
    try {
      r = await receipts.requests.retrieve(requestId);
    } catch {
      r = null;
    }
    const m = r?.metadata ?? {};
    const refunded = (r?.refunds ?? []).filter((x) => x.status === "succeeded").reduce((s, x) => s + x.amount_zatoshis, 0);
    const matches = r && r.kind === "single" && r.payee === payee && m.gate_route === routeKey && (bind == null || m.gate_bind === bind);
    if (matches && (r.received_zatoshis ?? 0) - refunded >= amountZatoshis && r.status === "fulfilled") {
      const fresh = maxAgeSeconds == null || (r.fulfillment?.fulfilled_at ?? 0) * 1000 > Date.now() - maxAgeSeconds * 1000;
      if (fresh && (!requireFinal || r.final)) return { allow: true, request: r };
      if (!fresh) return issue("access expired; pay again");
      return { allow: false, status: 402, body: challengeBody(r, "paid; waiting for 10 confirmations") };
    }
    if (matches && r.status === "open") return { allow: false, status: 402, body: challengeBody(r, "waiting for the receipt") };
  }
  return issue("payment required");

  async function issue(state) {
    const key = `${bind ?? "*"}|${routeKey}`;
    const prev = issued.get(key);
    if (prev && Date.now() - prev.at < Math.min(expiresIn, 600) * 1000) {
      try {
        const r = await receipts.requests.retrieve(prev.id);
        if (r.status === "open") return { allow: false, status: 402, body: challengeBody(r, state) };
      } catch {}
    }
    const now = Date.now();
    if (now - windowStart > 60_000) { windowStart = now; createdInWindow = 0; }
    if (++createdInWindow > maxNewPerMinute) {
      return { allow: false, status: 429, body: { error: { type: "rate_limited", message: "too many new payment requests; retry in a minute" } }, retryAfter: Math.ceil((windowStart + 60_000 - now) / 1000) };
    }
    const r = await receipts.requests.create({ payee, amount_zatoshis: amountZatoshis, label, expires_in: expiresIn, metadata: { gate_route: routeKey, ...(bind == null ? {} : { gate_bind: bind }) } });
    issued.set(key, { id: r.id, at: now });
    if (issued.size > 10_000) issued.clear();
    return { allow: false, status: 402, body: challengeBody(r, state) };
  }
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
        if (res.set && g.body.receipt_link) res.set("Link", `<${g.body.receipt_link}>; rel="payment"`);
        if (res.set && g.retryAfter) res.set("Retry-After", String(g.retryAfter));
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
    const headers = { "content-type": "application/json" };
    if (g.body.receipt_link) headers.link = `<${g.body.receipt_link}>; rel="payment"`;
    if (g.retryAfter) headers["retry-after"] = String(g.retryAfter);
    return new Response(JSON.stringify(g.body), { status: g.status, headers });
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

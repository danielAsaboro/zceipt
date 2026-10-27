// Zceipt API client: proof requests, verification and webhooks, for Node 18+, Deno, Bun,
// edge runtimes and browsers (server-side keys belong on servers).
//
//   import { Zceipt } from "zceipt/client";
//   const receipts = new Zceipt(process.env.ZCEIPT_KEY, { baseUrl: "http://127.0.0.1:8723" });
//   const req = await receipts.requests.create({ payee: "utest1…", amount_zatoshis: 1_000_000, label: "Order #42" });
//   // …payer answers with `zceipt create --request req.receipt_link`…
//   const done = await receipts.requests.submitReceipt(req.id, { receipt });
//
// Retries: network errors, 409 lock conflicts, 429 and 5xx are retried with backoff. Every POST
// gets an Idempotency-Key, so a retry can never act twice.

export class ZceiptError extends Error {
  constructor(status, body = {}) {
    const e = body.error ?? {};
    super(e.message ?? `HTTP ${status}`);
    this.name = new.target.name;
    this.status = status;
    this.type = e.type;
    this.code = e.code;
    this.param = e.param ?? null;
    this.docUrl = e.doc_url;
    this.raw = body;
  }
}
/** 401: missing or unknown API key. */
export class AuthenticationError extends ZceiptError {}
/** 400/404/409: the request is wrong (bad parameter, unknown id, already fulfilled…). */
export class InvalidRequestError extends ZceiptError {}
/** 422: the receipt was read but does not prove what is required. See `code`. */
export class VerificationError extends ZceiptError {}
/** 5xx or 502 `chain_unavailable`: safe to retry. */
export class ApiError extends ZceiptError {}
/** The server could not be reached. */
export class ConnectionError extends ZceiptError {
  constructor(cause) {
    super(0, { error: { type: "connection_error", code: "connection_failed", message: String(cause?.message ?? cause) } });
    this.cause = cause;
  }
}

function errorFor(status, body) {
  if (status === 401) return new AuthenticationError(status, body);
  if (status === 422) return new VerificationError(status, body);
  if (status >= 500) return new ApiError(status, body);
  return new InvalidRequestError(status, body);
}

function randomKey() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Zceipt {
  /**
   * @param {string} apiKey rcpt_test_… (testnet) or rcpt_live_… (mainnet)
   * @param {{ baseUrl?: string, maxRetries?: number, timeoutMs?: number, fetch?: typeof fetch }} [options]
   */
  constructor(apiKey, options = {}) {
    if (!apiKey) throw new AuthenticationError(401, { error: { code: "missing_api_key", message: "pass your rcpt_test_… or rcpt_live_… key" } });
    this.apiKey = apiKey;
    const envUrl = typeof process !== "undefined" ? process.env?.ZCEIPT_URL : undefined;
    this.baseUrl = (options.baseUrl ?? envUrl ?? "http://127.0.0.1:8723").replace(/\/$/, "");
    this.livemode = apiKey.startsWith("rcpt_live_");
    // A live key goes over https (or to this computer): never in the clear across a network.
    if (this.livemode && !/^https:\/\//i.test(this.baseUrl) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?([\/?#]|$)/i.test(this.baseUrl)) {
      throw new Error("a live API key must be sent over https; set baseUrl to an https:// URL");
    }
    this.maxRetries = options.maxRetries ?? 2;
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.livemode = apiKey.startsWith("rcpt_live_");

    const r = this;
    this.requests = {
      /** Create a proof request. Returns a ProofRequest with `payment_uri` and `receipt_link`. */
      create: (params, opts) => r._request("POST", "/v1/requests", params, opts),
      retrieve: (id) => r._request("GET", `/v1/requests/${encodeURIComponent(id)}`),
      list: (params = {}) => r._request("GET", `/v1/requests${qs(params)}`),
      /** Submit the payer's receipt. Resolves to the fulfilled ProofRequest, or throws VerificationError. */
      submitReceipt: (id, params, opts) => r._request("POST", `/v1/requests/${encodeURIComponent(id)}/receipts`, params, opts),
      /** Deposit desks: accept or reject a deposit held for review, `{ decision: "accept" | "reject", note }`. */
      review: (id, params, opts) => r._request("POST", `/v1/requests/${encodeURIComponent(id)}/review`, params, opts),
      /** Iterate every request across pages: `for await (const r of receipts.requests.each())`. */
      each: (params = {}) => paginate((p) => r.requests.list(p), params),
      /** The request's ZIP-321 payment URI as an SVG QR code (a string). */
      qr: (id) => r._text(`/v1/requests/${encodeURIComponent(id)}/qr.svg`),
    };
    /** What hosted pay and campaign pages use: no API key, a per-request client secret. */
    this.public = {
      getRequest: (id, secret) => r._request("GET", `/v1/public/requests/${encodeURIComponent(id)}?secret=${encodeURIComponent(secret)}`),
      submitReceipt: (id, params) => r._request("POST", `/v1/public/requests/${encodeURIComponent(id)}/receipts`, params),
      campaign: (id) => r._request("GET", `/v1/public/campaigns/${encodeURIComponent(id)}`),
    };
    this.paymentLinks = {
      /** Lint a ZIP-321 link: `{ uri, network? }`. */
      check: (params) => r._request("POST", "/v1/payment_links/check", typeof params === "string" ? { uri: params } : params),
    };
    this.deliveries = { list: (params = {}) => r._request("GET", `/v1/deliveries${qs(params)}`) };
    this.sandbox = { fixtures: () => r._request("GET", "/v1/sandbox/fixtures") };
    this.errors = { list: () => r._request("GET", "/v1/errors") };
    this.refunds = {
      /** Refund a payment to the payer's signed refund address: `{ amount_zatoshis?, reason?, payment_txid? }`. */
      create: (requestId, params = {}, opts) => r._request("POST", `/v1/requests/${encodeURIComponent(requestId)}/refunds`, params, opts),
      retrieve: (id) => r._request("GET", `/v1/refunds/${encodeURIComponent(id)}`),
      /** Settle a refund with the receipt for the refund payment. */
      submitReceipt: (id, params, opts) => r._request("POST", `/v1/refunds/${encodeURIComponent(id)}/receipts`, params, opts),
    };
    this.attestations = {
      /** A signed minimal statement about a fulfilled request: `{ at_least_zatoshis?, before?, disclose? }`. */
      create: (requestId, params = {}) => r._request("POST", `/v1/requests/${encodeURIComponent(requestId)}/attestations`, params),
      verify: (attestation) => r._request("POST", "/v1/attestations/verify", { attestation }),
      /** The server's attestation public keys (JWKS). */
      jwks: () => r._request("GET", "/.well-known/jwks.json"),
    };
    this.testClocks = {
      /** Sandbox: a frozen time and block height. `{ frozen_time?, height? }` */
      create: (params = {}) => r._request("POST", "/v1/test_clocks", params),
      retrieve: (id) => r._request("GET", `/v1/test_clocks/${encodeURIComponent(id)}`),
      /** Move the clock by `{ seconds?, blocks? }`; resolves with `fired` events. */
      advance: (id, params) => r._request("POST", `/v1/test_clocks/${encodeURIComponent(id)}/advance`, params),
      /** Roll the clock's chain back `{ depth }` blocks: unconfirmed payments fire request.payment_reorged. */
      reorg: (id, params = {}) => r._request("POST", `/v1/test_clocks/${encodeURIComponent(id)}/reorg`, params),
    };
    this.signIn = {
      /** Sign in with Zcash: a single-use nonce bound to `{ domain }`, valid 5 minutes. */
      createChallenge: (params = {}) => r._request("POST", "/v1/sign_in/challenges", params),
      /** Check a `zsig1…` once: `{ sign_in }` → `{ verified, address, domain }`. */
      verify: (params) => r._request("POST", "/v1/sign_in/verify", typeof params === "string" ? { sign_in: params } : params),
    };
    this.claims = {
      /** Check a `zip311t1…` claim `{ claim, domain, height }` or payer tag `{ claim, domain }`; returns its tag. */
      verify: (params) => r._request("POST", "/v1/claims/verify", params),
    };
    this.webhookEndpoints = {
      create: (params) => r._request("POST", "/v1/webhook_endpoints", params),
      list: () => r._request("GET", "/v1/webhook_endpoints"),
      del: (id) => r._request("DELETE", `/v1/webhook_endpoints/${encodeURIComponent(id)}`),
    };
    this.events = {
      list: (params = {}) => r._request("GET", `/v1/events${qs(params)}`),
      resend: (id) => r._request("POST", `/v1/events/${encodeURIComponent(id)}/resend`, {}),
    };
  }

  /** Verify a receipt or batch. Options: expect_address, min_zatoshis, challenge. */
  verify(params, opts) {
    if (typeof params === "string") params = { receipt: params };
    return this._request("POST", "/v1/verify", params, opts);
  }

  /** Server health and networks. */
  health() {
    return this._request("GET", "/v1/health");
  }

  async _text(path) {
    const res = await this._fetch(this.baseUrl + path, { headers: { authorization: `Bearer ${this.apiKey}` } });
    if (!res.ok) throw errorFor(res.status, await res.json().catch(() => ({})));
    return res.text();
  }

  async _request(method, path, body, opts = {}) {
    const headers = { authorization: `Bearer ${this.apiKey}`, "user-agent": "zceipt-js/0.1" };
    let payload;
    if (method === "POST") {
      headers["content-type"] = "application/json";
      headers["idempotency-key"] = opts.idempotencyKey ?? randomKey();
      payload = JSON.stringify(body ?? {});
    }
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
        res = await this._fetch(this.baseUrl + path, { method, headers, body: payload, signal: ctrl.signal });
        clearTimeout(timer);
      } catch (e) {
        if (attempt < this.maxRetries) { await sleep(500 * 2 ** attempt); continue; }
        throw new ConnectionError(e);
      }
      const text = await res.text();
      let json;
      try { json = text ? JSON.parse(text) : {}; } catch { json = { error: { message: text } }; }
      if (res.ok) return json;
      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && attempt < this.maxRetries) {
        const after = Number(res.headers.get("retry-after"));
        await sleep(after > 0 ? Math.min(after, 60) * 1000 : 500 * 2 ** attempt);
        continue;
      }
      throw errorFor(res.status, json);
    }
  }
}

function qs(params) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)]));
  const s = q.toString();
  return s ? `?${s}` : "";
}

async function* paginate(list, params) {
  let starting_after;
  for (;;) {
    const page = await list({ ...params, starting_after });
    for (const item of page.data) yield item;
    if (!page.has_more || page.data.length === 0) return;
    starting_after = page.data[page.data.length - 1].id;
  }
}

// ---------- webhooks ----------

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
  return Array.from(sig, (x) => x.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export class WebhookSignatureError extends Error {}

export const webhooks = {
  /**
   * Verifies a delivery and returns the parsed event. Pass the *raw* request body.
   *
   *   const event = await webhooks.constructEvent(rawBody, req.headers["zceipt-signature"], process.env.ZCEIPT_WHSEC);
   *   if (event.type === "request.fulfilled") markPaid(event.data.object.metadata.order_id);
   */
  async constructEvent(rawBody, signatureHeader, secret, { toleranceSecs = 300 } = {}) {
    const body = typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody);
    const parts = Object.fromEntries(String(signatureHeader ?? "").split(",").map((p) => p.split("=", 2)));
    const t = Number(parts.t);
    if (!t || !parts.v1) throw new WebhookSignatureError("missing or malformed Zceipt-Signature header");
    if (Math.abs(Date.now() / 1000 - t) > toleranceSecs) throw new WebhookSignatureError("timestamp outside the tolerance window");
    const expected = await hmacHex(secret, `${t}.${body}`);
    if (!safeEqual(expected, parts.v1)) throw new WebhookSignatureError("signature does not match");
    return JSON.parse(body);
  },
  /** Builds a valid header for tests: `t=…,v1=…`. */
  async sign(rawBody, secret, t = Math.floor(Date.now() / 1000)) {
    return `t=${t},v1=${await hmacHex(secret, `${t}.${rawBody}`)}`;
  },
};

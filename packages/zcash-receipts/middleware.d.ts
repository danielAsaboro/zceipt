import type { Receipts } from "./client";
export interface GateOptions { receipts: Receipts; payee: string; amountZatoshis: number; label?: string; expiresIn?: number; requireFinal?: boolean; bindTo?: string | ((req: any) => string); route?: string; maxAgeSeconds?: number; maxNewPerMinute?: number }
export interface GateResult { allow: boolean; status?: 402 | 429; retryAfter?: number; body?: { request: string; payment_uri: string; receipt_link: string; hosted_url: string; expires_at: number | null; retry_with_header: { "Receipt-Request": string }; error: { type: "payment_required"; message: string; state: string } }; request?: any }
export function checkGate(opts: GateOptions & { requestId?: string | null }): Promise<GateResult>;
export const receiptGate: {
  express(opts: GateOptions): (req: any, res: any, next: (err?: unknown) => void) => Promise<void>;
  fetch(request: Request, opts: GateOptions): Promise<Response | null>;
};
export interface WebhookOptions { secret: string; on?: Record<string, (event: any) => unknown>; toleranceSecs?: number }
export function handleWebhook(opts: WebhookOptions, rawBody: string, signatureHeader: string | null | undefined): Promise<any>;
export const webhookHandler: {
  express(opts: WebhookOptions): (req: any, res: any) => Promise<void>;
  fetch(request: Request, opts: WebhookOptions): Promise<Response>;
};

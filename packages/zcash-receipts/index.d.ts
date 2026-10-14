import type { Verification, BatchVerification } from "./client";
export type { Verification, BatchVerification, Output } from "./client";

export interface VerifyOptions {
  endpoint?: string;
  rawTx?: Uint8Array | string;
  /** With rawTx: the block height. Without: a block hint, so the whole block is fetched (also read from `&h=` in links). */
  height?: number;
  /** Set false to fetch by txid even when a block hint is present. */
  privateFetch?: boolean;
  /** Most transactions fetched from the hinted block (default 64, always including yours). */
  maxAnonymitySet?: number;
  regtest?: boolean;
  expectAddress?: string;
  minZatoshis?: number;
  challenge?: string;
}
export const DEFAULT_ENDPOINTS: { mainnet: string; testnet: string };
export function extractReceipt(input: string): string;
export function extractBatch(input: string): string | null;
export function inspectReceipt(input: string): Promise<{ network: string; pool: string; txid: string; message: string; outputs: number; spends: number; bytes: number }>;
export function orchardReceiver(ua: string): Promise<string>;
export function verifyReceipt(input: string, options?: VerifyOptions): Promise<Omit<Verification, "object" | "livemode" | "challenge" | "batch"> & { paidToExpected?: number; local: true; fetch: FetchInfo }>;
/** What the lightwalletd server could learn from this verification. */
export interface FetchInfo { mode: "offline" | "block" | "txid"; server: string | null; anonymity_set?: number; sees: string }
export function verifyBatch(input: string, options?: VerifyOptions): Promise<{ id: string; results: Verification[]; totals: Record<string, number> }>;
export function fetchTransaction(endpoint: string, displayTxid: string): Promise<{ raw: Uint8Array; height: number }>;
/** Fetches a transaction by downloading its whole block's shielded transactions, so the server can't tell which one you wanted. */
export function fetchTransactionPrivately(endpoint: string, displayTxid: string, height: number, options?: { maxSet?: number }): Promise<{ raw: Uint8Array; height: number; anonymitySet: number; blockTxs: number }>;
/** The `h=` block hint in a receipt link, or null. */
export function heightHint(input: string): number | null;
export function detectSecret(text: string): Promise<string | null>;
export function extractSignIn(input: string): string | null;
/** Sign in with Zcash, verified locally. Throws if the proof is not for this domain and nonce. */
export function verifySignIn(input: string, options: { domain: string; nonce: string }): Promise<{ address: string; network: string; issued_at: number }>;
export interface PaymentLinkFinding { level: "error" | "warning" | "info"; code: string; payment: number | null; message: string }
export interface PaymentLinkCheck {
  ok: boolean;
  uri_length: number;
  payments: { index: number; address: string; address_kind: "unified" | "sapling" | "transparent" | "tex" | "unknown"; network: string | null; receivers: string[]; amount_zatoshis: number | null; memo: string | null; label: string | null; message: string | null; receipt_provable: boolean }[];
  total_zatoshis?: number | null;
  qr?: { version: number; modules: number; error_correction: "M" } | null;
  findings: PaymentLinkFinding[];
}
/** Lints a ZIP-321 payment link: network, address type, provability, amount, memo, params, QR density. */
export function checkPaymentLink(uri: string, options?: { network?: "mainnet" | "testnet" | "regtest" }): Promise<PaymentLinkCheck>;

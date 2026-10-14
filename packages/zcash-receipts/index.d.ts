import type { Verification, BatchVerification } from "./client";
export type { Verification, BatchVerification, Output } from "./client";

export interface VerifyOptions {
  endpoint?: string;
  rawTx?: Uint8Array | string;
  height?: number;
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
export function verifyReceipt(input: string, options?: VerifyOptions): Promise<Omit<Verification, "object" | "livemode" | "challenge" | "batch"> & { paidToExpected?: number }>;
export function verifyBatch(input: string, options?: VerifyOptions): Promise<{ id: string; results: Verification[]; totals: Record<string, number> }>;
export function fetchTransaction(endpoint: string, displayTxid: string): Promise<{ raw: Uint8Array; height: number }>;
export function detectSecret(text: string): Promise<string | null>;
export function extractSignIn(input: string): string | null;
/** Sign in with Zcash, verified locally. Throws if the proof is not for this domain and nonce. */
export function verifySignIn(input: string, options: { domain: string; nonce: string }): Promise<{ address: string; network: string; issued_at: number }>;

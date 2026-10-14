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

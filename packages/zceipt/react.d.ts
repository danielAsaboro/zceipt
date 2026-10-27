import type { VerifyOptions } from "./index";
export function useVerifyReceipt(
  receipt: string | null | undefined,
  options?: VerifyOptions,
): { status: "idle" | "verifying" | "valid" | "invalid"; result: any | null; error: Error | null };

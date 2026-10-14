/* tslint:disable */
/* eslint-disable */
/**
 * Decodes a receipt without verifying it. Returns JSON.
 */
export function inspect(receipt: string): string;
/**
 * Splits a `zrcptb1…` batch into its receipts after checking it is complete and consistent.
 * Returns JSON `{ "id": "<batch id>", "receipts": ["zrcpt1…", …] }`.
 */
export function open_batch(batch: string): string;
/**
 * Builds the verifying key now (a few seconds), so `verify` is fast later.
 */
export function warm_up(): void;
/**
 * Lints a ZIP-321 payment URI (see `receipts_core::preflight`). `network` may be "".
 * Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
 */
export function check_payment_uri(uri: string, network: string): string;
/**
 * If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
 */
export function secret_kind(text: string): string;
/**
 * Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
 * and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
 * The caller must still make sure the nonce was its own, unexpired and is used only once.
 */
export function verify_sign_in(sign_in: string, domain: string, nonce: string): string;
/**
 * Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
 * `regtest` marks a local test chain (receipts there carry the testnet coin type).
 * Returns JSON describing what the receipt proves, or throws why it is invalid.
 */
export function verify(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
 */
export function orchard_receiver_hex(ua: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly check_payment_uri: (a: number, b: number, c: number, d: number) => [number, number];
  readonly inspect: (a: number, b: number) => [number, number, number, number];
  readonly open_batch: (a: number, b: number) => [number, number, number, number];
  readonly orchard_receiver_hex: (a: number, b: number) => [number, number, number, number];
  readonly secret_kind: (a: number, b: number) => [number, number];
  readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly verify_sign_in: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly warm_up: () => void;
  readonly rustsecp256k1_v0_14_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_14_context_create: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

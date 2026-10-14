/* tslint:disable */
/* eslint-disable */
/**
 * Builds the verifying key now (a few seconds), so `verify` is fast later.
 */
export function warm_up(): void;
/**
 * Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
 * Returns JSON describing what the receipt proves, or throws why it is invalid.
 */
export function verify(receipt: string, raw_tx: Uint8Array, height: number): string;
/**
 * Decodes a receipt without verifying it. Returns JSON.
 */
export function inspect(receipt: string): string;
/**
 * The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
 */
export function orchard_receiver_hex(ua: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly inspect: (a: number, b: number) => [number, number, number, number];
  readonly orchard_receiver_hex: (a: number, b: number) => [number, number, number, number];
  readonly verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly warm_up: () => void;
  readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
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

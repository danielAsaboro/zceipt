/* tslint:disable */
/* eslint-disable */
/**
 * Decodes an incoming receipt without verifying it: JSON `{ network, pool, txid, message, outputs, bytes }`.
 */
export function inspect_incoming(receipt: string): string;
/**
 * Reads output `index` of a transparent transaction output (`raw_tx`, mined at `height`):
 * JSON `{ address, zatoshis }`, for showing who funded a source transaction.
 */
export function transparent_output(raw_tx: Uint8Array, height: number, index: number, coin_type: number, regtest: boolean): string;
/**
 * Splits a `zip311b1…` batch into its receipts after checking it is complete and consistent.
 * Returns JSON `{ "id": "<batch id>", "receipts": ["zip311r1…", …] }`.
 */
export function open_batch(batch: string): string;
/**
 * The network a unified address belongs to: "mainnet", "testnet" or "regtest". A receipt's
 * recipient bytes carry no network, so an expected address is checked against the receipt's
 * network with this before its receiver is compared.
 */
export function address_network(ua: string): string;
/**
 * Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
 * and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
 * The caller must still make sure the nonce was its own, unexpired and is used only once.
 */
export function verify_sign_in(sign_in: string, domain: string, nonce: string): string;
/**
 * Builds the verifying key now (a few seconds), so `verify` is fast later.
 */
export function warm_up(): void;
/**
 * For a deposit receipt (it signs `tex-deposit:` and `second-tx:`): checks that `tx2_raw` (the
 * second ZIP 320 step, mined at `tx2_height`) spends the receipt's transaction `tx1_raw` and
 * pays the TEX address. Call `verify` on the receipt first; this adds the TEX hop.
 * Returns JSON `{ tex_address, deposit_zatoshis, first_tx, second_tx, warning }`.
 */
export function check_tex_deposit(receipt: string, tx1_raw: Uint8Array, tx1_height: number, tx2_raw: Uint8Array, tx2_height: number, regtest: boolean): string;
/**
 * Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
 * `regtest` marks a local test chain (receipts there carry the testnet coin type).
 * `sources`, for receipts with source proofs, is JSON `[{ "raw": "<hex>", "height": n }]`
 * holding each source transaction (see `source_txids`); without it such receipts are refused.
 * Returns JSON describing what the receipt proves, or throws why it is invalid.
 */
export function verify(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean, sources?: string | null): string;
/**
 * Decodes a receipt without verifying it. Returns JSON.
 */
export function inspect(receipt: string): string;
/**
 * If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
 */
export function secret_kind(text: string): string;
/**
 * Lints a ZIP-321 payment URI (see `receipts_core::preflight`). `network` may be "".
 * Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
 */
export function check_payment_uri(uri: string, network: string): string;
/**
 * The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
 */
export function orchard_receiver_hex(ua: string): string;
/**
 * The source transactions a receipt's source proofs name (explorer-order txids), as a JSON
 * array, so the page can fetch them before calling `verify`.
 */
export function source_txids(receipt: string): string;
/**
 * Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid) against `raw_tx`
 * mined at `height`. Returns JSON `{ valid, kind: "incoming", network, pool, txid, mined_height,
 * message, recipient, outputs: [{ action, recipient, zatoshis, memo }] }` or throws.
 */
export function verify_incoming(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * Checks a signed payment request (`zreq1…`) at Unix time `now`: the signature, that its signer
 * controls the payee address, and the expiry. Returns JSON `{ payee, domain, amount_zatoshis,
 * memo, code, expires_at, network, well_known }`; the caller should still confirm that
 * `well_known` (the domain's list of payees) contains `payee`.
 */
export function verify_payment_request(request: string, now: number): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly address_network: (a: number, b: number) => [number, number, number, number];
  readonly check_payment_uri: (a: number, b: number, c: number, d: number) => [number, number];
  readonly check_tex_deposit: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
  readonly inspect: (a: number, b: number) => [number, number, number, number];
  readonly inspect_incoming: (a: number, b: number) => [number, number, number, number];
  readonly open_batch: (a: number, b: number) => [number, number, number, number];
  readonly orchard_receiver_hex: (a: number, b: number) => [number, number, number, number];
  readonly secret_kind: (a: number, b: number) => [number, number];
  readonly source_txids: (a: number, b: number) => [number, number, number, number];
  readonly transparent_output: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly verify_incoming: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly verify_payment_request: (a: number, b: number, c: number) => [number, number, number, number];
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

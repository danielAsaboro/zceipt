/* tslint:disable */
/* eslint-disable */
/**
 * `text` as a QR code, an SVG image (for a payment or request link a phone can scan).
 */
export function qr_svg(text: string): string;
/**
 * Checks a payer tag (`zip311t1…` with no snapshot) for `domain` against the payment it names
 * (`raw_tx` mined at `height`). Returns `{ txid, tag }`: payments with different tags in one
 * domain were made by different wallets.
 */
export function verify_payer_tag(text: string, domain: string, raw_tx: Uint8Array, height: number): string;
/**
 * The receipt inside a one-verifier (`zip311d1…`) or delegated (`zip311a1…`) receipt, as
 * `zip311r1…` text with empty signatures: for [`inspect`], to know which payment to fetch.
 */
export function inner_receipt(text: string): string;
/**
 * Checks a policy proof (`zip311p1…`) for a receipt: signed under the published t-of-n key.
 * Returns JSON `{ threshold, holders, key }` (`key` hex, to compare with the published one).
 */
export function verify_policy(proof: string, receipt: string): string;
/**
 * Like [`verify_policy`], against the published commitment (JSON array of hex points, `C_0` first)
 * and holder count: only then are the threshold and holders a verified fact.
 */
export function verify_policy_pinned(proof: string, receipt: string, commitment: string, holders: number): string;
/**
 * Verifies a delegated receipt (`zip311a1…`): its certificate, links, session signature and
 * policy, then the receipt. Returns what [`verify`] returns, with `delegation` added.
 */
export function verify_delegated(text: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * The keys a key-set proof lists, hex, for comparing with the published set.
 */
export function key_set_keys(proof: string): string;
/**
 * Checks a key-set proof (`zip311m1…`) for a receipt (`zip311r1…`): it was signed under one of
 * the keys the proof lists, not saying which. Returns how many keys; compare them with the
 * published set ([`key_set_keys`]).
 */
export function verify_keyset(proof: string, receipt: string): number;
/**
 * Splits a `zip311b1…` batch into its receipts after checking it is complete and consistent.
 * Returns JSON `{ "id": "<batch id>", "receipts": ["zip311r1…", …] }`.
 */
export function open_batch(batch: string): string;
/**
 * The payments a proof of income counts, JSON `[{ txid, height, pool, index }]`, for fetching.
 */
export function inspect_income(proof: string): string;
/**
 * The outputs a receipt claims, opened with their `ock`s and nothing else checked (JSON list of
 * `{ action, recipient, zatoshis, memo }`): what a receipt that failed its spend proof says it
 * paid. Not a verification.
 */
export function claimed_outputs(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * Builds the verifying key now (a few seconds), so `verify` is fast later.
 */
export function warm_up(): void;
/**
 * If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
 */
export function secret_kind(text: string): string;
/**
 * Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
 * `regtest` marks a local test chain (receipts there carry the testnet coin type).
 * `sources`, for receipts with source proofs, is JSON `[{ "raw": "<hex>", "height": n }]`
 * holding each source transaction (see `source_txids`); without it such receipts are refused.
 * Returns JSON describing what the receipt proves, or throws why it is invalid.
 */
export function verify(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean, sources?: string | null): string;
/**
 * The network a unified address belongs to: "mainnet", "testnet" or "regtest". A receipt's
 * recipient bytes carry no network, so an expected address is checked against the receipt's
 * network with this before its receiver is compared.
 */
export function address_network(ua: string): string;
/**
 * Checks a same-payer proof (`zip311k1…`) for a batch (`zip311b1…`): every payment in it was
 * signed with one spend key. Returns how many spends it links. Checks only the link; verify the
 * batch's receipts as usual.
 */
export function verify_same_payer(link: string, batch: string): number;
/**
 * Signs a prepared `zip311u1…` receipt for `message` with a 32-byte Orchard spending key (hex),
 * the second half of `zceipt create --unsigned`. It makes no proofs, so it is instant; the key
 * never leaves this call. Returns the `zip311r1…` text.
 */
export function sign_prepared_text(prepared: string, spending_key_hex: string, message: string): string;
/**
 * Reads output `index` of a transparent transaction output (`raw_tx`, mined at `height`):
 * JSON `{ address, zatoshis }`, for showing who funded a source transaction.
 */
export function transparent_output(raw_tx: Uint8Array, height: number, index: number, coin_type: number, regtest: boolean): string;
/**
 * Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
 * and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
 * The caller must still make sure the nonce was its own, unexpired and is used only once.
 */
export function verify_sign_in(sign_in: string, domain: string, nonce: string): string;
/**
 * The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
 */
export function orchard_receiver_hex(ua: string): string;
/**
 * Decodes an incoming receipt without verifying it: JSON `{ network, pool, txid, message, outputs, bytes }`.
 */
export function inspect_incoming(receipt: string): string;
/**
 * The txid (block-explorer hex) of `raw_tx`, mined at `height`: lets the block-level fetch
 * check that each transaction a server sent is the one asked for, not a stand-in.
 */
export function txid_of(raw_tx: Uint8Array, height: number, coin_type: number): string;
/**
 * Decodes a receipt without verifying it. Returns JSON.
 */
export function inspect(receipt: string): string;
/**
 * Checks a signed payment request (`zreq1…`) at Unix time `now`: the signature, that its signer
 * controls the payee address, and the expiry. Returns JSON `{ payee, domain, amount_zatoshis,
 * memo, code, expires_at, network, well_known }`; the caller should still confirm that
 * `well_known` (the domain's list of payees) contains `payee`.
 */
export function verify_payment_request(request: string, now: number): string;
/**
 * Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid) against `raw_tx`
 * mined at `height`. Returns JSON `{ valid, kind: "incoming", network, pool, txid, mined_height,
 * message, recipient, outputs: [{ action, recipient, zatoshis, memo }] }` or throws.
 */
export function verify_incoming(receipt: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * Verifies an aggregated batch (`zip311b1…` version 2): `txs` is JSON `[{ raw, height }]`, each
 * receipt's mined transaction (raw hex) in batch order. Checks every receipt, then the batch's
 * one proof for all their spends. Returns a JSON list of what [`verify`] returns for each.
 */
export function verify_aggregated(batch: string, txs: string, regtest: boolean): string;
/**
 * Verifies a receipt made for one verifier (`zip311d1…`), with that verifier's secret key (hex,
 * from `zceipt verifier-key`): a receipt for another key proves nothing to it. Returns what
 * [`verify`] returns.
 */
export function verify_designated(text: string, verifier_secret: string, raw_tx: Uint8Array, height: number, regtest: boolean): string;
/**
 * For a deposit receipt (it signs `tex-deposit:` and `second-tx:`): checks that `tx2_raw` (the
 * second ZIP 320 step, mined at `tx2_height`) spends the receipt's transaction `tx1_raw` and
 * pays the TEX address. Call `verify` on the receipt first; this adds the TEX hop.
 * Returns JSON `{ tex_address, deposit_zatoshis, first_tx, second_tx, warning }`.
 */
export function check_tex_deposit(receipt: string, tx1_raw: Uint8Array, tx1_height: number, tx2_raw: Uint8Array, tx2_height: number, regtest: boolean): string;
/**
 * What a payer tag names, to fetch before [`verify_payer_tag`]: `{ txid, network, domain }`.
 */
export function inspect_payer_tag(text: string): string;
/**
 * Checks screened-set proofs (`zip311s1…`, any number in `proofs`) for a receipt already verified
 * against `raw_tx`: each spend the receipt proves was of a note in `set` (the published list, one
 * note commitment in hex per line, `#` comments allowed), which one hidden. The root is computed
 * here from the list. Returns JSON `{ root, size, covered_zatoshis }`.
 */
export function verify_screened(receipt: string, raw_tx: Uint8Array, height: number, proofs: string, set: string): string;
/**
 * Lints a ZIP-321 payment URI (see `zceipt_core::preflight`). `network` may be "".
 * Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
 */
export function check_payment_uri(uri: string, network: string): string;
/**
 * Checks a proof of income against the transactions it counts (`txs`: JSON `[{ raw, height }]`,
 * one per item, in order). Returns JSON `{ at_least_zatoshis, payments, message }`.
 */
export function verify_income(proof: string, txs: string): string;
/**
 * The source transactions a receipt's source proofs name (explorer-order txids), as a JSON
 * array, so the page can fetch them before calling `verify`.
 */
export function source_txids(receipt: string): string;
/**
 * The unified full viewing key (Orchard part only) of a seed phrase's ZIP 32 `account`, so a
 * wallet can be opened with its phrase alone. The phrase and the keys are dropped on return.
 */
export function viewing_key_from_phrase(phrase: string, testnet: boolean, account: number): string;
/**
 * [`viewing_key_from_phrase`] from a raw seed (32 to 252 bytes): for a wallet that holds a seed
 * rather than a phrase, such as a MetaMask snap's BIP 44 entropy.
 */
export function viewing_key_from_seed(seed: Uint8Array, testnet: boolean, account: number): string;
/**
 * Signs a prepared receipt with the wallet's seed phrase (BIP 39, ZIP 32 `account`), after
 * checking that the phrase's key made its spends. The phrase and the keys derived from it are
 * dropped when this returns; nothing is stored or sent. Returns `zip311r1…`.
 */
export function sign_with_phrase(prepared: string, phrase: string, account: number): string;
/**
 * What signing a prepared receipt would reveal, read from the receipt itself (not from whoever
 * handed it over), for a signer to show before it signs. JSON `{ network, txid, message,
 * outputs_with_memo, outputs_without_memo, spends, opened: [{ index, recipient, zatoshis }] }`.
 * `opened` lists the outputs disclosed without their memo, whose recipient and amount the
 * receipt carries in the open; the ones disclosed with a key show only as a count, since
 * opening them takes the transaction.
 */
export function describe_prepared(prepared: string): string;
/**
 * The BIP 39 seed of a phrase (no passphrase), checksum checked: for a signer that keeps the seed
 * rather than the words, like the MetaMask snap. The error never quotes the phrase.
 */
export function seed_from_phrase(phrase: string): Uint8Array;
/**
 * Builds the proving key now (it takes several seconds), so `prepare` doesn't wait for it.
 */
export function warm_up_prover(): void;
/**
 * [`sign_with_phrase`] from a raw seed (32 to 252 bytes).
 */
export function sign_with_seed(prepared: string, seed: Uint8Array, account: number): string;
/**
 * One receipt being made from a viewing key. Feed it chain data in order; see the module docs.
 */
export class ReceiptMaker {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Trial-decrypts one compact block's actions with the wallet's keys and keeps the notes
   * found. Returns true if the payment is in this block.
   */
  scan_block(height: number, packed: Uint8Array): boolean;
  /**
   * The payment to make the receipt for, as block explorers show its txid.
   */
  set_target(txid: string): void;
  /**
   * What `prepare` would reveal, for the payer to review before proving: JSON
   * `[{ index, pool, recipient, zatoshis, memo }]`, one per output the wallet sent to someone
   * else (change and self-sends are never listed). Callable once `spent_notes` has the payment.
   */
  disclosable(): string;
  /**
   * Takes the payment (raw bytes, mined at `height`) and returns the wallet's notes it spent
   * as JSON `[{ pool: 0|1, nf, note_height }]`. Fails if it spent none of them.
   */
  spent_notes(raw_tx: Uint8Array, height: number): string;
  /**
   * Feeds one block to the path being rebuilt. Returns true once the path at the payment's
   * anchor is found (later blocks are then ignored, but keep fetching to the window's end so
   * the server can't tell where it was found).
   */
  witness_block(height: number, packed: Uint8Array): boolean;
  /**
   * Starts rebuilding one spent note's Merkle path: `tree_hex` is the pool's tree from
   * GetTreeState at the block before the first block that will be fed (empty for genesis).
   */
  witness_start(pool: number, nf_hex: string, tree_hex: string): void;
  /**
   * Like `prepare`, disclosing only the outputs in `selected` (indices from `disclosable`).
   * An empty selection is refused while there is something to disclose: a receipt that shows
   * no output proves only spend authority, which is what it should say it does.
   */
  prepare_selected(message: string, selected: Uint32Array): string;
  /**
   * From a unified full viewing key (`uview1…`, `uviewtest1…`) with an Orchard part.
   */
  constructor(ufvk: string);
  /**
   * Makes the proofs (several seconds; the proving key is built on first use) and returns the
   * prepared receipt, `zip311u1…`. Discloses everything the wallet sent to others, with memos:
   * `prepare_selected` picks.
   */
  prepare(message: string): string;
  /**
   * The transactions the scan has seen spend the wallet's notes, newest first, as JSON
   * `[{ txid, height, spent_zatoshis }]`: the payments a receipt can be made for. Found on
   * this device from the compact blocks; nothing is fetched for them.
   */
  payments(): string;
  /**
   * How many of the wallet's notes the scan has found so far.
   */
  readonly notes_found: number;
  /**
   * The payment's txid as block explorers show it, once given.
   */
  readonly txid: string | undefined;
  /**
   * "mainnet" or "testnet".
   */
  readonly network: string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_receiptmaker_free: (a: number, b: number) => void;
  readonly address_network: (a: number, b: number) => [number, number, number, number];
  readonly check_payment_uri: (a: number, b: number, c: number, d: number) => [number, number];
  readonly check_tex_deposit: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
  readonly claimed_outputs: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly describe_prepared: (a: number, b: number) => [number, number, number, number];
  readonly inner_receipt: (a: number, b: number) => [number, number, number, number];
  readonly inspect: (a: number, b: number) => [number, number, number, number];
  readonly inspect_income: (a: number, b: number) => [number, number, number, number];
  readonly inspect_incoming: (a: number, b: number) => [number, number, number, number];
  readonly inspect_payer_tag: (a: number, b: number) => [number, number, number, number];
  readonly key_set_keys: (a: number, b: number) => [number, number, number, number];
  readonly open_batch: (a: number, b: number) => [number, number, number, number];
  readonly orchard_receiver_hex: (a: number, b: number) => [number, number, number, number];
  readonly qr_svg: (a: number, b: number) => [number, number, number, number];
  readonly receiptmaker_disclosable: (a: number) => [number, number, number, number];
  readonly receiptmaker_network: (a: number) => [number, number];
  readonly receiptmaker_new: (a: number, b: number) => [number, number, number];
  readonly receiptmaker_notes_found: (a: number) => number;
  readonly receiptmaker_payments: (a: number) => [number, number];
  readonly receiptmaker_prepare: (a: number, b: number, c: number) => [number, number, number, number];
  readonly receiptmaker_prepare_selected: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly receiptmaker_scan_block: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly receiptmaker_set_target: (a: number, b: number, c: number) => [number, number];
  readonly receiptmaker_spent_notes: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly receiptmaker_txid: (a: number) => [number, number];
  readonly receiptmaker_witness_block: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly receiptmaker_witness_start: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
  readonly secret_kind: (a: number, b: number) => [number, number];
  readonly seed_from_phrase: (a: number, b: number) => [number, number, number, number];
  readonly sign_prepared_text: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly sign_with_phrase: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly sign_with_seed: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly source_txids: (a: number, b: number) => [number, number, number, number];
  readonly transparent_output: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly txid_of: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly verify_aggregated: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly verify_delegated: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly verify_designated: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly verify_income: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly verify_incoming: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly verify_keyset: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly verify_payer_tag: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
  readonly verify_payment_request: (a: number, b: number, c: number) => [number, number, number, number];
  readonly verify_policy: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly verify_policy_pinned: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
  readonly verify_same_payer: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly verify_screened: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
  readonly verify_sign_in: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly viewing_key_from_phrase: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly viewing_key_from_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly warm_up_prover: () => void;
  readonly warm_up: () => void;
  readonly rustsecp256k1_v0_14_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_14_context_create: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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

const __wbg_star0 = { rustsecp256k1_v0_14_context_preallocated_create: () => { throw new Error('secp256k1 is not available in the Zceipt verifier'); }, rustsecp256k1_v0_14_context_preallocated_destroy: () => { throw new Error('secp256k1 is not available in the Zceipt verifier'); }, rustsecp256k1_v0_14_context_preallocated_size: () => { throw new Error('secp256k1 is not available in the Zceipt verifier'); }, };

let wasm;

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_3.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    }
}

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_3.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
/**
 * Checks a signed payment request (`zreq1…`) at Unix time `now`: the signature, that its signer
 * controls the payee address, and the expiry. Returns JSON `{ payee, domain, amount_zatoshis,
 * memo, code, expires_at, network, well_known }`; the caller should still confirm that
 * `well_known` (the domain's list of payees) contains `payee`.
 * @param {string} request
 * @param {number} now
 * @returns {string}
 */
export function verify_payment_request(request, now) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(request, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.verify_payment_request(ptr0, len0, now);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
 * The txid (block-explorer hex) of `raw_tx`, mined at `height`: lets the block-level fetch
 * check that each transaction a server sent is the one asked for, not a stand-in.
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {number} coin_type
 * @returns {string}
 */
export function txid_of(raw_tx, height, coin_type) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.txid_of(ptr0, len0, height, coin_type);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Builds the verifying key now (a few seconds), so `verify` is fast later.
 */
export function warm_up() {
    wasm.warm_up();
}

/**
 * Reads output `index` of a transparent transaction output (`raw_tx`, mined at `height`):
 * JSON `{ address, zatoshis }`, for showing who funded a source transaction.
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {number} index
 * @param {number} coin_type
 * @param {boolean} regtest
 * @returns {string}
 */
export function transparent_output(raw_tx, height, index, coin_type, regtest) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.transparent_output(ptr0, len0, height, index, coin_type, regtest);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Verifies a receipt made for one verifier (`zip311d1…`), with that verifier's secret key (hex,
 * from `zceipt verifier-key`): a receipt for another key proves nothing to it. Returns what
 * [`verify`] returns.
 * @param {string} text
 * @param {string} verifier_secret
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {boolean} regtest
 * @returns {string}
 */
export function verify_designated(text, verifier_secret, raw_tx, height, regtest) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(verifier_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify_designated(ptr0, len0, ptr1, len1, ptr2, len2, height, regtest);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
 * @param {string} ua
 * @returns {string}
 */
export function orchard_receiver_hex(ua) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ua, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.orchard_receiver_hex(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The payments a proof of income counts, JSON `[{ txid, height, pool, index }]`, for fetching.
 * @param {string} proof
 * @returns {string}
 */
export function inspect_income(proof) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspect_income(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Checks a payer tag (`zip311t1…` with no snapshot) for `domain` against the payment it names
 * (`raw_tx` mined at `height`). Returns `{ txid, tag }`: payments with different tags in one
 * domain were made by different wallets.
 * @param {string} text
 * @param {string} domain
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @returns {string}
 */
export function verify_payer_tag(text, domain, raw_tx, height) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify_payer_tag(ptr0, len0, ptr1, len1, ptr2, len2, height);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Verifies an aggregated batch (`zip311b1…` version 2): `txs` is JSON `[{ raw, height }]`, each
 * receipt's mined transaction (raw hex) in batch order. Checks every receipt, then the batch's
 * one proof for all their spends. Returns a JSON list of what [`verify`] returns for each.
 * @param {string} batch
 * @param {string} txs
 * @param {boolean} regtest
 * @returns {string}
 */
export function verify_aggregated(batch, txs, regtest) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(batch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(txs, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.verify_aggregated(ptr0, len0, ptr1, len1, regtest);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Decodes a receipt without verifying it. Returns JSON.
 * @param {string} receipt
 * @returns {string}
 */
export function inspect(receipt) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspect(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Verifies a delegated receipt (`zip311a1…`): its certificate, links, session signature and
 * policy, then the receipt. Returns what [`verify`] returns, with `delegation` added.
 * @param {string} text
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {boolean} regtest
 * @returns {string}
 */
export function verify_delegated(text, raw_tx, height, regtest) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.verify_delegated(ptr0, len0, ptr1, len1, height, regtest);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Checks a proof of income against the transactions it counts (`txs`: JSON `[{ raw, height }]`,
 * one per item, in order). Returns JSON `{ at_least_zatoshis, payments, message }`.
 * @param {string} proof
 * @param {string} txs
 * @returns {string}
 */
export function verify_income(proof, txs) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(txs, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.verify_income(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid) against `raw_tx`
 * mined at `height`. Returns JSON `{ valid, kind: "incoming", network, pool, txid, mined_height,
 * message, recipient, outputs: [{ action, recipient, zatoshis, memo }] }` or throws.
 * @param {string} receipt
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {boolean} regtest
 * @returns {string}
 */
export function verify_incoming(receipt, raw_tx, height, regtest) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.verify_incoming(ptr0, len0, ptr1, len1, height, regtest);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
 * and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
 * The caller must still make sure the nonce was its own, unexpired and is used only once.
 * @param {string} sign_in
 * @param {string} domain
 * @param {string} nonce
 * @returns {string}
 */
export function verify_sign_in(sign_in, domain, nonce) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(sign_in, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify_sign_in(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Signs a prepared `zip311u1…` receipt for `message` with a 32-byte Orchard spending key (hex),
 * the second half of `zceipt create --unsigned`. It makes no proofs, so it is instant; the key
 * never leaves this call. Returns the `zip311r1…` text.
 * @param {string} prepared
 * @param {string} spending_key_hex
 * @param {string} message
 * @returns {string}
 */
export function sign_prepared_text(prepared, spending_key_hex, message) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(prepared, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(spending_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sign_prepared_text(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Like [`verify_policy`], against the published commitment (JSON array of hex points, `C_0` first)
 * and holder count: only then are the threshold and holders a verified fact.
 * @param {string} proof
 * @param {string} receipt
 * @param {string} commitment
 * @param {number} holders
 * @returns {string}
 */
export function verify_policy_pinned(proof, receipt, commitment, holders) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify_policy_pinned(ptr0, len0, ptr1, len1, ptr2, len2, holders);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Checks a same-payer proof (`zip311k1…`) for a batch (`zip311b1…`): every payment in it was
 * signed with one spend key. Returns how many spends it links. Checks only the link; verify the
 * batch's receipts as usual.
 * @param {string} link
 * @param {string} batch
 * @returns {number}
 */
export function verify_same_payer(link, batch) {
    const ptr0 = passStringToWasm0(link, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(batch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_same_payer(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] >>> 0;
}

/**
 * The outputs a receipt claims, opened with their `ock`s and nothing else checked (JSON list of
 * `{ action, recipient, zatoshis, memo }`): what a receipt that failed its spend proof says it
 * paid. Not a verification.
 * @param {string} receipt
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {boolean} regtest
 * @returns {string}
 */
export function claimed_outputs(receipt, raw_tx, height, regtest) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.claimed_outputs(ptr0, len0, ptr1, len1, height, regtest);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Checks a policy proof (`zip311p1…`) for a receipt: signed under the published t-of-n key.
 * Returns JSON `{ threshold, holders, key }` (`key` hex, to compare with the published one).
 * @param {string} proof
 * @param {string} receipt
 * @returns {string}
 */
export function verify_policy(proof, receipt) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.verify_policy(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Splits a `zip311b1…` batch into its receipts after checking it is complete and consistent.
 * Returns JSON `{ "id": "<batch id>", "receipts": ["zip311r1…", …] }`.
 * @param {string} batch
 * @returns {string}
 */
export function open_batch(batch) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(batch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.open_batch(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * `text` as a QR code, an SVG image (for a payment or request link a phone can scan).
 * @param {string} text
 * @returns {string}
 */
export function qr_svg(text) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.qr_svg(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Checks a key-set proof (`zip311m1…`) for a receipt (`zip311r1…`): it was signed under one of
 * the keys the proof lists, not saying which. Returns how many keys; compare them with the
 * published set ([`key_set_keys`]).
 * @param {string} proof
 * @param {string} receipt
 * @returns {number}
 */
export function verify_keyset(proof, receipt) {
    const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_keyset(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] >>> 0;
}

/**
 * The source transactions a receipt's source proofs name (explorer-order txids), as a JSON
 * array, so the page can fetch them before calling `verify`.
 * @param {string} receipt
 * @returns {string}
 */
export function source_txids(receipt) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.source_txids(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Lints a ZIP-321 payment URI (see `zceipt_core::preflight`). `network` may be "".
 * Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
 * @param {string} uri
 * @param {string} network
 * @returns {string}
 */
export function check_payment_uri(uri, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(uri, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.check_payment_uri(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The network a unified address belongs to: "mainnet", "testnet" or "regtest". A receipt's
 * recipient bytes carry no network, so an expected address is checked against the receipt's
 * network with this before its receiver is compared.
 * @param {string} ua
 * @returns {string}
 */
export function address_network(ua) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ua, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.address_network(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * For a deposit receipt (it signs `tex-deposit:` and `second-tx:`): checks that `tx2_raw` (the
 * second ZIP 320 step, mined at `tx2_height`) spends the receipt's transaction `tx1_raw` and
 * pays the TEX address. Call `verify` on the receipt first; this adds the TEX hop.
 * Returns JSON `{ tex_address, deposit_zatoshis, first_tx, second_tx, warning }`.
 * @param {string} receipt
 * @param {Uint8Array} tx1_raw
 * @param {number} tx1_height
 * @param {Uint8Array} tx2_raw
 * @param {number} tx2_height
 * @param {boolean} regtest
 * @returns {string}
 */
export function check_tex_deposit(receipt, tx1_raw, tx1_height, tx2_raw, tx2_height, regtest) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(tx1_raw, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(tx2_raw, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.check_tex_deposit(ptr0, len0, ptr1, len1, tx1_height, ptr2, len2, tx2_height, regtest);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * The keys a key-set proof lists, hex, for comparing with the published set.
 * @param {string} proof
 * @returns {string}
 */
export function key_set_keys(proof) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(proof, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.key_set_keys(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The receipt inside a one-verifier (`zip311d1…`) or delegated (`zip311a1…`) receipt, as
 * `zip311r1…` text with empty signatures: for [`inspect`], to know which payment to fetch.
 * @param {string} text
 * @returns {string}
 */
export function inner_receipt(text) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inner_receipt(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Decodes an incoming receipt without verifying it: JSON `{ network, pool, txid, message, outputs, bytes }`.
 * @param {string} receipt
 * @returns {string}
 */
export function inspect_incoming(receipt) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspect_incoming(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * What a payer tag names, to fetch before [`verify_payer_tag`]: `{ txid, network, domain }`.
 * @param {string} text
 * @returns {string}
 */
export function inspect_payer_tag(text) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspect_payer_tag(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
 * @param {string} text
 * @returns {string}
 */
export function secret_kind(text) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secret_kind(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}
/**
 * Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
 * `regtest` marks a local test chain (receipts there carry the testnet coin type).
 * `sources`, for receipts with source proofs, is JSON `[{ "raw": "<hex>", "height": n }]`
 * holding each source transaction (see `source_txids`); without it such receipts are refused.
 * Returns JSON describing what the receipt proves, or throws why it is invalid.
 * @param {string} receipt
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {boolean} regtest
 * @param {string | null} [sources]
 * @returns {string}
 */
export function verify(receipt, raw_tx, height, regtest, sources) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(sources) ? 0 : passStringToWasm0(sources, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify(ptr0, len0, ptr1, len1, height, regtest, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Checks screened-set proofs (`zip311s1…`, any number in `proofs`) for a receipt already verified
 * against `raw_tx`: each spend the receipt proves was of a note in `set` (the published list, one
 * note commitment in hex per line, `#` comments allowed), which one hidden. The root is computed
 * here from the list. Returns JSON `{ root, size, covered_zatoshis }`.
 * @param {string} receipt
 * @param {Uint8Array} raw_tx
 * @param {number} height
 * @param {string} proofs
 * @param {string} set
 * @returns {string}
 */
export function verify_screened(receipt, raw_tx, height, proofs, set) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(receipt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(proofs, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(set, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.verify_screened(ptr0, len0, ptr1, len1, height, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Builds the proving key now (it takes several seconds), so `prepare` doesn't wait for it.
 */
export function warm_up_prover() {
    wasm.warm_up_prover();
}

/**
 * The unified full viewing key (Orchard part only) of a seed phrase's ZIP 32 `account`, so a
 * wallet can be opened with its phrase alone. The phrase and the keys are dropped on return.
 * @param {string} phrase
 * @param {boolean} testnet
 * @param {number} account
 * @returns {string}
 */
export function viewing_key_from_phrase(phrase, testnet, account) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.viewing_key_from_phrase(ptr0, len0, testnet, account);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Signs a prepared receipt with the wallet's seed phrase (BIP 39, ZIP 32 `account`), after
 * checking that the phrase's key made its spends. The phrase and the keys derived from it are
 * dropped when this returns; nothing is stored or sent. Returns `zip311r1…`.
 * @param {string} prepared
 * @param {string} phrase
 * @param {number} account
 * @returns {string}
 */
export function sign_with_phrase(prepared, phrase, account) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(prepared, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.sign_with_phrase(ptr0, len0, ptr1, len1, account);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * What signing a prepared receipt would reveal, read from the receipt itself (not from whoever
 * handed it over), for a signer to show before it signs. JSON `{ network, txid, message,
 * outputs_with_memo, outputs_without_memo, spends }`.
 * @param {string} prepared
 * @returns {string}
 */
export function describe_prepared(prepared) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(prepared, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.describe_prepared(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * [`viewing_key_from_phrase`] from a raw seed (32 to 252 bytes): for a wallet that holds a seed
 * rather than a phrase, such as a MetaMask snap's BIP 44 entropy.
 * @param {Uint8Array} seed
 * @param {boolean} testnet
 * @param {number} account
 * @returns {string}
 */
export function viewing_key_from_seed(seed, testnet, account) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.viewing_key_from_seed(ptr0, len0, testnet, account);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * [`sign_with_phrase`] from a raw seed (32 to 252 bytes).
 * @param {string} prepared
 * @param {Uint8Array} seed
 * @param {number} account
 * @returns {string}
 */
export function sign_with_seed(prepared, seed, account) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(prepared, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.sign_with_seed(ptr0, len0, ptr1, len1, account);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * The BIP 39 seed of a phrase (no passphrase), checksum checked: for a signer that keeps the seed
 * rather than the words, like the MetaMask snap. The error never quotes the phrase.
 * @param {string} phrase
 * @returns {Uint8Array}
 */
export function seed_from_phrase(phrase) {
    const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.seed_from_phrase(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

const ReceiptMakerFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_receiptmaker_free(ptr >>> 0, 1));
/**
 * One receipt being made from a viewing key. Feed it chain data in order; see the module docs.
 */
export class ReceiptMaker {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ReceiptMakerFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_receiptmaker_free(ptr, 0);
    }
    /**
     * Trial-decrypts one compact block's actions with the wallet's keys and keeps the notes
     * found. Returns true if the payment is in this block.
     * @param {number} height
     * @param {Uint8Array} packed
     * @returns {boolean}
     */
    scan_block(height, packed) {
        const ptr0 = passArray8ToWasm0(packed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.receiptmaker_scan_block(this.__wbg_ptr, height, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * The payment to make the receipt for, as block explorers show its txid.
     * @param {string} txid
     */
    set_target(txid) {
        const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.receiptmaker_set_target(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * How many of the wallet's notes the scan has found so far.
     * @returns {number}
     */
    get notes_found() {
        const ret = wasm.receiptmaker_notes_found(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Takes the payment (raw bytes, mined at `height`) and returns the wallet's notes it spent
     * as JSON `[{ pool: 0|1, nf, note_height }]`. Fails if it spent none of them.
     * @param {Uint8Array} raw_tx
     * @param {number} height
     * @returns {string}
     */
    spent_notes(raw_tx, height) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passArray8ToWasm0(raw_tx, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.receiptmaker_spent_notes(this.__wbg_ptr, ptr0, len0, height);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Feeds one block to the path being rebuilt. Returns true once the path at the payment's
     * anchor is found (later blocks are then ignored, but keep fetching to the window's end so
     * the server can't tell where it was found).
     * @param {number} height
     * @param {Uint8Array} packed
     * @returns {boolean}
     */
    witness_block(height, packed) {
        const ptr0 = passArray8ToWasm0(packed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.receiptmaker_witness_block(this.__wbg_ptr, height, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Starts rebuilding one spent note's Merkle path: `tree_hex` is the pool's tree from
     * GetTreeState at the block before the first block that will be fed (empty for genesis).
     * @param {number} pool
     * @param {string} nf_hex
     * @param {string} tree_hex
     */
    witness_start(pool, nf_hex, tree_hex) {
        const ptr0 = passStringToWasm0(nf_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(tree_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.receiptmaker_witness_start(this.__wbg_ptr, pool, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * From a unified full viewing key (`uview1…`, `uviewtest1…`) with an Orchard part.
     * @param {string} ufvk
     */
    constructor(ufvk) {
        const ptr0 = passStringToWasm0(ufvk, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.receiptmaker_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        ReceiptMakerFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * The payment's txid as block explorers show it, once given.
     * @returns {string | undefined}
     */
    get txid() {
        const ret = wasm.receiptmaker_txid(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * "mainnet" or "testnet".
     * @returns {string}
     */
    get network() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.receiptmaker_network(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Makes the proofs (several seconds; the proving key is built on first use) and returns the
     * prepared receipt, `zip311u1…`. Discloses what the wallet sent to others, with memos.
     * @param {string} message
     * @returns {string}
     */
    prepare(message) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.receiptmaker_prepare(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * The transactions the scan has seen spend the wallet's notes, newest first, as JSON
     * `[{ txid, height, spent_zatoshis }]`: the payments a receipt can be made for. Found on
     * this device from the compact blocks; nothing is fetched for them.
     * @returns {string}
     */
    payments() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.receiptmaker_payments(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) ReceiptMaker.prototype[Symbol.dispose] = ReceiptMaker.prototype.free;

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_Error_e17e777aac105295 = function(arg0, arg1) {
        const ret = Error(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
        let deferred0_0;
        let deferred0_1;
        try {
            deferred0_0 = arg0;
            deferred0_1 = arg1;
            console.error(getStringFromWasm0(arg0, arg1));
        } finally {
            wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
        }
    };
    imports.wbg.__wbg_getRandomValues_a8ddca022803a145 = function() { return handleError(function (arg0, arg1) {
        globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
    }, arguments) };
    imports.wbg.__wbg_new_8a6f238a6ece86ea = function() {
        const ret = new Error();
        return ret;
    };
    imports.wbg.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
        const ret = arg1.stack;
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_wbindgenthrow_451ec1a8469d7eb6 = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_3;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };
    imports['env'] = __wbg_star0;

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('zceipt_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;

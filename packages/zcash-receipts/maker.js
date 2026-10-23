// Makes a receipt from a unified full viewing key: no install and no terminal. Everything runs
// on this device; the lightwalletd server sees block ranges, one tree state and the payment's
// block, never the viewing key, the txid or which note.
//
//   const prepared = await prepareFromViewingKey({ ufvk, txid, birthday, message, onProgress });
//   const receipt = sign_with_phrase(prepared, phrase, 0);   // where the seed is, or another signer
//
// Takes the wasm module's exports (`ReceiptMaker`, `txid_of`) so it runs in a page, a worker or Node.

import { DEFAULT_ENDPOINTS, fetchCompactActions, fetchTipHeight, fetchTransactionPrivately, fetchTreeState } from "./grpc.js";

const WINDOW = 1000; // the witness is rebuilt over whole 1,000-block windows, as the CLI does
const windowStart = (h) => Math.max(1, Math.floor(h / WINDOW) * WINDOW);
const windowEnd = (h) => (Math.floor(h / WINDOW) + 1) * WINDOW - 1;

/**
 * `{ wasm, ufvk, txid, birthday, height?, message, endpoint?, onProgress? }` → `zip311u1…`.
 * `birthday`: the wallet's first block (any block before it first received funds). `height`: the
 * payment's block if known (a receipt link's `h=`); else the scan finds it.
 */
export async function prepareFromViewingKey({ wasm, ufvk, txid, birthday, height, message = "", endpoint, onProgress = () => {} }) {
  const maker = new wasm.ReceiptMaker(ufvk);
  const net = maker.network;
  endpoint = endpoint || DEFAULT_ENDPOINTS[net];
  maker.set_target(txid);
  const tip = await fetchTipHeight(endpoint);
  birthday = Math.max(1, Number(birthday) || 1);
  if (birthday > tip) throw new Error(`the birthday ${birthday} is after the chain tip ${tip}`);

  // 1. Find the wallet's notes, and the payment's block if it wasn't given.
  const scanEnd = height ? Number(height) - 1 : tip;
  let found = height ? Number(height) : null;
  for await (const b of fetchCompactActions(endpoint, birthday, scanEnd)) {
    if (maker.scan_block(b.height, b.packed) && !found) found = b.height;
    if (b.height % 500 === 0 || b.height === scanEnd) onProgress({ step: "scan", height: b.height, from: birthday, to: scanEnd, notes: maker.notes_found });
    // Found: finish its 1,000-block window (so the range doesn't point at the block) and stop.
    if (found && b.height >= Math.min(scanEnd, windowEnd(found))) break;
  }
  if (!found) throw new Error(`transaction ${txid.slice(0, 12)}… is not in blocks ${birthday}..${scanEnd}: is the birthday right?`);

  // 2. The payment, fetched among its block's transactions.
  onProgress({ step: "fetch", height: found });
  const tx = await fetchTransactionPrivately(endpoint, txid, found, { txidOf: (raw, h) => wasm.txid_of(raw, h, net === "mainnet" ? 133 : 1) });
  const spent = JSON.parse(maker.spent_notes(tx.raw, tx.height));

  // 3. Each spent note's Merkle path at the payment's anchor, from whole windows of blocks.
  for (const [i, s] of spent.entries()) {
    const start = windowStart(s.note_height);
    const end = Math.min(windowEnd(tx.height), tip);
    const trees = start > 1 ? await fetchTreeState(endpoint, start - 1) : { orchard: "", ironwood: "" };
    maker.witness_start(s.pool, s.nf, s.pool === 0 ? trees.orchard : trees.ironwood);
    let done = false;
    for await (const b of fetchCompactActions(endpoint, start, end)) {
      if (!done) done = maker.witness_block(b.height, b.packed);
      if (b.height % 500 === 0 || b.height === end) onProgress({ step: "path", note: i + 1, notes: spent.length, height: b.height, from: start, to: end });
    }
    if (!done) throw new Error("no block's tree matched the payment's anchor");
  }

  // 4. The proofs.
  onProgress({ step: "prove", spends: spent.length });
  return { prepared: maker.prepare(message), height: tx.height, network: net };
}

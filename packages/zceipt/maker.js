// Makes a receipt from a unified full viewing key: no install and no terminal. Everything runs
// on this device; the lightwalletd server sees block ranges, one tree state and the payment's
// block, never the viewing key, the txid or which note.
//
//   const { maker, payments } = await findPayments({ wasm, ufvk, birthday, onProgress });
//   const prepared = await prepareFromViewingKey({ wasm, maker, txid, height, birthday, message, onProgress, select });
//   const receipt = sign_with_phrase(prepared, phrase, 0);   // where the seed is, or another signer
//
// `select(outputs)` gets what the receipt would reveal (`[{ index, recipient, zatoshis, memo }]`)
// and answers with the indices to disclose; without it, every output sent to others is disclosed.
//
// Takes the wasm module's exports (`ReceiptMaker`, `txid_of`) so it runs in a page, a worker or Node.

import { DEFAULT_ENDPOINTS, fetchCompactActions, fetchTipHeight, fetchTransactionPrivately, fetchTreeState } from "./grpc.js";

const WINDOW = 1000; // the witness is rebuilt over whole 1,000-block windows, as the CLI does
const windowStart = (h) => Math.max(1, Math.floor(h / WINDOW) * WINDOW);
const windowEnd = (h) => (Math.floor(h / WINDOW) + 1) * WINDOW - 1;

/**
 * `{ wasm, ufvk, birthday, endpoint?, onProgress?, onPayment?, stopAfter? }` → `{ maker, payments, tip }`. Scans the wallet
 * from its birthday to the chain tip, as any light wallet sync does, and lists the transactions
 * that spent its notes (`[{ txid, height, spent_zatoshis }]`, newest first). Pass `maker` and a
 * payment's `txid` and `height` to prepareFromViewingKey to skip a second scan. `onPayment(p)`
 * fires as each is found; once `stopAfter()` returns a payment's height, the scan ends after it.
 */
export async function findPayments({ wasm, ufvk, birthday, endpoint, onProgress = () => {}, onPayment = () => {}, stopAfter = () => null }) {
  const maker = new wasm.ReceiptMaker(ufvk);
  endpoint = endpoint || DEFAULT_ENDPOINTS[maker.network];
  const tip = await fetchTipHeight(endpoint);
  birthday = Math.max(1, Number(birthday) || 1);
  if (birthday > tip) throw new Error(`the birthday ${birthday} is after the chain tip ${tip}`);
  onProgress({ step: "start", from: birthday, to: tip });
  let seen = 0, last = birthday;
  for await (const b of fetchCompactActions(endpoint, birthday, tip)) {
    maker.scan_block(b.height, b.packed);
    last = b.height;
    if (b.height % 50 === 0 || b.height === tip) {
      const list = JSON.parse(maker.payments());
      // Newest first: the ones not seen yet are at the front.
      for (const p of list.slice(0, list.length - seen).reverse()) onPayment(p);
      seen = list.length;
    }
    if (b.height % 500 === 0 || b.height === tip) onProgress({ step: "scan", height: b.height, from: birthday, to: tip, notes: maker.notes_found });
    // A payment was picked before the scan reached the tip: its notes are all known by now, so
    // stop, at the end of a whole 1,000-block window as prepareFromViewingKey does.
    const stop = stopAfter();
    if (stop && b.height >= Math.min(tip, windowEnd(stop))) break;
  }
  return { maker, payments: JSON.parse(maker.payments()), tip, scanned: last, network: maker.network };
}

/**
 * `{ wasm, ufvk, txid, birthday, height?, message, endpoint?, onProgress?, select? }` → `zip311u1…`.
 * `birthday`: the wallet's first block (any block before it first received funds). `height`: the
 * payment's block if known (a receipt link's `h=`); else the scan finds it. `select(outputs)`:
 * asked, once the payment is fetched, which of the outputs it sent to others to disclose
 * (`async (outputs) => indices`); the Merkle paths are rebuilt meanwhile. It may also answer
 * `{ selected, message }` to set the message at the same time.
 */
export async function prepareFromViewingKey({ wasm, ufvk, maker, txid, birthday, height, message = "", endpoint, onProgress = () => {}, select = null }) {
  // A `maker` from findPayments has already scanned the wallet: its notes are known.
  const scanned = Boolean(maker);
  maker = maker || new wasm.ReceiptMaker(ufvk);
  const net = maker.network;
  endpoint = endpoint || DEFAULT_ENDPOINTS[net];
  maker.set_target(txid);
  const tip = await fetchTipHeight(endpoint);
  birthday = Math.max(1, Number(birthday) || 1);
  if (birthday > tip) throw new Error(`the birthday ${birthday} is after the chain tip ${tip}`);
  if (scanned && !height) throw new Error("give the payment's block height with a scanned maker");

  // 1. Find the wallet's notes, and the payment's block if it wasn't given. With the block known,
  // the range still runs to the end of its 1,000-block window, so it doesn't point at the block;
  // the blocks from the payment on are fetched and ignored (its notes all came before it).
  const scanEnd = height ? Math.min(tip, windowEnd(Number(height))) : tip;
  let found = height ? Number(height) : null;
  if (!scanned) for await (const b of fetchCompactActions(endpoint, birthday, scanEnd)) {
    if (!(height && b.height >= Number(height)) && maker.scan_block(b.height, b.packed) && !found) found = b.height;
    if (b.height % 500 === 0 || b.height === scanEnd) onProgress({ step: "scan", height: b.height, from: birthday, to: scanEnd, notes: maker.notes_found });
    // Found: finish its 1,000-block window (so the range doesn't point at the block) and stop.
    if (found && b.height >= Math.min(scanEnd, windowEnd(found))) break;
  }
  if (!found) throw new Error(`transaction ${txid.slice(0, 12)}… is not in blocks ${birthday}..${scanEnd}: is the birthday right?`);

  // 2. The payment, fetched among its block's transactions.
  onProgress({ step: "fetch", height: found });
  const tx = await fetchTransactionPrivately(endpoint, txid, found, { txidOf: (raw, h) => wasm.txid_of(raw, h, net === "mainnet" ? 133 : 1) });
  const spent = JSON.parse(maker.spent_notes(tx.raw, tx.height));
  // What the receipt would reveal is known now: ask while the paths are rebuilt.
  const choice = select ? Promise.resolve(select(JSON.parse(maker.disclosable()))) : null;

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

  // 4. The proofs, disclosing the chosen outputs.
  let selected = null;
  if (choice) {
    const answer = await choice;
    if (answer && !Array.isArray(answer)) {
      if (typeof answer.message === "string") message = answer.message;
      selected = answer.selected;
    } else selected = answer;
  }
  onProgress({ step: "prove", spends: spent.length });
  const prepared = selected ? maker.prepare_selected(message, Array.from(selected, Number)) : maker.prepare(message);
  return { prepared, height: tx.height, network: net };
}

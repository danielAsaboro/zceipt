// Minimal grpc-web client for one lightwalletd call: CompactTxStreamer.GetTransaction.
// Works in browsers and Node 18+ (global fetch). No dependencies.

export const DEFAULT_ENDPOINTS = {
  mainnet: "https://zcash-mainnet.chainsafe.dev",
  testnet: "https://zcash-testnet.chainsafe.dev",
};

// Links can carry other text with a stray "%" (`&note=50%off`): never let that stop a check.
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function hexToBytes(h) {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}

function readVarint(buf, pos) {
  let result = 0n, shift = 0n;
  for (;;) {
    const b = buf[pos++];
    if (b === undefined) throw new Error("truncated protobuf");
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7n;
  }
  return [result, pos];
}

/**
 * Fetches a transaction by its display txid (block-explorer hex).
 * Resolves to `{ raw: Uint8Array, height: number }`; height is 0 if unmined.
 */
export async function fetchTransaction(endpoint, displayTxid) {
  const hash = hexToBytes(displayTxid).reverse();
  const msg = new Uint8Array(34);
  msg[0] = 0x1a; // TxFilter.hash, field 3, length-delimited
  msg[1] = 0x20;
  msg.set(hash, 2);
  const frame = new Uint8Array(5 + msg.length);
  new DataView(frame.buffer).setUint32(1, msg.length);
  frame.set(msg, 5);
  const res = await fetch(`${endpoint.replace(/\/$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction`, {
    method: "POST",
    headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" },
    body: frame,
  });
  if (!res.ok) throw new Error(`lightwalletd answered HTTP ${res.status}`);
  const status = res.headers.get("grpc-status");
  if (status && status !== "0") throw new Error(safeDecode(res.headers.get("grpc-message") || `grpc-status ${status}`));
  const body = new Uint8Array(await res.arrayBuffer());
  let pos = 0, data = null, height = 0n, trailer = "";
  while (pos + 5 <= body.length) {
    const flag = body[pos];
    const len = new DataView(body.buffer, body.byteOffset + pos + 1, 4).getUint32(0);
    const chunk = body.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (flag & 0x80) { trailer += new TextDecoder().decode(chunk); continue; }
    let p = 0;
    while (p < chunk.length) {
      const [key, p2] = readVarint(chunk, p); p = p2;
      const field = Number(key >> 3n), wire = Number(key & 7n);
      if (wire === 2) {
        const [l, p3] = readVarint(chunk, p); p = p3;
        const v = chunk.subarray(p, p + Number(l)); p += Number(l);
        if (field === 1) data = v;
      } else if (wire === 0) {
        const [v, p3] = readVarint(chunk, p); p = p3;
        if (field === 2) height = v;
      } else throw new Error("unexpected protobuf wire type");
    }
  }
  const m = trailer.match(/grpc-status:\s*(\d+)/);
  if (m && m[1] !== "0") {
    const why = (trailer.match(/grpc-message:\s*(.*)/) || [])[1] || "";
    throw new Error(`lightwalletd: ${safeDecode(why.trim()) || "status " + m[1]}`);
  }
  if (!data) throw new Error("lightwalletd returned no transaction");
  return { raw: data, height: Number(height) };
}

export { hexToBytes };

// ---------- block-level fetching: the server learns the block, not the transaction ----------

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function encodeVarint(n) {
  const out = [];
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
}

function parseFields(buf) {
  const fields = [];
  let p = 0;
  while (p < buf.length) {
    const [key, p2] = readVarint(buf, p); p = p2;
    const field = Number(key >> 3n), wire = Number(key & 7n);
    if (wire === 2) {
      const [l, p3] = readVarint(buf, p); p = p3;
      fields.push([field, buf.subarray(p, p + Number(l))]); p += Number(l);
    } else if (wire === 0) {
      const [v, p3] = readVarint(buf, p); p = p3;
      fields.push([field, v]);
    } else if (wire === 1) { p += 8; } else if (wire === 5) { p += 4; } else throw new Error("unexpected protobuf wire type");
  }
  return fields;
}

async function grpcUnary(endpoint, method, msg) {
  const frame = new Uint8Array(5 + msg.length);
  new DataView(frame.buffer).setUint32(1, msg.length);
  frame.set(msg, 5);
  const res = await fetch(`${endpoint.replace(/\/$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`, {
    method: "POST",
    headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" },
    body: frame,
  });
  if (!res.ok) throw new Error(`lightwalletd answered HTTP ${res.status}`);
  const status = res.headers.get("grpc-status");
  if (status && status !== "0") throw new Error(safeDecode(res.headers.get("grpc-message") || `grpc-status ${status}`));
  const body = new Uint8Array(await res.arrayBuffer());
  let pos = 0, data = new Uint8Array(0), trailer = "";
  while (pos + 5 <= body.length) {
    const flag = body[pos];
    const len = new DataView(body.buffer, body.byteOffset + pos + 1, 4).getUint32(0);
    const chunk = body.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (flag & 0x80) trailer += new TextDecoder().decode(chunk);
    else data = chunk;
  }
  const m = trailer.match(/grpc-status:\s*(\d+)/);
  if (m && m[1] !== "0") {
    const why = (trailer.match(/grpc-message:\s*(.*)/) || [])[1] || "";
    throw new Error(`lightwalletd: ${safeDecode(why.trim()) || "status " + m[1]}`);
  }
  return data;
}

async function grpcStream(endpoint, method, msg) {
  const frame = new Uint8Array(5 + msg.length);
  new DataView(frame.buffer).setUint32(1, msg.length);
  frame.set(msg, 5);
  const res = await fetch(`${endpoint.replace(/\/$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`, {
    method: "POST",
    headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" },
    body: frame,
  });
  if (!res.ok) throw new Error(`lightwalletd answered HTTP ${res.status}`);
  const body = new Uint8Array(await res.arrayBuffer());
  const out = [];
  let pos = 0, trailer = "";
  while (pos + 5 <= body.length) {
    const flag = body[pos];
    const len = new DataView(body.buffer, body.byteOffset + pos + 1, 4).getUint32(0);
    const chunk = body.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (flag & 0x80) trailer += new TextDecoder().decode(chunk);
    else out.push(chunk);
  }
  const m = trailer.match(/grpc-status:\s*(\d+)/);
  if (m && m[1] !== "0") throw new Error(`lightwalletd: ${safeDecode(((trailer.match(/grpc-message:\s*(.*)/) || [])[1] || "").trim()) || "status " + m[1]}`);
  return out;
}

const blockId = (h) => [0x0a, ...encodeVarint(encodeVarint(h).length + 1), 0x08, ...encodeVarint(h)];

/**
 * Compact blocks `start..=end` with their Orchard and Ironwood actions packed for the wasm
 * ReceiptMaker (181 bytes each: pool, txid, nf, cmx, epk, ciphertext). Yields `{ height, packed }`.
 */
// Public servers drop long-lived connections now and then; a wallet scan is hundreds of batches.
async function retry(fn, tries = 4) {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i >= tries) throw e;
      await new Promise((r) => setTimeout(r, 500 * 2 ** i));
    }
  }
}

export async function* fetchCompactActions(endpoint, start, end, { batch = 200, parallel = 6 } = {}) {
  const get = (from) => {
    const to = Math.min(end, from + batch - 1);
    const range = [...blockId(from)];
    const endId = [0x08, ...encodeVarint(to)];
    const msg = new Uint8Array([...range, 0x12, endId.length, ...endId, 0x1a, 0x02, 0x03, 0x04]); // poolTypes: Orchard, Ironwood
    return retry(() => grpcStream(endpoint, "GetBlockRange", msg));
  };
  // A few batches in flight, handed out in order: the same requests as one at a time, sooner.
  const ahead = [];
  let next = start;
  const fill = () => {
    while (ahead.length < parallel && next <= end) {
      const p = get(next);
      p.catch(() => {}); // awaited below, in order
      ahead.push(p);
      next += batch;
    }
  };
  for (fill(); ahead.length; fill()) {
    const blocks = await ahead.shift();
    for (const block of blocks) {
      let height = 0;
      const parts = [];
      for (const [f, v] of parseFields(block)) {
        if (f === 2) height = Number(v);
        if (f !== 7) continue;
        let txid = null;
        const acts = [];
        for (const [tf, tv] of parseFields(v)) {
          if (tf === 2) txid = tv;
          if (tf === 6 || tf === 9) acts.push([tf === 6 ? 0 : 1, tv]);
        }
        for (const [pool, a] of acts) {
          const rec = new Uint8Array(181);
          rec[0] = pool;
          if (txid) rec.set(txid.subarray(0, 32), 1);
          for (const [af, av] of parseFields(a)) {
            if (af === 1) rec.set(av.subarray(0, 32), 33);
            if (af === 2) rec.set(av.subarray(0, 32), 65);
            if (af === 3) rec.set(av.subarray(0, 32), 97);
            if (af === 4) rec.set(av.subarray(0, 52), 129);
          }
          parts.push(rec);
        }
      }
      const packed = new Uint8Array(parts.length * 181);
      parts.forEach((p, i) => packed.set(p, i * 181));
      yield { height, packed };
    }
  }
}

/** The Orchard and Ironwood note commitment trees after block `height` (hex, as lightwalletd sends them). */
export async function fetchTreeState(endpoint, height) {
  const ts = await grpcUnary(endpoint, "GetTreeState", new Uint8Array([0x08, ...encodeVarint(height)]));
  const out = { orchard: "", ironwood: "" };
  for (const [f, v] of parseFields(ts)) {
    if (f === 6) out.orchard = new TextDecoder().decode(v);
    if (f === 7) out.ironwood = new TextDecoder().decode(v);
  }
  return out;
}

/** The height of the server's latest block (CompactTxStreamer.GetLatestBlock). */
export async function fetchTipHeight(endpoint) {
  const id = await grpcUnary(endpoint, "GetLatestBlock", new Uint8Array(0));
  for (const [f, v] of parseFields(id)) if (f === 1) return Number(v); // BlockID.height
  throw new Error("lightwalletd sent no tip height");
}

/** Display txids (block-explorer hex) of the shielded transactions in block `height`. */
export async function fetchBlockTxids(endpoint, height, { shieldedOnly = false } = {}) {
  const msg = new Uint8Array([0x08, ...encodeVarint(height)]); // BlockID.height
  const block = await grpcUnary(endpoint, "GetBlock", msg);
  const ids = [];
  for (const [f, v] of parseFields(block)) {
    if (f === 5) ids.time = Number(v); // CompactBlock.time (Unix seconds)
    if (f !== 7) continue; // CompactBlock.vtx
    let id = null, index = 0, shielded = false;
    for (const [tf, tv] of parseFields(v)) {
      if (tf === 1) index = Number(tv);
      if (tf === 2) id = bytesToHex(Uint8Array.from(tv).reverse());
      if (tf === 6 || tf === 9) shielded = true; // Orchard or Ironwood actions: only those can carry a receipt
    }
    if (id && (!shieldedOnly || (shielded && index !== 0))) ids.push(id);
  }
  return ids;
}

/**
 * Fetches `displayTxid` without telling the server which transaction you care about: lists the
 * shielded transactions in block `height`, then fetches the run of up to `maxSet` of them that
 * holds yours (the same run every time), in random order. Resolves to `{ raw, height, anonymitySet, blockTxs }`.
 * Throws if the transaction is not in that block.
 */
export async function fetchTransactionPrivately(endpoint, displayTxid, height, { maxSet = 64, minSet = 8, txidOf = null } = {}) {
  const want = displayTxid.toLowerCase();
  // Cover is only transactions that could carry a receipt: shielded, not the coinbase. If the
  // server's compact data doesn't show ours as shielded, fall back to every transaction. A txid
  // listed twice counts once.
  const unique = (xs) => Object.assign([...new Set(xs)], { time: xs.time });
  // The whole aligned run of 4 blocks holding the payment is listed every time, all at once and
  // in random order, so neither which blocks are asked for nor their order points at the payment's.
  const first = height - (height % 4);
  const run = [first, first + 1, first + 2, first + 3];
  for (let i = run.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [run[i], run[j]] = [run[j], run[i]];
  }
  const listed = new Map((await Promise.allSettled(run.map((h) => fetchBlockTxids(endpoint, h, { shieldedOnly: true }).then((xs) => [h, xs]))))
    .filter((r) => r.status === "fulfilled").map((r) => r.value));
  let ids = unique(listed.get(height) || []);
  if (!ids.includes(want)) ids = unique(await fetchBlockTxids(endpoint, height));
  if (!ids.includes(want)) throw new Error(`transaction ${want.slice(0, 12)}… is not in block ${height}`);
  // The window of the block (in block order) that holds ours: the same set every time,
  // so checking one receipt twice can't be intersected down to it.
  // Equal windows of at most maxSet, so the last is never a lone transaction (65 → 33 + 32).
  const size = Math.max(1, Math.ceil(ids.length / Math.max(1, Math.ceil(ids.length / maxSet))));
  const start = Math.floor(ids.indexOf(want) / size) * size;
  const set = ids.slice(start, start + size);
  const blockOf = new Map(set.map((t) => [t, height]));
  let blocks = [height];
  // A quiet block (by its whole count, not the window holding the payment) hides little: then
  // the other quiet blocks of the run join the cover.
  if (ids.length < minSet) {
    blocks = [first, first + 1, first + 2, first + 3];
    for (const [h, xs] of listed) {
      // Only other quiet blocks: the server can see this check widened, so it knows the payment's
      // block is a quiet one, and a busy block's transactions would hide nothing.
      if (h === height || xs.length >= minSet) continue;
      for (const t of xs.slice(0, maxSet)) if (!blockOf.has(t)) { blockOf.set(t, h); set.push(t); }
    }
  }
  for (let i = set.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [set[i], set[j]] = [set[j], set[i]];
  }
  // Every request completes before any failure is reported, and a decoy only counts if the server
  // really has it in this block: a hostile server could list made-up txids around ours.
  const results = await Promise.allSettled(set.map((t) => fetchTransaction(endpoint, t)));
  const mine = results[set.indexOf(want)];
  if (mine.status === "rejected") throw mine.reason;
  // With `txidOf(raw, height)` (the wasm `txid_of`), each answer must hash to the txid asked for:
  // a server can't pass one transaction off as many. Heights remain the server's word.
  const isThe = (t, r) => !txidOf || (() => { try { return txidOf(r.raw, r.height) === t; } catch { return false; } })();
  if (!isThe(want, mine.value)) throw new Error("the server sent a different transaction than the one asked for");
  const real = results.filter((r, i) => set[i] !== want && r.status === "fulfilled" && r.value.height === blockOf.get(set[i]) && isThe(set[i], r.value)).length;
  return { ...mine.value, anonymitySet: real + 1, blockTxs: ids.length, blockTime: ids.time, blocks };
}

/** The block-height hint in a receipt link (`…&h=4500997`), or null. Unsigned: only a fetch hint. */
export function heightHint(input) {
  const m = /[#?&]h=(\d{1,9})(?:&|$)/.exec(safeDecode(String(input)));
  return m ? Number(m[1]) : null;
}

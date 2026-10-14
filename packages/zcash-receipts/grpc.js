// Minimal grpc-web client for one lightwalletd call: CompactTxStreamer.GetTransaction.
// Works in browsers and Node 18+ (global fetch). No dependencies.

export const DEFAULT_ENDPOINTS = {
  mainnet: "https://zcash-mainnet.chainsafe.dev",
  testnet: "https://zcash-testnet.chainsafe.dev",
};

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
  if (status && status !== "0") throw new Error(decodeURIComponent(res.headers.get("grpc-message") || `grpc-status ${status}`));
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
    throw new Error(`lightwalletd: ${decodeURIComponent(why.trim()) || "status " + m[1]}`);
  }
  if (!data) throw new Error("lightwalletd returned no transaction");
  return { raw: data, height: Number(height) };
}

export { hexToBytes };

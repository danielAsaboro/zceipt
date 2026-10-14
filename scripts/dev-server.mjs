#!/usr/bin/env node
// Local demo server: serves web/ and bridges grpc-web to a plain gRPC lightwalletd
// (for a regtest chain, whose lightwalletd speaks only HTTP/2 gRPC).
//
//   node scripts/dev-server.mjs [--port 5321] [--lightwalletd 127.0.0.1:9067]
//
// The page then uses its own origin as the lightwalletd endpoint (Settings → server).

import http from "node:http";
import http2 from "node:http2";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]]] : a), []),
);
const PORT = Number(args.port || 5321);
const LWD = args.lightwalletd || "127.0.0.1:9067";
const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..", "web");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };

let lwd;
function client() {
  if (!lwd || lwd.closed || lwd.destroyed) lwd = http2.connect(`http://${LWD}`);
  return lwd;
}

function grpcWebBridge(req, res) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const stream = client().request({
      ":method": "POST",
      ":path": req.url,
      "content-type": "application/grpc",
      te: "trailers",
    });
    const out = [];
    let status = "0", message = "";
    stream.on("response", (h) => {
      if (h["grpc-status"]) { status = String(h["grpc-status"]); message = String(h["grpc-message"] || ""); }
    });
    stream.on("trailers", (t) => {
      if (t["grpc-status"] !== undefined) status = String(t["grpc-status"]);
      if (t["grpc-message"]) message = String(t["grpc-message"]);
    });
    stream.on("data", (c) => out.push(c));
    stream.on("error", (e) => { res.writeHead(502); res.end(String(e)); });
    stream.on("end", () => {
      const trailer = Buffer.from(`grpc-status:${status}\r\ngrpc-message:${encodeURIComponent(message)}\r\n`);
      const head = Buffer.alloc(5);
      head[0] = 0x80;
      head.writeUInt32BE(trailer.length, 1);
      res.writeHead(200, { "content-type": "application/grpc-web+proto" });
      res.end(Buffer.concat([...out, head, trailer]));
    });
    stream.end(body);
  });
}

http
  .createServer(async (req, res) => {
    if (req.method === "POST" && req.url.startsWith("/cash.z.wallet.sdk.rpc.CompactTxStreamer/")) return grpcWebBridge(req, res);
    const path = normalize(decodeURIComponent(req.url.split("?")[0])).replace(/^(\.\.[/\\])+/, "");
    const file = join(ROOT, path.endsWith("/") ? path + "index.html" : path);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    try {
      const data = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream", "cache-control": "no-store" });
      res.end(data);
    } catch {
      res.writeHead(404); res.end("not found");
    }
  })
  .listen(PORT, "127.0.0.1", () => console.log(`receipts dev server on http://localhost:${PORT} (lightwalletd ${LWD})`));

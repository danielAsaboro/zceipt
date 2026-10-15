#!/usr/bin/env python3
"""Record and decode exactly what a verifier sends to a lightwalletd server.

    wire.py proxy  PORT UPSTREAM_HOST:443 OUT_DIR   # plaintext h2c on 127.0.0.1:PORT -> TLS upstream
    wire.py decode OUT_DIR                          # every HTTP/2 frame the client sent, decoded

The verifier talks plaintext to 127.0.0.1 (receipts-chain uses h2c for localhost), the proxy
opens TLS to the real server, and records both directions byte for byte. The decoder parses the
client's bytes as HTTP/2 (RFC 9113), HPACK (RFC 7541; tables from hpack-tables.json, extracted
from the h2 crate's RFC 7541 tables) and gRPC length-prefixed protobuf, so the report shows the
complete request content the server received inside TLS. A packet capture of the TLS link would
show only its size and timing, both of which are also recorded here.
Standard library only.
"""

import asyncio
import json
import os
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------- proxy ----------------

async def pipe(reader, writer, log, direction, t0):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            log.append({"t": round(time.time() - t0, 4), "dir": direction, "len": len(data), "hex": data.hex()})
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def proxy(port, upstream, out_dir):
    host, uport = upstream.rsplit(":", 1)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    n = [0]

    async def handle(cr, cw):
        n[0] += 1
        conn = n[0]
        t0 = time.time()
        log = []
        try:
            ur, uw = await asyncio.open_connection(host, int(uport), ssl=ctx, server_hostname=host)
            await asyncio.gather(pipe(cr, uw, log, "client->server", t0), pipe(ur, cw, log, "server->client", t0))
        finally:
            with open(os.path.join(out_dir, f"conn-{conn}.json"), "w") as f:
                json.dump({"upstream": upstream, "sni": host, "started": t0, "chunks": log}, f)

    os.makedirs(out_dir, exist_ok=True)
    srv = await asyncio.start_server(handle, "127.0.0.1", int(port))
    print(f"recording 127.0.0.1:{port} -> {upstream} (TLS) into {out_dir}", flush=True)
    async with srv:
        await srv.serve_forever()


# ---------------- HPACK ----------------

_T = json.load(open(os.path.join(HERE, "hpack-tables.json")))
STATIC = [None] + [tuple(x) for x in _T["static"]]
HUFF = {(l, c): sym for sym, (c, l) in enumerate(_T["huffman"])}


def huffman_decode(b):
    out, acc, nbits = bytearray(), 0, 0
    for byte in b:
        for i in range(7, -1, -1):
            acc = (acc << 1) | ((byte >> i) & 1)
            nbits += 1
            sym = HUFF.get((nbits, acc))
            if sym is not None:
                out.append(sym)
                acc, nbits = 0, 0
    if nbits > 7 or acc != (1 << nbits) - 1:
        raise ValueError("bad huffman padding")
    return bytes(out)


class Hpack:
    def __init__(self):
        self.dyn = []

    def entry(self, i):
        return STATIC[i] if i <= 61 else self.dyn[i - 62]

    @staticmethod
    def integer(b, i, prefix):
        mask = (1 << prefix) - 1
        v = b[i] & mask
        i += 1
        if v < mask:
            return v, i
        m = 0
        while True:
            v += (b[i] & 0x7F) << m
            m += 7
            i += 1
            if not b[i - 1] & 0x80:
                return v, i

    def string(self, b, i):
        huff = b[i] & 0x80
        n, i = self.integer(b, i, 7)
        s = b[i:i + n]
        return (huffman_decode(s) if huff else s).decode("latin-1"), i + n

    def decode(self, b):
        out, i = [], 0
        while i < len(b):
            x = b[i]
            if x & 0x80:
                idx, i = self.integer(b, i, 7)
                out.append(self.entry(idx))
            elif x & 0x40 or (x & 0xF0) in (0x00, 0x10):
                prefix = 6 if x & 0x40 else 4
                idx, i = self.integer(b, i, prefix)
                name = self.entry(idx)[0] if idx else None
                if name is None:
                    name, i = self.string(b, i)
                value, i = self.string(b, i)
                out.append((name, value))
                if x & 0x40:
                    self.dyn.insert(0, (name, value))
            elif x & 0x20:
                _, i = self.integer(b, i, 5)  # dynamic table size update
            else:
                raise ValueError("bad HPACK byte")
        return out


# ---------------- protobuf (generic) ----------------

def varint(b, i):
    v, s = 0, 0
    while True:
        v |= (b[i] & 0x7F) << s
        s += 7
        i += 1
        if not b[i - 1] & 0x80:
            return v, i


def protobuf(b):
    fields, i = [], 0
    while i < len(b):
        key, i = varint(b, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            n, i = varint(b, i)
            v, i = b[i:i + n].hex(), i + n
        elif wt == 1:
            v, i = b[i:i + 8].hex(), i + 8
        elif wt == 5:
            v, i = b[i:i + 4].hex(), i + 4
        else:
            raise ValueError("wire type")
        fields.append({"field": num, "value": v})
    return fields


# ---------------- HTTP/2 ----------------

FRAME = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}


def frames(b):
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if not b.startswith(preface):
        raise ValueError("not an HTTP/2 client stream")
    i = len(preface)
    while i + 9 <= len(b):
        n = int.from_bytes(b[i:i + 3], "big")
        yield FRAME.get(b[i + 3], str(b[i + 3])), b[i + 4], int.from_bytes(b[i + 5:i + 9], "big") & 0x7FFFFFFF, b[i + 9:i + 9 + n]
        i += 9 + n


def decode(out_dir):
    report = []
    for name in sorted(os.listdir(out_dir)):
        if not name.startswith("conn-"):
            continue
        c = json.load(open(os.path.join(out_dir, name)))
        sent = b"".join(bytes.fromhex(x["hex"]) for x in c["chunks"] if x["dir"] == "client->server")
        recv = sum(x["len"] for x in c["chunks"] if x["dir"] == "server->client")
        hp, data = Hpack(), {}
        conn = {"connection": name, "upstream": c["upstream"], "bytes_sent": len(sent), "bytes_received": recv, "requests": [], "other_frames": {}}
        for kind, flags, stream, payload in frames(sent):
            if kind == "HEADERS":
                pad = payload[0] if flags & 0x8 else 0
                start = (1 if flags & 0x8 else 0) + (5 if flags & 0x20 else 0)
                headers = hp.decode(payload[start:len(payload) - pad])
                conn["requests"].append({"stream": stream, "headers": headers, "messages": []})
            elif kind == "DATA":
                data.setdefault(stream, bytearray()).extend(payload)
            else:
                conn["other_frames"][kind] = conn["other_frames"].get(kind, 0) + 1
        for req in conn["requests"]:
            buf, j = bytes(data.get(req["stream"], b"")), 0
            while j + 5 <= len(buf):
                n = int.from_bytes(buf[j + 1:j + 5], "big")
                req["messages"].append({"compressed": buf[j], "bytes": n, "protobuf": protobuf(buf[j + 5:j + 5 + n])})
                j += 5 + n
        report.append(conn)
    return report


if __name__ == "__main__":
    if sys.argv[1:2] == ["proxy"]:
        asyncio.run(proxy(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif sys.argv[1:2] == ["decode"]:
        print(json.dumps(decode(sys.argv[2]), indent=1))
    else:
        print(__doc__)

#!/usr/bin/env python3
"""Soak test: run a fresh `receipts serve` under sustained mixed load and watch for leaks/drift.

    python3 scripts/soak.py --minutes 15 [--receipts path/to/receipts] [--port 8760]

Each loop: proof requests of every kind on test clocks, sandbox payments, refunds, attestations,
sign-in challenges, link checks, clock advances (finality) and reorgs, all with a webhook
endpoint that checks every signature. Every minute it samples the server's memory (RSS),
database size, pending webhook deliveries and error counts, and fails if memory keeps growing,
deliveries pile up, a webhook signature is wrong, or any call returns a 5xx.
Each sample also times one write on the server (`probe_ms`): if loop throughput falls while
probe_ms stays flat, the slowdown is in this Python client (and its webhook receiver), not the
server. Standard library only; sandbox only (no wallet, no chain writes).

Result on an M-series Mac (2026-10-15), 15 minutes: 297k API calls, 120.9k signed webhooks all
verified, 0 server errors, memory flat at 53 MB, backlog drained at once; a 6-minute run held
the server's write latency at 0.7-1.2 ms throughout.
"""
import argparse, hashlib, hmac, http.server, json, os, random, subprocess, sys, tempfile, threading, time, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--minutes", type=float, default=10)
ap.add_argument("--receipts", default="receipts")
ap.add_argument("--port", type=int, default=8760)
args = ap.parse_args()

PAYEE = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa"
work = tempfile.mkdtemp(prefix="receipts-soak-")
db = os.path.join(work, "soak.db")
log = open(os.path.join(work, "server.log"), "w")
# A high per-key limit: the soak drives one key far harder than the 300/min default allows.
srv = subprocess.Popen([args.receipts, "serve", "--listen", f"127.0.0.1:{args.port}", "--db", db, "--rate-limit", "1000000"], stderr=log, stdout=log)
base = f"http://127.0.0.1:{args.port}"
for _ in range(60):
    try:
        urllib.request.urlopen(base + "/v1/health", timeout=1)
        break
    except Exception:
        time.sleep(0.5)
key = next(l.split()[-1] for l in open(log.name) if "rcpt_test_" in l)

stats = {"calls": 0, "4xx": 0, "5xx": 0, "hooks": 0, "bad_sig": 0, "events": {}}
lock = threading.Lock()

def api(method, path, body=None, auth=True):
    data = None if body is None else json.dumps(body).encode()
    h = {"content-type": "application/json"}
    if auth:
        h["authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    with lock:
        stats["calls"] += 1
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        e.read(); e.close()
        with lock:
            stats["5xx" if e.code >= 500 else "4xx"] += 1
        return None

secret = {"v": ""}
class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        sig = dict(p.split("=", 1) for p in self.headers.get("receipts-signature", "").split(","))
        want = hmac.new(secret["v"].encode(), f"{sig.get('t')}.".encode() + raw, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(want, sig.get("v1", ""))
        t = json.loads(raw).get("type", "?")
        with lock:
            stats["hooks"] += 1
            stats["bad_sig"] += 0 if ok else 1
            stats["events"][t] = stats["events"].get(t, 0) + 1
        try:
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *a):
        pass
class HookServer(http.server.ThreadingHTTPServer):
    request_queue_size = 256  # the server sends up to 32 deliveries at once
    daemon_threads = True
hook = HookServer(("127.0.0.1", 0), Hook)
threading.Thread(target=hook.serve_forever, daemon=True).start()
ep = api("POST", "/v1/webhook_endpoints", {"url": f"http://127.0.0.1:{hook.server_address[1]}/hooks"})
secret["v"] = ep["secret"]

def rss_kb():
    return int(subprocess.run(["ps", "-o", "rss=", "-p", str(srv.pid)], capture_output=True, text=True).stdout.strip() or 0)

def pending():
    """Deliveries due now and not yet made (scheduled retries don't count)."""
    d = api("GET", "/v1/deliveries?limit=100") or {"data": []}
    now = time.time()
    return sum(1 for x in d.get("data", []) if x.get("status") == "pending" and (x.get("next_attempt_at") or 0) <= now - 2)

def one_loop():
    clock = api("POST", "/v1/test_clocks", {})
    if not clock:
        return
    kind = random.choice(["single", "partial", "campaign"])
    body = {"payee": PAYEE, "kind": kind, "test_clock": clock["id"], "expires_in": random.choice([60, 3600])}
    if kind != "campaign":
        body["amount_zatoshis"] = random.randint(1, 50) * 100_000
    r = api("POST", "/v1/requests", body)
    if not r:
        return
    fixture = {"single": "zrcpt_test_refund_to", "partial": "zrcpt_test_partial", "campaign": "zrcpt_test_public_note"}[kind]
    api("POST", f"/v1/requests/{r['id']}/receipts", {"receipt": fixture})
    if kind == "partial":
        api("POST", f"/v1/requests/{r['id']}/receipts", {"receipt": "zrcpt_test_valid"})
    api("POST", f"/v1/test_clocks/{clock['id']}/advance", {"blocks": random.choice([3, 9, 12])})
    if random.random() < 0.3:
        api("POST", f"/v1/test_clocks/{clock['id']}/reorg", {"depth": 2})
        api("POST", f"/v1/test_clocks/{clock['id']}/advance", {"blocks": 12})
    if kind == "single":
        rf = api("POST", f"/v1/requests/{r['id']}/refunds", {"amount_zatoshis": 1000})
        if rf:
            api("POST", f"/v1/refunds/{rf['id']}/receipts", {"receipt": "zrcpt_test_valid"})
        att = api("POST", f"/v1/requests/{r['id']}/attestations", {})
        if att:
            api("POST", "/v1/attestations/verify", {"attestation": att["presentation"]})
    api("POST", "/v1/sign_in/challenges", {"domain": "soak.test"})
    api("POST", "/v1/payment_links/check", {"uri": r["payment_uri"]})
    api("GET", f"/v1/requests?limit=20")
    api("POST", "/v1/test_clocks/" + clock["id"] + "/advance", {"seconds": 7200})

end = time.time() + args.minutes * 60
samples, loops, next_sample = [], 0, time.time()
try:
    while time.time() < end:
        threads = [threading.Thread(target=one_loop) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        loops += 4
        if time.time() >= next_sample:
            # Server-side latency of one typical write, to tell server drift from client drift.
            t0 = time.time(); api("POST", "/v1/requests", {"payee": PAYEE, "amount_zatoshis": 100000}); probe_ms = round((time.time() - t0) * 1000, 1)
            s = {"probe_ms": probe_ms, "t": round(time.time() - (end - args.minutes * 60)), "loops": loops, "rss_mb": round(rss_kb() / 1024, 1),
                 "db_mb": round(sum(os.path.getsize(db + x) for x in ("", "-wal") if os.path.exists(db + x)) / 1e6, 1),
                 "pending_deliveries": pending(), **{k: stats[k] for k in ("calls", "4xx", "5xx", "hooks", "bad_sig")}}
            samples.append(s)
            print(json.dumps(s), flush=True)
            next_sample += 60
    # Load stops: the webhook backlog must drain.
    drained_after = None
    for i in range(120):
        if pending() == 0:
            drained_after = i
            break
        time.sleep(1)
finally:
    srv.terminate()

# Verdict: memory must level off (last third no more than 15% above the middle third), no 5xx,
# no bad signatures, deliveries keep up.
problems = []
if stats["5xx"]:
    problems.append(f"{stats['5xx']} server errors")
if stats["bad_sig"]:
    problems.append(f"{stats['bad_sig']} webhook signatures did not verify")
if len(samples) >= 3:
    third = max(1, len(samples) // 3)
    mid = sum(s["rss_mb"] for s in samples[third:2 * third]) / third
    last = sum(s["rss_mb"] for s in samples[-third:]) / third
    if last > mid * 1.15:
        problems.append(f"memory still growing: {mid:.1f} MB -> {last:.1f} MB")
if drained_after is None:
    problems.append("webhook deliveries did not drain within 2 minutes after the load stopped")
print(json.dumps({"drained_after_s": drained_after, "loops": loops, "calls": stats["calls"], "hooks": stats["hooks"], "events": stats["events"], "work": work}))
print("SOAK OK" if not problems else "SOAK FAILED: " + "; ".join(problems))
sys.exit(1 if problems else 0)


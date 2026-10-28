#!/usr/bin/env bash
# Builds the static zceipt.xyz site into site/: the landing page at /, the browser verifier at
# /verify/, the Mintlify docs at /docs/, plus llms.txt and openapi.yaml. Vercel forwards the API
# paths (/v1, /dashboard, /pay, /c) to ZCEIPT_API_ORIGIN when it is set.
#   ./scripts/build-site.sh            (run scripts/build-web.sh first for the wasm)
#   cd site && vercel deploy --prod
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=site
API="${ZCEIPT_API_ORIGIN:-}"
[ -f web/zceipt/pkg/zceipt_wasm_bg.wasm ] || { echo "error: run ./scripts/build-web.sh first" >&2; exit 1; }
mkdir -p "$OUT" && find "$OUT" -mindepth 1 -maxdepth 1 ! -name .vercel -exec rm -rf {} +
mkdir -p "$OUT/verify" "$OUT/docs"

python3 - "$OUT/index.html" "${API:+1}" <<'EOF'
import re, sys
out, has_api = sys.argv[1], sys.argv[2] == "1"
s = open("site-src/index.html").read()
link = open("examples/testnet/receipt-link.txt").read().strip()
widget = re.search(r'<zcash-receipt id="r"[^>]*>.*?</zcash-receipt>', open("web/embed.html").read(), re.S).group(0)
s = s.replace("{{SAMPLE_LINK}}", link.split("#", 1)[-1]).replace("{{WIDGET}}", widget)
if has_api:
    s = s.replace("<!--DASHBOARD_NAV-->", '<a class="hide-sm" href="/dashboard">Dashboard</a>')
    s = s.replace("<!--DASHBOARD_CTA-->", '<a class="btn ghost" href="/dashboard">Open the dashboard</a>')
open(out, "w").write(s)
EOF

cp site-src/*.js site-src/style.html "$OUT/"
mkdir -p "$OUT/brand" && cp site-src/brand/*.svg "$OUT/brand/"
mkdir -p "$OUT/vendor/three" && cp site-src/vendor/three/* "$OUT/vendor/three/"
cp web/*.html web/*.js web/*.css "$OUT/verify/"
cp -R web/zceipt "$OUT/verify/"
cp docs/llms.txt docs/openapi.yaml "$OUT/"

TMP=$(mktemp -d)
(cd docs-site && npx -y mint@4.2.1125 export --base-path /docs --output "$TMP/docs.zip" >/dev/null)
unzip -q "$TMP/docs.zip" -d "$TMP/docs"
rm -f "$TMP/docs/serve.js" "$TMP/docs/README.md" "$TMP/docs/Start Docs."*
cp -R "$TMP/docs/." "$OUT/docs/"
rm -rf "$TMP"

python3 - "$OUT/vercel.json" "$API" <<'EOF'
import json, sys
out, api = sys.argv[1], sys.argv[2]
cfg = {
    "cleanUrls": True,
    "redirects": [{"source": "/verify", "destination": "/verify/", "permanent": True}],
    "headers": [],
}
# Nothing on the site may load from another host: a script, font or image from a CDN would hand
# every visitor's IP to it. No inline scripts outside /docs: an injected <script> on any page would
# reach localStorage (the sealed wallet, the request ledger) for the whole origin. Chain servers are
# reached with fetch (connect-src), any https host because the verifier lets you pick your own
# lightwalletd. The Mintlify docs evaluate page frontmatter with `new Function` and inline their
# runtime, so /docs alone allows 'unsafe-inline' and 'unsafe-eval' (still self-hosted only), and
# its connect-src is 'self': the docs contact no chain server and no third party.
def csp(docs):
    if docs:
        script, connect, base = "'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval'", "'self'", "'self'"
    else:
        script, connect, base = "'self' 'wasm-unsafe-eval'", "'self' https: http://127.0.0.1:* http://localhost:*", "'none'"
    return ("default-src 'self'; script-src " + script + "; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; "
            "connect-src " + connect + "; object-src 'none'; base-uri " + base + "; frame-ancestors 'self'")
for source, docs in [("/((?!docs).*)", False), ("/docs", True), ("/docs/(.*)", True)]:
    cfg["headers"].append({"source": source, "headers": [
        {"key": "x-content-type-options", "value": "nosniff"},
        {"key": "referrer-policy", "value": "no-referrer"},
        {"key": "content-security-policy", "value": csp(docs)},
    ]})
if api:
    cfg["rewrites"] = [{"source": p, "destination": api + p} for p in
                       ["/v1/:path*", "/dashboard", "/pay/:path*", "/c/:path*", "/.well-known/jwks.json"]]
json.dump(cfg, open(out, "w"), indent=2)
EOF
echo "site built in $OUT/ ($(du -sh "$OUT" | cut -f1))${API:+, API at $API}"

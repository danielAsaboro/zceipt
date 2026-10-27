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
s = open("docs/landing.html").read()
for a, b in [
    ("{net}", "testnet"),
    ("localhost:{port}", "https://zceipt.xyz"),
    ('href="/docs#QUICKSTART.md"', 'href="/docs/quickstart"'),
    ('href="/docs#THREAT-MODEL.md"', 'href="/docs/reference/assurance"'),
    ('href="/docs#COMPARISON.md"', 'href="/docs/reference/related-work"'),
    ('href="/docs#ZIP311-TODOS.md"', 'href="/docs/concepts/spend-authority"'),
    ('href="/docs#SPEC.md"', 'href="/docs/reference/formats"'),
    ('<a class="card" href="/docs">API reference<span>Every endpoint, with examples</span></a>',
     '<a class="card" href="/docs/">Docs<span>Concepts, guides and reference</span></a>'),
    ("This server's test mode runs on <b>testnet</b>. Live keys use mainnet. ", ""),
]:
    assert a in s, a
    s = s.replace(a, b)
if not has_api:
    s = re.sub(r'\s*<a class="card" href="/dashboard">.*?</a>', "", s)
    s = s.replace(' <a href="/v1/health">Health</a> ·', "")
open(out, "w").write(s)
EOF

cp web/*.html web/*.js "$OUT/verify/"
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
    "headers": [{"source": "/(.*)", "headers": [
        {"key": "x-content-type-options", "value": "nosniff"},
        {"key": "referrer-policy", "value": "no-referrer"},
    ]}],
}
if api:
    cfg["rewrites"] = [{"source": p, "destination": api + p} for p in
                       ["/v1/:path*", "/dashboard", "/pay/:path*", "/c/:path*", "/.well-known/jwks.json"]]
json.dump(cfg, open(out, "w"), indent=2)
EOF
echo "site built in $OUT/ ($(du -sh "$OUT" | cut -f1))${API:+, API at $API}"

#!/usr/bin/env python3
"""SDK parity: every API operation is covered by the JS, Python, Rust and Go SDKs.

Checks conformance/sdk-parity.json against docs/openapi.yaml (every operationId listed) and
against the SDKs (every method exists). The live check, calling every operation against a
server, is each SDK's own test (parity.test.js, test_client.py::Parity, receipts-client
tests/api.rs::every_operation, receipts-go TestEveryOperation) with RECEIPTS_URL/RECEIPTS_KEY set.
"""
import json, os, pathlib, re, subprocess, sys

root = pathlib.Path(__file__).resolve().parent.parent
table = {k: v for k, v in json.loads((root / "conformance/sdk-parity.json").read_text()).items() if not k.startswith("_")}
ops = re.findall(r"operationId:\s*(\w+)", (root / "docs/openapi.yaml").read_text())
problems = [f"openapi operation {o} is missing from sdk-parity.json" for o in ops if o not in table]
problems += [f"sdk-parity.json lists {o}, which openapi.yaml doesn't have" for o in table if o not in ops]

rust = (root / "crates/receipts-client/src/lib.rs").read_text()
problems += [f"Rust SDK lacks {m['rust']} ({o})" for o, m in table.items() if not re.search(rf"pub async fn {m['rust']}\b", rust)]
go = (root / "packages/receipts-go/receipts.go").read_text()
problems += [f"Go SDK lacks {m.get('go')} ({o})" for o, m in table.items() if not m.get("go") or not re.search(rf"func \(c \*Client\) {m['go']}\(", go)]

sys.path.insert(0, str(root / "packages/receipts-python"))
from zcash_receipts import Receipts  # noqa: E402
py = Receipts("rcpt_test_parity")
def py_has(path):
    obj = py
    for part in path.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return False
    return callable(obj)
problems += [f"Python SDK lacks {m['py']} ({o})" for o, m in table.items() if not py_has(m["py"])]

js = subprocess.run(["node", "-e", """
const t = JSON.parse(process.argv[1]);
import(process.argv[2]).then(({ Receipts }) => {
  const r = new Receipts("rcpt_test_parity");
  const missing = Object.entries(t).filter(([, m]) => typeof m.js.split(".").reduce((o, k) => o?.[k], r) !== "function").map(([o, m]) => `JS SDK lacks ${m.js} (${o})`);
  console.log(JSON.stringify(missing));
});""", json.dumps(table), (root / "packages/zcash-receipts/client.js").as_uri()], capture_output=True, text=True)
problems += json.loads(js.stdout or "[]") or ([f"JS check failed: {js.stderr}"] if js.returncode else [])

print(f"{len(ops)} operations × 4 SDKs")
for p in problems:
    print("MISSING", p)
if problems:
    sys.exit(1)
print("every operation is covered by every SDK")

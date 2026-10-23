#!/usr/bin/env node
// Drives the verifier page in headless Chrome (no dependencies: the DevTools protocol over the
// WebSocket built into Node 22+). It clicks "Try a real testnet receipt" and expects VERIFIED,
// clicks "Try an edited copy" and expects NOT VALID, at phone width expects the result above
// the form, and opens the committed answer to a payment request. Serve the page first: PORT=5321 ./scripts/serve-verifier.sh
//
//   node scripts/browser-smoke.mjs [http://127.0.0.1:5321/]
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url = process.argv[2] || "http://127.0.0.1:5321/";
const chrome = [process.env.CHROME, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/chromium", "/usr/bin/google-chrome", "/opt/pw-browsers/chromium"].find((p) => p && existsSync(p));
if (!chrome) {
  console.log("browser smoke test skipped: no Chrome found (set CHROME)");
  process.exit(0);
}
const port = 9300 + Math.floor(Math.random() * 500);
const proc = spawn(chrome, ["--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), "receipts-smoke-"))}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = false;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed = true; };
try {
  let tabs;
  for (let i = 0; i < 50 && !tabs; i++) { try { tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch { await sleep(200); } }
  const ws = new WebSocket(tabs.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r));
  let id = 0;
  const waiting = new Map();
  ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } });
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; waiting.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
  const until = async (expression, seconds) => { for (let i = 0; i < seconds * 2; i++) { const v = await evaluate(expression); if (v) return v; await sleep(500); } return null; };
  const resultText = `(() => { const x = document.querySelector('#result'); return x && !x.hidden ? x.innerText : '' })()`;

  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
  await send("Page.navigate", { url });
  await until(`!!document.querySelector('#sampleReal')`, 20);
  await evaluate(`document.querySelector('#sampleReal').click()`);
  // The first check also loads the verifier (3 to 10 s, longer on a busy machine) and the block.
  const real = await until(`(${resultText}).match(/VERIFIED|NOT VALID|NOT A RECEIPT|COULD NOT CHECK/)?.[0]`, 180);
  check(real === "VERIFIED", `real testnet receipt shows VERIFIED (got ${real})`);
  const order = await evaluate(`document.querySelector('#result').getBoundingClientRect().top < document.querySelector('#paste').getBoundingClientRect().top`);
  check(order === true, "at phone width the result is above the form");
  await evaluate(`document.querySelector('#sampleEdited').click()`);
  const edited = await until(`(${resultText}).includes('NOT VALID') ? 'NOT VALID' : ''`, 60);
  check(edited === "NOT VALID", "edited copy shows NOT VALID");
  // A new link that isn't one of ours, opened in the same tab: nothing of the old check may remain.
  await evaluate(`location.hash = 'zrcpt1eyJub3QtYS1yZWNlaXB0'; true`);
  await sleep(1500);
  const swapped = await evaluate(`document.querySelector('#paste').value === '' && !document.querySelector('#progress').innerText.includes('signature valid') && !(${resultText}).includes('VERIFIED')`);
  check(swapped === true, "a new link replaces the previous check: box, steps and verdict agree");
  // No chain server reachable: the sample is still checked, offline, and says so.
  await evaluate(`document.querySelector('#endpoint').value = 'http://127.0.0.1:9'; location.hash = ''; true`);
  await sleep(300);
  await evaluate(`document.querySelector('#sampleReal').click()`);
  const offline = await until(`(${resultText}).includes('Checked offline') ? 'offline' : ''`, 90);
  check(offline === "offline" && (await evaluate(`(${resultText}).includes('VERIFIED')`)), "with no chain server the sample is checked offline and labelled");
  await evaluate(`document.querySelector('#endpoint').value = ''; true`);
  // The committed answer to a payment request: valid, signs the request, pays enough.
  const answer = readFileSync(new URL("../examples/testnet/request-answer-link.txt", import.meta.url), "utf8").trim();
  await send("Page.navigate", { url: url.replace(/#.*$/, "") + "#" + answer.split("#")[1] });
  const req = await until(`document.querySelector('.reqhead')?.innerText || ''`, 90);
  check(req === "MATCHES THE REQUEST IN THIS LINK", `answered request link: ${req}`);
  // A link with other text carrying a stray "%" still verifies.
  await evaluate(`(async () => { const m = await import('./samples.js'); location.hash = m.SAMPLE_REAL + '&h=' + m.SAMPLE_HEIGHT + '&note=50%off'; return true })()`);
  await sleep(500);
  const pct = await until(`(${resultText}).match(/VERIFIED|NOT VALID|NOT A RECEIPT|COULD NOT CHECK/)?.[0]`, 90);
  check(pct === "VERIFIED", `a link with a stray % still verifies (got ${pct})`);
  const errors = await evaluate(`document.querySelector('#progress').innerText.includes('Maximum call stack')`);
  check(!errors, "no script errors in the progress steps");
  ws.close();
} catch (e) {
  check(false, `smoke test crashed: ${e.message}`);
} finally {
  proc.kill();
}
process.exit(failed ? 1 : 0);

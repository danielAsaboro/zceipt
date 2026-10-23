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
  // The buttons exist before the page's script has wired them: wait for the handler.
  await until(`!!document.querySelector('#sampleReal')?.onclick`, 60);
  await evaluate(`document.querySelector('#sampleReal').click()`);
  // The first check also loads the verifier (3 to 10 s, longer on a busy machine) and the block.
  const real = await until(`(${resultText}).match(/PAID TO YOU|NOT VALID|NOT A RECEIPT|COULD NOT CHECK/)?.[0]`, 180);
  const green = await evaluate(`document.querySelector('#result .stamp')?.classList.contains('good')`);
  check(real === "PAID TO YOU" && green, `the real sample opens as its merchant and shows a green PAID TO YOU (got ${real})`);
  // A receipt signed here for the visitor's own message, by the public demo wallet.
  await evaluate(`document.querySelector('#ownMsg').value = 'Signed in the smoke test'; document.querySelector('#ownBtn').click(); true`);
  const own = await until(`(${resultText}).includes('Signed in the smoke test') && (${resultText}).match(/DEMO WALLET|PAID TO YOU|NOT VALID|NOT A RECEIPT|COULD NOT CHECK/)?.[0] || ''`, 120);
  check(own === "DEMO WALLET", `a receipt signed here for your own message verifies, labelled as the public demo wallet (got ${own})`);
  const order = await evaluate(`document.querySelector('#result').getBoundingClientRect().top < document.querySelector('#paste').getBoundingClientRect().top`);
  check(order === true, "at phone width the result is above the form");
  await evaluate(`document.querySelector('#sampleEdited').click()`);
  const edited = await until(`(${resultText}).includes('NOT VALID') ? 'NOT VALID' : ''`, 60);
  check(edited === "NOT VALID", "edited copy shows NOT VALID");
  await evaluate(`document.querySelector('#sampleObserver').click()`);
  await sleep(500);
  const observer = await until(`(${resultText}).includes('NOT PROVEN BY THE PAYER') ? 'NOT PROVEN' : ''`, 60);
  check(observer === "NOT PROVEN" && (await evaluate(`(${resultText}).includes('CLAIMS')`)), "a claim by someone who only saw the payment shows NOT PROVEN BY THE PAYER, with what it claims");
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
  // The verdict table: the same answer against a request this browser made before the payment,
  // after it, and with no request in the link at all.
  const stampNow = `(() => { const s = document.querySelector('#result .stamp'); return s ? s.textContent + '|' + s.className : '' })()`;
  const withRequest = async (created) => {
    await evaluate(`localStorage.clear(); localStorage.setItem('receipts.requests.v1', JSON.stringify({ e1e14a5d182a: { to: new URLSearchParams(location.hash.slice(1)).get('to'), min: 1000000, label: '', created: '${created}' } })); location.reload(); true`);
    await sleep(1500);
    return until(`document.querySelector('.reqhead') ? ${stampNow} : ''`, 90);
  };
  const late = await withRequest(new Date().toISOString());
  check(late === "VALID · REQUEST NOT MET|stamp warn", `a payment older than the request doesn't answer it (got ${late})`);
  const timely = await withRequest("2026-01-01T00:00:00Z");
  check(timely === "PAID AS REQUESTED|stamp good", `a payment after this browser's request is PAID AS REQUESTED (got ${timely})`);
  await evaluate(`localStorage.clear(); location.hash = location.hash.replace(/^#.*?(zip311r1)/, '#$1'); true`);
  await sleep(500);
  const bare = await until(`(${resultText}).includes('VERIFIED') && !document.querySelector('.reqhead') ? ${stampNow} : ''`, 90);
  check(bare === "VERIFIED · RECIPIENT NOT CHECKED|stamp warn", `a signed challenge with no request anywhere proves nothing (got ${bare})`);
  // A link with other text carrying a stray "%" still verifies.
  await evaluate(`(async () => { const m = await import('./samples.js'); location.hash = m.SAMPLE_REAL + '&h=' + m.SAMPLE_HEIGHT + '&note=50%off'; return true })()`);
  await sleep(500);
  const pct = await until(`(${resultText}).match(/VERIFIED|NOT VALID|NOT A RECEIPT|COULD NOT CHECK/)?.[0]`, 90);
  check(pct === "VERIFIED", `a link with a stray % still verifies (got ${pct})`);
  const amber = await evaluate(`(() => { const s = document.querySelector('#result .stamp'); return s && s.textContent.includes('RECIPIENT NOT CHECKED') && s.classList.contains('warn') })()`);
  check(amber === true, "a link opened with no recipient check is amber and says so");
  // "Make a receipt": the demo wallet's viewing key and txid, proofs made in this browser.
  const ufvk = readFileSync(new URL("../examples/testnet/demo/viewing-key.txt", import.meta.url), "utf8").trim();
  await send("Page.navigate", { url: url.replace(/#.*$/, "").replace(/\/?$/, "/") + "make.html" });
  await until(`!!document.querySelector('#proveBtn')`, 30);
  await evaluate(`document.querySelector('#ufvk').value = ${JSON.stringify(ufvk)}; document.querySelector('#txid').value = 'd2d4c90445cb714e0ca8da14d881be4fb606cdcd9bd6b658ec3da76fb44252f4'; document.querySelector('#birthday').value = '4532853'; document.querySelector('#proveBtn').click(); true`);
  const made = await until(`(() => { const t = document.querySelector('#progress').innerText; return /Proofs made|err/.test(document.querySelector('#progress').innerHTML) ? t : '' })()`, 300);
  check(/Proofs made/.test(made || "") && !(await evaluate(`document.querySelector('#signPart').hidden`)), `a viewing key makes the proofs in the browser (${(made || "timed out").slice(0, 60)})`);
  await send("Page.navigate", { url: url.replace(/#.*$/, "") });
  await until(`!!document.querySelector('#sampleReal')?.onclick`, 60);
  // The README names the verdicts this run just saw, word for word.
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const missing = ["PAID TO YOU", "VERIFIED · RECIPIENT NOT CHECKED", "NOT VALID", "NOT PROVEN BY THE PAYER"].filter((s) => !readme.includes(`**${s}**`));
  check(!missing.length, `the README quotes the verdicts the page shows${missing.length ? ` (missing ${missing.join(", ")})` : ""}`);
  const errors = await evaluate(`document.querySelector('#progress').innerText.includes('Maximum call stack')`);
  check(!errors, "no script errors in the progress steps");
  // SHOTS=<dir>: the README's screenshots, at desktop width, from the same samples.
  if (process.env.SHOTS) {
    const { writeFileSync } = await import("node:fs");
    const shot = async (name) => writeFileSync(join(process.env.SHOTS, name), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    await evaluate(`location.hash = ''; document.querySelector('#sampleReal').click(); true`);
    await until(`(${resultText}).includes('PAID TO YOU') ? 'x' : ''`, 30);
    await evaluate(`window.scrollTo(0, 0); true`);
    await shot("verified.png");
    await evaluate(`document.querySelector('#sampleEdited').click(); true`);
    await sleep(500);
    await until(`(${resultText}).includes('NOT VALID') ? 'x' : ''`, 60);
    await evaluate(`window.scrollTo(0, 0); true`);
    await shot("refused.png");
    console.log(`screenshots written to ${process.env.SHOTS}`);
  }
  ws.close();
} catch (e) {
  check(false, `smoke test crashed: ${e.message}`);
} finally {
  proc.kill();
}
process.exit(failed ? 1 : 0);

// <zcash-receipt> web component: drop a verified Zcash payment receipt into any page.
//
//   <script type="module" src="https://…/zceipt/widget.js"></script>
//   <zcash-receipt receipt="zip311r1…" expect-address="u1…"></zcash-receipt>
//
// Attributes: receipt (or link), expect-address, min-zatoshis, challenge, endpoint, regtest.
// Fires `receipt-verified` (detail: result) or `receipt-invalid` (detail: { error }).

import { verifyInBackground as verifyInWorker } from "./background.js";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const zec = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
const short = (s, n = 10) => (s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);

const STYLE = `
  :host { display: block; font-family: ui-monospace, "SF Mono", Menlo, monospace; color: #161513; max-width: 420px; }
  .card { background: #f3efe4; border-radius: 10px; padding: 16px 18px; box-shadow: 0 6px 18px rgba(0,0,0,.18); }
  .top { display: flex; justify-content: space-between; align-items: center; font-size: 11px; letter-spacing: .18em; color: #5c574d; }
  .stamp { font-weight: 900; letter-spacing: .2em; border: 2px solid currentColor; border-radius: 5px; padding: 1px 7px; }
  .ok { color: #1d6b45; } .bad { color: #a3271f; } .wait { color: #5c574d; }
  .amount { font-size: 24px; font-weight: 800; margin: 10px 0 2px; }
  .row { font-size: 12.5px; color: #2f2c27; margin: 3px 0; word-break: break-all; }
  .k { color: #5c574d; display: inline-block; width: 52px; }
  .memo { font-family: ui-sans-serif, system-ui, sans-serif; font-style: italic; }
  .fine { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 11.5px; color: #5c574d; margin-top: 8px; }
`;

class ZcashReceipt extends HTMLElement {
  static get observedAttributes() { return ["receipt", "expect-address", "min-zatoshis", "challenge", "endpoint", "regtest"]; }
  constructor() { super(); this.attachShadow({ mode: "open" }); }
  connectedCallback() { this.run(); }
  attributeChangedCallback() { if (this.isConnected) this.run(); }

  async run() {
    const input = this.getAttribute("receipt") || this.textContent;
    if (!input?.includes("zip311r1")) return this.paint(`<div class="top"><span>ZCASH RECEIPT</span><span class="stamp bad">MISSING</span></div>`);
    this.paint(`<div class="top"><span>ZCASH RECEIPT</span><span class="stamp wait">CHECKING</span></div><div class="fine">Verifying the zero-knowledge proof in your browser…</div>`);
    const options = {
      expectAddress: this.getAttribute("expect-address") || undefined,
      minZatoshis: this.hasAttribute("min-zatoshis") ? Number(this.getAttribute("min-zatoshis")) : undefined,
      challenge: this.getAttribute("challenge") || undefined,
      endpoint: this.getAttribute("endpoint") || undefined,
      regtest: this.hasAttribute("regtest"),
    };
    const token = (this._token = {});
    try {
      const v = await verifyInWorker(input, options);
      if (token !== this._token) return;
      const o = v.outputs[0];
      this.paint(`
        <div class="top"><span>ZCASH RECEIPT · ${esc(v.network)}</span><span class="stamp ok">VERIFIED</span></div>
        ${o ? `<div class="amount">${zec(o.zatoshis)} ZEC</div>
        <div class="row"><span class="k">TO</span>${esc(short(o.recipient, 12))}</div>
        ${o.memo ? `<div class="row"><span class="k">MEMO</span><span class="memo">“${esc(o.memo)}”</span></div>` : o.memo_withheld ? `<div class="row"><span class="k">MEMO</span>withheld by the sender</div>` : ""}` : ""}
        ${v.outputs.length > 1 ? `<div class="row">+ ${v.outputs.length - 1} more output(s)</div>` : ""}
        ${(v.sender_addresses || []).map((s) => `<div class="row"><span class="k">FROM</span>${esc(short(s, 12))} (proven)</div>`).join("")}
        ${(v.sources || []).map((s) => `<div class="row"><span class="k">FUNDS</span>${s.zatoshis != null ? esc((s.zatoshis / 1e8).toFixed(8)) + " ZEC note " : ""}from ${esc(short(s.source_txid, 6))}:${s.source_action}${(s.transparent_inputs || []).filter((i) => i.address).map((i) => `, funded by ${esc(short(i.address, 8))}`).join("")} (proven)</div>`).join("")}
        <div class="row"><span class="k">TX</span>${esc(short(v.txid, 8))} · block ${v.mined_height.toLocaleString()}</div>
        ${v.message ? `<div class="row"><span class="k">NOTE</span>${esc(v.message)}</div>` : ""}
        ${options.expectAddress ? "" : `<div class="fine">The payee was not checked: this proves a payment was authorized, not that it was made to you. Add expect-address (and min-zatoshis, challenge).</div>`}
        <div class="fine">The sender proved they authorized this payment. Nothing else about their wallet is revealed.</div>
        <div class="fine">Verified on this device.${v.fetch?.mode === "block" ? ` The server saw only block ${v.mined_height.toLocaleString()} (${v.fetch.anonymity_set} transactions), not which one.` : v.fetch?.mode === "offline" ? " No server was contacted." : ""}</div>`);
      this.dispatchEvent(new CustomEvent("receipt-verified", { detail: v, bubbles: true }));
    } catch (e) {
      if (token !== this._token) return;
      this.paint(`<div class="top"><span>ZCASH RECEIPT</span><span class="stamp bad">NOT VALID</span></div><div class="fine">${esc(e.message)}</div>`);
      this.dispatchEvent(new CustomEvent("receipt-invalid", { detail: { error: e.message }, bubbles: true }));
    }
  }

  paint(html) { this.shadowRoot.innerHTML = `<style>${STYLE}</style><div class="card">${html}</div>`; }
}

if (!customElements.get("zcash-receipt")) customElements.define("zcash-receipt", ZcashReceipt);

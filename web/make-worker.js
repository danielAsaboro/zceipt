// Scans the wallet and makes the proofs off the main thread: both take tens of seconds. Gets a
// viewing key, never a seed phrase; only payments, what a receipt would reveal and the prepared
// receipt come back.
//
//   { find: { ufvk, birthday, endpoint } }   → { payment }…, { scanned }
//   { txid, height, run }                    → { disclosable, run } once the payment is fetched
//   { prove: { selected, message }, run }    → { result, run } (the paths were rebuilt meanwhile)
import init, * as wasm from "./zceipt/pkg/zceipt_wasm.js";
import { findPayments, prepareFromViewingKey } from "./zceipt/maker.js";

const ready = init();
let scan = null; // the running or finished findPayments
let birthday = 0;
let endpoint = undefined;
let stopAt = null; // a picked payment's height: the scan can end after its window
let pending = null; // { run, resolve, reject }: the review the page is showing
const onProgress = (p) => self.postMessage({ progress: p });

self.onmessage = async ({ data }) => {
  const run = data.run;
  try {
    await ready;
    if (data.find) {
      birthday = data.find.birthday;
      endpoint = data.find.endpoint || undefined;
      scan = findPayments({ wasm, ...data.find, endpoint, onProgress, onPayment: (payment) => self.postMessage({ payment }), stopAfter: () => stopAt });
      const { payments, tip, scanned, network } = await scan;
      return self.postMessage({ scanned: { payments, tip, height: scanned, network } });
    }
    if (data.prove) {
      if (!pending || pending.run !== run) return;
      const p = pending;
      pending = null;
      return p.resolve(data.prove);
    }
    // Another payment picked while a review was up: that receipt is not made.
    pending?.reject(new Error("another payment was picked"));
    pending = null;
    stopAt = data.height;
    const { maker } = await scan;
    const select = (outputs) =>
      new Promise((resolve, reject) => {
        pending = { run, resolve, reject };
        self.postMessage({ disclosable: outputs, run });
      });
    const r = await prepareFromViewingKey({ wasm, maker, birthday, endpoint, txid: data.txid, height: data.height, onProgress, select });
    self.postMessage({ result: r, run });
  } catch (e) {
    self.postMessage({ error: String(e && e.message ? e.message : e), run });
  }
};

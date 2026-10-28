// Scans the wallet and makes the proofs off the main thread: both take tens of seconds. Gets a
// viewing key, never a seed phrase; only payments and the prepared receipt come back.
import init, * as wasm from "./zceipt/pkg/zceipt_wasm.js";
import { findPayments, prepareFromViewingKey } from "./zceipt/maker.js";

const ready = init();
let scan = null; // the running or finished findPayments
let birthday = 0;
let stopAt = null; // a picked payment's height: the scan can end after its window
const onProgress = (p) => self.postMessage({ progress: p });

self.onmessage = async ({ data }) => {
  try {
    await ready;
    if (data.find) {
      birthday = data.find.birthday;
      scan = findPayments({ wasm, ...data.find, onProgress, onPayment: (payment) => self.postMessage({ payment }), stopAfter: () => stopAt });
      const { payments, tip, scanned, network } = await scan;
      return self.postMessage({ scanned: { payments, tip, height: scanned, network } });
    }
    stopAt = data.height;
    const { maker } = await scan;
    const r = await prepareFromViewingKey({ wasm, maker, birthday, ...data, onProgress });
    self.postMessage({ result: r });
  } catch (e) {
    self.postMessage({ error: String(e && e.message ? e.message : e) });
  }
};

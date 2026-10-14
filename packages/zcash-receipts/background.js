// Verify in a Web Worker so the page stays responsive while the verifier warms up.
let worker, seq = 0;
const pending = new Map();

/** Like `verifyReceipt`/`verifyBatch`, but off the main thread (browsers only). */
export function verifyInBackground(input, options = {}) {
  if (!worker) {
    worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    worker.onmessage = (e) => {
      const p = pending.get(e.data.id);
      pending.delete(e.data.id);
      e.data.ok ? p.resolve(e.data.result) : p.reject(new Error(e.data.error));
    };
    // A worker that fails to load would otherwise leave every caller waiting forever.
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(`verifier worker failed: ${e.message || "load error"}`));
      pending.clear();
      worker = undefined;
    };
  }
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, input, options });
  });
}

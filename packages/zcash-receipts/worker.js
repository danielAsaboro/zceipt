// Runs verification off the main thread (the first check builds the Halo 2 verifying key).
import { verifyReceipt } from "./index.js";

self.onmessage = async (e) => {
  const { id, input, options } = e.data;
  try {
    self.postMessage({ id, ok: true, result: await verifyReceipt(input, options) });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};

// Runs the WASM verifier off the main thread: building the Halo 2 verifying key takes a
// few seconds and would otherwise freeze the page.
import init, { inspect, verify, warm_up, orchard_receiver_hex } from "./pkg/receipts_wasm.js";

const ready = init();

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    await ready;
    let result;
    if (op === "inspect") result = JSON.parse(inspect(args.receipt));
    else if (op === "warm") { warm_up(); result = true; }
    else if (op === "verify") result = JSON.parse(verify(args.receipt, args.rawTx, args.height, !!args.regtest));
    else if (op === "receiver") result = orchard_receiver_hex(args.ua);
    else throw new Error("unknown op " + op);
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};

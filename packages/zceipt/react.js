// React bindings.
//
//   import { useVerifyReceipt } from "zceipt/react";
//   const { status, result, error } = useVerifyReceipt(link, { expectAddress: "u1…", minZatoshis: 1_000_000 });
//   if (status === "valid") return <Paid amount={result.outputs[0].zatoshis} />;
//
// Verification runs in a Web Worker. `status` is "idle" | "verifying" | "valid" | "invalid".

import { useEffect, useRef, useState } from "react";
import { verifyInBackground } from "./background.js";

export function useVerifyReceipt(receipt, options = {}) {
  const [state, setState] = useState({ status: receipt ? "verifying" : "idle", result: null, error: null });
  const key = JSON.stringify([receipt, options]);
  const latest = useRef(0);
  useEffect(() => {
    if (!receipt) { setState({ status: "idle", result: null, error: null }); return; }
    const run = ++latest.current;
    setState({ status: "verifying", result: null, error: null });
    const isBatch = String(receipt).includes("zip311b1");
    verifyInBackground(receipt, { ...options, batch: isBatch })
      .then((result) => run === latest.current && setState({ status: "valid", result, error: null }))
      .catch((error) => run === latest.current && setState({ status: "invalid", result: null, error }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return state;
}

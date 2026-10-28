// The Zceipt MetaMask snap (packages/zceipt-snap): MetaMask holds the wallet, hands this page a
// viewing key, and signs receipts after showing what each reveals. The page never sees a seed.
const SNAP = /^(localhost|127\.0\.0\.1)$/.test(location.hostname) ? "local:http://localhost:8080" : "npm:zceipt-snap";

const eth = () => {
  const p = window.ethereum;
  if (!p) throw new Error("MetaMask Flask isn't installed in this browser.");
  return p;
};

const invoke = (method, params) => eth().request({ method: "wallet_invokeSnap", params: { snapId: SNAP, request: { method, params } } });

/** Installs the snap if needed (MetaMask asks) and asks it for the wallet's viewing key. */
export async function connect(network) {
  const version = await eth().request({ method: "web3_clientVersion" }).catch(() => "");
  if (!/flask/i.test(version)) throw new Error("This needs MetaMask Flask, the build that runs snaps from outside MetaMask's list.");
  await eth().request({ method: "wallet_requestSnaps", params: { [SNAP]: {} } });
  return invoke("getViewingKey", { network });
}

/** MetaMask shows what the receipt reveals; on approval returns `zip311r1…`. */
export async function sign(prepared) {
  return (await invoke("signReceipt", { prepared })).receipt;
}

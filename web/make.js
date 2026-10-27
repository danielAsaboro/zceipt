// "Make a receipt": the proofs from a viewing key (in make-worker.js), then the signature from the
// seed phrase, both on this device. The verifier page then checks the result.
import init, { sign_with_phrase } from "./zcash-receipts/pkg/receipts_wasm.js";

const $ = (s) => document.querySelector(s);
const local = init();
let made = null;

// Opened from a payment request (the verifier page's "Make it in your browser"): answer it.
const hash = new URLSearchParams(location.hash.slice(1));
const request = hash.get("request") ? hash : null;
if (request && /^[0-9a-f]{6,64}$/.test(request.get("request"))) $("#msg").value = `challenge:${request.get("request")}`;
if (hash.get("txid")) $("#txid").value = hash.get("txid");

function need(sel, what) {
  const el = $(sel);
  el.setCustomValidity(what);
  el.reportValidity();
  el.addEventListener("input", () => el.setCustomValidity(""), { once: true });
  el.focus();
}

const say = (text, cls = "") => { $("#progress").innerHTML = `<span class="${cls}"></span>`; $("#progress span").textContent = text; };
const progress = (p) => {
  if (p.step === "scan") say(`Finding your notes: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()} (${p.notes} found)`);
  if (p.step === "fetch") say(`Found the payment in block ${p.height.toLocaleString()}; fetching it among its block's transactions`);
  if (p.step === "path") say(`Rebuilding the note's place in the tree: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()}`);
  if (p.step === "prove") say("Making the zero-knowledge proof (about 20 seconds)");
};

$("#proveBtn").onclick = () => {
  const ufvk = $("#ufvk").value.trim(), txid = $("#txid").value.trim().toLowerCase(), birthday = Number($("#birthday").value.trim());
  if (!/^uview(test)?1/.test(ufvk)) return need("#ufvk", "Paste the viewing key your wallet exports (uview1…).");
  if (!/^[0-9a-f]{64}$/.test(txid)) return need("#txid", "A transaction id is 64 hex digits.");
  if (!Number.isInteger(birthday) || birthday < 1) return need("#birthday", "The block your wallet was created at (any block before it first received funds).");
  $("#proveBtn").disabled = true;
  $("#signPart").hidden = true;
  say("Starting");
  const w = new Worker("./make-worker.js", { type: "module" });
  w.onmessage = ({ data }) => {
    if (data.progress) return progress(data.progress);
    w.terminate();
    $("#proveBtn").disabled = false;
    if (data.error) return say(data.error, "err");
    made = { ...data.result, txid };
    say(`Proofs made for ${txid.slice(0, 12)}… Your viewing key stayed on this device.`, "done");
    $("#signPart").hidden = false;
    $("#phrase").focus();
  };
  w.postMessage({ ufvk, txid, birthday, height: Number(hash.get("h")) || undefined, message: $("#msg").value });
};

$("#signBtn").onclick = async () => {
  const phrase = $("#phrase").value;
  $("#phrase").value = "";
  if (!phrase.trim()) return need("#phrase", "Type your seed phrase.");
  await local;
  let receipt;
  try {
    receipt = sign_with_phrase(made.prepared, phrase, 0);
  } catch (e) {
    return say(String(e.message || e), "err");
  }
  // To the verifier, with the request it answers when there is one, so it is checked there.
  const req = request ? `${["request", "to", "min", "label"].filter((k) => request.get(k)).map((k) => `${k}=${encodeURIComponent(request.get(k))}`).join("&")}&` : "";
  location.href = `./#${req}${receipt}&h=${made.height}`;
};

// For a hardware wallet or another machine: `receipts sign <file>` reads this.
$("#saveBtn").onclick = () => {
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([`${made.prepared}\nh=${made.height}\n`], { type: "text/plain" })),
    download: `prepared-${made.txid.slice(0, 12)}.zip311u1.txt`,
  });
  a.click();
  URL.revokeObjectURL(a.href);
};

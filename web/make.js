// "Make a receipt": open the wallet with its seed phrase or viewing key, pick one of the payments
// the scan finds, review what the receipt will reveal, and the proofs and signature are made on
// this device. The worker only ever gets the viewing key; a seed phrase stays in this page's
// memory until it signs, then is dropped.
import init, { sign_with_phrase, viewing_key_from_phrase } from "./zceipt/pkg/zceipt_wasm.js";
import { DEFAULT_ENDPOINTS } from "./zceipt/grpc.js";
import * as passkey from "./passkey.js";
import * as metamask from "./metamask.js";

const $ = (s) => document.querySelector(s);
const local = init();
let worker = null;
let phrase = null; // only when the wallet was opened with its seed phrase
let viaMetaMask = false; // the Zceipt snap holds the keys and signs
let network = "testnet";
let picked = null; // { txid, height }
let run = 0; // which pick the worker's answers belong to; older ones are ignored
let outputs = null; // what the picked payment's receipt can reveal
let made = null;

// Opened from a payment request (the verifier page's "Make it in your browser"): answer it.
const hash = new URLSearchParams(location.hash.slice(1));
const request = hash.get("request") ? hash : null;
if (request && /^[0-9a-f]{6,64}$/.test(request.get("request"))) $("#msg").value = `challenge:${request.get("request")}`;
const wanted = /^[0-9a-f]{64}$/.test(hash.get("txid") || "") ? hash.get("txid") : null;

function need(sel, what) {
  const el = $(sel);
  el.setCustomValidity(what);
  el.reportValidity();
  el.addEventListener("input", () => el.setCustomValidity(""), { once: true });
  el.focus();
}

const say = (text, cls = "") => { $("#progress").innerHTML = `<span class="${cls}"></span>`; $("#progress span").textContent = text; };
const coin = () => (network === "mainnet" ? "ZEC" : "TAZ");
const amount = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
const isViewingKey = (s) => /^uview(test)?1/.test(s);
const minutes = (s) => (s < 90 ? `${Math.max(1, Math.round(s))} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`);

// The scan's size is known once the tip is: say how much is left, and after 1,000 blocks how long.
let scanStart = 0;
const progress = (p) => {
  if (p.step === "start") {
    scanStart = performance.now();
    say(`About ${(p.to - p.from + 1).toLocaleString()} blocks to read`);
  }
  if (p.step === "scan") {
    const done = p.height - p.from + 1, left = p.to - p.height;
    const eta = done >= 1000 && scanStart ? `, about ${minutes(left / (done / ((performance.now() - scanStart) / 1000)))}` : "";
    say(`Reading your wallet: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()} (${p.notes} notes). ${left.toLocaleString()} blocks left${eta}`);
  }
  if (p.step === "fetch") say(`Fetching block ${p.height.toLocaleString()} with all its transactions`);
  if (p.step === "path") say(`Rebuilding the note's place in the tree: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()}`);
  if (p.step === "prove") say("Making the zero-knowledge proof (about 20 seconds)");
};

const forget = () => { phrase = null; };
addEventListener("pagehide", forget);

// The chain server: the network's default until the field is edited.
let endpointEdited = false;
const chosenNet = () => {
  const v = $("#key").value.trim();
  if (isViewingKey(v)) return v.startsWith("uviewtest1") ? "testnet" : "mainnet";
  return $("#net").value === "test" ? "testnet" : "mainnet";
};
function syncEndpoint() {
  if (!endpointEdited) $("#endpoint").value = DEFAULT_ENDPOINTS[chosenNet()];
  let host = $("#endpoint").value.trim() || DEFAULT_ENDPOINTS[chosenNet()];
  try { host = new URL(host).host; } catch {}
  $("#host").textContent = host;
}
$("#endpoint").addEventListener("input", () => { endpointEdited = Boolean($("#endpoint").value.trim()); syncEndpoint(); });
$("#net").addEventListener("change", syncEndpoint);
$("#key").addEventListener("input", () => {
  // A viewing key names its network; a phrase doesn't, so the choice stays explicit.
  $("#netBox").hidden = isViewingKey($("#key").value.trim());
  syncEndpoint();
});
syncEndpoint();
// Only a server the user typed is sent: otherwise the worker takes the default for the key's own
// network, which a prefilled field can't be trusted to match (the key can arrive by paste or script).
const endpoint = () => (endpointEdited ? $("#endpoint").value.trim() : undefined);

let scanning = false;
function onWorker({ data }) {
  if (data.progress) return progress(data.progress);
  if (data.payment) return addPayment(data.payment);
  if (data.scanned) {
    scanning = false;
    $("#openBtn").disabled = false;
    if (!made && !$("#makeBtn").dataset.busy && !outputs) {
      if (!data.scanned.payments.length) return noPayments(data.scanned.tip);
      say(`${data.scanned.payments.length} payment${data.scanned.payments.length === 1 ? "" : "s"} found. Your keys stayed on this device.`, "done");
    }
    return;
  }
  if (data.run !== undefined && data.run !== run) return; // an earlier pick
  if (data.disclosable) return review(data.disclosable);
  if (data.error) {
    scanning = false;
    forget();
    delete $("#makeBtn").dataset.busy;
    $("#openBtn").disabled = false;
    $("#makeBtn").disabled = !outputs;
    return say(data.error, "err");
  }
  if (data.result) return proved(data.result);
}

$("#openBtn").onclick = async () => {
  const key = $("#key").value.trim(), birthday = Number($("#birthday").value.trim());
  if (!key) return need("#key", "Your wallet's seed phrase, or the viewing key it exports (uview1…).");
  if (!Number.isInteger(birthday) || birthday < 1) return need("#birthday", "The block your wallet was created at (any block before it first received funds).");
  const net = isViewingKey(key) ? (key.startsWith("uviewtest1") ? "test" : "main") : $("#net").value;
  if (!net) return need("#net", "Which chain is this wallet on?");
  viaMetaMask = false;
  await openWallet({ key, birthday, net, endpoint: endpoint(), remember: $("#remember").checked });
};

$("#unlockBtn").onclick = async () => {
  $("#unlockBtn").disabled = true;
  try {
    viaMetaMask = false;
    const rec = await passkey.unlock();
    if (rec.ufvk) {
      await openWallet({ key: rec.ufvk, birthday: rec.birthday, net: rec.net, endpoint: endpoint() });
    } else {
      // A record from before only the viewing key was kept: open with it this once, then keep
      // the viewing key alone under the same passkey.
      await openWallet({ key: rec.key, birthday: rec.birthday, net: rec.net, endpoint: endpoint(), reseal: true });
    }
  } catch (e) {
    say(e.name === "NotAllowedError" ? "Unlock cancelled." : String(e.message || e), "err");
  } finally {
    $("#unlockBtn").disabled = false;
  }
};

$("#otherBtn").onclick = () => {
  passkey.forget();
  $("#unlockPart").hidden = true;
  $("#openPart").hidden = false;
  $("#key").focus();
};

async function openWallet({ key, birthday, net, endpoint, remember = false, reseal = false }) {
  let ufvk = key;
  if (!isViewingKey(key)) {
    await local;
    try {
      ufvk = viewing_key_from_phrase(key, net !== "main", 0);
    } catch (e) {
      return say(String(e.message || e), "err");
    }
    phrase = key;
  } else {
    phrase = null;
  }
  // Out of the form once it opened; a typo stays in the field to be fixed.
  $("#key").value = "";
  $("#netBox").hidden = true;
  network = ufvk.startsWith("uviewtest1") ? "testnet" : "mainnet";
  net = network === "testnet" ? "test" : "main";
  if (!endpointEdited) $("#endpoint").value = DEFAULT_ENDPOINTS[network];
  endpoint = endpoint || DEFAULT_ENDPOINTS[network];
  $("#host").textContent = new URL(endpoint).host;
  if (remember || reseal) {
    try {
      await (reseal ? passkey.reseal({ ufvk, birthday, net }) : passkey.save({ ufvk, birthday, net }, "Your Zcash wallet"));
    } catch (e) {
      say(`Not remembered: ${e.message || e}`, "err");
    }
  }
  made = null;
  picked = null;
  outputs = null;
  run++;
  $("#payments").replaceChildren();
  $("#review").hidden = true;
  $("#makeBtn").disabled = true;
  $("#openBtn").disabled = true;
  $("#pickPart").hidden = false;
  $("#signPart").hidden = true;
  say("Starting");
  worker?.terminate();
  worker = new Worker("./make-worker.js", { type: "module" });
  worker.onmessage = onWorker;
  scanning = true;
  worker.postMessage({ find: { ufvk, birthday, endpoint } });
}

// A wallet remembered here opens with the passkey alone.
if (passkey.saved()) {
  $("#savedLabel").textContent = passkey.saved();
  $("#unlockPart").hidden = false;
  $("#openPart").hidden = true;
}
passkey.supported().then((ok) => { $("#rememberBox").hidden = !ok; });

function noPayments(tip) {
  const p = document.createElement("p");
  p.textContent = `No payments from this wallet up to block ${tip.toLocaleString()}. Is the birthday before its first deposit?`;
  $("#payments").replaceChildren(p);
  say("");
}

// Payments arrive oldest first as the scan meets them; the newest goes on top. The amount is
// what the notes were worth, not what was sent: that is known once the payment is fetched.
function addPayment(p) {
  const box = $("#payments");
  const b = Object.assign(document.createElement("button"), { type: "button", className: "pay" });
  b.setAttribute("role", "radio");
  b.setAttribute("aria-checked", "false");
  b.innerHTML = "<span></span><b></b><small></small>";
  b.querySelector("span").textContent = `Block ${p.height.toLocaleString()}`;
  b.querySelector("b").textContent = `${amount(p.spent_zatoshis)} ${coin()} in notes spent`;
  b.querySelector("small").textContent = `${p.txid.slice(0, 16)}…${p.txid.slice(-8)}`;
  b.onclick = () => {
    if ($("#makeBtn").dataset.busy || picked?.txid === p.txid) return;
    box.querySelectorAll(".pay").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
    picked = { ...p, button: b };
    pick();
  };
  box.prepend(b);
  if (p.txid === wanted) b.click();
}

// Fetch the payment and show what its receipt would reveal; the Merkle paths are rebuilt while
// the list is read, so "Make receipt" only has the proofs left to do.
function pick() {
  outputs = null;
  made = null;
  run++;
  $("#review").hidden = true;
  $("#signPart").hidden = true;
  $("#makeBtn").disabled = true;
  say(scanning ? "Reading the rest of this payment's part of the chain" : "Fetching the payment");
  worker.postMessage({ txid: picked.txid, height: picked.height, run });
}

function review(list) {
  outputs = list;
  const box = $("#outputs");
  box.replaceChildren();
  for (const o of list) {
    const l = Object.assign(document.createElement("label"), { className: "out" });
    l.innerHTML = '<input type="checkbox" checked><span class="to"></span><b></b><small></small>';
    l.querySelector("input").dataset.index = o.index;
    const to = l.querySelector(".to");
    to.textContent = `${o.recipient.slice(0, 14)}…${o.recipient.slice(-6)}`;
    to.title = o.recipient;
    l.querySelector("b").textContent = `${amount(o.zatoshis)} ${coin()}`;
    l.querySelector("small").textContent = o.memo;
    box.append(l);
  }
  $("#reveals").textContent = list.length
    ? "Signing reveals these outputs, your message and that your key spent the money. Nothing else."
    : "Nothing was sent to someone else in this payment: signing reveals your message and that your key spent the money. Nothing else.";
  if (list.length) picked.button.querySelector("b").textContent = `${amount(list.reduce((s, o) => s + o.zatoshis, 0))} ${coin()} sent`;
  $("#review").hidden = false;
  $("#makeBtn").disabled = false;
  say("");
}

$("#makeBtn").onclick = () => {
  if (!picked || !outputs) return;
  const selected = [...$("#outputs").querySelectorAll("input:checked")].map((i) => Number(i.dataset.index));
  if (outputs.length && !selected.length) return say("Keep at least one output checked: a receipt that shows none proves only that your key spent the money.", "err");
  $("#makeBtn").disabled = true;
  $("#makeBtn").dataset.busy = "1";
  $("#signPart").hidden = true;
  say("Making the zero-knowledge proof (about 20 seconds)");
  worker.postMessage({ prove: { selected, message: $("#msg").value }, run });
};

function proved(result) {
  delete $("#makeBtn").dataset.busy;
  $("#openBtn").disabled = false;
  made = { ...result, txid: picked.txid };
  if (viaMetaMask) return signInMetaMask();
  if (phrase) return sign(phrase);
  say(`Proofs made for ${picked.txid.slice(0, 12)}… Your viewing key stayed on this device.`, "done");
  $("#makeBtn").disabled = false;
  $("#signPart").hidden = false;
  $("#phrase").focus();
}

$("#mmBtn").onclick = async () => {
  const net = $("#net").value;
  if (!net) return need("#net", "Which chain is this wallet on?");
  $("#mmBtn").disabled = true;
  try {
    say("Approve in MetaMask");
    const { viewingKey, birthday } = await metamask.connect(net === "main" ? "main" : "test");
    const b = birthday ?? Number($("#birthday").value.trim());
    if (!Number.isInteger(b) || b < 1) { say(""); return need("#birthday", "The block your wallet was created at (any block before it first received funds)."); }
    viaMetaMask = true;
    await openWallet({ key: viewingKey, birthday: b, net, endpoint: endpoint() });
  } catch (e) {
    say(String(e.message || e), "err");
  } finally {
    $("#mmBtn").disabled = false;
  }
};

async function signInMetaMask() {
  say("Approve the receipt in MetaMask");
  try {
    const receipt = await metamask.sign(made.prepared);
    done(receipt);
  } catch (e) {
    $("#makeBtn").disabled = false;
    say(String(e.message || e), "err");
  }
}

// To the verifier, with the request it answers when there is one, so it is checked there.
function done(receipt) {
  const req = request ? `${["request", "to", "min", "label"].filter((k) => request.get(k)).map((k) => `${k}=${encodeURIComponent(request.get(k))}`).join("&")}&` : "";
  location.href = `./#${req}${receipt}&h=${made.height}`;
}

async function sign(words) {
  await local;
  let receipt;
  try {
    receipt = sign_with_phrase(made.prepared, words, 0);
  } catch (e) {
    return say(String(e.message || e), "err");
  } finally {
    forget();
  }
  done(receipt);
}

$("#signBtn").onclick = () => {
  const words = $("#phrase").value;
  $("#phrase").value = "";
  if (!words.trim()) return need("#phrase", "Type your seed phrase.");
  sign(words);
};

// For a hardware wallet or another machine: `zceipt sign <file>` reads this.
$("#saveBtn").onclick = () => {
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([`${made.prepared}\nh=${made.height}\n`], { type: "text/plain" })),
    download: `prepared-${made.txid.slice(0, 12)}.zip311u1.txt`,
  });
  a.click();
  URL.revokeObjectURL(a.href);
};

// The buttons wait for this module: a click before it loaded would do nothing, silently.
for (const id of ["#openBtn", "#mmBtn", "#unlockBtn"]) $(id).disabled = false;

// "Make a receipt": open the wallet with its seed phrase or viewing key, pick one of the payments
// the scan finds, and the proofs and signature are made on this device. The worker only ever gets
// the viewing key; a seed phrase stays in this page's memory until it signs, then is dropped.
import init, { sign_with_phrase, viewing_key_from_phrase } from "./zceipt/pkg/zceipt_wasm.js";
import * as passkey from "./passkey.js";

const $ = (s) => document.querySelector(s);
const local = init();
let worker = null;
let phrase = null; // only when the wallet was opened with its seed phrase
let network = "testnet";
let picked = null; // { txid, height }
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
const progress = (p) => {
  if (p.step === "scan") say(`Reading your wallet: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()} (${p.notes} notes)`);
  if (p.step === "fetch") say(`Fetching block ${p.height.toLocaleString()} with all its transactions`);
  if (p.step === "path") say(`Rebuilding the note's place in the tree: block ${p.height.toLocaleString()} of ${p.to.toLocaleString()}`);
  if (p.step === "prove") say("Making the zero-knowledge proof (about 20 seconds)");
};
const coin = () => (network === "mainnet" ? "ZEC" : "TAZ");
const amount = (z) => (z / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
const isViewingKey = (s) => /^uview(test)?1/.test(s);

const forget = () => { phrase = null; };
addEventListener("pagehide", forget);

$("#key").addEventListener("input", () => {
  const v = $("#key").value.trim();
  $("#netBox").hidden = !v || isViewingKey(v);
});

let scanning = false;
function onWorker({ data }) {
  if (data.progress) return progress(data.progress);
  if (data.payment) return addPayment(data.payment);
  if (data.scanned) {
    scanning = false;
    $("#openBtn").disabled = false;
    if (!made && !$("#makeBtn").dataset.busy) {
      if (!data.scanned.payments.length) return noPayments(data.scanned.tip);
      say(`${data.scanned.payments.length} payment${data.scanned.payments.length === 1 ? "" : "s"} found. Your keys stayed on this device.`, "done");
    }
    return;
  }
  if (data.error) {
    scanning = false;
    forget();
    delete $("#makeBtn").dataset.busy;
    $("#openBtn").disabled = false;
    $("#makeBtn").disabled = !picked;
    return say(data.error, "err");
  }
  if (data.result) return proved(data.result);
}

$("#openBtn").onclick = async () => {
  const key = $("#key").value.trim(), birthday = Number($("#birthday").value.trim());
  if (!key) return need("#key", "Your wallet's seed phrase, or the viewing key it exports (uview1…).");
  if (!Number.isInteger(birthday) || birthday < 1) return need("#birthday", "The block your wallet was created at (any block before it first received funds).");
  const net = $("#net").value;
  // Out of the form as soon as it's read: the field keeps nothing.
  $("#key").value = "";
  $("#netBox").hidden = true;
  if ($("#remember").checked) {
    try {
      await passkey.save({ key, birthday, net }, "Your Zcash wallet");
    } catch (e) {
      say(`Not remembered: ${e.message || e}`, "err");
    }
  }
  openWallet({ key, birthday, net });
};

$("#unlockBtn").onclick = async () => {
  $("#unlockBtn").disabled = true;
  try {
    openWallet(await passkey.unlock());
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

async function openWallet({ key, birthday, net }) {
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
  network = ufvk.startsWith("uviewtest1") ? "testnet" : "mainnet";
  made = null;
  picked = null;
  $("#payments").replaceChildren();
  $("#makeBtn").disabled = true;
  $("#openBtn").disabled = true;
  $("#pickPart").hidden = false;
  $("#signPart").hidden = true;
  say("Starting");
  worker?.terminate();
  worker = new Worker("./make-worker.js", { type: "module" });
  worker.onmessage = onWorker;
  scanning = true;
  worker.postMessage({ find: { ufvk, birthday } });
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

// Payments arrive oldest first as the scan meets them; the newest goes on top.
function addPayment(p) {
  const box = $("#payments");
  const b = Object.assign(document.createElement("button"), { type: "button", className: "pay" });
  b.setAttribute("role", "radio");
  b.setAttribute("aria-checked", "false");
  b.innerHTML = "<span></span><b></b><small></small>";
  b.querySelector("span").textContent = `Block ${p.height.toLocaleString()}`;
  b.querySelector("b").textContent = `${amount(p.spent_zatoshis)} ${coin()} spent`;
  b.querySelector("small").textContent = `${p.txid.slice(0, 16)}…${p.txid.slice(-8)}`;
  b.onclick = () => {
    if ($("#makeBtn").dataset.busy) return;
    box.querySelectorAll(".pay").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
    picked = p;
    $("#makeBtn").disabled = false;
  };
  box.prepend(b);
  if (p.txid === wanted) b.click();
}

$("#makeBtn").onclick = () => {
  if (!picked) return;
  $("#makeBtn").disabled = true;
  $("#makeBtn").dataset.busy = "1";
  $("#signPart").hidden = true;
  if (scanning) say("Reading the rest of this payment's part of the chain");
  worker.postMessage({ txid: picked.txid, height: picked.height, message: $("#msg").value });
};

function proved(result) {
  delete $("#makeBtn").dataset.busy;
  $("#openBtn").disabled = false;
  made = { ...result, txid: picked.txid };
  if (phrase) return sign(phrase);
  say(`Proofs made for ${picked.txid.slice(0, 12)}… Your viewing key stayed on this device.`, "done");
  $("#makeBtn").disabled = false;
  $("#signPart").hidden = false;
  $("#phrase").focus();
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
  // To the verifier, with the request it answers when there is one, so it is checked there.
  const req = request ? `${["request", "to", "min", "label"].filter((k) => request.get(k)).map((k) => `${k}=${encodeURIComponent(request.get(k))}`).join("&")}&` : "";
  location.href = `./#${req}${receipt}&h=${made.height}`;
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

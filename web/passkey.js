// "Remember this wallet on this device": the viewing key and birthday, sealed with AES-GCM under
// a key that only this device's passkey can produce (the WebAuthn PRF extension, behind Touch
// ID, Face ID or the device PIN). The sealed copy lives in this browser's storage and nowhere
// else; no server is asked, and without the passkey it can't be opened. The seed phrase is never
// stored: a viewing key can't spend, so an injection that got the sealed record and this site's
// own Touch ID prompt would still not hold the money. Signing asks for the phrase each time.

const SLOT = "zceipt.wallet";
const enc = new TextEncoder(), dec = new TextDecoder();
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
let opened = null; // the AES key of the last unlock, for reseal() without a second prompt

function read() {
  try {
    const v = JSON.parse(localStorage.getItem(SLOT) || "null");
    return v && v.id && v.salt && v.iv && v.ct ? v : null;
  } catch {
    return null;
  }
}

/** True when this browser can make a passkey that derives keys (PRF). */
export async function supported() {
  if (!window.PublicKeyCredential || !isSecureContext) return false;
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps && "extension:prf" in caps) return Boolean(caps["extension:prf"]);
  } catch {}
  return true; // older browsers don't say; save() finds out
}

/** The remembered wallet's label, or null. */
export function saved() {
  return read()?.label ?? null;
}

export function forget() {
  opened = null;
  try { localStorage.removeItem(SLOT); } catch {}
}

async function aesKey(prf) {
  const base = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("zceipt wallet v1") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function prfOf(id, salt) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      allowCredentials: [{ type: "public-key", id }],
      userVerification: "required",
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const out = cred.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error("this passkey can't lock a wallet (no PRF support)");
  return out;
}

async function seal(v, key, secret) {
  const iv = random(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(secret)));
  localStorage.setItem(SLOT, JSON.stringify({ ...v, iv: b64(iv), ct: b64(ct) }));
}

/** Makes a passkey and seals `secret` (`{ ufvk, birthday, net }`) under it. Two device prompts at most. */
export async function save(secret, label) {
  if (!secret || !secret.ufvk) throw new Error("only a viewing key is remembered, never a seed phrase");
  const salt = random(32);
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "Zceipt" },
      user: { id: random(16), name: label, displayName: label },
      challenge: random(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const ext = cred.getClientExtensionResults().prf;
  if (ext && ext.enabled === false) throw new Error("this device's passkeys can't lock a wallet (no PRF support)");
  const id = new Uint8Array(cred.rawId);
  // Some authenticators only answer PRF on a sign-in, not on creation.
  const prf = ext?.results?.first || (await prfOf(id, salt));
  opened = await aesKey(prf);
  await seal({ id: b64(id), salt: b64(salt), label }, opened, secret);
}

/** Asks for the passkey and opens the remembered wallet: `{ ufvk, birthday, net }`, or an older
 *  record's `{ key, birthday, net }` with the seed phrase (make.js converts and reseals it). */
export async function unlock() {
  const v = read();
  if (!v) throw new Error("no wallet is remembered on this device");
  const prf = await prfOf(unb64(v.id), unb64(v.salt));
  opened = await aesKey(prf);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv) }, opened, unb64(v.ct));
  return JSON.parse(dec.decode(pt));
}

/** Replaces what the passkey seals, under the same passkey; no prompt right after an unlock. */
export async function reseal(secret) {
  const v = read();
  if (!v) throw new Error("no wallet is remembered on this device");
  if (!secret || !secret.ufvk) throw new Error("only a viewing key is remembered, never a seed phrase");
  const key = opened || (await aesKey(await prfOf(unb64(v.id), unb64(v.salt))));
  await seal(v, key, secret);
}

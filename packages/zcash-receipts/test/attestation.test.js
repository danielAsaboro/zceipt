// verifyAttestation against SD-JWTs built here with a fresh Ed25519 key (no server needed).
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAttestation } from "../index.js";

const enc = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
const sha = async (s) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("base64url");

async function issue(claims, hidden) {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const x = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("base64url");
  const disclosures = Object.entries(hidden).map(([k, v]) => enc([enc("salt-" + k), k, v]));
  const payload = { ...claims, _sd: (await Promise.all(disclosures.map(sha))).sort(), _sd_alg: "sha-256" };
  const input = `${enc({ alg: "EdDSA", typ: "vc+sd-jwt", kid: "k1" })}.${enc(payload)}`;
  const sig = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(input))).toString("base64url");
  return { jwt: `${input}.${sig}`, disclosures, jwks: { keys: [{ kty: "OKP", crv: "Ed25519", kid: "k1", x }] } };
}

test("attestations verify, reveal selectively, and reject tampering", async () => {
  const { jwt, disclosures, jwks } = await issue({ iss: "https://x", paid_at_least_zatoshis: 1000000, paid_on_or_before: "2026-10-14" }, { txid: "ab", label: "Grant" });
  const plain = await verifyAttestation(`${jwt}~`, { jwks });
  assert.equal(plain.paid_at_least_zatoshis, 1000000);
  assert.deepEqual(plain.revealed, {});
  const withLabel = await verifyAttestation(`${jwt}~${disclosures[1]}~`, { jwks });
  assert.equal(withLabel.revealed.label, "Grant");
  // Raise the stated amount: the signature fails.
  const [h, p, s] = jwt.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url"));
  claims.paid_at_least_zatoshis = 9e9;
  await assert.rejects(verifyAttestation(`${h}.${enc(claims)}.${s}~`, { jwks }), /signature/);
  // A disclosure from elsewhere is refused.
  await assert.rejects(verifyAttestation(`${jwt}~${enc(["s", "txid", "ff"])}~`, { jwks }), /not part/);
});

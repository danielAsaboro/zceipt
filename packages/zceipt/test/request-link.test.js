// The request written in a verifier link: what the page accepts, and what it must not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRequestLink } from "../index.js";

const UA = "utest1zkkkjfxkamagznjr6ayemffj2d2gacdwpzcyw669pvg06xevzqslpmm27zjsctlkstl2vsw62xrjktmzqcu4yu9zdhdxqz3kafa4j2q85y6mv5yvn3sr3hq0kpqgm9vnhh5qq5rwxydkd9l3m2pydk3z4qx5qcewxk2c3hwmrs7pcrgtj8jr7qgp4d5kqevkl4zjxwt5f3p";
const CODE = "0123456789abcdef0123456789abcdef";

test("request links: code, whole-zatoshi minimum and address-shaped payee", () => {
  const r = parseRequestLink(`#request=${CODE}&to=${UA}&min=1000000&label=Order%2042`);
  assert.deepEqual(r, { code: CODE, to: UA, min: 1_000_000, label: "Order 42" });
  // Older links put the request in the query string.
  assert.deepEqual(parseRequestLink("", `?request=${CODE}&min=5`), { code: CODE, to: "", min: 5, label: "" });
  // The receipt in the same fragment is not a request parameter.
  assert.equal(parseRequestLink(`#zip311r1abc&request=${CODE}`).code, CODE);
  // No minimum, or an empty one (the make page writes `min=`), means zero.
  assert.equal(parseRequestLink(`#request=${CODE}`).min, 0);
  assert.equal(parseRequestLink(`#request=${CODE}&min=&label=`).min, 0);
});

test("request links: a minimum that is not whole zatoshis is no request", () => {
  // "0.01" means ZEC to whoever wrote it; as zatoshis it would let any payment through.
  for (const min of ["0.01", "1e6", "-1", "abc", "12345678901234567", " 5", "5 "]) {
    assert.equal(parseRequestLink(`#request=abc123&min=${encodeURIComponent(min)}`), null, JSON.stringify(min));
  }
});

test("request links: a bad code is no request", () => {
  for (const code of ["abc12", "ABCDEF", "xyz123", "a".repeat(65), ""]) assert.equal(parseRequestLink(`#request=${code}&min=1`), null, code);
});

test("request links: a payee that is not shaped like a unified address is dropped", () => {
  for (const to of [`${UA}?amount=250&memo=order`, "u1", "utest1b" + "q".repeat(30), "zs1" + "q".repeat(60), "<b>", "u1" + "Q".repeat(30)]) {
    const r = parseRequestLink(`#request=${CODE}&to=${encodeURIComponent(to)}&min=1`);
    assert.equal(r.to, "", to);
    assert.equal(r.code, CODE);
  }
  assert.equal(parseRequestLink(`#request=${CODE}&to=u1${"q".repeat(30)}`).to, `u1${"q".repeat(30)}`);
  assert.equal(parseRequestLink(`#request=${CODE}&to=uregtest1${"q".repeat(30)}`).to, `uregtest1${"q".repeat(30)}`);
});

// The API the live tests talk to: ZCEIPT_URL and ZCEIPT_KEY if set, else a throwaway local
// `zceipt serve` (from $ZCEIPT, PATH, or this repository's release build), else none, and
// the live tests skip.
import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function findBinary() {
  const repo = new URL("../../../", import.meta.url).pathname;
  const candidates = [process.env.ZCEIPT, process.env.CARGO_TARGET_DIR && join(process.env.CARGO_TARGET_DIR, "release/zceipt"), join(repo, "target/release/zceipt")];
  try { candidates.push(execFileSync("sh", ["-c", "command -v zceipt"], { encoding: "utf8" }).trim()); } catch { /* not on PATH */ }
  return candidates.find((c) => c && existsSync(c));
}

async function start() {
  if (process.env.ZCEIPT_URL && process.env.ZCEIPT_KEY) return { url: process.env.ZCEIPT_URL, key: process.env.ZCEIPT_KEY };
  const bin = findBinary();
  if (!bin) return { url: null, key: null };
  const dir = mkdtempSync(join(tmpdir(), "zceipt-sdk-test-"));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(bin, ["serve", "--listen", `127.0.0.1:${port}`, "--db", join(dir, "api.db")], { stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  process.on("exit", () => child.kill());
  child.unref();
  for (let i = 0; i < 100; i++) {
    const key = log.match(/rcpt_test_[A-Za-z0-9_]+/)?.[0];
    if (key) {
      try {
        await fetch(`http://127.0.0.1:${port}/v1/health`);
        // Let the test process exit when its tests are done; the server goes with it.
        child.stdout.destroy();
        child.stderr.destroy();
        return { url: `http://127.0.0.1:${port}`, key };
      } catch { /* not up yet */ }
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  return { url: null, key: null };
}

export const { url: URL_, key: KEY } = await start();

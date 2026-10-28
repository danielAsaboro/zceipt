// The page's back layer: columns of note ciphertext, which is all the chain shows of a shielded
// payment. While the story is on "exposed" a viewing key decrypts it into the wallet's plain lines;
// on "proved" only one line comes through, in gold.
(() => {
  const canvas = document.getElementById("cipher");
  if (!canvas) return;
  const g = canvas.getContext("2d");
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const HEX = "0123456789abcdef";
  const PLAIN = ["RENT −4.20", "CLINIC −1.35", "MUM −2.00", "SALARY +12.50", "BAL 48.2130", "DONATION −0.50", "WITHDRAW +20.00"];
  const PROVED = canvas.dataset.proved || "KEMI'S COFFEE −0.01";
  const STEP = 22, LINE = 17;
  let cols = [], dpr = 1, w = 0, h = 0;
  const rnd = (n) => Math.floor(Math.random() * n);
  function resize() {
    dpr = Math.min(devicePixelRatio, 2); w = innerWidth; h = innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Array.from({ length: Math.ceil(w / STEP) }, (_, i) => ({
      x: i * STEP + 6, y: Math.random() * h, speed: 6 + Math.random() * 18,
      chars: Array.from({ length: Math.ceil(h / LINE) + 2 }, () => HEX[rnd(16)]),
      plain: PLAIN[rnd(PLAIN.length)], at: rnd(30),
    }));
  }
  addEventListener("resize", resize); resize();
  // on the verifier, a verified receipt lets one gold line through
  const result = document.getElementById("result");
  if (result) new MutationObserver(() => { document.body.dataset.phase = result.querySelector(".stamp.good") ? "proved" : "sealed"; })
    .observe(result, { childList: true, subtree: true });
  let last = performance.now(), acc = 0;
  function tick(now) {
    const dt = Math.min(0.1, (now - last) / 1000); last = now; acc += dt;
    if (acc > 1 / 20 || still) {
      acc = 0;
      const phase = document.body.dataset.phase || "sealed";
      g.clearRect(0, 0, w, h);
      g.font = "500 11px 'JetBrains Mono', ui-monospace, monospace";
      for (const c of cols) {
        if (!still) c.y = (c.y + c.speed * dt * 20) % (LINE * c.chars.length);
        if (Math.random() < 0.08) c.chars[rnd(c.chars.length)] = HEX[rnd(16)];
        for (let r = 0; r < c.chars.length; r++) {
          const y = (r * LINE + c.y) % (LINE * c.chars.length) - LINE;
          let ch = c.chars[r], a = 0.2, col = "255,255,255";
          const k = r - c.at;
          if (phase === "exposed" && k >= 0 && k < c.plain.length) { ch = c.plain[k]; a = 0.8; }
          else if (phase === "exposed") a = 0.28;
          else if (phase === "proved" && c.x % (STEP * 9) < STEP && k >= 0 && k < PROVED.length) { ch = PROVED[k]; a = 0.6; col = "252,163,17"; }
          g.fillStyle = `rgba(${col},${a})`;
          g.fillText(ch, c.x, y);
        }
      }
    }
    if (!document.hidden) requestAnimationFrame(tick);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) { last = performance.now(); requestAnimationFrame(tick); } });
  requestAnimationFrame(tick);
})();

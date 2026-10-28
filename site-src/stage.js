// The landing story: a wallet is a deck of payment cards. Scrolling through #story fans the deck
// out (sealed), lets a viewing key expose every card, reseals it, pulls one card out with only
// recipient, amount and memo shown, and stamps a proof seal on it.
// Captions and the phase on <body> work without WebGL; the 3D deck is added when three loads.

const story = document.getElementById("story");
const canvas = document.getElementById("stage");
const beats = [document.querySelector(".beat-0"), ...document.querySelectorAll(".beat")];
const dots = [...document.querySelectorAll(".story-dots i")];
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const span = (p, a, b) => ease(clamp((p - a) / (b - a)));
const lerp = (a, b, t) => a + (b - a) * t;

// Story timeline, as fractions of the scroll through #story.
const T = {
  fan: [0.08, 0.2], expose: [0.3, 0.42], reseal: [0.52, 0.6], gather: [0.54, 0.64],
  choose: [0.66, 0.76], stamp: [0.8, 0.86],
};
const BEATS = [[0, 0.07], [0.12, 0.29], [0.31, 0.53], [0.56, 0.79], [0.8, 1.01]];

let target = 0, p = 0, top = 0, len = 1;
function measure() {
  const r = story.getBoundingClientRect();
  top = r.top + scrollY;
  len = Math.max(1, r.height - innerHeight);
}
const read = () => { target = clamp((scrollY - top) / len); };
addEventListener("resize", () => { measure(); read(); });
addEventListener("scroll", read, { passive: true });
measure(); read(); p = target;

function paintCopy() {
  let on = 0;
  BEATS.forEach(([a, b], i) => { if (p >= a && p < b) on = i; });
  beats.forEach((el, i) => el.classList.toggle("on", i === on && p < BEATS[i][1] && p >= BEATS[i][0]));
  dots.forEach((d, i) => d.classList.toggle("on", i === on - 1));
  document.body.classList.toggle("in-story", p > 0.06 && p < 0.995);
  const exposed = span(p, ...T.expose) * (1 - span(p, ...T.reseal));
  document.body.dataset.phase = exposed > 0.5 ? "exposed" : p > T.stamp[0] ? "proved" : "sealed";
  document.documentElement.style.setProperty("--exposed", exposed.toFixed(3));
  document.documentElement.style.setProperty("--hero", (1 - span(p, 0.015, 0.07)).toFixed(3));
}

let scene3d = null;
window.zceiptStage = { get gl() { return scene3d; }, settle: () => { measure(); read(); p = target; paintCopy(); scene3d?.render(performance.now() / 1000); } };

let last = performance.now();
function loop(now) {
  const dt = Math.min(0.05, (now - last) / 1000); last = now;
  p = still ? target : lerp(p, target, 1 - Math.exp(-dt * 7));
  if (Math.abs(p - target) < 1e-4) p = target;
  paintCopy();
  if (scene3d && visible) scene3d.render(now / 1000);
  requestAnimationFrame(loop);
}
let visible = true;
new IntersectionObserver(([e]) => { visible = e.isIntersecting; }).observe(story);
requestAnimationFrame(loop);

// ---------------------------------------------------------------- the deck
const FONT = '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Helvetica Neue", Arial, sans-serif';
const MONO = 'ui-monospace, "SF Mono", Menlo, monospace';
const INK = "#111114", INK2 = "#6B6B74", INK3 = "#A3A3AD";
const ACCENT = "#0071E3", FLARE = "#FF4D2E";

const CARDS = [
  { title: "Rent", amount: "−4.20", to: "utest1q8w…m3xk7", memo: "October rent", from: "utest1zr4…8hkd2", balance: "48.2130 ZEC" },
  { title: "Clinic", amount: "−1.35", to: "utest1k2d…w9e0q", memo: "Consultation", from: "utest1zr4…8hkd2", balance: "52.4130 ZEC" },
  { title: "Salary", amount: "+12.50", to: "utest1zr4…8hkd2", memo: "Payroll, September", from: "utest1n7c…2xq4s", balance: "53.7630 ZEC" },
  { title: "Kemi's Coffee", amount: "−0.01", to: "utest14te…0zndfa", memo: "Invoice 42: two coffees", from: "utest1zr4…8hkd2", balance: "41.2630 ZEC", block: "BLOCK 4,500,997" },
  { title: "Mum", amount: "−2.00", to: "utest1h5u…t6r2m", memo: "For the weekend", from: "utest1zr4…8hkd2", balance: "41.2730 ZEC" },
  { title: "Donation", amount: "−0.50", to: "utest1p0e…v8c3n", memo: "Monthly", from: "utest1zr4…8hkd2", balance: "43.2730 ZEC" },
  { title: "Next payment", amount: "−?.??", to: "not made yet", memo: "Every future payment", from: "utest1zr4…8hkd2", balance: "?" },
];
const CHOSEN = 3, N = CARDS.length;
const W = 600, H = 820, PAD = 54;

function hex(seed, n) {
  let s = seed * 2654435761 >>> 0, out = "";
  for (let i = 0; i < n; i++) { s = (s ^ (s << 13)) >>> 0; s = (s ^ (s >>> 17)) >>> 0; s = (s ^ (s << 5)) >>> 0; out += "0123456789abcdef"[s & 15]; }
  return out;
}

function drawFace(card, rev, accent, glow, sealOn) {
  const g = card.ctx, c = card.data;
  g.clearRect(0, 0, W, H);
  g.save();
  g.beginPath(); g.roundRect(0, 0, W, H, 46); g.fillStyle = "#fff"; g.fill();
  // receipt notches
  if (glow > 0.01) {
    g.globalAlpha = glow * 0.75; g.lineWidth = 6; g.strokeStyle = accent;
    g.beginPath(); g.roundRect(5, 5, W - 10, H - 10, 42); g.stroke(); g.globalAlpha = 1;
  }
  g.fillStyle = INK3; g.font = `600 19px ${FONT}`;
  try { g.letterSpacing = "3px"; } catch {}
  g.fillText("ZCASH · SHIELDED", PAD, 86);
  try { g.letterSpacing = "0px"; } catch {}
  // mark
  g.fillStyle = INK; g.beginPath(); g.roundRect(W - PAD - 34, 60, 34, 34, 10); g.fill();
  g.strokeStyle = "#fff"; g.lineWidth = 3.4; g.lineJoin = "round";
  g.beginPath(); g.moveTo(W - PAD - 25, 70); g.lineTo(W - PAD - 9, 70); g.lineTo(W - PAD - 25, 84); g.lineTo(W - PAD - 9, 84); g.stroke();

  field(g, c.title, PAD, 176, 48, 600, rev[0], card.i * 7 + 1, INK);
  const amtW = field(g, c.amount, PAD, 280, 96, 600, rev[1], card.i * 7 + 2, INK);
  if (rev[1] > 0.5) { g.globalAlpha = (rev[1] - 0.5) * 2; g.fillStyle = INK2; g.font = `600 30px ${FONT}`; g.fillText("ZEC", PAD + amtW + 14, 280); g.globalAlpha = 1; }

  g.strokeStyle = "#E4E4EA"; g.lineWidth = 3; g.setLineDash([10, 10]);
  g.beginPath(); g.moveTo(34, 318); g.lineTo(W - 34, 318); g.stroke(); g.setLineDash([]);

  const rows = [["TO", c.to], ["MEMO", c.memo], ["FROM", c.from], ["BALANCE", c.balance]];
  rows.forEach(([k, v], j) => {
    const y = 394 + j * 92, r = rev[2 + j];
    g.beginPath(); g.arc(PAD + 7, y - 7, 7, 0, Math.PI * 2);
    g.fillStyle = r > 0.02 ? accent : "#D6D6DE"; g.globalAlpha = r > 0.02 ? clamp(r * 1.6) : 1; g.fill(); g.globalAlpha = 1;
    g.fillStyle = INK3; g.font = `600 18px ${FONT}`;
    try { g.letterSpacing = "2.5px"; } catch {}
    g.fillText(k, PAD + 26, y);
    try { g.letterSpacing = "0px"; } catch {}
    field(g, v, PAD, y + 46, 30, 500, r, card.i * 7 + 3 + j, INK, j < 1 ? MONO : FONT);
  });
  g.fillStyle = INK3; g.font = `500 18px ${MONO}`;
  g.fillText(c.block || `BLOCK 4,49${card.i}…`, PAD, H - 50);
  g.restore();
  card.tex.needsUpdate = true;
}

// Draws text, then a graphite redaction bar over the part not yet revealed. Returns the text width.
function field(g, text, x, y, size, weight, rev, seed, color, family = FONT) {
  g.font = `${weight} ${size}px ${family}`;
  const tw = g.measureText(text).width, bw = Math.max(tw, size * 2.4) + 16;
  if (rev > 0) { g.save(); g.beginPath(); g.rect(x - 8, y - size, bw * rev, size * 1.4); g.clip(); g.fillStyle = color; g.fillText(text, x, y); g.restore(); }
  const bx = x - 8 + bw * rev, w = bw * (1 - rev), h = size * 1.12, top = y - size * 0.88;
  if (w > 0.5) {
    // sealed: ciphertext seen through frosted glass
    g.save();
    g.beginPath(); g.roundRect(bx, top, w, h, Math.min(16, h / 2.6)); g.clip();
    g.fillStyle = "#EEF0F5"; g.fillRect(bx, top, w, h);
    try { g.filter = `blur(${Math.max(3, size * 0.16)}px)`; } catch {}
    g.fillStyle = "#5E6372"; g.font = `600 ${size}px ${family}`;
    g.fillText(hex(seed, Math.ceil(bw / (size * 0.5))), x, y);
    try { g.filter = "none"; } catch {}
    const sheen = g.createLinearGradient(0, top, 0, top + h);
    sheen.addColorStop(0, "rgba(255,255,255,.75)"); sheen.addColorStop(0.45, "rgba(255,255,255,.28)"); sheen.addColorStop(1, "rgba(255,255,255,.5)");
    g.fillStyle = sheen; g.fillRect(bx, top, w, h);
    g.restore();
    g.save();
    g.beginPath(); g.roundRect(bx + 0.75, top + 0.75, w - 1.5, h - 1.5, Math.min(16, h / 2.6));
    g.strokeStyle = "rgba(255,255,255,.95)"; g.lineWidth = 1.5; g.stroke();
    g.restore();
  }
  return tw;
}

function sealTexture(THREE) {
  const c = document.createElement("canvas"); c.width = c.height = 512;
  const g = c.getContext("2d");
  const grad = g.createLinearGradient(0, 0, 512, 512);
  grad.addColorStop(0, "#2B8CFF"); grad.addColorStop(0.55, ACCENT); grad.addColorStop(1, "#0A5BD6");
  g.fillStyle = grad; g.beginPath(); g.arc(256, 256, 250, 0, Math.PI * 2); g.fill();
  g.strokeStyle = "rgba(255,255,255,.55)"; g.lineWidth = 4; g.beginPath(); g.arc(256, 256, 196, 0, Math.PI * 2); g.stroke();
  g.strokeStyle = "#fff"; g.lineWidth = 30; g.lineCap = "round"; g.lineJoin = "round";
  g.beginPath(); g.moveTo(176, 262); g.lineTo(232, 316); g.lineTo(340, 200); g.stroke();
  g.fillStyle = "#fff"; g.font = `700 30px ${FONT}`; g.textAlign = "center"; g.textBaseline = "middle";
  const text = "PROVEN BY THE PAYER · ZIP 311 · ";
  for (let i = 0; i < text.length; i++) {
    const a = (i / text.length) * Math.PI * 2 - Math.PI / 2;
    g.save(); g.translate(256 + Math.cos(a) * 222, 256 + Math.sin(a) * 222); g.rotate(a + Math.PI / 2); g.fillText(text[i], 0, 0); g.restore();
  }
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 8;
  return t;
}

function shadowTexture(THREE) {
  const c = document.createElement("canvas"); c.width = c.height = 256;
  const g = c.getContext("2d"), r = g.createRadialGradient(128, 128, 0, 128, 128, 128);
  r.addColorStop(0, "rgba(17,17,20,.32)"); r.addColorStop(0.5, "rgba(17,17,20,.1)"); r.addColorStop(1, "rgba(17,17,20,0)");
  g.fillStyle = r; g.fillRect(0, 0, 256, 256);
  return new THREE.CanvasTexture(c);
}

async function build() {
  const THREE = await import("three");
  const { RoundedBoxGeometry } = await import("three/addons/geometries/RoundedBoxGeometry.js");
  const { RoomEnvironment } = await import("three/addons/environments/RoomEnvironment.js");

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;
  const scene = new THREE.Scene();
  scene.environment = new THREE.PMREMGenerator(renderer).fromScene(new RoomEnvironment(), 0.04).texture;
  scene.fog = new THREE.Fog(0xf4f4f6, 15, 24);
  const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 100);
  camera.position.set(0, 0, 14);
  const key = new THREE.DirectionalLight(0xffffff, 1.4); key.position.set(-4, 6, 8); scene.add(key);

  const world = new THREE.Group(); scene.add(world);
  const bodyGeo = new RoundedBoxGeometry(2.18, 2.98, 0.04, 4, 0.15);
  const faceGeo = new THREE.PlaneGeometry(2.2, 3.0);
  const bodyMat = new THREE.MeshPhysicalMaterial({ color: 0xffffff, roughness: 0.35, clearcoat: 0.6, clearcoatRoughness: 0.2, emissive: 0xffffff, emissiveIntensity: 0.55 });
  const cards = CARDS.map((data, i) => {
    const c = document.createElement("canvas"); c.width = W; c.height = H;
    const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 8;
    const g = new THREE.Group();
    const body = new THREE.Mesh(bodyGeo, bodyMat);
    const face = new THREE.Mesh(faceGeo, new THREE.MeshBasicMaterial({ map: tex, transparent: true, toneMapped: false }));
    face.position.z = 0.024; body.renderOrder = i * 2; face.renderOrder = i * 2 + 1;
    g.add(body, face); world.add(g);
    return { i, data, g, ctx: c.getContext("2d"), tex, key: "" };
  });
  const seal = new THREE.Mesh(new THREE.CircleGeometry(0.56, 96), new THREE.MeshBasicMaterial({ map: sealTexture(THREE), transparent: true, toneMapped: false }));
  seal.position.set(0.86, -1.18, 0.05); seal.scale.setScalar(0.001);
  cards[CHOSEN].g.add(seal);
  const shadow = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), new THREE.MeshBasicMaterial({ map: shadowTexture(THREE), transparent: true, depthWrite: false }));
  shadow.rotation.x = -Math.PI / 2; scene.add(shadow);

  let aspect = 1, vw = 10, narrow = false;
  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    renderer.setSize(w, h, false);
    aspect = w / h; camera.aspect = aspect; camera.updateProjectionMatrix();
    vw = 2 * 14 * Math.tan((15 * Math.PI) / 180) * aspect;
    narrow = aspect < 1.05;
    // the fan lives right of the captions on wide screens
    const beat = document.querySelector(".beat"), edge = narrow || !beat ? 0 : (beat.offsetLeft + beat.offsetWidth + 24) / w;
    region = vw * (1 - edge) - 0.4;
    side = narrow ? 0 : vw * (edge - 0.5) + 0.2 + region / 2;
  }
  let region = 8, side = 0;
  // In the hero the stack's top card starts just under the buttons and runs off the fold.
  let heroY = -1.5;
  function placeHero() {
    const cta = document.querySelector(".hero-copy .row");
    if (!cta) return;
    const vh = 2 * 14 * Math.tan((15 * Math.PI) / 180), f = cta.getBoundingClientRect().bottom / canvas.clientHeight;
    heroY = vh * (0.5 - f) - 0.55 - 1.5;
  }
  addEventListener("resize", () => { resize(); placeHero(); }); resize(); placeHero();

  let mx = 0, my = 0, tmx = 0, tmy = 0;
  addEventListener("pointermove", (e) => { tmx = e.clientX / innerWidth - 0.5; tmy = e.clientY / innerHeight - 0.5; }, { passive: true });

  const e = new THREE.Euler(), n = new THREE.Vector3();
  // The wallet as a cascade of sealed cards, dealt left to right, the front one nearest.
  function stack(i) {
    const rx = -0.16, ry = -0.62, rz = 0;
    e.set(rx, ry, rz);
    n.set((i - (N - 1) / 2) * (narrow ? 0.34 : 0.6), 0, i * 0.1).applyEuler(e);
    return { x: n.x, y: n.y, z: n.z, rx, ry, rz, s: 1 };
  }
  // The rest of the deck, shut, peeking out behind the chosen card.
  function behind(i) {
    const j = i < CHOSEN ? i : i - 1, m = N - 2;
    return { x: -0.55 - (m - j) * 0.2, y: 0.18 + (m - j) * 0.05, z: 1.2 - (m - j) * 0.28, rx: 0, ry: 0.08, rz: 0.05 + (m - j) * 0.03, s: 0.94 };
  }
  function fan(i) {
    if (narrow) { // a small grid on phones, so every exposed card can be seen
      const row = Math.floor(i / 3), col = i % 3, x = row === 2 ? 0 : (col - 1) * 1.0;
      return { x, y: 0.33 + (1 - row) * 1.3, z: i * 0.02, rx: 0, ry: 0, rz: 0, s: 0.4 };
    }
    // two tidy rows (4 + 3) so every card can be read and none overlaps another
    const row = i < 4 ? 0 : 1, cnt = row ? 3 : 4, col = row ? i - 4 : i;
    const sc = Math.min(0.66, (region - 0.6) / (4 * 2.2 + 3 * 0.25));
    const gx = 2.2 * sc + 0.24, gy = 3 * sc + 0.3;
    return { x: (col - (cnt - 1) / 2) * gx, y: row ? -gy / 2 : gy / 2, z: 0, rx: 0, ry: 0, rz: 0, s: sc };
  }
  function chosen() { return { x: 0.25, y: 0, z: 2.6, rx: 0.02, ry: -0.2, rz: 0.015, s: 1.02 }; }
  const mix = (a, b, t) => ({ x: lerp(a.x, b.x, t), y: lerp(a.y, b.y, t), z: lerp(a.z, b.z, t), rx: lerp(a.rx, b.rx, t), ry: lerp(a.ry, b.ry, t), rz: lerp(a.rz, b.rz, t), s: lerp(a.s, b.s, t) });

  function render(time) {
    mx = lerp(mx, tmx, 0.06); my = lerp(my, tmy, 0.06);
    const fanT = span(p, ...T.fan), gather = span(p, ...T.gather);
    const expose = span(p, ...T.expose), reseal = span(p, ...T.reseal);
    const choose = span(p, ...T.choose), stamp = span(p, ...T.stamp);
    const exposed = expose * (1 - reseal);

    // where the deck sits: under the headline in the hero, beside the captions after
    world.position.x = lerp(0, side, fanT);
    world.position.y = lerp(heroY, narrow ? 1.15 : 0, span(p, 0, T.fan[1]));
    world.rotation.y = (still ? 0 : Math.sin(time * 0.35) * 0.06 * (1 - fanT)) + mx * 0.12;
    world.rotation.x = my * 0.06;
    world.scale.setScalar(narrow ? Math.min(1, vw / 4.2) : 1);

    cards.forEach((c, i) => {
      const s0 = stack(i), f = fan(i);
      let pose = mix(s0, f, fanT);
      if (gather > 0) pose = mix(pose, i === CHOSEN ? chosen() : behind(i), gather);
      if (!still && p < T.fan[1]) pose.y += Math.sin(time * 0.9 + i * 0.5) * 0.025 * (1 - fanT);
      c.g.position.set(pose.x, pose.y, pose.z);
      c.g.rotation.set(pose.rx, pose.ry, pose.rz);
      c.g.scale.setScalar(pose.s);

      // what the face shows
      const stagger = (t, k) => clamp(t * 1.6 - (k / (N - 1)) * 0.6);
      let rev = [0, 0, 0, 0, 0, 0], accent = FLARE, glow = 0;
      if (exposed > 0) { const r = stagger(exposed, i); rev = rev.map(() => r); glow = r * 0.9; }
      if (i === CHOSEN && choose > 0) {
        accent = ACCENT;
        rev = [0, 1, 2, 3].map((j) => clamp(choose * 1.7 - j * 0.22)).concat([0, 0]);
        glow = 0;
      }
      const k = rev.map((r) => r.toFixed(2)).join() + accent + glow.toFixed(2);
      if (k !== c.key) { c.key = k; drawFace(c, rev, accent, glow); }
    });

    const st = clamp(stamp * 1.25);
    const pop = st < 1 ? 1 + Math.sin(st * Math.PI) * 0.35 : 1;
    seal.scale.setScalar(Math.max(0.001, st * pop));
    seal.rotation.z = (1 - st) * 1.2;
    seal.position.z = 0.05 + (1 - st) * 1.4;

    shadow.position.set(world.position.x, world.position.y - 2.3 * (narrow ? 0.8 : 1), lerp(0, 1.4, gather));
    shadow.scale.set(lerp(4.2, 9, fanT * (1 - gather)), 1.6, 1);
    shadow.material.opacity = narrow ? 0 : 0.7 * Math.max(1 - fanT, gather);

    renderer.render(scene, camera);
  }
  scene3d = { render, scene, camera, cards };
  document.body.classList.add("has-3d");
  render(0);
}

build().catch((err) => { console.warn("3D deck unavailable:", err); document.body.classList.add("no-3d"); });

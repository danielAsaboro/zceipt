// The landing page's 3D story, driven by scroll. Privacy is frosted glass: a whole wallet (balance,
// rent, clinic, the coffee) sits behind fluted, frosted glass. 0/I: sealed, unreadable. II: a viewing
// key clears all of the frost at once and everything is exposed. III: a Zceipt receipt cuts one clear
// window over the single payment being proved, and a seal lands on it. The rest stays sealed.
import * as THREE from "three";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";

const canvas = document.getElementById("stage");
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

let renderer;
try { renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: "high-performance" }); }
catch { canvas.remove(); throw new Error("no WebGL"); }
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 100);
camera.position.set(0, 0, 9);

// ---------- backdrop: deep green aurora that warms when the wallet is exposed ----------
const sky = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), new THREE.ShaderMaterial({
  depthWrite: false, depthTest: false,
  uniforms: { uTime: { value: 0 }, uWarn: { value: 0 }, uProof: { value: 0 }, uRes: { value: new THREE.Vector2(1, 1) } },
  vertexShader: `varying vec2 vUv; void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }`,
  fragmentShader: /* glsl */`
    varying vec2 vUv; uniform float uTime, uWarn, uProof; uniform vec2 uRes;
    float blob(vec2 p, vec2 c, float r) { return exp(-dot(p - c, p - c) / (r * r)); }
    float hash(vec2 p) { return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }
    void main() {
      vec2 p = vUv; p.x *= uRes.x / uRes.y;
      float t = uTime * 0.05, ar = uRes.x / uRes.y;
      vec3 col = vec3(0.002, 0.005, 0.004);
      vec3 castleton = vec3(0.0, 0.10, 0.045), go = vec3(0.0, 0.32, 0.14), teal = vec3(0.0, 0.08, 0.09), ink = vec3(0.012, 0.014, 0.05);
      vec3 ember = vec3(0.30, 0.08, 0.01), rose = vec3(0.20, 0.02, 0.025);
      col += mix(castleton, ember, uWarn) * blob(p, vec2(ar * (0.78 + 0.08 * sin(t * 3.0)), 0.78 + 0.05 * cos(t * 2.0)), 0.55) * 0.9;
      col += mix(teal, rose, uWarn) * blob(p, vec2(ar * (0.18 + 0.06 * cos(t * 2.5)), 0.28 + 0.06 * sin(t * 3.1)), 0.5) * 0.7;
      col += ink * blob(p, vec2(ar * 0.45, 1.05), 0.6) * 0.8;
      col += go * blob(p, vec2(ar * (0.62 + 0.05 * sin(t * 4.0)), 0.42), 0.32) * (0.18 + 0.45 * uProof) * (1.0 - uWarn);
      col *= 1.0 - 0.35 * smoothstep(0.4, 1.3, length(vUv - vec2(0.5, 0.55)) * 1.4);
      col += (hash(vUv * uRes + fract(uTime)) - 0.5) * 0.006;
      gl_FragColor = vec4(col, 1.0);
    }`,
}));
sky.frustumCulled = false;
sky.renderOrder = -10;
scene.add(sky);

// ---------- the wallet behind the glass ----------
const W = 1024, H = 1424;
const ledger = document.createElement("canvas"); ledger.width = W; ledger.height = H;
const map = new THREE.CanvasTexture(ledger);
map.colorSpace = THREE.SRGBColorSpace; map.anisotropy = 8; map.minFilter = THREE.LinearMipmapLinearFilter;
const ROWS = [
  ["SL", "Salary", "Lagos Labs · October", "+12.50", "Oct 01", "#6aa2ff"],
  ["AH", "Rent", "Ade Homes · flat 3B", "−4.20", "Oct 03", "#c48cff"],
  ["KC", "Kemi's Coffee", "Invoice 42: two coffees", "−0.01", "Oct 14", "#01b763"],
  ["FC", "Fertility clinic", "Consultation, second visit", "−1.35", "Oct 16", "#ff8a80"],
  ["MU", "Mum", "For the hospital bills", "−2.00", "Oct 19", "#ffc35c"],
  ["BX", "Exchange withdrawal", "Binance → shielded", "+20.00", "Oct 21", "#7fd6ff"],
  ["DN", "Donation", "Independent press fund", "−0.50", "Oct 24", "#9be7a9"],
];
let WIN = [0, 0, 0, 0];
function drawLedger() {
  const g = ledger.getContext("2d"), pad = 76;
  const sans = "'General Sans', ui-sans-serif, sans-serif", mono = "'JetBrains Mono', ui-monospace, monospace";
  const bg = g.createLinearGradient(0, 0, W, H);
  bg.addColorStop(0, "#14211d"); bg.addColorStop(1, "#0b1311");
  g.fillStyle = bg; g.fillRect(0, 0, W, H);
  g.textBaseline = "alphabetic";
  g.fillStyle = "rgba(255,255,255,.55)"; g.font = `500 30px ${sans}`; g.fillText("Shielded wallet · Orchard", pad, 120);
  g.fillStyle = "#fff"; g.font = `500 112px ${sans}`; g.fillText("48.2130", pad, 260);
  const bw = g.measureText("48.2130").width;
  g.fillStyle = "rgba(255,255,255,.5)"; g.font = `500 48px ${sans}`; g.fillText("ZEC", pad + bw + 20, 260);
  g.fillStyle = "rgba(255,255,255,.4)"; g.font = `400 26px ${mono}`; g.fillText("u1q7v4…xg9e2kd0lmz3ehn6", pad, 320);
  g.fillStyle = "rgba(255,255,255,.12)"; g.fillRect(pad, 372, W - 2 * pad, 2);
  let y = 400;
  ROWS.forEach(([ini, name, memo, amt, day, c], i) => {
    const h = 132;
    if (i === 2) WIN = [(pad - 26) / W, 1 - (y + h - 4) / H, (W - pad + 26) / W, 1 - (y + 4) / H];
    g.fillStyle = c + "33"; g.beginPath(); g.arc(pad + 38, y + h / 2, 38, 0, Math.PI * 2); g.fill();
    g.fillStyle = c; g.font = `600 26px ${sans}`; g.textAlign = "center"; g.fillText(ini, pad + 38, y + h / 2 + 9); g.textAlign = "left";
    g.fillStyle = "#fff"; g.font = `500 38px ${sans}`; g.fillText(name, pad + 104, y + 58);
    g.fillStyle = "rgba(255,255,255,.55)"; g.font = `400 28px ${sans}`; g.fillText(memo, pad + 104, y + 100);
    g.textAlign = "right";
    g.fillStyle = amt.startsWith("+") ? "#5fe3a1" : "#fff"; g.font = `500 38px ${sans}`; g.fillText(amt + " ZEC", W - pad, y + 58);
    g.fillStyle = "rgba(255,255,255,.4)"; g.font = `400 26px ${mono}`; g.fillText(day, W - pad, y + 100);
    g.textAlign = "left";
    if (i < ROWS.length - 1) { g.fillStyle = "rgba(255,255,255,.07)"; g.fillRect(pad + 104, y + h, W - 2 * pad - 104, 2); }
    y += h;
  });
  g.fillStyle = "rgba(255,255,255,.35)"; g.font = `400 26px ${mono}`; g.fillText("viewing key  uviewtest1…7hf3k  ·  birthday 2,941,200", pad, H - 70);
  map.needsUpdate = true;
  if (card) card.material.uniforms.uWin.value.set(...WIN);
}

const CW = 2.6, CH = CW * H / W;
const card = new THREE.Mesh(new THREE.PlaneGeometry(CW, CH), new THREE.ShaderMaterial({
  transparent: true, depthWrite: false,
  uniforms: {
    uMap: { value: map }, uTime: { value: 0 }, uExpose: { value: 0 }, uWarn: { value: 0 }, uOpen: { value: 0 },
    uWin: { value: new THREE.Vector4() }, uSize: { value: new THREE.Vector2(CW, CH) },
  },
  vertexShader: `varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`,
  fragmentShader: /* glsl */`
    varying vec2 vUv;
    uniform sampler2D uMap; uniform float uTime, uExpose, uWarn, uOpen; uniform vec4 uWin; uniform vec2 uSize;
    float box(vec2 p, vec2 b, float r) { vec2 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r; }
    void main() {
      vec2 uv = vUv;
      float d = box((uv - 0.5) * uSize, uSize * 0.5, 0.16);
      float alpha = 1.0 - smoothstep(-0.004, 0.004, d);
      if (alpha < 0.001) discard;

      // the window opens from the middle of its row outwards
      vec2 wc = (uWin.xy + uWin.zw) * 0.5;
      vec2 wmin = mix(wc, uWin.xy, vec2(uOpen, smoothstep(0.0, 0.4, uOpen)));
      vec2 wmax = mix(wc, uWin.zw, vec2(uOpen, smoothstep(0.0, 0.4, uOpen)));
      vec2 wp = (uv - (wmin + wmax) * 0.5) * uSize;
      float wd = box(wp, max((wmax - wmin) * 0.5 * uSize, vec2(0.0001)), 0.05);
      float inWin = (1.0 - smoothstep(-0.01, 0.01, wd)) * step(0.001, uOpen);
      float clear = max(uExpose, inWin);
      float frost = 1.0 - clear;

      // fluted glass: vertical ribs that bend the image sideways, then a soft blur
      float rib = sin(uv.x * 170.0);
      vec2 suv = uv + vec2(rib * 0.012 + sin(uv.y * 9.0 + uTime * 0.3) * 0.004, 0.0) * frost;
      vec3 col = vec3(0.0);
      float rad = 0.03 * frost;
      for (int i = 0; i < 16; i++) {
        float a = float(i) * 2.39996, r = sqrt((float(i) + 0.5) / 16.0);
        col += texture2D(uMap, suv + vec2(cos(a), sin(a) * 0.6) * r * rad, 3.5 * frost).rgb;
      }
      col /= 16.0;
      vec3 sharp = texture2D(uMap, uv).rgb;
      col = mix(col, sharp, clear);

      // frost: milky, ribbed, with a slow sheen crossing it
      col = mix(col, col * 0.8 + vec3(0.03, 0.07, 0.055), frost * 0.6);
      col += (rib * 0.5 + 0.5) * 0.03 * frost;
      float sweep = fract(uTime * 0.06) * 2.6 - 0.8;
      col += smoothstep(0.12, 0.0, abs(uv.x * 0.8 + uv.y * 0.6 - sweep)) * 0.07 * frost;

      // exposed: the light turns harsh and a scan line runs down the page
      col = mix(col, col * vec3(1.15, 0.95, 0.8) + vec3(0.05, 0.02, 0.0), uWarn * 0.7);
      float scan = fract(uTime * 0.25);
      col += vec3(1.0, 0.55, 0.2) * smoothstep(0.012, 0.0, abs(uv.y - 1.0 + scan)) * uWarn * 0.6;

      // the window's lit edge
      col += vec3(0.1, 1.0, 0.55) * (1.0 - smoothstep(0.0, 0.012, abs(wd))) * uOpen * 1.4;
      // rim light on the glass edge, brighter at the top
      col += mix(vec3(0.35, 0.55, 0.48), vec3(0.9, 1.0, 0.96), uv.y) * (1.0 - smoothstep(0.0, 0.014, abs(d))) * 0.5;
      gl_FragColor = vec4(col, alpha);
    }`,
}));
scene.add(card);
// a back plate gives the glass some depth, and a glow sits under it
const plate = new THREE.Mesh(new THREE.PlaneGeometry(CW * 1.02, CH * 1.015), new THREE.MeshBasicMaterial({
  map: roundTex("rgba(1,183,99,.22)"), transparent: true, depthWrite: false }));
plate.position.z = -0.06;
card.add(plate);
const glow = new THREE.Mesh(new THREE.PlaneGeometry(CW * 2.4, CH * 1.6), new THREE.MeshBasicMaterial({
  map: radialTex([[0, "rgba(1,183,99,.35)"], [0.5, "rgba(1,120,70,.12)"], [1, "rgba(0,0,0,0)"]]), transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
glow.position.z = -0.5;
card.add(glow);

function roundTex(color) {
  const c = document.createElement("canvas"); c.width = 512; c.height = 712;
  const g = c.getContext("2d"); g.strokeStyle = color; g.lineWidth = 4;
  g.beginPath(); g.roundRect(4, 4, 504, 704, 34); g.stroke();
  return new THREE.CanvasTexture(c);
}
function radialTex(stops) {
  const c = document.createElement("canvas"); c.width = c.height = 256;
  const g = c.getContext("2d"), grd = g.createRadialGradient(128, 128, 0, 128, 128, 128);
  for (const [o, col] of stops) grd.addColorStop(o, col);
  g.fillStyle = grd; g.fillRect(0, 0, 256, 256);
  return new THREE.CanvasTexture(c);
}

// ---------- the seal that lands on the window ----------
const sealCanvas = document.createElement("canvas"); sealCanvas.width = sealCanvas.height = 512;
const sealTex = new THREE.CanvasTexture(sealCanvas); sealTex.colorSpace = THREE.SRGBColorSpace;
function drawSeal() {
  const g = sealCanvas.getContext("2d"), c = 256;
  g.clearRect(0, 0, 512, 512);
  const fill = g.createLinearGradient(0, 0, 512, 512);
  fill.addColorStop(0, "#3ff0a0"); fill.addColorStop(1, "#01874a");
  g.fillStyle = fill; g.beginPath(); g.arc(c, c, 200, 0, Math.PI * 2); g.fill();
  g.strokeStyle = "rgba(255,255,255,.55)"; g.lineWidth = 4; g.beginPath(); g.arc(c, c, 168, 0, Math.PI * 2); g.stroke();
  g.strokeStyle = "#fff"; g.lineWidth = 26; g.lineCap = "round"; g.lineJoin = "round";
  g.beginPath(); g.moveTo(c - 70, c + 4); g.lineTo(c - 18, c + 56); g.lineTo(c + 78, c - 52); g.stroke();
  g.fillStyle = "#fff"; g.font = "600 30px 'General Sans', sans-serif"; g.textAlign = "center";
  const text = "PROVED · ZIP 311 · HALO 2 · ";
  for (let i = 0; i < text.length * 2; i++) {
    const a = (i / (text.length * 2)) * Math.PI * 2 - Math.PI / 2;
    g.save(); g.translate(c + Math.cos(a) * 228, c + Math.sin(a) * 228); g.rotate(a + Math.PI / 2);
    g.fillText(text[i % text.length], 0, 0); g.restore();
  }
  sealTex.needsUpdate = true;
}
const seal = new THREE.Mesh(new THREE.PlaneGeometry(0.95, 0.95), new THREE.MeshBasicMaterial({ map: sealTex, transparent: true, depthWrite: false, toneMapped: false }));
seal.position.z = 0.08;
card.add(seal);

drawLedger(); drawSeal();
Promise.all([document.fonts?.load("500 38px 'General Sans'"), document.fonts?.load("400 26px 'JetBrains Mono'")])
  .then(() => { drawLedger(); drawSeal(); }, () => {});

// ---------- drifting light, for depth ----------
const DUST = 260;
const dpos = new Float32Array(DUST * 3), dseed = new Float32Array(DUST);
for (let i = 0; i < DUST; i++) { dpos.set([(Math.random() - 0.5) * 16, (Math.random() - 0.5) * 10, -2 - Math.random() * 6], i * 3); dseed[i] = Math.random(); }
const dgeo = new THREE.BufferGeometry();
dgeo.setAttribute("position", new THREE.BufferAttribute(dpos, 3));
dgeo.setAttribute("aSeed", new THREE.BufferAttribute(dseed, 1));
const dust = new THREE.Points(dgeo, new THREE.ShaderMaterial({
  transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  uniforms: { uTime: { value: 0 }, uPix: { value: renderer.getPixelRatio() }, uWarn: { value: 0 } },
  vertexShader: `attribute float aSeed; uniform float uTime, uPix; varying float vS;
    void main() { vS = aSeed; vec3 p = position; p.y += mod(uTime * (0.05 + aSeed * 0.08) + aSeed * 10.0, 10.0) - 5.0; p.x += sin(uTime * 0.2 + aSeed * 30.0) * 0.3;
      vec4 mv = modelViewMatrix * vec4(p, 1.0); gl_Position = projectionMatrix * mv; gl_PointSize = (4.0 + aSeed * 18.0) * uPix * (6.0 / -mv.z); }`,
  fragmentShader: `varying float vS; uniform float uWarn;
    void main() { float a = smoothstep(0.5, 0.0, length(gl_PointCoord - 0.5)); vec3 c = mix(vec3(0.3, 0.95, 0.65), vec3(1.0, 0.6, 0.25), uWarn);
      gl_FragColor = vec4(c * a, a * (0.06 + vS * 0.1)); }`,
}));
dust.frustumCulled = false;
scene.add(dust);

// ---------- post ----------
const composer = new EffectComposer(renderer);
composer.addPass(new RenderPass(scene, camera));
const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.5, 0.6, 0.62);
composer.addPass(bloom);
composer.addPass(new OutputPass());

const L = { narrow: false };
function resize() {
  const w = innerWidth, h = innerHeight;
  renderer.setSize(w, h, false);
  composer.setSize(w, h);
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
  L.narrow = w / h < 1.05;
  camera.position.z = L.narrow ? 12.5 : 9;
  sky.material.uniforms.uRes.value.set(w, h);
}
addEventListener("resize", resize);
resize();

// ---------- scroll ----------
const chapters = [...document.querySelectorAll(".chapter")];
const rail = [...document.querySelectorAll(".rail li")];
let target = 0, p = 0;
function measure() {
  const vh = innerHeight;
  target = chapters.reduce((s, el) => {
    const r = el.getBoundingClientRect();
    return s + Math.min(1, Math.max(0, (vh * 0.7 - r.top) / r.height));
  }, 0);
  const last = chapters[chapters.length - 1];
  document.body.classList.toggle("past-story", !!last && last.getBoundingClientRect().bottom < vh * 0.6);
  const on = Math.min(3, Math.round(target));
  rail.forEach((li, i) => li.classList.toggle("on", i === on));
}
addEventListener("scroll", measure, { passive: true });
measure(); p = target;
rail.forEach((li, i) => li.addEventListener("click", () => {
  const el = chapters[i - 1];
  scrollTo({ top: i === 0 ? 0 : el.offsetTop + el.offsetHeight * 0.35, behavior: still ? "auto" : "smooth" });
}));

const mouse = new THREE.Vector2(), sm = new THREE.Vector2();
addEventListener("pointermove", (e) => mouse.set(e.clientX / innerWidth - 0.5, e.clientY / innerHeight - 0.5), { passive: true });
const ss = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;
let lastT = performance.now(), time = 0;

function frame(now) {
  const dt = Math.min(0.25, (now - lastT) / 1000); lastT = now;
  if (!still) time += dt;
  p += (target - p) * (still ? 1 : 1 - Math.exp(-dt * 3.5));
  sm.lerp(mouse, 1 - Math.exp(-dt * 3));

  const expose = ss(1.3, 1.75, p) * (1 - ss(2.15, 2.45, p));
  const open = ss(2.45, 2.85, p);
  const stamp = ss(2.75, 3.0, p);
  const u = card.material.uniforms;
  u.uTime.value = time; u.uExpose.value = expose; u.uWarn.value = expose; u.uOpen.value = open;
  sky.material.uniforms.uTime.value = time; sky.material.uniforms.uWarn.value = expose; sky.material.uniforms.uProof.value = open;
  dust.material.uniforms.uTime.value = time; dust.material.uniforms.uWarn.value = expose;

  // hero: low and centred under the headline; story: to the right of the text (above it on phones)
  const k = ss(0.0, 0.9, p);
  const sx = L.narrow ? 0 : 2.05, sy = L.narrow ? 1.25 : 0;
  card.position.set(lerp(0, sx, k), lerp(L.narrow ? -1.5 : -1.25, sy, k) + Math.sin(time * 0.7) * 0.04, 0);
  const sc = lerp(L.narrow ? 0.9 : 0.7, L.narrow ? 0.95 : 0.92, k) * (1 + expose * 0.04);
  card.scale.setScalar(sc);
  const tilt = lerp(-0.22, 0.0, k);
  card.rotation.set(tilt + sm.y * 0.12, lerp(-0.18, -0.24, k) + sm.x * 0.3 + expose * 0.2 - open * 0.08, lerp(0.04, 0.0, k));

  const w = WIN;
  seal.position.set((w[2] - 0.5) * CW + 0.02, (w[3] - 0.5) * CH + 0.36, 0.08 + (1 - stamp) * 0.6);
  seal.scale.setScalar(lerp(1.6, 0.56, stamp));
  seal.rotation.z = lerp(-0.6, -0.12, stamp);
  seal.material.opacity = stamp;
  seal.visible = stamp > 0.001;

  bloom.strength = 0.45 + expose * 0.35 + stamp * 0.15;
  composer.render();
  if (!document.hidden) requestAnimationFrame(frame);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) { lastT = performance.now(); requestAnimationFrame(frame); } });
requestAnimationFrame(frame);

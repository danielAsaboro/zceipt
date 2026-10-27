// The landing page's 3D story, driven by scroll. Privacy is glass: a whole wallet (salary, rent, a
// clinic, money to Mum, the coffee) sits behind a slab of reeded, frosted glass that refracts it into
// nothing. 0/I: sealed, among other sealed wallets. II: a viewing key shatters the glass and every
// line is exposed. III: the shards fly back, one clear window is left over the single payment being
// proved, and an emerald seal lands on it. Everything else stays sealed.
import * as THREE from "three";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";
import { Delaunay } from "d3-delaunay";

const canvas = document.getElementById("stage");
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
const phone = innerWidth < 760;

let renderer;
try { renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: "high-performance" }); }
catch { canvas.remove(); throw new Error("no WebGL"); }
renderer.setPixelRatio(Math.min(devicePixelRatio, phone ? 1.5 : 2));
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.05;

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(35, 1, 0.1, 100);
camera.position.set(0, 0, 9);
const pmrem = new THREE.PMREMGenerator(renderer);
scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.03).texture;
scene.environmentIntensity = 0.9;

const key = new THREE.DirectionalLight("#e8fff4", 2.2); key.position.set(3, 4, 6); scene.add(key);
const sweep = new THREE.PointLight("#9dffd2", 2.5, 8, 2); scene.add(sweep);

// ---------- backdrop: a deep green aurora that burns amber when the wallet is exposed ----------
const sky = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), new THREE.ShaderMaterial({
  depthWrite: false, depthTest: false,
  uniforms: { uTime: { value: 0 }, uWarn: { value: 0 }, uProof: { value: 0 }, uRes: { value: new THREE.Vector2(1, 1) } },
  vertexShader: `varying vec2 vUv; void main() { vUv = uv; gl_Position = vec4(position.xy, 0.9999, 1.0); }`,
  fragmentShader: /* glsl */`
    varying vec2 vUv; uniform float uTime, uWarn, uProof; uniform vec2 uRes;
    float blob(vec2 p, vec2 c, float r) { return exp(-dot(p - c, p - c) / (r * r)); }
    float hash(vec2 p) { return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }
    void main() {
      float ar = uRes.x / uRes.y, t = uTime * 0.05;
      vec2 p = vUv; p.x *= ar;
      vec3 col = vec3(0.002, 0.005, 0.004);
      vec3 castleton = vec3(0.0, 0.10, 0.045), go = vec3(0.0, 0.32, 0.14), teal = vec3(0.0, 0.08, 0.09), ink = vec3(0.012, 0.014, 0.05);
      vec3 ember = vec3(0.30, 0.08, 0.01), rose = vec3(0.20, 0.02, 0.025);
      col += mix(castleton, ember, uWarn) * blob(p, vec2(ar * (0.78 + 0.08 * sin(t * 3.0)), 0.78 + 0.05 * cos(t * 2.0)), 0.55) * 0.9;
      col += mix(teal, rose, uWarn) * blob(p, vec2(ar * (0.18 + 0.06 * cos(t * 2.5)), 0.28 + 0.06 * sin(t * 3.1)), 0.5) * 0.7;
      col += ink * blob(p, vec2(ar * 0.45, 1.05), 0.6) * 0.8;
      col += go * blob(p, vec2(ar * (0.64 + 0.05 * sin(t * 4.0)), 0.45), 0.32) * (0.15 + 0.5 * uProof) * (1.0 - uWarn);
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
const ledgerTex = new THREE.CanvasTexture(ledger);
ledgerTex.colorSpace = THREE.SRGBColorSpace; ledgerTex.anisotropy = 8;
const ROWS = [
  ["SL", "Salary", "Lagos Labs · October", "+12.50", "Oct 01", "#6aa2ff"],
  ["AH", "Rent", "Ade Homes · flat 3B", "−4.20", "Oct 03", "#c48cff"],
  ["KC", "Kemi's Coffee", "Invoice 42: two coffees", "−0.01", "Oct 14", "#01b763"],
  ["FC", "Fertility clinic", "Consultation, second visit", "−1.35", "Oct 16", "#ff8a80"],
  ["MU", "Mum", "For the hospital bills", "−2.00", "Oct 19", "#ffc35c"],
  ["BX", "Exchange withdrawal", "Binance → shielded", "+20.00", "Oct 21", "#7fd6ff"],
  ["DN", "Donation", "Independent press fund", "−0.50", "Oct 24", "#9be7a9"],
];
let WIN = [0.05, 0.5, 0.95, 0.6]; // the proved row, in uv (x0, y0, x1, y1)
function drawLedger() {
  const g = ledger.getContext("2d"), pad = 76;
  const sans = "'General Sans', ui-sans-serif, sans-serif", mono = "'JetBrains Mono', ui-monospace, monospace";
  const bg = g.createLinearGradient(0, 0, W, H);
  bg.addColorStop(0, "#16251f"); bg.addColorStop(1, "#0a1210");
  g.fillStyle = bg; g.fillRect(0, 0, W, H);
  g.textBaseline = "alphabetic"; g.textAlign = "left";
  g.fillStyle = "rgba(255,255,255,.55)"; g.font = `500 30px ${sans}`; g.fillText("Shielded wallet · Orchard", pad, 120);
  g.fillStyle = "#fff"; g.font = `500 112px ${sans}`; g.fillText("48.2130", pad, 260);
  const bw = g.measureText("48.2130").width;
  g.fillStyle = "rgba(255,255,255,.5)"; g.font = `500 48px ${sans}`; g.fillText("ZEC", pad + bw + 20, 260);
  g.fillStyle = "rgba(255,255,255,.4)"; g.font = `400 26px ${mono}`; g.fillText("u1q7v4…xg9e2kd0lmz3ehn6", pad, 320);
  g.fillStyle = "rgba(255,255,255,.12)"; g.fillRect(pad, 372, W - 2 * pad, 2);
  let y = 400;
  ROWS.forEach(([ini, name, memo, amt, day, c], i) => {
    const h = 132;
    if (i === 2) WIN = [(pad - 30) / W, 1 - (y + h - 2) / H, (W - pad + 30) / W, 1 - (y + 2) / H];
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
  ledgerTex.needsUpdate = true;
  lastOpen = -1;
}

const CW = 2.6, CH = CW * H / W, RADIUS = 0.16, DEPTH = 0.07;
const roundRect = (() => { // the pane outline, counter-clockwise, as a convex polygon
  const pts = [], hw = CW / 2, hh = CH / 2, r = RADIUS;
  for (const [cx, cy, a0] of [[hw - r, -hh + r, -Math.PI / 2], [hw - r, hh - r, 0], [-hw + r, hh - r, Math.PI / 2], [-hw + r, -hh + r, Math.PI]])
    for (let i = 0; i <= 8; i++) { const a = a0 + (i / 8) * Math.PI / 2; pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]); }
  return pts;
})();
const alphaCanvas = document.createElement("canvas"); alphaCanvas.width = 256; alphaCanvas.height = 356;
{ const g = alphaCanvas.getContext("2d"); g.fillStyle = "#000"; g.fillRect(0, 0, 256, 356); g.fillStyle = "#fff"; g.beginPath(); g.roundRect(0, 0, 256, 356, 16); g.fill(); }
const roundAlpha = new THREE.CanvasTexture(alphaCanvas);

const pane = new THREE.Group();
scene.add(pane);
const ledgerMat = new THREE.MeshBasicMaterial({ map: ledgerTex, alphaMap: roundAlpha, alphaTest: 0.5, toneMapped: false });
const ledgerMesh = new THREE.Mesh(new THREE.PlaneGeometry(CW, CH), ledgerMat);
ledgerMesh.position.z = -0.28;
pane.add(ledgerMesh);

// ---------- reeded, frosted glass: ribs in the normal map, frost in the roughness map ----------
const MW = 512, MH = Math.round(512 * H / W), RIBS = 24;
const nCanvas = document.createElement("canvas"); nCanvas.width = MW; nCanvas.height = MH;
const rCanvas = document.createElement("canvas"); rCanvas.width = MW; rCanvas.height = MH;
const eCanvas = document.createElement("canvas"); eCanvas.width = MW; eCanvas.height = MH;
const ribRow = new Uint8ClampedArray(MW * 4);
for (let x = 0; x < MW; x++) {
  const ph = (x / MW) * RIBS * Math.PI * 2, nx = Math.sin(ph) * 0.75, nz = Math.sqrt(1 - nx * nx);
  ribRow.set([(nx * 0.5 + 0.5) * 255, 128, nz * 255, 255], x * 4);
}
const normalTex = new THREE.CanvasTexture(nCanvas), roughTex = new THREE.CanvasTexture(rCanvas), emitTex = new THREE.CanvasTexture(eCanvas);
let lastOpen = -1;
function drawGlassMaps(open) {
  // the window grows from the middle of the proved row outwards
  const [x0, y0, x1, y1] = WIN, cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
  const ox = THREE.MathUtils.smootherstep(open, 0, 1), oy = THREE.MathUtils.smoothstep(open, 0, 0.35);
  const wx0 = (cx + (x0 - cx) * ox) * MW, wx1 = (cx + (x1 - cx) * ox) * MW;
  const wy0 = (1 - (cy + (y1 - cy) * oy)) * MH, wy1 = (1 - (cy + (y0 - cy) * oy)) * MH;
  const has = open > 0.002, rr = Math.min(10, (wy1 - wy0) / 2);
  const ng = nCanvas.getContext("2d"), img = ng.createImageData(MW, MH);
  for (let y = 0; y < MH; y++) img.data.set(ribRow, y * MW * 4);
  ng.putImageData(img, 0, 0);
  const rg = rCanvas.getContext("2d");
  rg.fillStyle = "rgb(0,95,0)"; rg.fillRect(0, 0, MW, MH);
  const eg = eCanvas.getContext("2d");
  eg.fillStyle = "#000"; eg.fillRect(0, 0, MW, MH);
  if (has) {
    ng.fillStyle = "rgb(128,128,255)"; ng.beginPath(); ng.roundRect(wx0, wy0, wx1 - wx0, wy1 - wy0, rr); ng.fill();
    rg.fillStyle = "rgb(0,0,0)"; rg.beginPath(); rg.roundRect(wx0, wy0, wx1 - wx0, wy1 - wy0, rr); rg.fill();
    eg.strokeStyle = "#fff"; eg.lineWidth = 2.5; eg.beginPath(); eg.roundRect(wx0, wy0, wx1 - wx0, wy1 - wy0, rr); eg.stroke();
  }
  normalTex.needsUpdate = roughTex.needsUpdate = emitTex.needsUpdate = true;
  lastOpen = open;
}
drawGlassMaps(0);

const glassMat = new THREE.MeshPhysicalMaterial({
  color: "#f2fff8", metalness: 0, roughness: 1, roughnessMap: roughTex, normalMap: normalTex, normalScale: new THREE.Vector2(0.4, 0.4),
  transmission: 1, thickness: 0.45, ior: 1.5, attenuationColor: "#c9f5dd", attenuationDistance: 3.5,
  clearcoat: 0.6, clearcoatRoughness: 0.08, specularIntensity: 0.8, envMapIntensity: 0.55,
  emissive: "#2bff9a", emissiveMap: emitTex, emissiveIntensity: 2.4,
});

function slabGeometry(poly) {
  const shape = new THREE.Shape(poly.map(([x, y]) => new THREE.Vector2(x, y)));
  const g = new THREE.ExtrudeGeometry(shape, { depth: DEPTH, bevelEnabled: true, bevelThickness: 0.012, bevelSize: 0.008, bevelSegments: 2, curveSegments: 1 });
  g.translate(0, 0, -DEPTH / 2);
  const pos = g.attributes.position, uv = g.attributes.uv;
  for (let i = 0; i < pos.count; i++) uv.setXY(i, pos.getX(i) / CW + 0.5, pos.getY(i) / CH + 0.5);
  g.computeVertexNormals();
  return g;
}
const whole = new THREE.Mesh(slabGeometry(roundRect), glassMat);
pane.add(whole);

// shards: a Voronoi of jittered seeds, each cell clipped to the pane outline
function clip(subject, clipPoly) {
  let out = subject;
  for (let i = 0; i < clipPoly.length; i++) {
    const [ax, ay] = clipPoly[i], [bx, by] = clipPoly[(i + 1) % clipPoly.length];
    const inside = ([x, y]) => (bx - ax) * (y - ay) - (by - ay) * (x - ax) >= 0;
    const cut = ([px, py], [qx, qy]) => {
      const a1 = by - ay, b1 = ax - bx, c1 = a1 * ax + b1 * ay, a2 = qy - py, b2 = px - qx, c2 = a2 * px + b2 * py, det = a1 * b2 - a2 * b1;
      return [(b2 * c1 - b1 * c2) / det, (a1 * c2 - a2 * c1) / det];
    };
    const input = out; out = [];
    for (let j = 0; j < input.length; j++) {
      const cur = input[j], prev = input[(j + input.length - 1) % input.length];
      if (inside(cur)) { if (!inside(prev)) out.push(cut(prev, cur)); out.push(cur); }
      else if (inside(prev)) out.push(cut(prev, cur));
    }
    if (!out.length) break;
  }
  return out;
}
const seeds = [], GX = 6, GY = 8;
let rs = 7; const rnd = () => ((rs = (rs * 16807) % 2147483647) / 2147483647);
for (let i = 0; i < GX; i++) for (let j = 0; j < GY; j++)
  seeds.push([(-0.5 + (i + 0.5 + (rnd() - 0.5) * 0.85) / GX) * CW, (-0.5 + (j + 0.5 + (rnd() - 0.5) * 0.85) / GY) * CH]);
const vor = Delaunay.from(seeds).voronoi([-CW / 2 - 1, -CH / 2 - 1, CW / 2 + 1, CH / 2 + 1]);
const shards = [];
seeds.forEach((s, i) => {
  const cell = vor.cellPolygon(i); if (!cell) return;
  let poly = clip(cell.slice(0, -1), roundRect);
  if (poly.length < 3) return;
  let area = 0; for (let k = 0; k < poly.length; k++) { const [x1, y1] = poly[k], [x2, y2] = poly[(k + 1) % poly.length]; area += x1 * y2 - x2 * y1; }
  if (area < 0) poly = poly.reverse();
  const cx = poly.reduce((a, p) => a + p[0], 0) / poly.length, cy = poly.reduce((a, p) => a + p[1], 0) / poly.length;
  const g = slabGeometry(poly); g.translate(-cx, -cy, 0);
  const m = new THREE.Mesh(g, glassMat);
  m.position.set(cx, cy, 0); m.visible = false;
  const out = new THREE.Vector3(cx, cy, 0).normalize();
  m.userData = { home: new THREE.Vector3(cx, cy, 0), dir: new THREE.Vector3(out.x * (0.3 + rnd() * 0.5) + 0.25, out.y * (0.3 + rnd() * 0.5) + 0.15, 0.9 + rnd() * 1.4),
    spin: new THREE.Vector3((rnd() - 0.5) * 2.6, (rnd() - 0.5) * 2.6, (rnd() - 0.5) * 1.2), delay: Math.hypot(cx, cy) / 3 * 0.25 };
  pane.add(m); shards.push(m);
});

// the viewing key's scan line, running down the exposed wallet
const scan = new THREE.Mesh(new THREE.PlaneGeometry(CW * 0.98, 0.012), new THREE.MeshBasicMaterial({ color: "#ffb054", transparent: true, opacity: 0, blending: THREE.AdditiveBlending, toneMapped: false }));
scan.position.z = -0.2;
pane.add(scan);

// ---------- the emerald seal ----------
const sealCanvas = document.createElement("canvas"); sealCanvas.width = sealCanvas.height = 512;
const sealTex = new THREE.CanvasTexture(sealCanvas); sealTex.colorSpace = THREE.SRGBColorSpace; sealTex.anisotropy = 8;
function drawSeal() {
  const g = sealCanvas.getContext("2d"), c = 256;
  const fill = g.createRadialGradient(180, 160, 20, 256, 256, 280);
  fill.addColorStop(0, "#5dffb4"); fill.addColorStop(0.55, "#01b763"); fill.addColorStop(1, "#005b31");
  g.fillStyle = fill; g.fillRect(0, 0, 512, 512);
  g.strokeStyle = "rgba(255,255,255,.5)"; g.lineWidth = 4; g.beginPath(); g.arc(c, c, 176, 0, Math.PI * 2); g.stroke();
  g.strokeStyle = "#fff"; g.lineWidth = 30; g.lineCap = "round"; g.lineJoin = "round";
  g.beginPath(); g.moveTo(c - 74, c + 4); g.lineTo(c - 20, c + 58); g.lineTo(c + 82, c - 54); g.stroke();
  g.fillStyle = "rgba(255,255,255,.92)"; g.font = "600 30px 'General Sans', sans-serif"; g.textAlign = "center"; g.textBaseline = "middle";
  const text = "PROVED · ZIP 311 · HALO 2 · ";
  for (let i = 0; i < text.length * 2; i++) {
    const a = (i / (text.length * 2)) * Math.PI * 2 - Math.PI / 2;
    g.save(); g.translate(c + Math.cos(a) * 216, c + Math.sin(a) * 216); g.rotate(a + Math.PI / 2); g.fillText(text[i % text.length], 0, 0); g.restore();
  }
  sealTex.needsUpdate = true;
}
const faceMat = new THREE.MeshPhysicalMaterial({ map: sealTex, metalness: 0.35, roughness: 0.28, clearcoat: 1, clearcoatRoughness: 0.05, emissive: "#01b763", emissiveMap: sealTex, emissiveIntensity: 0.08 });
const rimMat = new THREE.MeshPhysicalMaterial({ color: "#0d8f53", metalness: 0.8, roughness: 0.25, clearcoat: 1 });
const seal = new THREE.Mesh(new THREE.CylinderGeometry(0.34, 0.34, 0.07, 72), [rimMat, faceMat, faceMat]);
seal.geometry.rotateX(Math.PI / 2);
seal.geometry.rotateZ(Math.PI / 2);
pane.add(seal);

// ---------- other people's wallets, sealed, out in the dark ----------
const crowd = [];
const crowdNormal = new THREE.CanvasTexture((() => { const c = document.createElement("canvas"); c.width = MW; c.height = 4; const g = c.getContext("2d"), img = g.createImageData(MW, 4); for (let y = 0; y < 4; y++) img.data.set(ribRow, y * MW * 4); g.putImageData(img, 0, 0); return c; })());
const crowdMat = glassMat.clone();
Object.assign(crowdMat, { roughnessMap: null, roughness: 0.37, normalMap: crowdNormal, emissiveMap: null, emissiveIntensity: 0 });
[[-7.2, 2.4, -9, 0.5], [7.6, 2.8, -10, 0.55], [-6.4, -3.2, -8, 0.45], [6.8, -3.0, -9, 0.5]]
  .forEach(([x, y, z, s], i) => {
    const g = new THREE.Group();
    const l = new THREE.Mesh(ledgerMesh.geometry, ledgerMat); l.position.z = -0.28; g.add(l);
    g.add(new THREE.Mesh(whole.geometry, crowdMat));
    g.position.set(x, y, z); g.scale.setScalar(s);
    g.userData = { base: new THREE.Vector3(x, y, z), ph: i * 1.7 };
    scene.add(g); crowd.push(g);
  });

drawLedger(); drawSeal();
Promise.all([document.fonts?.load("500 38px 'General Sans'"), document.fonts?.load("400 26px 'JetBrains Mono'")])
  .then(() => { drawLedger(); drawSeal(); }, () => {});

// ---------- post ----------
const composer = new EffectComposer(renderer);
composer.addPass(new RenderPass(scene, camera));
const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.55, 0.55, 0.72);
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
const WHITE = new THREE.Color("#ffffff"), WARM = new THREE.Color("#ffd2a6");
let lastT = performance.now(), time = 0;

function frame(now) {
  const dt = Math.min(0.25, (now - lastT) / 1000); lastT = now;
  if (!still) time += dt;
  p += (target - p) * (still ? 1 : 1 - Math.exp(-dt * 3.5));
  sm.lerp(mouse, 1 - Math.exp(-dt * 3));

  const burst = ss(1.25, 1.65, p) * (1 - ss(2.15, 2.5, p)); // shards out, then back
  const expose = burst;
  const open = ss(2.5, 2.85, p);
  const stamp = ss(2.7, 2.92, p);

  sky.material.uniforms.uTime.value = time;
  sky.material.uniforms.uWarn.value = expose;
  sky.material.uniforms.uProof.value = open;

  // hero: low and centred under the headline; story: right of the text (above it on phones)
  const k = ss(0.0, 0.9, p);
  const sx = L.narrow ? 0 : 2.05, sy = L.narrow ? 1.25 : 0;
  pane.position.set(lerp(0, sx, k), lerp(L.narrow ? -1.5 : -1.3, sy, k) + Math.sin(time * 0.7) * 0.04, 0);
  pane.scale.setScalar(lerp(L.narrow ? 0.9 : 0.72, L.narrow ? 0.95 : 0.92, k));
  pane.rotation.set(lerp(-0.2, 0, k) + sm.y * 0.12, lerp(-0.22, -0.26, k) + sm.x * 0.3 + Math.sin(time * 0.3) * 0.04 + expose * 0.12, lerp(0.03, 0, k));

  // the glass: whole when sealed, shards while the viewing key is in play
  const broken = burst > 0.001;
  whole.visible = !broken;
  for (const s of shards) {
    s.visible = broken;
    if (!broken) continue;
    const t = Math.max(0, Math.min(1, (burst - s.userData.delay) / (1 - s.userData.delay)));
    const e = t * t * (3 - 2 * t);
    s.position.copy(s.userData.home).addScaledVector(s.userData.dir, e * 1.1);
    s.position.y -= e * e * 0.5;
    s.rotation.set(s.userData.spin.x * e, s.userData.spin.y * e, s.userData.spin.z * e);
  }
  ledgerMat.color.copy(WHITE).lerp(WARM, expose * 0.6);
  scan.material.opacity = expose * 0.9;
  scan.position.y = CH / 2 - ((time * 0.35) % 1) * CH;

  if (Math.abs(open - lastOpen) > 0.004 || (open === 0 && lastOpen !== 0) || (open === 1 && lastOpen !== 1)) drawGlassMaps(open);

  // the seal drops and spins onto the right end of the proved row
  const [x0, y0, x1, y1] = WIN;
  seal.visible = stamp > 0.001;
  seal.position.set((x1 - 0.5) * CW - 0.02, (y1 - 0.5) * CH + 0.38 + (1 - stamp) * 0.4, DEPTH / 2 + 0.06 + (1 - stamp) * 2.2);
  seal.rotation.set(0, (1 - ss(0, 0.8, stamp)) * Math.PI * 3, -0.15);
  seal.scale.setScalar(Math.max(0.01, stamp));

  // a soft light drifts across the ribs
  sweep.position.set(pane.position.x + Math.sin(time * 0.5) * 2.4, pane.position.y + Math.cos(time * 0.37) * 1.6, 2.2);
  for (const g of crowd) {
    const b = g.userData.base;
    g.position.set(b.x * (1 + k * 0.6) + Math.sin(time * 0.15 + g.userData.ph) * 0.3, b.y * (1 + k * 0.4) + Math.cos(time * 0.2 + g.userData.ph) * 0.25, b.z - k * 6);
    g.visible = k < 0.98;
    g.rotation.set(Math.sin(time * 0.2 + g.userData.ph) * 0.2, Math.cos(time * 0.17 + g.userData.ph) * 0.4 - 0.2, 0);
  }
  camera.position.x = sm.x * 0.4; camera.position.y = -sm.y * 0.25;
  camera.lookAt(0, 0, 0);

  bloom.strength = 0.5 + expose * 0.3;
  composer.render();
  if (!document.hidden) requestAnimationFrame(frame);
}
// lets a test harness skip the scroll easing
window.zceiptStage = { settle: () => { measure(); p = target; } };
document.addEventListener("visibilitychange", () => { if (!document.hidden) { lastT = performance.now(); requestAnimationFrame(frame); } });
requestAnimationFrame(frame);

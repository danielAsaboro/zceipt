// The landing page's 3D story, driven by scroll: a payment drops into the shielded pool (01),
// a viewing key floods the whole pool with light (02), then one Zceipt receipt crystallizes out of
// that single payment while everything else goes dark (03).
import * as THREE from "three";
import { RoundedBoxGeometry } from "three/addons/geometries/RoundedBoxGeometry.js";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";

const canvas = document.getElementById("stage");
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
const small = () => innerWidth < 760;

let renderer;
try { renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: "high-performance" }); }
catch { canvas.remove(); throw new Error("no WebGL"); }
renderer.setPixelRatio(Math.min(devicePixelRatio, small() ? 1.5 : 2));
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.05;

const scene = new THREE.Scene();
scene.background = new THREE.Color("#070a0f");
scene.fog = new THREE.FogExp2("#070a0f", 0.045);
const pmrem = new THREE.PMREMGenerator(renderer);
scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
const GREEN = new THREE.Color("#01b763");

// ---------- the receipt slab ----------
const slab = new THREE.Group();
const glass = new THREE.MeshPhysicalMaterial({
  color: "#cfe9dc", metalness: 0, roughness: 0.12, transmission: 1, thickness: 0.6, ior: 1.45,
  clearcoat: 1, clearcoatRoughness: 0.08, iridescence: 0.35, iridescenceIOR: 1.3,
  transparent: true, opacity: 0, envMapIntensity: 1.4,
});
const body = new THREE.Mesh(new RoundedBoxGeometry(2.3, 3.2, 0.09, 6, 0.14), glass);
slab.add(body);
const edge = new THREE.Mesh(new RoundedBoxGeometry(2.34, 3.24, 0.05, 6, 0.15),
  new THREE.MeshBasicMaterial({ color: GREEN, transparent: true, opacity: 0, side: THREE.BackSide }));
slab.add(edge);

const tex = document.createElement("canvas");
tex.width = 1024; tex.height = 1424;
const texture = new THREE.CanvasTexture(tex);
texture.colorSpace = THREE.SRGBColorSpace;
texture.anisotropy = 8;
const face = new THREE.Mesh(new THREE.PlaneGeometry(2.3, 3.2),
  new THREE.MeshBasicMaterial({ map: texture, transparent: true, opacity: 0, depthWrite: false, toneMapped: false }));
face.position.z = 0.05;
slab.add(face);
scene.add(slab);

function drawReceipt() {
  const g = tex.getContext("2d");
  const W = tex.width, H = tex.height, pad = 84;
  g.clearRect(0, 0, W, H);
  const rr = (x, y, w, h, r) => { g.beginPath(); g.roundRect(x, y, w, h, r); };
  g.fillStyle = "rgba(8,14,12,.38)"; rr(0, 0, W, H, 60); g.fill();
  // header
  g.fillStyle = "#01b763"; rr(pad, pad, 76, 76, 20); g.fill();
  g.fillStyle = "#fff"; g.font = "600 64px 'General Sans', sans-serif"; g.textBaseline = "middle";
  g.fillText("Zceipt", pad + 100, pad + 40);
  g.font = "500 30px 'JetBrains Mono', monospace"; g.fillStyle = "#01b763";
  const pill = "VERIFIED"; const pw = g.measureText(pill).width + 52;
  g.strokeStyle = "#01b763"; g.lineWidth = 4; rr(W - pad - pw, pad + 12, pw, 56, 28); g.stroke();
  g.fillText(pill, W - pad - pw + 26, pad + 41);
  g.strokeStyle = "rgba(255,255,255,.14)"; g.lineWidth = 2; g.setLineDash([10, 10]);
  g.beginPath(); g.moveTo(pad, 236); g.lineTo(W - pad, 236); g.stroke(); g.setLineDash([]);
  // rows
  const rows = [["PAID TO", "utest1a7f2…xgnv956"], ["AMOUNT", "0.01 ZEC"], ["MEMO", "Order #42 at Kemi's Coffee"], ["FROM", null], ["BALANCE", null], ["HISTORY", null]];
  let y = 320;
  for (const [k, v] of rows) {
    g.font = "500 28px 'JetBrains Mono', monospace"; g.fillStyle = "rgba(255,255,255,.45)";
    g.fillText(k, pad, y);
    if (v) {
      g.fillStyle = "#fff";
      g.font = k === "AMOUNT" ? "600 76px 'General Sans', sans-serif" : "500 40px 'General Sans', sans-serif";
      g.fillText(v, pad, y + (k === "AMOUNT" ? 74 : 60));
      y += k === "AMOUNT" ? 172 : 150;
    } else {
      g.fillStyle = "rgba(255,255,255,.13)"; rr(pad, y + 34, (W - 2 * pad) * (k === "FROM" ? .62 : k === "BALANCE" ? .38 : .5), 40, 10); g.fill();
      g.font = "500 26px 'JetBrains Mono', monospace"; g.fillStyle = "rgba(255,255,255,.35)";
      g.fillText("hidden", W - pad - g.measureText("hidden").width, y);
      y += 128;
    }
  }
  // seal
  y = H - 170;
  g.strokeStyle = "rgba(255,255,255,.14)"; g.beginPath(); g.moveTo(pad, y - 50); g.lineTo(W - pad, y - 50); g.stroke();
  g.fillStyle = "#01b763"; g.beginPath(); g.arc(pad + 32, y + 30, 32, 0, Math.PI * 2); g.fill();
  g.strokeStyle = "#fff"; g.lineWidth = 7; g.beginPath(); g.moveTo(pad + 17, y + 31); g.lineTo(pad + 28, y + 42); g.lineTo(pad + 48, y + 20); g.stroke();
  g.fillStyle = "rgba(255,255,255,.75)"; g.font = "500 30px 'General Sans', sans-serif";
  g.fillText("Halo 2 proof: the payer's key spent this", pad + 88, y + 14);
  g.fillStyle = "rgba(255,255,255,.4)"; g.font = "500 26px 'JetBrains Mono', monospace";
  g.fillText("testnet · ZIP 311", pad + 88, y + 56);
  texture.needsUpdate = true;
}
drawReceipt();
document.fonts?.ready.then(drawReceipt);
Promise.all([document.fonts?.load("600 64px 'General Sans'"), document.fonts?.load("500 28px 'JetBrains Mono'")]).then(drawReceipt, () => {});

// ---------- the shielded pool ----------
const N = small() ? 4500 : 10000;
const aPool = new Float32Array(N * 3), aTarget = new Float32Array(N * 3), aSeed = new Float32Array(N);
for (let i = 0; i < N; i++) {
  const r = 0.5 + Math.pow(Math.random(), 0.7) * 6.2;
  aPool[i * 3] = r;
  aPool[i * 3 + 1] = Math.random() * Math.PI * 2;
  aPool[i * 3 + 2] = (Math.random() - 0.5) * (0.12 + r * 0.05);
  aSeed[i] = Math.random();
  // receipt-bound particles sit on the slab: a third on the rim, the rest on the face
  const u = Math.random(), v = Math.random();
  let tx = (u - 0.5) * 2.3, ty = (v - 0.5) * 3.2;
  if (Math.random() < 0.35) { if (Math.random() < 0.5) tx = Math.sign(tx) * 1.15; else ty = Math.sign(ty) * 1.6; }
  aTarget[i * 3] = tx; aTarget[i * 3 + 1] = ty; aTarget[i * 3 + 2] = (Math.random() - 0.5) * 0.08;
}
const geo = new THREE.BufferGeometry();
geo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(N * 3), 3));
geo.setAttribute("aPool", new THREE.BufferAttribute(aPool, 3));
geo.setAttribute("aTarget", new THREE.BufferAttribute(aTarget, 3));
geo.setAttribute("aSeed", new THREE.BufferAttribute(aSeed, 1));
const uniforms = {
  uTime: { value: 0 }, uReveal: { value: 0 }, uConverge: { value: 0 }, uSlab: { value: 0 },
  uPix: { value: renderer.getPixelRatio() }, uCenter: { value: new THREE.Vector3() },
  uSlabMat: { value: new THREE.Matrix4() }, uScan: { value: 0 },
};
const points = new THREE.Points(geo, new THREE.ShaderMaterial({
  uniforms, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  vertexShader: /* glsl */`
    attribute vec3 aPool; attribute vec3 aTarget; attribute float aSeed;
    uniform float uTime, uReveal, uConverge, uSlab, uPix, uScan; uniform vec3 uCenter; uniform mat4 uSlabMat;
    varying vec3 vColor; varying float vAlpha;
    void main() {
      float r = aPool.x;
      float th = aPool.y + uTime * (0.32 / (0.5 + r * 0.45));
      vec3 pool = uCenter + vec3(cos(th) * r, aPool.z + sin(uTime * 0.7 + aSeed * 40.0) * 0.05, sin(th) * r);
      float pick = step(aSeed, 0.45);
      float k = smoothstep(0.0, 1.0, clamp(uConverge * 1.6 - aSeed * 1.2, 0.0, 1.0)) * pick;
      vec3 target = (uSlabMat * vec4(aTarget, 1.0)).xyz;
      vec3 swirl = vec3(sin(aSeed * 90.0 + uTime), cos(aSeed * 70.0 + uTime), 0.0) * 0.25 * k * (1.0 - k) * 4.0;
      vec3 p = mix(pool, target, k) + swirl;
      // the viewing key's light front sweeps outward through the pool
      float lit = uReveal * smoothstep(uScan - 0.6, uScan, r) * 0.6 + uReveal * (1.0 - step(uScan, r)) ;
      lit = clamp(lit, 0.0, 1.0);
      vec3 mist = vec3(0.42, 0.56, 0.72);
      vec3 amber = vec3(1.0, 0.62, 0.20);
      vec3 green = vec3(0.0, 0.85, 0.45);
      vColor = mix(mix(mist, amber, lit), green, k);
      float dark = uConverge * (1.0 - pick);
      vAlpha = (0.7 + 0.3 * lit) * (1.0 - 0.85 * dark) * (1.0 - 0.75 * uSlab * pick);
      vec4 mv = modelViewMatrix * vec4(p, 1.0);
      gl_Position = projectionMatrix * mv;
      gl_PointSize = (2.2 + aSeed * 2.8) * (1.0 + 0.9 * lit + 0.4 * k) * uPix * (9.0 / -mv.z);
    }`,
  fragmentShader: /* glsl */`
    varying vec3 vColor; varying float vAlpha;
    void main() {
      float d = length(gl_PointCoord - 0.5);
      float a = smoothstep(0.5, 0.0, d);
      gl_FragColor = vec4(vColor * a, a * vAlpha);
    }`,
}));
points.frustumCulled = false;
scene.add(points);

// the viewing key's sweep ring
const ring = new THREE.Mesh(new THREE.RingGeometry(0.97, 1, 128),
  new THREE.MeshBasicMaterial({ color: "#f2a93b", transparent: true, opacity: 0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
ring.rotation.x = -Math.PI / 2;
scene.add(ring);

// the one payment
const orb = new THREE.Mesh(new THREE.SphereGeometry(0.075, 24, 24), new THREE.MeshBasicMaterial({ color: GREEN, toneMapped: false }));
const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTexture(), color: GREEN, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
halo.scale.setScalar(0.9);
orb.add(halo);
scene.add(orb);
const TRAIL = 40;
const trailGeo = new THREE.BufferGeometry();
trailGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(TRAIL * 3), 3));
const trail = new THREE.Line(trailGeo, new THREE.LineBasicMaterial({ color: GREEN, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending }));
trail.frustumCulled = false;
scene.add(trail);
let trailInit = false;

function glowTexture() {
  const c = document.createElement("canvas"); c.width = c.height = 128;
  const g = c.getContext("2d");
  const grd = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grd.addColorStop(0, "rgba(255,255,255,1)"); grd.addColorStop(0.25, "rgba(255,255,255,.35)"); grd.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grd; g.fillRect(0, 0, 128, 128);
  return new THREE.CanvasTexture(c);
}

// ---------- post ----------
const composer = new EffectComposer(renderer);
composer.addPass(new RenderPass(scene, camera));
const bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.75, 0.55, 0.12);
composer.addPass(bloom);
composer.addPass(new OutputPass());

// ---------- layout ----------
const L = { center: new THREE.Vector3(), slabPos: new THREE.Vector3(), camFar: 0 };
function resize() {
  const w = innerWidth, h = innerHeight;
  renderer.setSize(w, h, false);
  composer.setSize(w, h);
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
  const narrow = w / h < 1.05;
  L.center.set(narrow ? 0 : 3.2, -1.1, -0.5);
  L.slabPos.set(narrow ? 0 : 2.9, 0.45, 1.1);
  L.camFar = narrow ? 5 : 0;
  L.lookShift = narrow ? 0 : 1.9;
  uniforms.uCenter.value.copy(L.center);
}
addEventListener("resize", resize);
resize();

// ---------- scroll ----------
const chapters = [...document.querySelectorAll(".chapter")];
let target = 0, p = 0;
function measure() {
  const vh = innerHeight;
  target = chapters.reduce((s, el) => {
    const r = el.getBoundingClientRect();
    return s + Math.min(1, Math.max(0, (vh * 0.75 - r.top) / r.height));
  }, 0);
}
addEventListener("scroll", measure, { passive: true });
measure(); p = target;

const mouse = new THREE.Vector2();
addEventListener("pointermove", (e) => mouse.set(e.clientX / innerWidth - 0.5, e.clientY / innerHeight - 0.5), { passive: true });

const ss = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;
const v3 = (x, y, z) => new THREE.Vector3(x, y, z);
const camPos = new THREE.Vector3(), look = new THREE.Vector3(), smoothMouse = new THREE.Vector2();
const orbPos = new THREE.Vector3();
let last = performance.now(), time = 0;

function frame(now) {
  const dt = Math.min(0.05, (now - last) / 1000); last = now;
  if (!still) time += dt;
  p += (target - p) * (still ? 1 : 1 - Math.exp(-dt * 4));
  smoothMouse.lerp(mouse, 1 - Math.exp(-dt * 3));

  const reveal = ss(1.25, 1.7, p) * (1 - ss(2.25, 2.6, p));
  const scan = ss(1.25, 1.9, p) * 7.5;
  const converge = ss(2.3, 2.95, p);
  const slabIn = ss(2.65, 3.0, p);
  uniforms.uTime.value = time;
  uniforms.uReveal.value = reveal;
  uniforms.uScan.value = scan;
  uniforms.uConverge.value = converge;
  uniforms.uSlab.value = slabIn;

  // slab
  slab.position.copy(L.slabPos).add(v3(0, Math.sin(time * 0.8) * 0.06, 0));
  slab.rotation.set(-0.06 + smoothMouse.y * 0.12, -0.42 + Math.sin(time * 0.3) * 0.05 + smoothMouse.x * 0.25, 0.02);
  slab.scale.setScalar(lerp(0.82, 1, slabIn));
  slab.updateMatrixWorld();
  uniforms.uSlabMat.value.copy(slab.matrixWorld);
  glass.opacity = slabIn * 0.9;
  edge.material.opacity = slabIn * 0.55;
  face.material.opacity = ss(2.8, 3.0, p);
  slab.visible = slabIn > 0.001;

  ring.position.copy(L.center).setY(L.center.y + 0.01);
  ring.scale.setScalar(Math.max(0.01, scan));
  ring.material.opacity = reveal * 0.55;

  // the payment: arrives over the pool, sinks into it, then rises into the receipt
  const hover = v3(L.center.x - 0.2 + Math.cos(time * 0.9) * 0.9, 1.0 + Math.sin(time * 1.3) * 0.25, 1.6 + Math.sin(time * 0.9) * 0.6);
  const sunk = v3(L.center.x + Math.cos(time * 0.2 + 1) * 2.4, L.center.y, L.center.z + Math.sin(time * 0.2 + 1) * 2.4);
  const sink = ss(0.15, 0.85, p), rise = ss(2.3, 2.85, p);
  orbPos.copy(hover).lerp(sunk, sink).lerp(slab.position, rise);
  orb.position.copy(orbPos);
  const orbVis = (1 - ss(0.7, 1.0, p)) + ss(2.25, 2.45, p) * (1 - ss(2.8, 3.0, p));
  orb.visible = orbVis > 0.01;
  orb.scale.setScalar(Math.max(0.01, orbVis));
  const tp = trailGeo.attributes.position.array;
  if (!trailInit) { for (let i = 0; i < TRAIL; i++) tp.set([orbPos.x, orbPos.y, orbPos.z], i * 3); trailInit = true; }
  tp.copyWithin(3, 0, (TRAIL - 1) * 3); tp.set([orbPos.x, orbPos.y, orbPos.z], 0);
  trailGeo.attributes.position.needsUpdate = true;
  trail.material.opacity = 0.45 * Math.min(1, orbVis);

  // camera: wide on the pool, overhead for the viewing key, close on the receipt
  const c0 = v3(0, 2.4, 10.5 + L.camFar), c2 = v3(0.6, 6.8, 12 + L.camFar), c3 = v3(0.4, 1.3, 7.6 + L.camFar);
  camPos.copy(c0).lerp(c2, ss(0.6, 1.8, p)).lerp(c3, ss(2.2, 3.0, p));
  camPos.x += smoothMouse.x * 0.6; camPos.y -= smoothMouse.y * 0.35;
  look.copy(L.center).add(v3(-1.6, 0.9, 0)).lerp(v3(L.center.x - 0.6, L.center.y, L.center.z), ss(0.6, 1.8, p)).lerp(v3(L.slabPos.x - L.lookShift, L.slabPos.y, L.slabPos.z), ss(2.2, 3.0, p));
  camera.position.copy(camPos);
  camera.lookAt(look);

  bloom.strength = 0.65 + reveal * 0.5;
  composer.render();
  if (!document.hidden) requestAnimationFrame(frame);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) { last = performance.now(); requestAnimationFrame(frame); } });
requestAnimationFrame(frame);

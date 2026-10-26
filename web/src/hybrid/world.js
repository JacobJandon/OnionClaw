// OnionClaw Hybrid — Peel × Planet.
// Planet's toon onion world (stations, engine moons, free exploration) staged as
// Peel's scroll journey (wireframe construct, HUD, data constellation, the skin
// peeling open to the swarm core, particles becoming the mascot).
// Stock three.js materials and passes only.
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { ShaderPass } from "three/examples/jsm/postprocessing/ShaderPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { RGBShiftShader } from "three/examples/jsm/shaders/RGBShiftShader.js";
import { FEATURES, ENGINES, PROVIDERS, COLLECTORS } from "../shared.js";

const INK = 0x2a1838;

/* ── toon helpers ──────────────────────────────── */
const gradient = (() => {
  const t = new THREE.DataTexture(new Uint8Array([70, 150, 255]), 3, 1, THREE.RedFormat);
  t.minFilter = t.magFilter = THREE.NearestFilter;
  t.generateMipmaps = false;
  t.needsUpdate = true;
  return t;
})();
const toon = (color, extra = {}) => new THREE.MeshToonMaterial({ color, gradientMap: gradient, ...extra });
const inkMat = new THREE.MeshBasicMaterial({ color: INK, side: THREE.BackSide });
function outlined(geo, mat, thick = 0.06) {
  const g = new THREE.Group();
  const m = new THREE.Mesh(geo, mat);
  const o = new THREE.Mesh(geo, inkMat);
  o.scale.setScalar(1 + thick);
  g.add(o, m);
  g.userData.body = m;
  return g;
}

// onion silhouette (squat bulb + short neck), y from bottom to top
function profile() {
  const pts = [];
  for (let i = 0; i <= 40; i++) {
    const a = (i / 40) * Math.PI * 0.82;
    pts.push(new THREE.Vector2(Math.max(1.0 * Math.sin(a), 1e-3), -0.08 - 0.8 * Math.cos(a)));
  }
  const r0 = pts[pts.length - 1].x, y0 = pts[pts.length - 1].y;
  for (let i = 1; i <= 14; i++) { const u = i / 14; pts.push(new THREE.Vector2(r0 * Math.pow(1 - u, 2) + 0.02, y0 + u * 0.55)); }
  return pts;
}
const PROFILE = profile();
const radiusAt = (y) => {
  for (let i = 1; i < PROFILE.length; i++) {
    const a = PROFILE[i - 1], b = PROFILE[i];
    if (y >= a.y && y <= b.y) return a.x + (b.x - a.x) * ((y - a.y) / (b.y - a.y || 1));
  }
  return 0;
};

function onionSkin() {
  const c = document.createElement("canvas");
  c.width = 1024; c.height = 256;
  const g = c.getContext("2d");
  g.fillStyle = "#e8dfee"; g.fillRect(0, 0, 512, 256);
  g.fillStyle = "#8e44ad"; g.fillRect(512, 0, 512, 256);
  for (let i = 0; i < 24; i++) {
    const x = (i + 0.5) * (1024 / 24);
    g.fillStyle = x < 512 ? "#dccbe6" : "#6d2c88";
    g.fillRect(x - 2, 0, 4, 256);
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

/* ── station models (built "up" along +Y) ──────── */
function station(f) {
  const g = new THREE.Group();
  const col = new THREE.Color(f.color);
  const dark = col.clone().multiplyScalar(0.62);
  const base = outlined(new THREE.CylinderGeometry(0.17, 0.21, 0.08, 18), toon(dark));
  base.position.y = 0.04;
  g.add(base);
  const anim = [];
  const add = (geo, mat, pos, rot) => { const o = outlined(geo, mat); if (pos) o.position.set(...pos); if (rot) o.rotation.set(...rot); g.add(o); return o; };

  if (f.id === "search") {                          // radar dish that sweeps the sky
    add(new THREE.CylinderGeometry(0.025, 0.035, 0.32, 10), toon(0xf6eef8), [0, 0.24, 0]);
    const dish = new THREE.Group();
    dish.position.y = 0.42;
    const d = outlined(new THREE.SphereGeometry(0.16, 20, 10, 0, Math.PI * 2, 0, Math.PI / 2.4), toon(col, { side: THREE.DoubleSide }));
    d.rotation.x = Math.PI * 0.75;
    dish.add(d);
    g.add(dish);
    anim.push((t) => { dish.rotation.y = t * 0.9; });
  } else if (f.id === "fetch") {                    // tower with blinking window
    add(new THREE.CylinderGeometry(0.06, 0.09, 0.5, 12), toon(0xf6eef8), [0, 0.33, 0]);
    add(new THREE.ConeGeometry(0.1, 0.18, 12), toon(col), [0, 0.67, 0]);
    const lamp = new THREE.Mesh(new THREE.SphereGeometry(0.03, 10, 8), new THREE.MeshBasicMaterial({ color: 0xfff3a8 }));
    lamp.position.set(0, 0.42, 0.075);
    g.add(lamp);
    anim.push((t) => { lamp.visible = Math.sin(t * 3) > -0.3; });
  } else if (f.id === "rotate") {                   // windmill: a fresh circuit, round and round
    add(new THREE.CylinderGeometry(0.07, 0.12, 0.42, 10), toon(0xf6eef8), [0, 0.29, 0]);
    add(new THREE.ConeGeometry(0.1, 0.12, 10), toon(col), [0, 0.56, 0]);
    const hub = new THREE.Group();
    hub.position.set(0, 0.44, 0.12);
    for (let k = 0; k < 4; k++) {
      const b = outlined(new THREE.BoxGeometry(0.035, 0.3, 0.012), toon(col));
      b.position.y = 0.15;
      const arm = new THREE.Group();
      arm.rotation.z = k * Math.PI / 2;
      arm.add(b);
      hub.add(arm);
    }
    g.add(hub);
    anim.push((t) => { hub.rotation.z = t * 1.6; });
  } else if (f.id === "investigate") {              // lighthouse with a sweeping beam
    for (let k = 0; k < 4; k++) add(new THREE.CylinderGeometry(0.075 - k * 0.006, 0.085 - k * 0.006, 0.12, 14), toon(k % 2 ? col : 0xf6eef8), [0, 0.14 + k * 0.12, 0]);
    add(new THREE.CylinderGeometry(0.06, 0.06, 0.07, 10), toon(0xfff3a8, { emissive: 0x806a20 }), [0, 0.63, 0]);
    add(new THREE.ConeGeometry(0.08, 0.08, 10), toon(col), [0, 0.7, 0]);
    const beamPivot = new THREE.Group();
    beamPivot.position.y = 0.63;
    const beam = new THREE.Mesh(new THREE.ConeGeometry(0.12, 0.9, 16, 1, true),
      new THREE.MeshBasicMaterial({ color: 0xfff3a8, transparent: true, opacity: 0.28, depthWrite: false, side: THREE.DoubleSide }));
    beam.rotation.z = Math.PI / 2;
    beam.position.x = 0.45;
    beamPivot.add(beam);
    g.add(beamPivot);
    anim.push((t) => { beamPivot.rotation.y = t * 1.2; });
  } else if (f.id === "monitor") {                  // five domes, one per collector, blinking in turn
    const lights = [];
    for (let k = 0; k < 5; k++) {
      const a = k / 5 * Math.PI * 2;
      add(new THREE.SphereGeometry(0.065, 14, 8, 0, Math.PI * 2, 0, Math.PI / 2), toon(0xf6eef8), [Math.cos(a) * 0.13, 0.08, Math.sin(a) * 0.13]);
      const l = new THREE.Mesh(new THREE.SphereGeometry(0.02, 8, 6), new THREE.MeshBasicMaterial({ color: col }));
      l.position.set(Math.cos(a) * 0.13, 0.16, Math.sin(a) * 0.13);
      g.add(l);
      lights.push(l);
    }
    anim.push((t) => lights.forEach((l, k) => { l.visible = ((t * 2 + k) % 5) < 2.4; }));
  } else if (f.id === "export") {                   // antenna sending pulses
    add(new THREE.CylinderGeometry(0.018, 0.03, 0.55, 8), toon(0xf6eef8), [0, 0.33, 0]);
    add(new THREE.SphereGeometry(0.05, 12, 10), toon(col), [0, 0.62, 0]);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.1, 0.008, 6, 40), new THREE.MeshBasicMaterial({ color: INK, transparent: true }));
    ring.position.y = 0.62;
    ring.rotation.x = Math.PI / 2;
    g.add(ring);
    anim.push((t) => { const p = (t * 0.7) % 1; ring.scale.setScalar(1 + p * 3); ring.material.opacity = 1 - p; });
  }
  return { group: g, anim };
}


/* ── hybrid world ──────────────────────────────── */
const VOID = 0x07050b;
const PETALS = 8;
const S = 1.55;                          // planet scale
const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;
const SPOTS = [[0.35, 0.1], [1.4, -0.35], [2.45, 0.22], [3.45, -0.22], [4.45, 0.15], [5.45, -0.42]];

function dotTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grd = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grd.addColorStop(0, "rgba(255,255,255,1)");
  grd.addColorStop(0.35, "rgba(255,255,255,.85)");
  grd.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grd;
  g.fillRect(0, 0, 64, 64);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

export class World {
  constructor(canvas, { coarse = false } = {}) {
    this.coarse = coarse;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: !coarse, powerPreference: "high-performance" });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio || 1, coarse ? 1.25 : 1.75));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(VOID);
    this.scene.fog = new THREE.FogExp2(VOID, 0.022);
    this.camera = new THREE.PerspectiveCamera(40, 1, 0.05, 120);
    this.camera.position.set(0, 2, 14);
    this.state = { intro: 0, c: 0, velocity: 0 };
    this.explore = 0;            // 0 = story, 1 = free exploration
    this.exploring = false;
    this.anchors = [];
    this.introNumbers = [];
    this.vw = 1; this.vh = 1; this.viewShift = 0;
  }

  async load(progress = () => {}) {
    const img = await new Promise((res, rej) => new THREE.ImageLoader().load("/assets/mascot-sample.png", res, undefined, rej));
    progress(0.3);
    this.scene.add(new THREE.HemisphereLight(0xfff1e6, 0x2a1838, 1.25));
    const sun = new THREE.DirectionalLight(0xffffff, 1.7);
    sun.position.set(4, 6, 5);
    const rim = new THREE.DirectionalLight(0x8ea2ff, 1.6);       // cool rim so the planet reads against the void
    rim.position.set(-6, 2, -5);
    this.scene.add(sun, rim);

    this.buildPlanet();
    this.buildCore();
    this.buildMoons();
    this.buildNetwork();
    this.buildParticles(img);
    this.buildPost();
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    Object.assign(this.controls, { enabled: false, enablePan: false, enableDamping: true, dampingFactor: 0.07, rotateSpeed: 0.6, minDistance: 6, maxDistance: 13 });
    progress(0.7);
    this.resize();
    this.renderer.compile(this.scene, this.camera);       // compile up front, Igloo's lesson
    progress(0.95);
    this.composer.render();
    progress(1);
  }

  /* the planet: Planet's toon onion, split into petals that can peel like Peel's shells */
  buildPlanet() {
    this.planet = new THREE.Group();
    this.scene.add(this.planet);
    const skin = onionSkin();
    this.petals = [];
    for (let k = 0; k < PETALS; k++) {
      const len = (Math.PI * 2) / PETALS, phi0 = k * len;
      const geo = new THREE.LatheGeometry(PROFILE, 10, phi0, len * 0.992);
      // lathe UVs restart per petal; remap so the white/purple skin wraps the whole bulb
      const uv = geo.attributes.uv;
      for (let i = 0; i < uv.count; i++) uv.setX(i, (phi0 + uv.getX(i) * len * 0.992) / (Math.PI * 2));
      const mat = toon(0xffffff, { map: skin, transparent: true, opacity: 0 });
      const mesh = new THREE.Mesh(geo, mat);
      const line = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ color: INK, side: THREE.BackSide, transparent: true, opacity: 0 }));
      line.scale.setScalar(1.022);
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo, 18),
        new THREE.LineBasicMaterial({ color: 0xc9a6ff, transparent: true, opacity: 0, depthWrite: false }));
      edges.geometry.setDrawRange(0, 0);
      const skinGroup = new THREE.Group();
      skinGroup.scale.setScalar(S);
      skinGroup.add(line, mesh, edges);
      const wrap = new THREE.Group();
      wrap.add(skinGroup);
      this.planet.add(wrap);
      const mid = phi0 + len / 2;
      this.petals.push({ wrap, mesh, line, edges, edgeCount: edges.geometry.attributes.position.count,
        dir: new THREE.Vector3(Math.sin(mid), 0.15, Math.cos(mid)).normalize(), seed: Math.random() * 6, spin: (Math.random() - 0.5) * 2 });
    }

    // sprout
    this.sprout = new THREE.Group();
    this.sprout.position.y = PROFILE[PROFILE.length - 1].y * S - 0.05;
    [[-0.35, 0.1], [0.05, -0.2], [0.42, 0.25]].forEach(([tz, tx], k) => {
      const leaf = outlined(new THREE.ConeGeometry(0.07, 0.95 - k * 0.12, 8), toon(0x6fbf4a));
      leaf.position.y = 0.42 - k * 0.04;
      const pivot = new THREE.Group();
      pivot.rotation.set(tx, k * 2.1, tz);
      pivot.add(leaf);
      this.sprout.add(pivot);
    });
    this.planet.add(this.sprout);

    // stations ride on the petal they stand on, so they fly away with it
    this.stations = FEATURES.map((f, i) => {
      const [phi, y] = SPOTS[i];
      const r = radiusAt(y) * S;
      const pos = new THREE.Vector3(Math.sin(phi) * r, y * S, Math.cos(phi) * r);
      const normal = new THREE.Vector3(pos.x, (y + 0.08) * S * 0.9, pos.z).normalize();
      const { group, anim } = station(f);
      group.position.copy(pos).addScaledVector(normal, -0.02);
      group.scale.setScalar(1.45);
      group.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), normal);
      group.traverse((o) => { o.userData.station = i; });
      const petal = this.petals[Math.floor(((phi % (Math.PI * 2)) / (Math.PI * 2)) * PETALS) % PETALS];
      petal.wrap.add(group);
      const view = normal.clone().add(new THREE.Vector3(0, 0.32, 0)).normalize();
      return { f, group, anim, normal, view, petal, top: pos.clone().addScaledVector(normal, 1.25) };
    });

    // intro: real vertex indices, labelled while the wireframe draws
    for (let i = 0; i < 24; i++) {
      const p = this.petals[(Math.random() * PETALS) | 0];
      const vi = (Math.random() * p.mesh.geometry.attributes.position.count) | 0;
      this.introNumbers.push({ p, vi, label: String(vi).padStart(2, "0") });
    }
  }

  /* Peel's core: the monitoring swarm */
  buildCore() {
    this.core = new THREE.Group();
    this.scene.add(this.core);
    this.core.add(new THREE.Mesh(new THREE.IcosahedronGeometry(0.16, 1),
      new THREE.MeshStandardMaterial({ color: 0xcfe9e6, emissive: 0x9feee7, emissiveIntensity: 1.1, flatShading: true })));
    this.coreWire = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.3, 1)),
      new THREE.LineBasicMaterial({ color: 0x9feee7, transparent: true, opacity: 0.6 }));
    this.core.add(this.coreWire);
    this.core.add(new THREE.PointLight(0xd9fffb, 3, 4, 2));
    this.collectors = COLLECTORS.map((c, i) => {
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.035, 16, 12),
        new THREE.MeshStandardMaterial({ color: 0x34d6c9, emissive: 0x34d6c9, emissiveIntensity: 1.4 }));
      this.core.add(m);
      return { m, name: c.id, r: 0.6 + i * 0.07, speed: 0.35 + i * 0.07, tilt: new THREE.Euler(0.4 + i * 0.5, i * 1.1, 0.2 * i), phase: i * 1.3 };
    });
    const lg = new THREE.BufferGeometry();
    lg.setAttribute("position", new THREE.BufferAttribute(new Float32Array(COLLECTORS.length * 6), 3));
    this.links = new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0x34d6c9, transparent: true, opacity: 0.4 }));
    this.core.add(this.links);
    this.core.scale.setScalar(0.001);
  }

  /* Planet's moons: one per search engine */
  buildMoons() {
    this.moons = ENGINES.map((name, i) => {
      const m = outlined(new THREE.SphereGeometry(0.05 + (i % 3) * 0.013, 14, 10),
        toon(new THREE.Color().setHSL(0.75 + (i % 5) * 0.04, 0.45, 0.72)), 0.12);
      this.scene.add(m);
      return { name, m, r: 2.75 + (i % 6) * 0.2, speed: 0.1 + (i % 4) * 0.03, phase: i * 0.37 * Math.PI, tilt: new THREE.Euler((i % 7) * 0.3 - 0.9, i * 0.9, 0) };
    });
  }

  /* Peel's far relay network */
  buildNetwork() {
    const n = this.coarse ? 70 : 130, pts = [];
    for (let i = 0; i < n; i++) { const v = new THREE.Vector3().randomDirection().multiplyScalar(16 + Math.random() * 7); v.y *= 0.55; pts.push(v); }
    const seg = [];
    pts.forEach((a, i) => pts.map((b, j) => [a.distanceToSquared(b), j]).sort((x, y) => x[0] - y[0]).slice(1, 3)
      .forEach(([, j]) => { if (j > i) seg.push(a.x, a.y, a.z, pts[j].x, pts[j].y, pts[j].z); }));
    const lg = new THREE.BufferGeometry();
    lg.setAttribute("position", new THREE.Float32BufferAttribute(seg, 3));
    this.network = new THREE.Group();
    this.network.add(new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0x8c7aa6, transparent: true, opacity: 0.22, fog: false })));
    this.network.add(new THREE.Points(new THREE.BufferGeometry().setFromPoints(pts), new THREE.PointsMaterial({ color: 0xcfc4e0, size: 0.1, transparent: true, opacity: 0.7, fog: false })));
    this.scene.add(this.network);
  }

  /* Peel's dust that becomes the mascot */
  buildParticles(img) {
    const N = this.coarse ? 2600 : 4200;
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const g = c.getContext("2d", { willReadFrequently: true });
    g.drawImage(img, 0, 0);
    const data = g.getImageData(0, 0, c.width, c.height).data, solid = [];
    for (let y = 0; y < c.height; y++) for (let x = 0; x < c.width; x++) {
      const i = (y * c.width + x) * 4;
      if (data[i + 3] > 150) solid.push([x / c.width, y / c.height, data[i] / 255, data[i + 1] / 255, data[i + 2] / 255]);
    }
    const ambient = new Float32Array(N * 3), target = new Float32Array(N * 3), cA = new Float32Array(N * 3), cT = new Float32Array(N * 3), delay = new Float32Array(N);
    const col = new THREE.Color();
    for (let i = 0; i < N; i++) {
      const v = new THREE.Vector3().randomDirection().multiplyScalar(3.4 + Math.pow(Math.random(), 0.8) * 4);
      ambient.set([v.x, v.y * 0.7, v.z], i * 3);
      const s = solid[(Math.random() * solid.length) | 0];
      target.set([(s[0] - 0.5) * 1.75, (0.5 - s[1]) * 1.75, (Math.random() - 0.5) * 0.06], i * 3);
      col.setRGB(s[2], s[3], s[4], THREE.SRGBColorSpace);
      cT.set([col.r, col.g, col.b], i * 3);
      col.set(0xd7cde6).multiplyScalar(0.5 + Math.random() * 0.4);
      cA.set([col.r, col.g, col.b], i * 3);
      delay[i] = Math.random() * 0.45;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(ambient.slice(), 3));
    geo.setAttribute("color", new THREE.BufferAttribute(cA.slice(), 3));
    this.particles = new THREE.Points(geo, new THREE.PointsMaterial({ size: this.coarse ? 0.034 : 0.028, map: dotTexture(), vertexColors: true, transparent: true, opacity: 0.7, depthWrite: false }));
    this.particles.renderOrder = 20;
    this.scene.add(this.particles);
    this.pData = { N, ambient, target, cA, cT, delay, offset: new THREE.Vector3(), scale: 1 };
  }

  buildPost() {
    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));
    this.bloom = new UnrealBloomPass(new THREE.Vector2(256, 256), 0.5, 0.35, 0.96);
    this.composer.addPass(this.bloom);
    this.rgb = new ShaderPass(RGBShiftShader);
    this.rgb.uniforms.amount.value = 0;
    this.composer.addPass(this.rgb);
    this.composer.addPass(new OutputPass());
  }

  resize() {
    const w = innerWidth, h = innerHeight;
    this.vw = w; this.vh = h;
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.fov = w < h ? 58 : 40;
    this.camera.updateProjectionMatrix();
    this.viewShift = w > h * 1.15 ? 0.16 : 0;
    if (this.composer) {
      this.composer.setPixelRatio(this.renderer.getPixelRatio());
      this.composer.setSize(w, h);
      this.bloom.setSize(w * (this.coarse ? 0.4 : 0.6), h * (this.coarse ? 0.4 : 0.6));
    }
    if (this.pData) { this.pData.offset.set(w > h ? -0.62 : 0, w > h ? 0.02 : 1.08, 0); this.pData.scale = w > h ? 1 : 0.58; }
  }

  /* camera path: a stop per chapter; station chapters face that station */
  storyCamera(c) {
    const st = this.stations;
    const KEYS = [
      [0.0, new THREE.Vector3(0.2, 0.3, 1), 11.5],
      [0.5, new THREE.Vector3(0.2, 0.3, 1), 9.6],
      [1.5, st[0].view, 7.3], [2.5, st[1].view, 7.0], [3.5, st[2].view, 7.0], [4.5, st[3].view, 7.0],
      [5.5, st[4].view, 2.7],
      [6.5, st[4].view.clone().applyAxisAngle(new THREE.Vector3(0, 1, 0), 1.2), 2.5],
      [7.35, new THREE.Vector3(0, 0, 1), 3.6],
      [8.0, new THREE.Vector3(0, 0, 1), 3.4],
    ];
    let i = 0;
    while (i < KEYS.length - 2 && c > KEYS[i + 1][0]) i++;
    const [c0, d0, r0] = KEYS[i], [c1, d1, r1] = KEYS[i + 1];
    const t = smooth(c0, c1, c);
    const q0 = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), d0.clone().normalize());
    const q1 = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), d1.clone().normalize());
    q0.slerp(q1, t);
    return new THREE.Vector3(0, 0, 1).applyQuaternion(q0).multiplyScalar(lerp(r0, r1, t));
  }

  enterExplore() {
    this.exploring = true;
    this.fly = { t0: performance.now(), from: this.camera.position.clone(), to: new THREE.Vector3(0.35, 0.3, 1).normalize().multiplyScalar(innerWidth < innerHeight ? 10.5 : 8.4) };
  }
  exitExplore() {
    this.exploring = false;
    this.controls.enabled = false;
    this.fly = null;
    this.blend = { t0: performance.now(), from: this.camera.position.clone() };
  }
  /* explore mode: swing the camera round to face a station */
  focusStation(i) {
    const s = this.stations[i];
    const dist = Math.max(innerWidth < innerHeight ? 9.6 : 7.6, Math.min(12, this.camera.position.length()));
    this.fly = { t0: performance.now(), from: this.camera.position.clone(), to: s.view.clone().multiplyScalar(dist) };
  }
  pickStation(ndc) {
    const ray = new THREE.Raycaster();
    ray.setFromCamera(ndc, this.camera);
    const hit = ray.intersectObjects(this.stations.map((s) => s.group), true)[0];
    return hit ? hit.object.userData.station ?? -1 : -1;
  }
  /* screen position of each station's pin; hidden when on the far side */
  stationScreens() {
    const v = new THREE.Vector3(), camDir = this.camera.position.clone().normalize();
    return this.stations.map((s) => {
      v.copy(s.top).applyMatrix4(s.petal.wrap.matrixWorld);
      const facing = s.group.getWorldPosition(new THREE.Vector3()).normalize().dot(camDir);
      v.project(this.camera);
      return { x: (v.x * 0.5 + 0.5) * this.vw, y: (-v.y * 0.5 + 0.5) * this.vh, visible: facing > 0.12 };
    });
  }

  update(time, dt) {
    const { intro, velocity } = this.state;
    const c = this.state.c;
    this.explore += ((this.exploring ? 1 : 0) - this.explore) * Math.min(1, dt * 2.5);
    const story = 1 - this.explore;

    // camera: scripted by scroll in the story, orbit controls while exploring
    const now = performance.now();
    if (this.fly) {
      const p = smooth(0, 1, (now - this.fly.t0) / 1300);
      const q0 = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), this.fly.from.clone().normalize());
      const q1 = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), this.fly.to.clone().normalize());
      q0.slerp(q1, p);
      this.camera.position.set(0, 0, 1).applyQuaternion(q0).multiplyScalar(lerp(this.fly.from.length(), this.fly.to.length(), p));
      this.camera.lookAt(0, 0, 0);
      if (p >= 1) { this.fly = null; this.controls.enabled = this.exploring; this.controls.update(); }
    } else if (this.exploring) {
      this.controls.update();
    } else {
      const target = this.storyCamera(c);
      target.y += (1 - intro) * 0.8;
      target.multiplyScalar(1 + (1 - intro) * 0.25);
      if (this.blend) {
        const p = smooth(0, 1, (now - this.blend.t0) / 1200);
        target.lerpVectors(this.blend.from, target, p);
        if (p >= 1) this.blend = null;
      }
      this.camera.position.copy(target);
      this.camera.position.x += Math.sin(time * 0.21) * 0.05;
      this.camera.lookAt(0, 0, 0);
    }
    const shift = this.viewShift * (1 - smooth(6.75, 7.25, c)) * story;
    // phones exploring with a card open: lift the planet into the space above the card
    const wantLift = this.exploring && this.cardOpen && this.vw < this.vh ? 0.24 : 0;
    this.lift = (this.lift || 0) + (wantLift - (this.lift || 0)) * Math.min(1, dt * 6);
    if (shift > 0.001 || this.lift > 0.002) this.camera.setViewOffset(this.vw, this.vh, -this.vw * shift, this.vh * this.lift, this.vw, this.vh);
    else this.camera.clearViewOffset();

    // planet: wireframe construct → toon fill → breathe → peel open at the core chapter
    const build = smooth(0, 0.62, intro), fill = smooth(0.45, 1, intro);
    const peel = smooth(4.78, 5.3, c) * story;
    this.petals.forEach((p, k) => {
      const breathe = (0.012 + 0.014 * Math.sin(time * 0.9 + p.seed)) * (1 - peel);
      p.wrap.position.copy(p.dir).multiplyScalar(breathe + peel * (2.4 + (k % 3) * 0.6));
      p.wrap.rotation.set(peel * p.spin * 0.5, peel * p.spin, 0);
      const alive = 1 - peel;
      p.mesh.material.opacity = fill * alive;
      p.line.material.opacity = fill * alive;
      p.mesh.material.depthWrite = fill > 0.98 && alive > 0.98;
      p.edges.material.opacity = (1 - 0.8 * fill) * build * alive;
      p.edges.geometry.setDrawRange(0, Math.floor(p.edgeCount * build));
      p.wrap.visible = alive > 0.003;
    });
    this.sprout.position.y = PROFILE[PROFILE.length - 1].y * S - 0.05 + peel * 2.5;
    this.sprout.scale.setScalar(Math.max(0.001, fill * (1 - peel)));
    this.sprout.children.forEach((pv, k) => { pv.rotation.x += Math.sin(time * 1.3 + k) * 0.0008; });
    this.stations.forEach((s) => { s.anim.forEach((fn) => fn(time)); s.group.scale.setScalar(1.45 * Math.max(0.001, fill)); });

    // core
    const coreOn = smooth(4.85, 5.4, c) * (1 - smooth(6.8, 7.2, c)) * story;
    this.core.scale.setScalar(Math.max(0.001, coreOn) * (1 + Math.sin(time * 2.2) * 0.02));
    this.core.visible = coreOn > 0.01;
    this.core.rotation.y += dt * 0.4;
    this.coreWire.rotation.x += dt * 0.25;
    const lp = this.links.geometry.attributes.position, tmp = new THREE.Vector3();
    this.collectors.forEach((col, k) => {
      const a = time * col.speed + col.phase;
      tmp.set(Math.cos(a) * col.r, 0, Math.sin(a) * col.r).applyEuler(col.tilt);
      col.m.position.copy(tmp);
      lp.setXYZ(k * 2, 0, 0, 0);
      lp.setXYZ(k * 2 + 1, tmp.x, tmp.y, tmp.z);
    });
    lp.needsUpdate = true;

    // moons orbit the whole time; they step aside for the mascot
    const moonsAway = smooth(6.8, 7.3, c) * story;
    this.moons.forEach((mo) => {
      const a = time * mo.speed + mo.phase;
      mo.m.position.set(Math.cos(a) * mo.r, 0, Math.sin(a) * mo.r).applyEuler(mo.tilt).multiplyScalar(1 + moonsAway * 1.8);
      mo.m.scale.setScalar(Math.max(0.001, fill));
    });
    this.network.rotation.y += dt * 0.012;

    // dust → mascot at the finale
    const m = smooth(7.05, 7.75, c) * story;
    const P = this.pData, pos = this.particles.geometry.attributes.position, colr = this.particles.geometry.attributes.color;
    const rot = time * 0.03, cs = Math.cos(rot), sn = Math.sin(rot);
    for (let n = 0; n < P.N; n++) {
      const j = n * 3;
      const k = Math.min(1, Math.max(0, (m - P.delay[n]) / 0.55)), e = k * k * (3 - 2 * k);
      const ax = P.ambient[j] * cs - P.ambient[j + 2] * sn, az = P.ambient[j] * sn + P.ambient[j + 2] * cs;
      const ay = P.ambient[j + 1] + Math.sin(time * 0.4 + n) * 0.05;
      pos.array[j] = lerp(ax, P.target[j] * P.scale + P.offset.x, e);
      pos.array[j + 1] = lerp(ay, P.target[j + 1] * P.scale + P.offset.y, e);
      pos.array[j + 2] = lerp(az, P.target[j + 2] * P.scale + P.offset.z, e);
      colr.array[j] = lerp(P.cA[j], P.cT[j], e);
      colr.array[j + 1] = lerp(P.cA[j + 1], P.cT[j + 1], e);
      colr.array[j + 2] = lerp(P.cA[j + 2], P.cT[j + 2], e);
    }
    pos.needsUpdate = colr.needsUpdate = true;
    this.particles.material.opacity = 0.3 + 0.65 * Math.max(intro * 0.6, m);

    // chromatic aberration: scroll speed, the peel, and the intro
    const peeling = Math.sin(Math.PI * Math.min(1, peel));
    this.rgb.uniforms.amount.value = Math.min(0.006, Math.abs(velocity) * 0.00009 * story + peeling * 0.003 + (1 - intro) * 0.004);
    this.rgb.uniforms.angle.value = time * 0.4;

    this.scene.updateMatrixWorld();
    this.collectAnchors(c, build, story);
    this.composer.render();
  }

  /* constellation labels: real data around whatever the camera is looking at */
  collectAnchors(c, build, story) {
    const A = this.anchors;
    A.length = 0;
    if (story < 0.5) return;
    const win = (a, b) => smooth(a, a + 0.3, c) * (1 - smooth(b - 0.3, b, c));
    const around = (si, names, layer, vis, r = 0.85) => {
      if (vis < 0.02) return;
      const s = this.stations[si];
      const centre = s.top.clone().applyMatrix4(s.petal.wrap.matrixWorld);
      const n = s.group.getWorldPosition(new THREE.Vector3()).normalize();
      const t1 = new THREE.Vector3(0, 1, 0).cross(n).normalize(), t2 = n.clone().cross(t1).normalize();
      names.forEach((label, k) => {
        const a = (k / names.length) * Math.PI * 2;
        A.push({ pos: centre.clone().addScaledVector(t1, Math.cos(a) * r).addScaledVector(t2, Math.sin(a) * r * 0.75), label, layer, alpha: vis });
      });
    };
    const searchVis = win(0.9, 2.1);
    if (searchVis > 0.02) this.moons.forEach((mo) => A.push({ pos: mo.m.position.clone(), label: mo.name, layer: 0, alpha: searchVis }));
    around(1, ["fetch.py", "clean text", "links", "entities", "any .onion", "clearnet too"], 1, win(1.9, 3.1));
    around(2, ["renew.py", "NEWNYM", "new circuit", "new exit relay"], 4, win(2.9, 4.1), 0.7);
    around(3, PROVIDERS, 2, win(3.9, 4.95), 1.0);
    const coreVis = win(4.95, 6.95);
    if (coreVis > 0.02) this.collectors.forEach((col) => A.push({ pos: col.m.getWorldPosition(new THREE.Vector3()), label: col.name, layer: 3, alpha: coreVis }));
    const sigVis = win(5.95, 6.95);
    if (sigVis > 0.02) ["STIX 2.1", "shared wallet", "shared host", "alias", "HMAC-signed", "exactly once", "71 tests"].forEach((label, k) => {
      const a = (k / 7) * Math.PI * 2 + 0.4;
      A.push({ pos: new THREE.Vector3(Math.cos(a) * 1.05, Math.sin(a * 2) * 0.3, Math.sin(a) * 1.05), label, layer: 4, alpha: sigVis });
    });
    const introVis = build * (1 - smooth(0.7, 1, this.state.intro));
    if (introVis > 0.02) this.introNumbers.forEach((n) => {
      const v = new THREE.Vector3().fromBufferAttribute(n.p.mesh.geometry.attributes.position, n.vi).applyMatrix4(n.p.mesh.matrixWorld);
      A.push({ pos: v, label: n.label, layer: -1, alpha: introVis });
    });
  }
}

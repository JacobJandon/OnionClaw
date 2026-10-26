// OnionClaw — the 3D world.
//
//  * An onion of three glass shells (the three Tor encryption layers). Each shell is
//    built from 8 lathe "petals" so it can breathe like Igloo's ice blocks and peel
//    away petal by petal as the camera flies inward.
//  * A glowing core with five orbiting collectors (the monitoring swarm).
//  * A sparse relay network in the far background (the Tor network).
//  * One particle cloud that drifts as dust, then morphs into the mascot,
//    sampled from the real logo PNG (positions and colours).
//  * Post: bloom + chromatic aberration (three's built-in passes).
import * as THREE from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { ShaderPass } from "three/examples/jsm/postprocessing/ShaderPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { RGBShiftShader } from "three/examples/jsm/shaders/RGBShiftShader.js";

const VOID = 0x07050b;
export const LAYERS = [
  { name: "GUARD", tint: 0xec6b84, scale: 1.0 },
  { name: "MIDDLE", tint: 0xb98fe0, scale: 0.72 },
  { name: "EXIT", tint: 0x34d6c9, scale: 0.47 },
];
const PETALS = 8;

const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;

// onion silhouette: a squat bulb (half-ellipse) that flows into a tapered neck
function onionProfile(seg = 52) {
  const pts = [];
  const bulb = Math.round(seg * 0.68), A = Math.PI * 0.8, RX = 1.05, RY = 0.82, CY = -0.08;
  for (let i = 0; i <= bulb; i++) {
    const a = (i / bulb) * A;
    pts.push(new THREE.Vector2(Math.max(RX * Math.sin(a), 1e-4), CY - RY * Math.cos(a)));
  }
  const r0 = RX * Math.sin(A), y0 = CY - RY * Math.cos(A);
  for (let i = 1; i <= seg - bulb; i++) {
    const u = i / (seg - bulb);
    pts.push(new THREE.Vector2(r0 * Math.pow(1 - u, 2.2) + 0.025 * (1 - u * 0.6), y0 + u * 0.88));
  }
  return pts;
}
const PROFILE = onionProfile();
// radius of the profile at height y (for placing anchors on a shell)
function radiusAt(y) {
  for (let i = 1; i < PROFILE.length; i++) {
    const a = PROFILE[i - 1], b = PROFILE[i];
    if ((y >= a.y && y <= b.y) || (y <= a.y && y >= b.y)) return lerp(a.x, b.x, (y - a.y) / (b.y - a.y || 1));
  }
  return 0;
}

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
    this.canvas = canvas;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: !coarse, powerPreference: "high-performance" });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, coarse ? 1.25 : 1.75));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.05;

    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(VOID);
    this.scene.fog = new THREE.FogExp2(VOID, 0.055);

    this.camera = new THREE.PerspectiveCamera(40, 1, 0.01, 80);
    this.camera.position.set(0, 0.6, 9);
    this.look = new THREE.Vector3();

    this.state = { intro: 0, breathe: 1, c: 0, velocity: 0 };
    this.viewShift = 0; this.vw = 1; this.vh = 1;
    this.anchors = [];      // filled per frame: { pos: Vector3, label, layer, alpha }
    this.introNumbers = []; // outer-shell vertices labelled during the intro
  }

  async load(progress = () => {}) {
    const mgr = new THREE.LoadingManager();
    const img = await new Promise((res, rej) => new THREE.ImageLoader(mgr).load("/assets/mascot-sample.png", res, undefined, rej));
    progress(0.35);

    const pmrem = new THREE.PMREMGenerator(this.renderer);
    this.scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
    pmrem.dispose();
    progress(0.55);

    this.buildOnion();
    this.buildCore();
    this.buildNetwork();
    this.buildParticles(img);
    this.buildPost();
    progress(0.75);

    // compile every program up front so the first scroll never stutters (Igloo lesson)
    this.resize();
    this.renderer.compile(this.scene, this.camera);
    progress(0.95);
    this.composer.render();
    progress(1);
  }

  /* ── onion ─────────────────────────────────────── */
  buildOnion() {
    this.onion = new THREE.Group();
    this.scene.add(this.onion);
    this.shells = LAYERS.map((L, li) => {
      const shell = new THREE.Group();
      shell.scale.setScalar(L.scale);
      shell.rotation.y = li * 0.31;
      this.onion.add(shell);
      const tint = new THREE.Color(L.tint);
      const glassColor = tint.clone().lerp(new THREE.Color(0xffffff), 0.3);
      const petals = [];
      for (let k = 0; k < PETALS; k++) {
        const phiLen = (Math.PI * 2 / PETALS) * 0.955;
        const phi0 = k * Math.PI * 2 / PETALS;
        const geo = new THREE.LatheGeometry(PROFILE, 7, phi0, phiLen);
        const mat = new THREE.MeshPhysicalMaterial({
          color: glassColor, emissive: tint, emissiveIntensity: 0.02,
          roughness: 0.07, metalness: 0, clearcoat: 1, clearcoatRoughness: 0.08,
          iridescence: 0.75, iridescenceIOR: 1.28, envMapIntensity: 1.7,
          transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.renderOrder = 10 - li;                 // inner shells draw first
        const edges = new THREE.LineSegments(
          new THREE.EdgesGeometry(geo, 20),
          new THREE.LineBasicMaterial({ color: tint.clone().multiplyScalar(1.6), transparent: true, opacity: 0, depthWrite: false })
        );
        edges.renderOrder = 11 - li;
        edges.geometry.setDrawRange(0, 0);
        mesh.add(edges);
        const mid = phi0 + phiLen / 2;
        const dir = new THREE.Vector3(Math.sin(mid), 0.12, Math.cos(mid)).normalize();
        const seed = Math.random() * Math.PI * 2;
        shell.add(mesh);
        petals.push({ mesh, edges, dir, seed, spin: (Math.random() - 0.5) * 2.4, edgeCount: edges.geometry.attributes.position.count });
      }
      return { group: shell, petals, layer: L, peel: 0 };
    });

    // intro labels: a scatter of real vertex indices on the outer shell
    for (let i = 0; i < 26; i++) {
      const petal = this.shells[0].petals[(Math.random() * PETALS) | 0];
      const p = petal.mesh.geometry.attributes.position;
      const vi = (Math.random() * p.count) | 0;
      this.introNumbers.push({ petal, vi, label: String(vi).padStart(2, "0") });
    }
  }

  /* ── core + swarm collectors ───────────────────── */
  buildCore() {
    this.core = new THREE.Group();
    this.scene.add(this.core);
    const coreMesh = new THREE.Mesh(
      new THREE.IcosahedronGeometry(0.1, 1),
      new THREE.MeshStandardMaterial({ color: 0xcfe9e6, emissive: 0x9feee7, emissiveIntensity: 0.9, flatShading: true, roughness: 0.35 })
    );
    this.core.add(coreMesh);
    this.coreWire = new THREE.LineSegments(
      new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.19, 1)),
      new THREE.LineBasicMaterial({ color: 0x9feee7, transparent: true, opacity: 0.55 })
    );
    this.core.add(this.coreWire);
    this.coreLight = new THREE.PointLight(0xd9fffb, 1.5, 3, 2);
    this.core.add(this.coreLight);

    const names = ["leaksites", "groupinfra", "kev", "wallets", "onionsites"];
    this.collectors = names.map((name, i) => {
      const m = new THREE.Mesh(
        new THREE.SphereGeometry(0.016, 16, 12),
        new THREE.MeshStandardMaterial({ color: 0x34d6c9, emissive: 0x34d6c9, emissiveIntensity: 1.25 })
      );
      this.core.add(m);
      return {
        mesh: m, name,
        radius: 0.34 + i * 0.035,
        speed: 0.35 + i * 0.07,
        tilt: new THREE.Euler(0.4 + i * 0.5, i * 1.1, 0.2 * i),
        phase: i * 1.3,
      };
    });
    const linkGeo = new THREE.BufferGeometry();
    linkGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(names.length * 2 * 3), 3));
    this.links = new THREE.LineSegments(linkGeo, new THREE.LineBasicMaterial({ color: 0x34d6c9, transparent: true, opacity: 0.4 }));
    this.core.add(this.links);
  }

  /* ── far relay network ─────────────────────────── */
  buildNetwork() {
    const n = this.coarse ? 70 : 130, pts = [];
    for (let i = 0; i < n; i++) {
      const v = new THREE.Vector3().randomDirection().multiplyScalar(13 + Math.random() * 6);
      v.y *= 0.55;
      pts.push(v);
    }
    const seg = [];
    pts.forEach((a, i) => {
      const near = pts.map((b, j) => [a.distanceToSquared(b), j]).sort((x, y) => x[0] - y[0]).slice(1, 3);
      near.forEach(([, j]) => { if (j > i) seg.push(a.x, a.y, a.z, pts[j].x, pts[j].y, pts[j].z); });
    });
    const lg = new THREE.BufferGeometry();
    lg.setAttribute("position", new THREE.Float32BufferAttribute(seg, 3));
    this.network = new THREE.Group();
    this.network.add(new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0x8c7aa6, transparent: true, opacity: 0.22, fog: false })));
    const pg = new THREE.BufferGeometry().setFromPoints(pts);
    this.network.add(new THREE.Points(pg, new THREE.PointsMaterial({ color: 0xcfc4e0, size: 0.09, transparent: true, opacity: 0.7, fog: false })));
    this.scene.add(this.network);
  }

  /* ── dust → mascot particles ───────────────────── */
  buildParticles(img) {
    const N = this.coarse ? 2600 : 4200;
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const g = c.getContext("2d", { willReadFrequently: true });
    g.drawImage(img, 0, 0);
    const data = g.getImageData(0, 0, c.width, c.height).data;
    const solid = [];
    for (let y = 0; y < c.height; y++) for (let x = 0; x < c.width; x++) {
      const i = (y * c.width + x) * 4;
      if (data[i + 3] > 150) solid.push([x / c.width, y / c.height, data[i] / 255, data[i + 1] / 255, data[i + 2] / 255]);
    }

    const ambient = new Float32Array(N * 3), target = new Float32Array(N * 3);
    const cA = new Float32Array(N * 3), cT = new Float32Array(N * 3), delay = new Float32Array(N);
    const col = new THREE.Color();
    for (let i = 0; i < N; i++) {
      const v = new THREE.Vector3().randomDirection().multiplyScalar(2.3 + Math.pow(Math.random(), 0.8) * 3.4);
      ambient.set([v.x, v.y * 0.7, v.z], i * 3);
      const s = solid[(Math.random() * solid.length) | 0];
      target.set([(s[0] - 0.5) * 1.75 + (Math.random() - 0.5) * 0.008, (0.5 - s[1]) * 1.75, (Math.random() - 0.5) * 0.06], i * 3);
      col.setRGB(s[2], s[3], s[4], THREE.SRGBColorSpace);
      cT.set([col.r, col.g, col.b], i * 3);
      col.set(0xd7cde6).multiplyScalar(0.55 + Math.random() * 0.45);
      cA.set([col.r, col.g, col.b], i * 3);
      delay[i] = Math.random() * 0.45;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(ambient.slice(), 3));
    geo.setAttribute("color", new THREE.BufferAttribute(cA.slice(), 3));
    this.particles = new THREE.Points(geo, new THREE.PointsMaterial({
      size: this.coarse ? 0.034 : 0.028, map: dotTexture(), vertexColors: true,
      transparent: true, opacity: 0.9, depthWrite: false, sizeAttenuation: true,
    }));
    this.particles.renderOrder = 20;
    this.scene.add(this.particles);
    this.pData = { N, ambient, target, cA, cT, delay, offset: new THREE.Vector3(), scale: 1 };
  }

  /* ── post ──────────────────────────────────────── */
  buildPost() {
    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));
    this.bloom = new UnrealBloomPass(new THREE.Vector2(256, 256), 0.6, 0.35, 0.9);
    this.composer.addPass(this.bloom);
    this.rgb = new ShaderPass(RGBShiftShader);
    this.rgb.uniforms.amount.value = 0;
    this.composer.addPass(this.rgb);
    this.composer.addPass(new OutputPass());
  }

  resize() {
    const w = window.innerWidth, h = window.innerHeight;
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.fov = w < h ? 58 : 40;           // portrait screens need a wider lens
    this.camera.updateProjectionMatrix();
    if (this.composer) {
      this.composer.setPixelRatio(this.renderer.getPixelRatio());
      this.composer.setSize(w, h);
      this.bloom.setSize(w * (this.coarse ? 0.4 : 0.6), h * (this.coarse ? 0.4 : 0.6));
    }
    // where the mascot assembles: left of the end panel on wide screens, raised on phones
    this.vw = w; this.vh = h;
    this.viewShift = w > h * 1.15 ? 0.16 : 0;
    if (this.pData) {
      this.pData.offset.set(w > h ? -0.62 : 0, w > h ? 0.02 : 1.08, 0);
      this.pData.scale = w > h ? 1 : 0.58;          // portrait: smaller, above the text block
    }
  }

  /* ── per-frame ─────────────────────────────────── */
  update(time, dt) {
    const { c, intro, velocity } = this.state;

    // camera path through the onion (keyed on chapter units, see main.js)
    const KEYS = [
      [0.0, [0, 0.5, 7.4], [0, 0.12, 0]],
      [0.9, [2.0, 0.6, 5.0], [0, 0.15, 0]],
      [1.5, [2.25, 0.95, 3.15], [0, 0.22, 0]],
      [2.5, [-1.7, 0.42, 2.25], [0, 0.12, 0]],
      [3.5, [1.05, -0.12, 1.55], [0, 0.06, 0]],
      [4.5, [-0.7, 0.32, 1.45], [0, 0, 0]],
      [5.5, [1.05, 0.5, 1.25], [0, 0, 0]],
      [6.35, [0, 0, 3.5], [0, 0, 0]],
      [7.0, [0, 0, 3.3], [0, 0, 0]],
    ];
    let i = 0;
    while (i < KEYS.length - 2 && c > KEYS[i + 1][0]) i++;
    const [c0, p0, l0] = KEYS[i], [c1, p1, l1] = KEYS[i + 1];
    const t = smooth(c0, c1, c);
    const introDolly = (1 - intro) * 2.2;
    const drift = 0.06;
    this.camera.position.set(
      lerp(p0[0], p1[0], t) + Math.sin(time * 0.21) * drift,
      lerp(p0[1], p1[1], t) + Math.sin(time * 0.17) * drift * 0.6,
      lerp(p0[2], p1[2], t) + introDolly
    );
    this.look.set(lerp(l0[0], l1[0], t), lerp(l0[1], l1[1], t), lerp(l0[2], l1[2], t));
    this.camera.lookAt(this.look);
    // text sits on the left for chapters 0-5, so the scene is offset right in screen space
    const shift = this.viewShift * (1 - smooth(5.75, 6.25, c));
    if (shift > 0.001) this.camera.setViewOffset(this.vw, this.vh, -this.vw * shift, 0, this.vw, this.vh);
    else this.camera.clearViewOffset();

    // shells: construct (intro) → breathe → peel
    const peelAt = [2.0, 3.0, 4.0];
    const build = smooth(0, 0.62, intro), glass = smooth(0.45, 1, intro);
    this.shells.forEach((sh, li) => {
      sh.peel = smooth(peelAt[li] - 0.22, peelAt[li] + 0.28, c);
      sh.group.rotation.y += dt * (0.05 + li * 0.025) * (li % 2 ? -1 : 1);
      sh.petals.forEach((pt, k) => {
        const breathe = (0.018 + 0.022 * Math.sin(time * 0.9 + pt.seed)) * this.state.breathe;
        const out = breathe + sh.peel * (1.6 + (k % 3) * 0.45);
        pt.mesh.position.copy(pt.dir).multiplyScalar(out);
        pt.mesh.rotation.set(sh.peel * pt.spin * 0.6, sh.peel * pt.spin, 0);
        const alive = 1 - sh.peel;
        pt.mesh.material.opacity = (li === 0 ? 0.12 : 0.16) * glass * alive;
        pt.edges.material.opacity = (1 - 0.45 * glass) * alive * build;
        pt.edges.geometry.setDrawRange(0, Math.floor(pt.edgeCount * build));
        pt.mesh.visible = alive > 0.002 && build > 0;
      });
    });

    // core and collectors
    const coreOn = smooth(3.7, 4.3, c) * (1 - smooth(6.0, 6.45, c));
    this.core.scale.setScalar(0.25 + 0.75 * Math.max(coreOn, 0.3 * build) + Math.sin(time * 2.2) * 0.02);
    this.core.visible = this.core.scale.x > 0.01 && c < 6.5;
    this.core.rotation.y += dt * 0.4;
    this.coreWire.rotation.x += dt * 0.25;
    this.coreLight.intensity = (0.6 + 1.4 * build) * (0.5 + 0.5 * smooth(3.5, 4.3, c));
    const lp = this.links.geometry.attributes.position;
    const tmp = new THREE.Vector3();
    this.collectors.forEach((col, k) => {
      const a = time * col.speed + col.phase;
      tmp.set(Math.cos(a) * col.radius, 0, Math.sin(a) * col.radius).applyEuler(col.tilt);
      col.mesh.position.copy(tmp);
      col.mesh.visible = coreOn > 0.05;
      lp.setXYZ(k * 2, 0, 0, 0);
      lp.setXYZ(k * 2 + 1, tmp.x, tmp.y, tmp.z);
    });
    lp.needsUpdate = true;
    this.links.material.opacity = 0.45 * coreOn;

    this.network.rotation.y += dt * 0.012;

    // particles: drift as dust, then assemble into the mascot
    const m = smooth(6.0, 6.75, c);
    const P = this.pData, pos = this.particles.geometry.attributes.position, colr = this.particles.geometry.attributes.color;
    const rot = time * 0.03, cs = Math.cos(rot), sn = Math.sin(rot);
    for (let n = 0; n < P.N; n++) {
      const j = n * 3;
      const k = Math.min(1, Math.max(0, (m - P.delay[n]) / (1 - 0.45)));
      const e = k * k * (3 - 2 * k);
      const ax = P.ambient[j] * cs - P.ambient[j + 2] * sn, az = P.ambient[j] * sn + P.ambient[j + 2] * cs;
      const ay = P.ambient[j + 1] + Math.sin(time * 0.4 + n) * 0.05;
      pos.array[j] = lerp(ax, P.target[j] * P.scale + P.offset.x, e);
      pos.array[j + 1] = lerp(ay, P.target[j + 1] * P.scale + P.offset.y, e);
      pos.array[j + 2] = lerp(az, P.target[j + 2] * P.scale + P.offset.z, e);
      colr.array[j] = lerp(P.cA[j], P.cT[j], e);
      colr.array[j + 1] = lerp(P.cA[j + 1], P.cT[j + 1], e);
      colr.array[j + 2] = lerp(P.cA[j + 2], P.cT[j + 2], e);
    }
    pos.needsUpdate = true;
    colr.needsUpdate = true;
    this.particles.material.size = (this.coarse ? 0.034 : 0.028) * (1 - 0.35 * m);
    this.particles.material.opacity = 0.35 + 0.6 * Math.max(intro, m);

    // chromatic aberration: scroll speed + a pulse while a layer is peeling
    const peeling = Math.max(...this.shells.map((s) => Math.sin(Math.PI * s.peel)));
    this.rgb.uniforms.amount.value = Math.min(0.006, Math.abs(velocity) * 0.00009 + peeling * 0.0028 + (1 - intro) * 0.004);
    this.rgb.uniforms.angle.value = time * 0.4;

    this.scene.updateMatrixWorld();
    this.collectAnchors(c, build);
    this.composer.render();
  }

  /* ── anchors for the 2D constellation overlay ─── */
  collectAnchors(c, build) {
    const A = this.anchors;
    A.length = 0;
    const LABELS = [
      ["Ahmia", "OnionLand", "Amnesia", "Torland", "Excavator", "Onionway", "Tor66", "OSS", "Torgol",
        "TheDeepSearches", "Kaizer", "Anima", "Tornado", "FindTor", "Torgle", "DuckDuckGo-Tor", "Ahmia-clearnet"],
      ["fetch.py", "renew.py", "NEWNYM", "links", "entities", "clean text", "exit relay", "circuit"],
      ["OpenAI", "Anthropic", "Gemini", "Mistral", "Ollama", "llama.cpp", "OpenRouter", "Together", "Perplexity", "Replicate"],
    ];
    const windows = [[0.85, 2.05], [1.9, 3.05], [2.9, 4.05]];
    this.shells.forEach((sh, li) => {
      const vis = smooth(windows[li][0], windows[li][0] + 0.3, c) * (1 - smooth(windows[li][1] - 0.3, windows[li][1], c));
      if (vis < 0.02) return;
      const names = LABELS[li];
      names.forEach((label, k) => {
        const y = -0.78 + 1.32 * (k + 0.5) / names.length;
        const phi = k * 2.39996 + li;           // golden-angle spread
        const r = radiusAt(y) * 1.01;
        const v = new THREE.Vector3(Math.sin(phi) * r, y, Math.cos(phi) * r);
        v.applyMatrix4(sh.group.matrixWorld);
        A.push({ pos: v, label, layer: li, alpha: vis });
      });
    });
    const coreVis = smooth(3.95, 4.3, c) * (1 - smooth(5.9, 6.2, c));
    if (coreVis > 0.02) {
      this.collectors.forEach((col) => A.push({ pos: col.mesh.getWorldPosition(new THREE.Vector3()), label: col.name, layer: 3, alpha: coreVis }));
    }
    const sigVis = smooth(4.95, 5.3, c) * (1 - smooth(5.9, 6.2, c));
    if (sigVis > 0.02) {
      ["STIX 2.1", "shared wallet", "shared host", "alias", "HMAC-signed", "exactly once", "71 tests"].forEach((label, k) => {
        const a = k / 7 * Math.PI * 2 + 0.4;
        A.push({ pos: new THREE.Vector3(Math.cos(a) * 0.62, Math.sin(a * 2) * 0.18, Math.sin(a) * 0.62), label, layer: 4, alpha: sigVis });
      });
    }
    // intro: numbered vertices while the wireframe constructs
    const introVis = build * (1 - smooth(0.7, 1, this.state.intro));
    if (introVis > 0.02) {
      this.introNumbers.forEach((n) => {
        const p = n.petal.mesh.geometry.attributes.position;
        const v = new THREE.Vector3().fromBufferAttribute(p, n.vi).applyMatrix4(n.petal.mesh.matrixWorld);
        A.push({ pos: v, label: n.label, layer: -1, alpha: introVis });
      });
    }
  }
}

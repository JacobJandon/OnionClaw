// OnionClaw web — boot, scroll journey, HUD.
// Scroll position is converted to "chapter units" (c = chapter index + progress
// through it). The world reads c to place the camera, peel layers and morph
// particles; the DOM panels fade on the same value, so text and scene stay in step.
import "lenis/dist/lenis.css";
import "./style.css";
import Lenis from "lenis";
import { scramble, scrambleAll } from "./scramble.js";
import { mountSwitcher } from "./shared.js";

const root = document.documentElement;
const $ = (s) => document.querySelector(s);
const chapters = [...document.querySelectorAll(".chapter")];
const panels = chapters.map((c) => c.querySelector(".panel"));
const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };

wireCopy();
wireStars();
mountSwitcher("Peel", "dark");

if (root.classList.contains("mode-3d")) {
  start3d().catch((err) => {
    console.warn("[onionclaw] 3D experience unavailable, showing the document version:", err);
    toDoc();
  });
} else {
  toDoc();
}

/* ── document fallback ─────────────────────────── */
function toDoc() {
  root.classList.remove("mode-3d");
  root.classList.add("mode-doc");
  $("#loader")?.classList.add("done");
  panels.forEach((p) => p.style.removeProperty("--o"));
  scrambleAll(document, { duration: 700 });
}

/* ── 3D experience ─────────────────────────────── */
async function start3d() {
  if ("scrollRestoration" in history) history.scrollRestoration = "manual";
  window.scrollTo(0, 0);

  const bar = $("#loaderBar"), pct = $("#loaderPct");
  const setProgress = (p) => {
    bar.style.width = `${(p * 100).toFixed(0)}%`;
    pct.textContent = String(Math.round(p * 100)).padStart(3, "0");
  };
  scrambleAll($("#loader"), { duration: 1400 });
  setProgress(0.05);

  // three.js only loads in 3D mode (split chunk)
  const [{ World }, { Overlay }] = await Promise.all([import("./world.js"), import("./overlay.js")]);
  setProgress(0.15);

  const coarse = window.matchMedia("(pointer: coarse)").matches;
  const world = new World($("#gl"), { coarse });
  const overlay = new Overlay($("#overlay"));
  await world.load((p) => setProgress(0.15 + p * 0.8));
  await Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 1500))]);
  setProgress(1);

  const lenis = new Lenis({ lerp: 0.085, wheelMultiplier: 0.9, touchMultiplier: 1.2 });
  lenis.stop();                                          // no scrolling until the onion is built

  // geometry of the scroll story
  let tops = [], heights = [], vh = window.innerHeight;
  function measure() {
    vh = window.innerHeight;
    tops = chapters.map((c) => c.offsetTop);
    heights = chapters.map((c) => c.offsetHeight);
  }
  measure();

  // chapter navigation ticks
  const ticks = $("#ticks");
  chapters.forEach((ch, i) => {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = `#${ch.id}`;
    a.setAttribute("aria-label", `Chapter ${i}: ${ch.dataset.name.toLowerCase()}`);
    li.appendChild(a);
    ticks.appendChild(li);
  });
  const tickLinks = [...ticks.querySelectorAll("a")];
  document.addEventListener("click", (e) => {
    const a = e.target.closest('a[href^="#ch-"]');
    if (!a) return;
    const i = chapters.findIndex((c) => `#${c.id}` === a.getAttribute("href"));
    if (i < 0) return;
    e.preventDefault();
    // land in the middle of the chapter's pinned phase
    lenis.scrollTo(tops[i] + Math.max(0, heights[i] - vh) * (i === chapters.length - 1 ? 1 : 0.5), { duration: 2.2 });
  });

  // Scroll → chapter units. Each chapter's pinned phase (text on screen) maps to
  // [i+0.15, i+0.85], so its text is centred on the camera stop at i+0.5. The hand-over
  // between chapters maps to [i+0.85, i+1.15]: that is where layers peel.
  function chapterUnits(y) {
    let i = 0;
    while (i < chapters.length - 1 && y >= tops[i + 1]) i++;
    const pinned = Math.max(1, heights[i] - vh);
    const into = y - tops[i];
    const lastCh = i === chapters.length - 1;
    if (into <= pinned || lastCh) {
      const lp = Math.min(1, Math.max(0, into / pinned));
      return { i, c: i === 0 ? 0.85 * lp : lastCh ? i + 0.15 + 0.85 * lp : i + 0.15 + 0.7 * lp };
    }
    const t = Math.min(1, (into - pinned) / vh);
    return { i, c: i + 0.85 + 0.3 * t };
  }

  // hand over from loader to the intro
  $("#loader").classList.add("done");
  const INTRO = 3400;
  scrambleAll($(".hud-tl"), { duration: 1600 });

  let introStart = performance.now();
  if (import.meta.env.DEV) {
    // dev-only hooks for checking the experience frame by frame
    window.__onionclaw = { world, lenis, replayIntro: () => { introStart = performance.now(); } };
  }
  let active = -1, last = performance.now(), hudTick = 0;
  let slowFrames = 0, frames = 0, degraded = false;

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    lenis.raf(now);

    const intro = smooth(0, 1, (now - introStart) / INTRO);
    if (intro > 0.62 && !lenis.isScrolling && lenis.isStopped) lenis.start();

    const y = lenis.scroll;
    const { i, c } = chapterUnits(y);

    // panels
    panels.forEach((p, k) => {
      const lp = (y - tops[k]) / Math.max(1, heights[k] - vh);
      let o;
      if (k === 0) o = (1 - smooth(0.55, 0.95, lp)) * smooth(0.55, 1, intro);
      else if (k === panels.length - 1) o = smooth(0.12, 0.42, lp);
      else o = smooth(0, 0.22, lp) * (1 - smooth(0.78, 1, lp));
      p.style.setProperty("--o", o.toFixed(3));
    });

    // chapter change → HUD + headline scramble
    if (i !== active) {
      active = i;
      const ch = chapters[i];
      $("#hudIndex").textContent = String(i).padStart(2, "0");
      scramble($("#hudName"), { text: ch.dataset.name, duration: 700 });
      $("#hudLayer").textContent = ch.dataset.layer === "—" ? "— / 03" : ch.dataset.layer === "00" ? "CORE" : `${ch.dataset.layer} / 03`;
      const h = ch.querySelector("h2[data-scr]");
      if (h && i > 0) scramble(h, { duration: 1100 });
      tickLinks.forEach((a, k) => a.classList.toggle("on", k === i));
    }
    $("#hint").classList.toggle("gone", y > 40);

    world.state.c = c;
    world.state.intro = intro;
    world.state.velocity = lenis.velocity;
    world.update(now / 1000, dt);
    overlay.draw(world.anchors, world.camera, now / 1000);

    if (now - hudTick > 120) {
      hudTick = now;
      const p = world.camera.position;
      $("#hudCam").textContent = `${p.x.toFixed(2)} ${p.y.toFixed(2)} ${p.z.toFixed(2)}`;
      const peeled = world.shells.filter((s) => s.peel > 0.5).length;
      $("#hudCircuit").textContent = ["GUARD ▸ MIDDLE ▸ EXIT", "MIDDLE ▸ EXIT", "EXIT", "CORE REACHED"][peeled];
    }

    // adaptive quality: if frames run long for ~2s, render fewer pixels
    frames++;
    if (dt > 0.034) slowFrames++;
    if (!degraded && frames > 120) {
      if (slowFrames / frames > 0.5) {
        degraded = true;
        world.renderer.setPixelRatio(1);
        world.resize();
      }
      frames = slowFrames = 0;
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  let rz;
  window.addEventListener("resize", () => {
    clearTimeout(rz);
    rz = setTimeout(() => { world.resize(); overlay.resize(); measure(); lenis.resize(); }, 120);
  });
}

/* ── shared bits ───────────────────────────────── */
function wireCopy() {
  const btn = $("#copy"), cmd = $("#cmd");
  if (!btn || !cmd) return;
  btn.addEventListener("click", () => {
    const say = (t) => { btn.textContent = t; setTimeout(() => { btn.textContent = "COPY"; }, 1800); };
    const select = () => {
      const r = document.createRange();
      r.selectNodeContents(cmd);
      const s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      say("SELECTED");
    };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(cmd.textContent).then(() => say("COPIED"), select);
    else select();
  });
}

function wireStars() {
  fetch("https://api.github.com/repos/JacobJandon/OnionClaw", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d || typeof d.stargazers_count !== "number") return;
      $("#hudStars").textContent = `★ ${d.stargazers_count} · ${d.forks_count} FORKS`;
      $("#ctaStars").textContent = `· ★ ${d.stargazers_count}`;
    })
    .catch(() => { /* offline or rate-limited: the HUD keeps its dash */ });
}

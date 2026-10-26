// OnionClaw Hybrid — boot, scroll story and explore mode.
// Scroll is converted to chapter units exactly as in Peel; the world uses them to fly
// station to station and to peel the planet open. "Explore the planet" hands the camera
// to orbit controls with Planet's pins, cards and dock.
import "lenis/dist/lenis.css";
import "../style.css";
import "./style.css";
import Lenis from "lenis";
import { scramble, scrambleAll } from "../scramble.js";
import { FEATURES, ENGINES, PROVIDERS, COLLECTORS, fetchRepoStats, wireCopy, mountSwitcher } from "../shared.js";

const root = document.documentElement;
const $ = (s) => document.querySelector(s);
const chapters = [...document.querySelectorAll(".chapter")];
const panels = chapters.map((c) => c.querySelector(".panel"));
const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const EXTRA = { search: ENGINES, investigate: PROVIDERS, monitor: COLLECTORS.map((c) => c.id) };

mountSwitcher("Hybrid", "dark");
wireCopy($("#copy"), $("#cmd"), { idle: "COPY", ok: "COPIED", sel: "SELECTED" });
fetchRepoStats().then((s) => {
  if (!s) return;
  $("#hudStars").textContent = `★ ${s.stars} · ${s.forks} FORKS`;
  $("#ctaStars").textContent = `· ★ ${s.stars}`;
});

function toDoc() {
  root.classList.remove("mode-3d");
  root.classList.add("mode-doc");
  $("#loader")?.classList.add("done");
  panels.forEach((p) => p.style.removeProperty("--o"));
  $("#exploreBtn").hidden = true;
  scrambleAll(document, { duration: 700 });
}

async function start3d() {
  if ("scrollRestoration" in history) history.scrollRestoration = "manual";
  window.scrollTo(0, 0);
  const bar = $("#loaderBar"), pct = $("#loaderPct");
  const setProgress = (p) => { bar.style.width = `${(p * 100).toFixed(0)}%`; pct.textContent = String(Math.round(p * 100)).padStart(3, "0"); };
  scrambleAll($("#loader"), { duration: 1400 });
  setProgress(0.05);

  const [{ World }, { Overlay }] = await Promise.all([import("./world.js"), import("../overlay.js")]);
  setProgress(0.15);
  const coarse = matchMedia("(pointer: coarse)").matches;
  const world = new World($("#gl"), { coarse });
  const overlay = new Overlay($("#overlay"));
  await world.load((p) => setProgress(0.15 + p * 0.8));
  await Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 1500))]);
  setProgress(1);

  const lenis = new Lenis({ lerp: 0.085, wheelMultiplier: 0.9, touchMultiplier: 1.2 });
  lenis.stop();

  let tops = [], heights = [], vh = innerHeight;
  const measure = () => { vh = innerHeight; tops = chapters.map((c) => c.offsetTop); heights = chapters.map((c) => c.offsetHeight); };
  measure();

  // chapter ticks
  const ticks = $("#ticks");
  chapters.forEach((ch, i) => {
    const li = document.createElement("li"), a = document.createElement("a");
    a.href = `#${ch.id}`;
    a.setAttribute("aria-label", `Chapter ${i}: ${ch.dataset.name.toLowerCase()}`);
    li.appendChild(a);
    ticks.appendChild(li);
  });
  const tickLinks = [...ticks.querySelectorAll("a")];
  document.addEventListener("click", (e) => {
    const a = e.target.closest('a[href^="#ch-"]');
    if (!a || exploring) return;
    const i = chapters.findIndex((c) => `#${c.id}` === a.getAttribute("href"));
    if (i < 0) return;
    e.preventDefault();
    lenis.scrollTo(tops[i] + Math.max(0, heights[i] - vh) * (i === chapters.length - 1 ? 1 : 0.5), { duration: 2.2 });
  });

  // identical mapping to Peel: pinned text phase → [i+0.15, i+0.85], hand-over → [i+0.85, i+1.15]
  function chapterUnits(y) {
    let i = 0;
    while (i < chapters.length - 1 && y >= tops[i + 1]) i++;
    const pinned = Math.max(1, heights[i] - vh), into = y - tops[i], lastCh = i === chapters.length - 1;
    if (into <= pinned || lastCh) {
      const lp = Math.min(1, Math.max(0, into / pinned));
      return { i, c: i === 0 ? 0.85 * lp : lastCh ? i + 0.15 + 0.85 * lp : i + 0.15 + 0.7 * lp };
    }
    return { i, c: i + 0.85 + 0.3 * Math.min(1, (into - pinned) / vh) };
  }

  /* ── explore mode ───────────────────────────── */
  let exploring = false, current = -1;
  const pins = world.stations.map((s, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pin";
    b.innerHTML = `<i style="color:${s.f.color};background:${s.f.color}"></i>${s.f.name}`;
    b.addEventListener("click", () => select(i));
    $("#pins").appendChild(b);
    return b;
  });
  const dock = $("#dock");
  const dockButtons = FEATURES.map((f, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.innerHTML = `<i style="background:${f.color}"></i>${f.name}`;
    b.addEventListener("click", () => select(i));
    dock.appendChild(b);
    return b;
  });
  const back = document.createElement("button");
  back.type = "button";
  back.className = "back";
  back.textContent = "↩ Back to the story";
  back.addEventListener("click", leaveExplore);
  dock.appendChild(back);

  function select(i) {
    current = (i + FEATURES.length) % FEATURES.length;
    const f = FEATURES[current];
    world.focusStation(current);
    $("#xcard").style.setProperty("--accent", f.color);
    $("#xcardCmd").textContent = f.cmd;
    $("#xcardTitle").textContent = f.line;
    $("#xcardBody").textContent = f.body;
    $("#xcardList").innerHTML = (EXTRA[f.id] || []).map((x) => `<li>${x}</li>`).join("");
    $("#xcard").hidden = false;
    world.cardOpen = true;
    pins.forEach((p, k) => p.classList.toggle("on", k === current));
    dockButtons.forEach((b, k) => b.setAttribute("aria-pressed", String(k === current)));
  }
  function closeCard() {
    $("#xcard").hidden = true;
    world.cardOpen = false;
    current = -1;
    pins.forEach((p) => p.classList.remove("on"));
    dockButtons.forEach((b) => b.setAttribute("aria-pressed", "false"));
  }
  function enterExplore() {
    exploring = true;
    lenis.stop();
    root.classList.add("exploring");
    dock.hidden = false;
    world.enterExplore();
    dockButtons[0].focus({ preventScroll: true });
  }
  function leaveExplore() {
    exploring = false;
    closeCard();
    root.classList.remove("exploring");
    dock.hidden = true;
    world.exitExplore();
    lenis.start();
    $("#exploreBtn").focus({ preventScroll: true });
  }
  $("#exploreBtn").addEventListener("click", enterExplore);
  $("#xcardClose").addEventListener("click", closeCard);
  $("#xprev").addEventListener("click", () => select(current - 1));
  $("#xnext").addEventListener("click", () => select(current + 1));
  addEventListener("keydown", (e) => {
    if (!exploring) return;
    if (e.key === "Escape") { if (!$("#xcard").hidden) closeCard(); else leaveExplore(); }
    if (e.key === "ArrowRight") select(current + 1);
    if (e.key === "ArrowLeft") select(current - 1);
  });
  // click a station in 3D (ignore drags)
  let downAt = null;
  $("#gl").addEventListener("pointerdown", (e) => { downAt = [e.clientX, e.clientY]; });
  $("#gl").addEventListener("pointerup", (e) => {
    if (!exploring || !downAt || Math.hypot(e.clientX - downAt[0], e.clientY - downAt[1]) > 6) return;
    const i = world.pickStation({ x: e.clientX / innerWidth * 2 - 1, y: -(e.clientY / innerHeight) * 2 + 1 });
    if (i >= 0) select(i);
  });

  /* ── run ────────────────────────────────────── */
  $("#loader").classList.add("done");
  scrambleAll($(".hud-tl"), { duration: 1600 });
  let introStart = performance.now();
  const INTRO = 3600;
  if (import.meta.env.DEV) window.__onionclaw = { world, lenis, replayIntro: () => { introStart = performance.now(); } };

  let active = -1, last = performance.now(), hudTick = 0, frames = 0, slow = 0, degraded = false;
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    lenis.raf(now);
    const intro = smooth(0, 1, (now - introStart) / INTRO);
    if (intro > 0.62 && lenis.isStopped && !exploring) lenis.start();

    const y = lenis.scroll;
    const { i, c } = chapterUnits(y);

    panels.forEach((p, k) => {
      const lp = (y - tops[k]) / Math.max(1, heights[k] - vh);
      let o;
      if (k === 0) o = (1 - smooth(0.55, 0.95, lp)) * smooth(0.55, 1, intro);
      else if (k === panels.length - 1) o = smooth(0.12, 0.42, lp);
      else o = smooth(0, 0.22, lp) * (1 - smooth(0.78, 1, lp));
      p.style.setProperty("--o", o.toFixed(3));
    });

    if (i !== active) {
      active = i;
      const ch = chapters[i];
      $("#hudIndex").textContent = String(i).padStart(2, "0");
      scramble($("#hudName"), { text: ch.dataset.name, duration: 700 });
      scramble($("#hudStation"), { text: ch.dataset.station, duration: 600 });
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

    // pins follow their stations while exploring
    if (world.explore > 0.05) {
      world.stationScreens().forEach((s, k) => {
        pins[k].style.transform = `translate(${s.x}px, ${s.y}px) translate(-50%, -100%)`;
        pins[k].classList.toggle("away", !s.visible || world.explore < 0.9);
      });
    }

    if (now - hudTick > 120) {
      hudTick = now;
      const p = world.camera.position;
      $("#hudCam").textContent = `${p.x.toFixed(2)} ${p.y.toFixed(2)} ${p.z.toFixed(2)}`;
      $("#hudSkin").textContent = exploring ? "EXPLORING" : c > 5.2 ? "PEELED" : c > 4.8 ? "PEELING" : "INTACT";
    }

    frames++;
    if (dt > 0.034) slow++;
    if (!degraded && frames > 120) {
      if (slow / frames > 0.5) { degraded = true; world.renderer.setPixelRatio(1); world.resize(); }
      frames = slow = 0;
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  let rz;
  addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => { world.resize(); overlay.resize(); measure(); lenis.resize(); }, 120); });
}

if (root.classList.contains("mode-3d")) start3d().catch((err) => { console.warn("[hybrid] 3D unavailable, showing the document version:", err); toDoc(); });
else toDoc();

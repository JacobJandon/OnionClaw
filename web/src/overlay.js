// OnionClaw — constellation overlay.
// Igloo draws thin lines between points of its 3D scene with tiny number labels.
// Here every point carries real data: engine names on the guard layer, commands on
// the middle, LLM providers on the exit, collectors around the core.
// Drawn in 2D on top of the WebGL canvas from projected 3D anchor positions.
import * as THREE from "three";

const TINT = ["#ec6b84", "#b98fe0", "#34d6c9", "#34d6c9", "#f2eef7"];

export class Overlay {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.v = new THREE.Vector3();
    this.camDir = new THREE.Vector3();
    this.resize();
  }

  resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.w = window.innerWidth;
    this.h = window.innerHeight;
    this.canvas.width = Math.round(this.w * dpr);
    this.canvas.height = Math.round(this.h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.small = this.w < 760;
  }

  draw(anchors, camera, time) {
    const g = this.ctx;
    g.clearRect(0, 0, this.w, this.h);
    if (!anchors.length) return;
    camera.getWorldDirection(this.camDir);

    // project, drop points behind the camera or off-screen, fade points on the far side
    const pts = [];
    for (const a of anchors) {
      const toPoint = this.v.copy(a.pos).sub(camera.position);
      const dist = toPoint.length();
      if (toPoint.dot(this.camDir) <= 0.05) continue;
      this.v.copy(a.pos).project(camera);
      const x = (this.v.x * 0.5 + 0.5) * this.w, y = (-this.v.y * 0.5 + 0.5) * this.h;
      if (x < -40 || x > this.w + 40 || y < -40 || y > this.h + 40) continue;
      // far-side points (further than the onion centre) fade out
      const centreDist = camera.position.length();
      const facing = Math.min(1, Math.max(0.15, 1 - (dist - centreDist) * 1.6));
      pts.push({ x, y, a: a.alpha * facing, label: a.label, layer: a.layer });
    }
    if (this.small && pts.length > 9) pts.length = 9;

    // connecting polyline, in anchor order (Igloo's constellation)
    g.lineWidth = 0.75;
    for (let i = 1; i < pts.length; i++) {
      const p = pts[i - 1], q = pts[i];
      if (p.layer !== q.layer) continue;
      const alpha = Math.min(p.a, q.a) * 0.32;
      if (alpha < 0.01) continue;
      g.strokeStyle = `rgba(242,238,247,${alpha})`;
      g.beginPath();
      g.moveTo(p.x, p.y);
      g.lineTo(q.x, q.y);
      g.stroke();
    }

    // markers and labels; a label that would collide with one already drawn is skipped
    g.font = `500 ${this.small ? 9 : 10}px "Geist Mono", ui-monospace, monospace`;
    g.textBaseline = "middle";
    const placed = [];
    for (const p of [...pts].sort((m, n) => n.a - m.a)) {
      if (p.a < 0.02) continue;
      const tint = TINT[Math.max(0, p.layer)] || "#f2eef7";
      g.globalAlpha = p.a;
      g.strokeStyle = tint;
      g.lineWidth = 1;
      g.beginPath();
      g.moveTo(p.x - 4, p.y); g.lineTo(p.x + 4, p.y);
      g.moveTo(p.x, p.y - 4); g.lineTo(p.x, p.y + 4);
      g.stroke();
      // labels flicker in, like Igloo's bitmap HUD
      const text = p.label.toUpperCase();
      const lw = g.measureText(text).width, lx = p.x + 7, ly = p.y - 7;
      if (placed.some((r) => lx < r.x + r.w + 6 && lx + lw + 6 > r.x && Math.abs(ly - r.y) < 13)) continue;
      placed.push({ x: lx, y: ly, w: lw });
      const flick = p.layer === -1 && Math.sin(time * 9 + p.x) > 0.92 ? 0.35 : 1;
      g.globalAlpha = p.a * 0.9 * flick;
      g.fillStyle = "#f2eef7";
      g.fillText(text, lx, ly);
    }
    g.globalAlpha = 1;
  }
}

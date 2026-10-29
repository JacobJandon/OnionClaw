// Text scramble: characters resolve from random glyphs, left-to-right-ish.
// The element's final text is kept in `dataset.text`, so repeated calls are safe
// and screen readers always get the real words via aria-label.
const GLYPHS = "!<>-_\\/[]{}=+*^?#░▒▓01";

const running = new WeakMap();

export function scramble(el, { duration = 900, text } = {}) {
  if (!el) return;
  const final = text ?? el.dataset.text ?? el.textContent;
  el.dataset.text = final;
  if (!el.hasAttribute("aria-label") && el.tagName !== "SPAN") el.setAttribute("aria-label", final);

  const prev = running.get(el);
  if (prev) cancelAnimationFrame(prev);

  const t0 = performance.now();
  const n = final.length;
  // each character settles at its own moment, biased left to right
  const settle = Array.from({ length: n }, (_, i) => (i / n) * 0.65 + Math.random() * 0.35);

  const tick = (now) => {
    const p = Math.min(1, (now - t0) / duration);
    let out = "";
    for (let i = 0; i < n; i++) {
      const ch = final[i];
      if (ch === " " || p >= settle[i]) out += ch;
      else out += GLYPHS[(Math.random() * GLYPHS.length) | 0];
    }
    el.textContent = out;
    if (p < 1) running.set(el, requestAnimationFrame(tick));
    else { el.textContent = final; running.delete(el); }
  };
  running.set(el, requestAnimationFrame(tick));
}

export function scrambleAll(root = document, opts) {
  root.querySelectorAll("[data-scr]").forEach((el) => scramble(el, opts));
}

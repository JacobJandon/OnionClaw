// Content and small behaviours shared by every OnionClaw site variant.
// Everything here is factual: names come from the real code (sicry.py engine list,
// LLM providers, swarm collectors) and the numbers from the real test suite.

export const ENGINES = ["Ahmia", "OnionLand", "Amnesia", "Torland", "Excavator", "Onionway", "Tor66", "OSS",
  "Torgol", "TheDeepSearches", "Kaizer", "Anima", "Tornado", "FindTor", "Torgle", "DuckDuckGo-Tor", "Ahmia-clearnet"];

export const PROVIDERS = ["OpenAI", "Anthropic", "Gemini", "Mistral", "Ollama", "llama.cpp", "OpenRouter",
  "Together", "Perplexity", "Replicate"];

export const COLLECTORS = [
  { id: "leaksites", what: "new ransomware victim disclosures" },
  { id: "groupinfra", what: "leak-site infrastructure going up or down" },
  { id: "kev", what: "exploited CVEs newly tied to ransomware" },
  { id: "wallets", what: "movement on tracked ransom wallets" },
  { id: "onionsites", what: "changes on .onion pages you choose" },
];

export const FEATURES = [
  { id: "search", name: "Search", cmd: "search.py", color: "#ec6b84",
    line: "Seventeen engines, one query.",
    body: "One search goes to 17 .onion search engines in parallel. Results come back merged, deduplicated and ranked by relevance." },
  { id: "fetch", name: "Fetch", cmd: "fetch.py", color: "#b98fe0",
    line: "Read any hidden service.",
    body: "Load any .onion or clearnet page through Tor and get clean text, links and extracted entities back." },
  { id: "rotate", name: "Rotate", cmd: "renew.py", color: "#e8b54c",
    line: "A fresh circuit on demand.",
    body: "Ask Tor for a new circuit, so the next request leaves from a different exit relay." },
  { id: "investigate", name: "Investigate", cmd: "pipeline.py", color: "#34d6c9",
    line: "From raw pages to a report.",
    body: "One command refines the query, searches, filters, scrapes the top hits and writes an analyst report. Four modes, ten LLM providers." },
  { id: "monitor", name: "Monitor", cmd: "swarm.py", color: "#79d568",
    line: "A swarm that watches for you.",
    body: "Five read-only collectors run in parallel and report only what changed since the last sweep." },
  { id: "export", name: "Export", cmd: "stix.py", color: "#f2eef7",
    line: "Evidence, not guesses.",
    body: "Groups are linked only by hard evidence. Findings export as validated STIX 2.1 and go out as signed webhooks, delivered once." },
];

export const INSTALL = "cp -r OnionClaw ~/.openclaw/skills/onionclaw";
export const REPO = "https://github.com/JacobJandon/OnionClaw";
export const FINEPRINT = "Built for OSINT, threat intelligence and security research. The collectors only read public data and never contact, negotiate with or deceive anyone. Accessing some hidden services may be unlawful where you live, and you are responsible for how you use this tool. OnionClaw™ by JacobJandon · Apache License 2.0.";

/** Live star/fork counts; resolves to null when offline or rate-limited. */
export function fetchRepoStats() {
  return fetch("https://api.github.com/repos/JacobJandon/OnionClaw", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => (d && typeof d.stargazers_count === "number" ? { stars: d.stargazers_count, forks: d.forks_count } : null))
    .catch(() => null);
}

/** Wire a copy button; falls back to selecting the text when the clipboard is refused. */
export function wireCopy(button, source, labels = { idle: "Copy", ok: "Copied", sel: "Selected" }) {
  if (!button || !source) return;
  button.addEventListener("click", () => {
    const say = (t) => { button.textContent = t; setTimeout(() => { button.textContent = labels.idle; }, 1800); };
    const select = () => {
      const r = document.createRange();
      r.selectNodeContents(source);
      const s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      say(labels.sel);
    };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(source.textContent).then(() => say(labels.ok), select);
    else select();
  });
}

export const VARIANTS = [
  { href: "/", name: "Peel" },
  { href: "/hybrid/", name: "Hybrid" },
];

/** Small fixed switcher so the variants can be compared side by side. */
export function mountSwitcher(current, theme = "dark") {
  const nav = document.createElement("nav");
  nav.className = `oc-switcher oc-switcher--${theme}`;
  nav.setAttribute("aria-label", "Site variants");
  nav.innerHTML = VARIANTS.map((v) =>
    `<a href="${v.href}"${v.name === current ? ' aria-current="page"' : ""}>${v.name}</a>`).join("");
  document.body.appendChild(nav);
  if (!document.getElementById("oc-switcher-css")) {
    const st = document.createElement("style");
    st.id = "oc-switcher-css";
    st.textContent = `.oc-switcher{position:fixed;left:50%;transform:translateX(-50%);bottom:calc(14px + env(safe-area-inset-bottom,0px));z-index:80;display:flex;gap:2px;padding:3px;border-radius:99px;font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;backdrop-filter:blur(10px)}
.oc-switcher a{padding:7px 11px;border-radius:99px;text-decoration:none;opacity:.6;transition:opacity .2s,background .2s}
.oc-switcher a:hover{opacity:1}.oc-switcher a[aria-current]{opacity:1}
.oc-switcher--dark{background:rgba(10,7,16,.6);border:1px solid rgba(255,255,255,.12);color:#f2eef7}
.oc-switcher--dark a[aria-current]{background:#f2eef7;color:#0a0710}
.oc-switcher--light{background:rgba(255,255,255,.7);border:1px solid rgba(0,0,0,.1);color:#16131a}
.oc-switcher--light a[aria-current]{background:#16131a;color:#fff}
@media (max-width:760px){.oc-switcher{bottom:auto;top:calc(16px + env(safe-area-inset-top,0px));left:auto;right:max(14px,env(safe-area-inset-right,0px));transform:none}}`;
    document.head.appendChild(st);
  }
}

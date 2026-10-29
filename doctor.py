#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — doctor.py
Check the whole setup and say exactly what to fix.

Adapted from PRISM-Intel's `doctor` command. OnionClaw has a lot of moving parts —
Tor, the ControlPort, a .env, LLM keys, the observation store, engine health — and
until now a misconfiguration surfaced as a confusing failure in whichever command you
happened to run. This reports every layer at once, and every failing check carries the
command that fixes it.

Required checks decide the exit code; optional ones are reported but never fail the run,
because search and fetch work without an LLM key and the swarm's clearnet collectors work
without Tor.

Usage:
  python3 doctor.py            # full report
  python3 doctor.py --deep     # also make one live request through Tor (slower)
  python3 doctor.py --json     # machine-readable, for agents and CI
"""
from __future__ import annotations

import sys, os, json, socket, sqlite3, argparse, importlib, time
from datetime import datetime, timezone

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

_env = os.path.join(_skill_dir, ".env")
if os.path.exists(_env):
    try:
        from dotenv import load_dotenv
        load_dotenv(_env, override=False)
    except ImportError:
        pass

__version__ = "2.4.0"

MIN_PY = (3, 10)          # the CI matrix; modules use PEP 604 unions at runtime
OK, WARN, FAIL = "ok", "warn", "fail"
_MARK = {OK: "✓", WARN: "○", FAIL: "✗"}


class Report:
    def __init__(self):
        self.groups: list[tuple[str, list[dict]]] = []

    def group(self, name):
        rows: list[dict] = []
        self.groups.append((name, rows))

        def add(label, state, detail="", fix="", required=True):
            rows.append({"check": label, "state": state, "detail": detail,
                         "fix": fix, "required": required})
        return add

    @property
    def rows(self):
        return [r for _, rows in self.groups for r in rows]

    def failures(self):
        return [r for r in self.rows if r["required"] and r["state"] == FAIL]


def _port_open(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def build(deep=False) -> Report:
    rep = Report()

    # ── core ──────────────────────────────────────────────────
    add = rep.group("Core")
    v = sys.version_info
    add("Python", OK if v[:2] >= MIN_PY else FAIL, f"{v.major}.{v.minor}.{v.micro}",
        f"OnionClaw needs Python {MIN_PY[0]}.{MIN_PY[1]}+")

    try:
        import sicry
        add("SICRY engine", OK, f"v{getattr(sicry, '__version__', '?')}, "
            f"{len(getattr(sicry, 'SEARCH_ENGINES', []))} engines")
    except Exception as e:
        sicry = None
        add("SICRY engine", FAIL, repr(e)[:70], "sicry.py must sit beside this script")

    for mod, label, required in (("requests", "requests", True), ("bs4", "beautifulsoup4", True),
                                 ("dotenv", "python-dotenv", True), ("socks", "requests[socks]", True),
                                 ("stem", "stem (ControlPort)", False)):
        try:
            importlib.import_module(mod)
            add(label, OK, "installed", required=required)
        except ImportError:
            add(label, FAIL if required else WARN, "missing",
                f"pip install {'requests[socks] beautifulsoup4 python-dotenv' if required else 'stem'}",
                required=required)

    # ── tor ───────────────────────────────────────────────────
    add = rep.group("Tor")
    host = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    sport = os.getenv("TOR_SOCKS_PORT", "9050")
    cport = os.getenv("TOR_CONTROL_PORT", "9051")
    socks_up = _port_open(host, sport)
    add("SOCKS port", OK if socks_up else WARN, f"{host}:{sport}" + ("" if socks_up else " unreachable"),
        "Start Tor:  sudo systemctl start tor   (or: tor -f /path/to/torrc)",
        required=False)

    ctrl_up = _port_open(host, cport)
    add("ControlPort", OK if ctrl_up else WARN,
        f"{host}:{cport}" + ("" if ctrl_up else " unreachable — renew.py needs it"),
        "Add to torrc:  ControlPort 9051  +  CookieAuthentication 1", required=False)

    data_dir = os.getenv("TOR_DATA_DIR", "")
    if ctrl_up:
        if data_dir and os.path.isdir(data_dir):
            cookie = os.path.join(data_dir, "control_auth_cookie")
            add("Control auth", OK if os.path.exists(cookie) else WARN,
                data_dir if os.path.exists(cookie) else f"no control_auth_cookie in {data_dir}",
                "TOR_DATA_DIR must be Tor's DataDirectory", required=False)
        else:
            add("Control auth", WARN, "TOR_DATA_DIR not set or not a directory",
                "Set TOR_DATA_DIR=<Tor DataDirectory> in .env so renew.py can authenticate",
                required=False)

    if deep and socks_up and sicry:
        try:
            t0 = time.time()
            st = sicry.check_tor()
            ms = int((time.time() - t0) * 1000)
            add("Live circuit", OK if st.get("tor_active") else FAIL,
                f"exit IP {st.get('exit_ip')} ({ms} ms)" if st.get("tor_active") else str(st.get("error"))[:70],
                "Tor is listening but no circuit completed; check the Tor log", required=False)
        except Exception as e:
            add("Live circuit", WARN, repr(e)[:70], required=False)

    # ── configuration ─────────────────────────────────────────
    add = rep.group("Configuration")
    add(".env", OK if os.path.exists(_env) else WARN,
        _env if os.path.exists(_env) else "not found (defaults in use)",
        "cp .env.example .env", required=False)

    provider = (os.getenv("LLM_PROVIDER") or "").strip()
    key_for = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY",
               "mistral": "MISTRAL_API_KEY", "openrouter": "OPENROUTER_API_KEY",
               "together": "TOGETHER_API_KEY", "perplexity": "PERPLEXITY_API_KEY",
               "replicate": "REPLICATE_API_KEY"}
    if not provider:
        add("LLM provider", WARN, "not set — ask.py and pipeline.py analysis are unavailable",
            "Set LLM_PROVIDER in .env (search, fetch, crawl and the swarm work without it)",
            required=False)
    elif provider in ("ollama", "llamacpp"):
        add("LLM provider", OK, f"{provider} (local, no key needed)", required=False)
    else:
        env_key = key_for.get(provider)
        has = bool(os.getenv(env_key or "", "").strip())
        add("LLM provider", OK if has else WARN,
            f"{provider}" + ("" if has else f" but {env_key} is empty"),
            f"Set {env_key} in .env", required=False)

    rl = bool(os.getenv("RANSOMWARE_LIVE_API_KEY", "").strip())
    add("ransomware.live", OK if rl else WARN,
        "PRO key set" if rl else "free tier: personal use only, 1 request/minute/endpoint",
        "Set RANSOMWARE_LIVE_API_KEY for business use", required=False)

    # ── data ──────────────────────────────────────────────────
    add = rep.group("Data")
    try:
        from store import Store, DEFAULT_DB
        db = os.getenv("ONIONCLAW_DB", DEFAULT_DB)
        if os.path.exists(db):
            st = Store(db)
            counts = {k: st.count(k) for k in ("victim", "dls", "group_profile", "kev",
                                               "wallet", "wallet_state", "onion_page")}
            total = sum(counts.values())
            runs = st.recent_runs(1)
            when = "never"
            if runs and runs[0].get("finished"):
                age = (time.time() - runs[0]["finished"]) / 3600
                when = f"{age:.1f} h ago" if age < 48 else f"{age / 24:.1f} days ago"
            add("Observation store", OK if total else WARN,
                f"{total} observations, last sweep {when}" if total else "empty",
                "Run:  python3 swarm.py", required=False)
            add("Store detail", OK, ", ".join(f"{k}={v}" for k, v in counts.items() if v) or "—",
                required=False)
        else:
            add("Observation store", WARN, f"not created yet ({db})",
                "Run:  python3 swarm.py", required=False)
    except Exception as e:
        add("Observation store", FAIL, repr(e)[:70], "The store module failed to load")

    if sicry:
        try:
            health = sicry.check_search_engines(_cached=True)
            up = [e for e in health if e.get("status") == "up"]
            add("Engine health cache", OK if up else WARN,
                f"{len(up)}/{len(health)} engines recorded alive" if health else "no cached health",
                "Run:  python3 check_engines.py   (then search.py --alive)", required=False)
        except Exception:
            add("Engine health cache", WARN, "no cached health",
                "Run:  python3 check_engines.py", required=False)

    return rep


def render(rep: Report, deep: bool) -> str:
    L = [f"OnionClaw doctor {__version__}" + ("" if deep else "   (--deep also tests a live Tor circuit)"), ""]
    width = max(len(r["check"]) for r in rep.rows) + 2
    for name, rows in rep.groups:
        if not rows:
            continue
        L.append(name.upper())
        for r in rows:
            L.append(f"  {_MARK[r['state']]} {r['check']:<{width}}{r['detail']}")
            if r["state"] != OK and r["fix"]:
                L.append(f"    {'':<{width}}→ {r['fix']}")
        L.append("")
    fails = rep.failures()
    warns = [r for r in rep.rows if r["state"] == WARN]
    if fails:
        L.append(f"NOT READY — {len(fails)} required check(s) failed. Fix the arrows above.")
    elif warns:
        L.append(f"READY — {len(warns)} optional item(s) not configured; everything required is in place.")
    else:
        L.append("READY — every check passed.")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Check the OnionClaw setup and report what to fix")
    ap.add_argument("--version", action="version", version=f"OnionClaw doctor {__version__}")
    ap.add_argument("--deep", action="store_true", help="also make one live request through Tor")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rep = build(deep=args.deep)
    if args.json:
        print(json.dumps({
            "version": __version__,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ready": not rep.failures(),
            "groups": [{"name": n, "checks": rows} for n, rows in rep.groups],
        }, indent=2))
    else:
        print(render(rep, args.deep))
    return 1 if rep.failures() else 0


if __name__ == "__main__":
    sys.exit(main())

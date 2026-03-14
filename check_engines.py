#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — check_engines.py
Ping all 18 dark web search engines via Tor and report status + latency.

Usage:
  python3 check_engines.py
"""
import sys, os, json

# ── bootstrap ─────────────────────────────────────────────────────
_skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _skill_dir)

_env = os.path.join(_skill_dir, ".env")
if os.path.exists(_env):
    try:
        from dotenv import load_dotenv
        load_dotenv(_env, override=False)
    except ImportError:
        pass
# ──────────────────────────────────────────────────────────────────

try:
    import sicry
except Exception as _e:
    if "sicry" in str(_e).lower() or "No module named 'sicry'" in str(_e):
        print("ERROR: sicry.py not found in", _skill_dir)
    else:
        print("ERROR: failed to import sicry:", _e)
        print("       Run:  pip install requests[socks] beautifulsoup4 python-dotenv stem")
    sys.exit(1)

print("Checking all 18 search engines via Tor...")
print("(This takes ~15–30 seconds)")
print()

results = sicry.check_search_engines()

alive = sorted([r for r in results if r["status"] == "up"],
               key=lambda x: x.get("latency_ms") or 999999)
dead  = [r for r in results if r["status"] != "up"]

print(f"ALIVE  {len(alive)}/{len(results)}")
print("─" * 50)
for r in alive:
    ms = r.get("latency_ms")
    bar = "█" * min(int((ms or 0) / 200), 20) if ms else ""
    print(f"  ✓  {r['name']:<20}  {ms:>5}ms  {bar}")

if dead:
    print()
    print(f"DOWN   {len(dead)}/{len(results)}")
    print("─" * 50)
    for r in dead:
        err = (r.get("error") or "down")[:40]
        print(f"  ✗  {r['name']:<20}  {err}")

if alive:
    print()
    fastest = alive[0]
    print(f"Fastest: {fastest['name']} ({fastest.get('latency_ms')}ms)")
    print(f"Alive engines for --engines flag:")
    print("  " + " ".join(r["name"] for r in alive))

print()
print(json.dumps(results, indent=2))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — search.py
Search 12 active dark web search engines simultaneously.

Usage:
  python3 search.py --query "TERM"
  python3 search.py --query "TERM" --max 30
  python3 search.py --query "TERM" --engines Ahmia Tor66 Ahmia-clearnet
  python3 search.py --query "TERM" --json          # machine-readable output only
"""
import sys, os, json, argparse

# ── bootstrap ─────────────────────────────────────────────────────
_skill_dir = os.path.dirname(os.path.abspath(__file__))
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

parser = argparse.ArgumentParser(description="Search 17 dark web engines via Tor")
parser.add_argument("--version", action="version",
                    version=f"OnionClaw search {getattr(sicry, '__version__', '?')}")
parser.add_argument("--query",   required=True, help="Search query (≤5 keywords works best)")
parser.add_argument("--max",     type=int, default=20, help="Max results (default 20)")
parser.add_argument("--engines", nargs="*", metavar="ENGINE",
                    help="Specific engines (default: all 17). E.g: Ahmia Tor66 Ahmia-clearnet")
parser.add_argument("--alive", action="store_true",
                    help="Only engines the last check_engines run found alive. Dark web indexes go "
                         "down often and each dead one costs the full TOR_TIMEOUT, so this is much "
                         "faster. Run check_engines.py first to refresh the list.")
parser.add_argument("--json",    action="store_true",
                    help="Output raw JSON only — no human-readable headers")
args = parser.parse_args()

# BUG-5: reject blank queries immediately
if not args.query.strip():
    print("ERROR: --query cannot be empty", file=sys.stderr)
    sys.exit(1)

# BUG-4: validate engine names before searching
if args.engines:
    known_names = {e["name"].lower() for e in getattr(sicry, "SEARCH_ENGINES", [])}
    bad = [n for n in args.engines if n.lower() not in known_names] if known_names else []
    valid = [n for n in args.engines if n.lower() in known_names] if known_names else args.engines
    if bad and not args.json:
        print(f"WARN: unknown engine name(s): {', '.join(bad)}", file=sys.stderr)
    if not valid:
        print(f"ERROR: none of the specified engines are known. "
              f"Known: {', '.join(e['name'] for e in getattr(sicry, 'SEARCH_ENGINES', []))}",
              file=sys.stderr)
        sys.exit(1)
    engines_to_use = valid
elif args.alive:
    try:
        health = sicry.check_search_engines(_cached=True)
    except Exception as _e:
        print(f"ERROR: could not read cached engine health ({_e}). Run check_engines.py first.",
              file=sys.stderr)
        sys.exit(1)
    engines_to_use = [e["name"] for e in health if e.get("status") == "up"]
    if not engines_to_use:
        print("ERROR: no engines recorded as alive. Run check_engines.py first to refresh.",
              file=sys.stderr)
        sys.exit(1)
else:
    engines_to_use = None

if not args.json:
    print(f'Searching dark web: "{args.query}"')
    if engines_to_use:
        print(f"Engines : {', '.join(engines_to_use)}")
    else:
        print("Engines : all 17")
    print()

# Verify Tor is reachable before attempting network calls
if not getattr(sicry, '_tor_port_open', lambda: True)():
    host = getattr(sicry, 'TOR_SOCKS_HOST', '127.0.0.1')
    port = getattr(sicry, 'TOR_SOCKS_PORT', 9050)
    print(f"\u2717 Tor SOCKS port {host}:{port} is not reachable.", file=sys.stderr)
    print("  Start Tor first:  apt install tor && systemctl start tor", file=sys.stderr)
    sys.exit(1)

results = sicry.search(args.query, engines=engines_to_use, max_results=args.max)

if args.json:
    print(json.dumps(results, indent=2))
    sys.exit(0)

if not results:
    print("No results found.")
    print("Tip: run check_engines.py first to see which engines are alive.")
    sys.exit(0)

print(f"Found {len(results)} results:\n")
for i, r in enumerate(results, 1):
    print(f"  {i:>2}. [{r.get('engine', '?')}] {r.get('title', '(no title)')}")
    print(f"       {r.get('url', '')}")

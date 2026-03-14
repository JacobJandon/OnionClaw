#!/usr/bin/env python3
"""
OnionClaw — search.py
Search 18 dark web search engines simultaneously.

Usage:
  python3 search.py --query "TERM"
  python3 search.py --query "TERM" --max 30
  python3 search.py --query "TERM" --engines Ahmia Tor66 Ahmia-clearnet
"""
import sys, os, json, argparse

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
except ImportError:
    print("ERROR: sicry.py not found in", _skill_dir)
    sys.exit(1)

parser = argparse.ArgumentParser(description="Search 18 dark web engines via Tor")
parser.add_argument("--query",   required=True, help="Search query (≤5 keywords works best)")
parser.add_argument("--max",     type=int, default=20, help="Max results (default 20)")
parser.add_argument("--engines", nargs="*", metavar="ENGINE",
                    help="Specific engines (default: all 18). E.g: Ahmia Tor66 Ahmia-clearnet")
args = parser.parse_args()

print(f"Searching dark web: \"{args.query}\"")
if args.engines:
    print(f"Engines : {', '.join(args.engines)}")
else:
    print(f"Engines : all 18")
print()

results = sicry.search(args.query, engines=args.engines, max_results=args.max)

if not results:
    print("No results found.")
    print("Try: check_engines.py first to see which engines are alive.")
    print(json.dumps([], indent=2))
    sys.exit(0)

print(f"Found {len(results)} results:\n")
for i, r in enumerate(results, 1):
    print(f"  {i:>2}. [{r.get('engine', '?')}] {r.get('title', '(no title)')}")
    print(f"       {r.get('url', '')}")

print()
print(json.dumps(results, indent=2))

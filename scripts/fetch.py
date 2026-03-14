#!/usr/bin/env python3
"""
OnionClaw — fetch.py
Fetch any URL or .onion hidden service through Tor.

Usage:
  python3 fetch.py --url "http://example.onion"
  python3 fetch.py --url "http://example.onion" --links
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
except Exception as _e:
    if "sicry" in str(_e).lower() or "No module named 'sicry'" in str(_e):
        print("ERROR: sicry.py not found in", _skill_dir)
    else:
        print("ERROR: failed to import sicry:", _e)
        print("       Run:  pip install requests[socks] beautifulsoup4 python-dotenv stem")
    sys.exit(1)

parser = argparse.ArgumentParser(description="Fetch any URL via Tor")
parser.add_argument("--url",   required=True, help="URL or .onion address to fetch")
parser.add_argument("--links", action="store_true", help="Print all extracted links")
parser.add_argument("--json",  action="store_true", help="Output raw JSON only")
args = parser.parse_args()

url = args.url
if not url.startswith(("http://", "https://")):
    url = "http://" + url

is_onion = ".onion" in url
print(f"Fetching {'[.onion]' if is_onion else '[clearnet via Tor]'}: {url}")
print()

result = sicry.fetch(url)

if args.json:
    print(json.dumps(result, indent=2))
    sys.exit(0 if not result.get("error") else 1)

if result.get("error"):
    print(f"✗ Fetch failed")
    print(f"  Status : {result.get('status', 0)}")
    print(f"  Error  : {result['error']}")
    if is_onion:
        print()
        print("  The hidden service may be offline. Try again in a few minutes.")
    sys.exit(1)

print(f"✓ {result.get('title', '(no title)')}")
print(f"  Status : {result['status']}")
print(f"  Links  : {len(result.get('links', []))} found")
print()
print("─" * 60)
print("CONTENT")
print("─" * 60)
content = result.get("text", "")
print(content[:4000])
if len(content) > 4000:
    print(f"\n... [{len(content) - 4000} more chars — use --json for full output]")

if args.links and result.get("links"):
    print()
    print("─" * 60)
    print("LINKS")
    print("─" * 60)
    for link in result["links"][:40]:
        label = link.get("text", "").strip() or "(no label)"
        href  = link.get("href", "")
        print(f"  {label[:50]:<50}  {href}")

print()
print(json.dumps(result, indent=2))

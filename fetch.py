#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — fetch.py
Fetch any URL or .onion hidden service through Tor.

Usage:
  python3 fetch.py --url "http://example.onion"
  python3 fetch.py --url "http://example.onion" --links  python3 fetch.py --url "http://example.onion" --json   # machine-readable only"""
import sys, os, json, argparse

# ── bootstrap ─────────────────────────────────────────────────────
_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)
from _version import __version__ as ONIONCLAW_VERSION  # noqa: E402

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
parser.add_argument("--version",     action="version",
                    version=f"OnionClaw fetch {ONIONCLAW_VERSION} (SICRY\u2122 engine {getattr(sicry, '__version__', '?')})")
parser.add_argument("--url",         required=True, help="URL or .onion address to fetch")
parser.add_argument("--links",       action="store_true", help="Print all extracted links")
parser.add_argument("--json",        action="store_true", help="Output raw JSON only")
parser.add_argument("--clear-cache", action="store_true", help="Delete all cached fetch results before running")
args = parser.parse_args()

if args.clear_cache:
    n = sicry.clear_cache()
    # stderr, so --json output stays valid JSON
    print(f"Cleared {n} cached fetch result(s).", file=sys.stderr)

url = args.url
if not url.startswith(("http://", "https://")):
    url = "http://" + url

is_onion = ".onion" in url

# Verify Tor is reachable before attempting to fetch
if not getattr(sicry, '_tor_port_open', lambda: True)():
    host = getattr(sicry, 'TOR_SOCKS_HOST', '127.0.0.1')
    port = getattr(sicry, 'TOR_SOCKS_PORT', 9050)
    print(f"\u2717 Tor SOCKS port {host}:{port} is not reachable.", file=sys.stderr)
    print("  Start Tor first:  apt install tor && systemctl start tor", file=sys.stderr)
    sys.exit(1)

# BUG-2: only print human header when not in --json mode
if not args.json:
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
# The whole text sicry returned: a second, silent cut at 4,000 chars hid the rest of
# pages up to SICRY_MAX_CHARS long.
print(content)
if result.get("truncated"):
    print(f"\n... [page longer than SICRY_MAX_CHARS ({len(content):,} chars shown); "
          f"raise SICRY_MAX_CHARS to see more]")

if args.links and result.get("links"):
    print()
    print("─" * 60)
    print("LINKS")
    print("─" * 60)
    for link in result["links"][:40]:
        label = link.get("text", "").strip() or "(no label)"
        href  = link.get("href", "")
        print(f"  {label[:50]:<50}  {href}")

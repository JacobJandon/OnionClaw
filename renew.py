#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — renew.py
Rotate the Tor circuit and get a new exit node / identity.
"""
import sys, os, json

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

import argparse as _ap
_parser = _ap.ArgumentParser(
    description="OnionClaw — rotate Tor circuit and get a new exit identity")
_parser.add_argument("--version", action="version",
                     version=f"OnionClaw renew {getattr(sicry, '__version__', '?')}")
_parser.add_argument("--json", action="store_true",
                     help="Print only the JSON result, no human-readable output")
_args = _parser.parse_args()

if not _args.json:
    print("Rotating Tor circuit...")
result = sicry.renew_identity()

if _args.json:
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["success"] else 1)

if result["success"]:
    print("✓ Identity renewed — new Tor circuit established")
    print("  The next request will use a different exit node.")
else:
    print(f"✗ Renew failed: {result['error']}")
    print()
    print("  Common causes:")
    print("  1. ControlPort 9051 not enabled in torrc")
    print("     → Add: ControlPort 9051  and  CookieAuthentication 1")
    print("  2. TOR_DATA_DIR not set in .env")
    print("     → Set TOR_DATA_DIR=/tmp/tor_data  (your Tor DataDirectory)")
    print("  3. TOR_CONTROL_PASSWORD wrong (if HashedControlPassword is set)")
    sys.exit(1)

print()
print(json.dumps(result, indent=2))

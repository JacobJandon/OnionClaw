#!/usr/bin/env python3
"""
OnionClaw — check_tor.py
Verify Tor is running and return the exit IP address.
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
except ImportError:
    print("ERROR: sicry.py not found in", _skill_dir)
    print("       Make sure sicry.py is in the OnionClaw folder.")
    sys.exit(1)

result = sicry.check_tor()

if result["tor_active"]:
    print(f"✓ Tor active")
    print(f"  Exit IP  : {result['exit_ip']}")
    print(f"  Error    : {result['error']}")
else:
    print(f"✗ Tor NOT active")
    print(f"  Error    : {result['error']}")
    print()
    print("  Start Tor first:")
    print("    Linux : apt install tor && tor &")
    print("    macOS : brew install tor && tor &")
    sys.exit(1)

print()
print(json.dumps(result, indent=2))

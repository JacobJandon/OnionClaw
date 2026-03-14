#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — ask.py
Analyse dark web content with an LLM and get a structured OSINT report.

Usage:
  python3 ask.py --query "QUERY" --mode MODE --content "RAW TEXT"
  python3 ask.py --query "QUERY" --mode MODE --file /path/to/content.txt
  echo "content" | python3 ask.py --query "QUERY" --mode MODE

Modes: threat_intel (default), ransomware, personal_identity, corporate
"""
import sys, os, argparse

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
        print("       Make sure sicry.py is in the OnionClaw folder.")
    else:
        print("ERROR: failed to import sicry:", _e)
        print("       Run:  pip install requests[socks] beautifulsoup4 python-dotenv stem")
    sys.exit(1)

MODES = ["threat_intel", "ransomware", "personal_identity", "corporate"]

parser = argparse.ArgumentParser(description="OSINT analysis of dark web content")
parser.add_argument("--query",   default="", help="Investigation query / topic")
parser.add_argument("--mode",    default="threat_intel", choices=MODES,
                    help="Analysis mode (default: threat_intel)")
parser.add_argument("--content", default=None, help="Content to analyse (inline string)")
parser.add_argument("--file",    default=None, help="File containing content to analyse")
parser.add_argument("--custom",  default="", help="Custom instructions appended to the mode prompt")
args = parser.parse_args()

# ── Load content ──────────────────────────────────────────────────
if args.file:
    try:
        with open(args.file, "r", errors="replace") as f:
            content = f.read()
        print(f"Content: loaded from {args.file} ({len(content)} chars)")
    except OSError as e:
        print(f"ERROR: cannot read file: {e}")
        sys.exit(1)
elif args.content:
    content = args.content
    print(f"Content: {len(content)} chars (inline)")
elif not sys.stdin.isatty():
    content = sys.stdin.read()
    print(f"Content: {len(content)} chars (stdin)")
else:
    print("ERROR: provide content via --content, --file, or stdin")
    parser.print_help()
    sys.exit(1)

if not content.strip():
    print("ERROR: content is empty")
    sys.exit(1)

print(f"Query  : {args.query or '(none)'}")
print(f"Mode   : {args.mode}")
if args.custom:
    print(f"Custom : {args.custom[:80]}")
print()
print("Analysing via LLM...")
print()

report = sicry.ask(
    content,
    query=args.query,
    mode=args.mode,
    custom_instructions=args.custom,
)

if report.startswith("[SICRY:"):
    print("✗ LLM error:", report)
    print()
    print("  Set LLM_PROVIDER and API key in", os.path.join(_skill_dir, ".env"))
    print("  Options: LLM_PROVIDER=openai|anthropic|gemini|ollama|llamacpp")
    sys.exit(1)

print(report)

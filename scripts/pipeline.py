#!/usr/bin/env python3
"""
OnionClaw — pipeline.py
Full Robin OSINT pipeline: refine → check engines → search → filter → scrape → ask.

This is the recommended single-command investigation workflow.

Usage:
  python3 pipeline.py --query "INVESTIGATION TOPIC"
  python3 pipeline.py --query "QUERY" --mode ransomware
  python3 pipeline.py --query "QUERY" --mode corporate --max 50 --scrape 12
  python3 pipeline.py --query "QUERY" --mode threat_intel --out report.md
"""
import sys, os, argparse, json

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

MODES = ["threat_intel", "ransomware", "personal_identity", "corporate"]

parser = argparse.ArgumentParser(description="Full dark web OSINT pipeline")
parser.add_argument("--query",  required=True, help="Investigation topic (natural language OK)")
parser.add_argument("--mode",   default="threat_intel", choices=MODES,
                    help="Analysis mode (default: threat_intel)")
parser.add_argument("--max",    type=int, default=30,
                    help="Max raw search results (default 30)")
parser.add_argument("--scrape", type=int, default=8,
                    help="Pages to batch-scrape (default 8)")
parser.add_argument("--custom", default="",
                    help="Custom LLM instructions appended to mode prompt")
parser.add_argument("--out",    default=None,
                    help="Write final report to this file")
parser.add_argument("--engines", nargs="*", metavar="ENGINE",
                    help="Limit search to specific engines (default: check live first)")
args = parser.parse_args()

def _step(n, total, label):
    print(f"\n[{n}/{total}] {label}")
    print("─" * 55)

TOTAL = 7

# ──────────────────────────────────────────────────────────────────
# Step 1: Verify Tor
# ──────────────────────────────────────────────────────────────────
_step(1, TOTAL, "Verify Tor connectivity")
status = sicry.check_tor()
if not status["tor_active"]:
    print(f"✗ Tor is not active: {status['error']}")
    print("  Start Tor first:  apt install tor && tor &")
    sys.exit(1)
print(f"✓ Tor active | exit IP: {status['exit_ip']}")

# ──────────────────────────────────────────────────────────────────
# Step 2: Health-check engines
# ──────────────────────────────────────────────────────────────────
live_names = args.engines
if not live_names:
    _step(2, TOTAL, "Check which search engines are alive")
    engine_status = sicry.check_search_engines()
    alive = sorted([e for e in engine_status if e["status"] == "up"],
                   key=lambda x: x.get("latency_ms") or 999999)
    dead  = [e for e in engine_status if e["status"] != "up"]
    live_names = [e["name"] for e in alive]
    total_engines = len(engine_status)
    print(f"✓ {len(alive)}/{total_engines} engines alive  |  {len(dead)} down")
    if alive:
        print(f"  Fastest: {alive[0]['name']} ({alive[0].get('latency_ms')}ms)")
    if not alive:
        print("✗ No engines alive — check your Tor connection")
        sys.exit(1)
else:
    # Validate specified engine names against SICRY's known list
    known = {e["name"].lower() for e in getattr(sicry, "SEARCH_ENGINES", [])}
    bad = [n for n in live_names if n.lower() not in known] if known else []
    if bad:
        print(f"WARN: unknown engine(s): {', '.join(bad)} — will be ignored by search()")
    _step(2, TOTAL, f"Using specified engines: {', '.join(live_names)}")

# ──────────────────────────────────────────────────────────────────
# Step 3: Refine query (Robin quality pattern)
# ──────────────────────────────────────────────────────────────────
_step(3, TOTAL, "Refine query")
raw_query = args.query
refined = sicry.refine_query(raw_query)
if refined != raw_query:
    print(f"  Original : {raw_query}")
    print(f"  Refined  : {refined}")
else:
    print(f"  Query    : {refined}  (no LLM key — using as-is)")

# ──────────────────────────────────────────────────────────────────
# Step 4: Search
# ──────────────────────────────────────────────────────────────────
_step(4, TOTAL, f"Search {len(live_names)} engines for: \"{refined}\"")
raw_results = sicry.search(refined, engines=live_names, max_results=args.max)
print(f"✓ {len(raw_results)} raw results (deduplicated)")
if not raw_results:
    print("No results found. Try a broader query or different engines.")
    sys.exit(0)
for r in raw_results[:5]:
    print(f"  [{r.get('engine','?')}] {r.get('title', '?')[:65]}")
if len(raw_results) > 5:
    print(f"  ... and {len(raw_results) - 5} more")

# ──────────────────────────────────────────────────────────────────
# Step 5: Filter to best results (Robin quality pattern)
# ──────────────────────────────────────────────────────────────────
_step(5, TOTAL, "Filter to most relevant results")
best = sicry.filter_results(refined, raw_results)
print(f"✓ {len(best)} most relevant results selected")
if len(best) == len(raw_results[:20]):
    print("  (no LLM key — using top 20 by position)")

# ──────────────────────────────────────────────────────────────────
# Step 6: Batch scrape
# ──────────────────────────────────────────────────────────────────
scrape_count = min(args.scrape, len(best))
_step(6, TOTAL, f"Batch-scrape top {scrape_count} pages concurrently")
pages = sicry.scrape_all(best[:scrape_count], max_workers=5)
print(f"✓ {len(pages)}/{scrape_count} pages scraped successfully")
if len(pages) < scrape_count:
    print(f"  {scrape_count - len(pages)} pages were unreachable (hidden services can be offline)")
total_chars = sum(len(v) for v in pages.values())
print(f"  Total content: {total_chars:,} chars")

if not pages:
    print("No pages could be scraped — all hidden services unreachable.")
    sys.exit(0)

# ──────────────────────────────────────────────────────────────────
# Step 7: OSINT analysis
# ──────────────────────────────────────────────────────────────────
_step(7, TOTAL, f"OSINT analysis — mode: {args.mode}")
combined = "\n\n".join(f"[SOURCE: {url}]\n{text}" for url, text in pages.items())
report = sicry.ask(
    combined,
    query=refined,
    mode=args.mode,
    custom_instructions=args.custom,
)

print()
if report.startswith("[SICRY:"):
    print("✗ LLM error:", report)
    print()
    print("  Set LLM_PROVIDER and API key in", os.path.join(_skill_dir, ".env"))
    print("  The scraped content is available even without an LLM key.")
    print()
    print("  Scraped URLs:")
    for url in pages:
        print(f"    {url}")
    sys.exit(1)

print("=" * 55)
print("INVESTIGATION REPORT")
print("=" * 55)
print(report)

if args.out:
    try:
        with open(args.out, "w") as f:
            f.write(f"# OnionClaw OSINT Report\n\n")
            f.write(f"**Query:** {args.query}\n")
            f.write(f"**Mode:** {args.mode}\n\n")
            f.write(report)
        print(f"\nReport saved to: {args.out}")
    except OSError as e:
        print(f"\nWARN: could not write output file: {e}")

# ── Rotate identity when done ──────────────────────────────────────
sicry.renew_identity()
print("\n[+] Tor identity rotated.")

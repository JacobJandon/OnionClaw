#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — pipeline.py v2.0.0
Full OSINT pipeline: refine → check engines → search → filter → scrape → ask.
Includes: SQLite resume checkpoints, confidence scores, STIX/CSV/JSON/MD output,
          watch/alert mode, no-LLM mode via analyze_nollm(), mode routing.

Usage:
  python3 pipeline.py --query "INVESTIGATION TOPIC"
  python3 pipeline.py --query "QUERY" --mode ransomware --format stix --out bundle.json
  python3 pipeline.py --query "QUERY" --mode corporate --max 50 --scrape 12
  python3 pipeline.py --query "QUERY" --no-llm --confidence
  python3 pipeline.py --query "QUERY" --watch --interval 4
  python3 pipeline.py --watch-check
  python3 pipeline.py --query "QUERY" --resume <job_id>
  python3 pipeline.py --interactive
"""
import sys, os, argparse, json, uuid, time as _time

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

MODES = ["threat_intel", "ransomware", "personal_identity", "corporate"]

parser = argparse.ArgumentParser(
    prog="pipeline",
    description="OnionClaw full dark web OSINT pipeline",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  python3 pipeline.py --query "ransomware data leak" --mode ransomware
  python3 pipeline.py --query "QUERY" --no-llm --confidence
  python3 pipeline.py --query "QUERY" --format stix --out bundle.json
  python3 pipeline.py --query "QUERY" --watch --interval 6
  python3 pipeline.py --watch-check
  python3 pipeline.py --query "QUERY" --resume abc123
  python3 pipeline.py --interactive
    """,
)
parser.add_argument("--version",      action="version",
                    version=f"OnionClaw pipeline {getattr(sicry, '__version__', '?')}")
parser.add_argument("--query",        default=None,
                    help="Investigation topic (required unless --watch-check or --interactive)")
parser.add_argument("--mode",         default="threat_intel", choices=MODES,
                    help="Analysis mode — routes to optimal engines (default: threat_intel)")
parser.add_argument("--max",          type=int, default=30,
                    help="Max raw search results (default 30)")
parser.add_argument("--scrape",       type=int, default=8,
                    help="Pages to batch-scrape (default 8)")
parser.add_argument("--custom",       default="",
                    help="Custom LLM instructions appended to mode prompt")
parser.add_argument("--out",          default=None,
                    help="Write final report to this file")
parser.add_argument("--engines",      nargs="*", metavar="ENGINE",
                    help="Limit search to specific engines")
parser.add_argument("--no-llm",       action="store_true",
                    help="Skip LLM steps — use analyze_nollm() for structured entity/keyword extraction")
parser.add_argument("--confidence",   action="store_true",
                    help="Show BM25 confidence scores next to each search result")
parser.add_argument("--format",       choices=["md", "json", "csv", "stix"], default="md",
                    help="Output format for --out (default: md)")
parser.add_argument("--clear-cache",  action="store_true",
                    help="Clear all cached fetch results before running")
parser.add_argument("--check-update", action="store_true",
                    help="Check GitHub for the latest OnionClaw release and exit")
parser.add_argument("--watch",        action="store_true",
                    help="Register this query as a watch/alert job and exit")
parser.add_argument("--interval",     type=float, default=6.0,
                    help="Watch re-check interval in hours (default: 6, requires --watch)")
parser.add_argument("--watch-check",  action="store_true",
                    help="Run all due watch jobs now and exit")
parser.add_argument("--resume",       default=None, metavar="JOB_ID",
                    help="Resume a previous pipeline run from its SQLite checkpoint")
parser.add_argument("--interactive",  action="store_true",
                    help="Interactive drill-down mode — ask follow-up questions after the report")
parser.add_argument("--no-cache",     action="store_true",
                    help="Skip search cache, force live queries")
args = parser.parse_args()

# ── BUG-4: warn if --interval used without --watch ─────────────────────────
if args.interval != 6.0 and not args.watch and not args.watch_check:
    print("WARN: --interval only takes effect with --watch. Ignoring.",
          file=sys.stderr)

# ── pre-run actions ───────────────────────────────────────────────
if args.clear_cache:
    n = sicry.clear_cache()
    print(f"[cache] Cleared {n} cached result(s).")

if args.check_update:
    _u = sicry.check_update()
    if _u["error"] and not _u["latest"]:
        print(f"Update check failed: {_u['error']}")
    elif _u["up_to_date"]:
        print(f"OnionClaw {_u['current']} is up-to-date.")
    else:
        print(f"Update available: v{_u['current']} → v{_u['latest']}")
        if _u["url"]:
            print(f"  Release notes : {_u['url']}")
        print(f"  Upgrade       : git -C {_skill_dir} pull")
        print(f"                  python3 {os.path.join(_skill_dir, 'sync_sicry.py')}")
    sys.exit(0)

# ── standalone: watch-check ───────────────────────────────────────
if args.watch_check:
    print("[watch-check] Running all due watch jobs…")
    alerts = sicry.watch_check()
    if not alerts:
        print("  No due jobs or no new results.")
    else:
        for a in alerts:
            print(f"  [{a['job_id']}] {a.get('new_count', 0)} new results "
                  f"for query: {a.get('query')!r}")
    sys.exit(0)

# ── standalone: interactive mode (no --query required) ───────────
if args.interactive and not args.query:
    print("OnionClaw Interactive Mode  (type 'exit' to quit)")
    print("=" * 55)
    while True:
        try:
            q = input("\nQuery > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break
        if q.lower() in ("exit", "quit", "q"):
            print("Goodbye.")
            break
        if not q:
            continue
        results = sicry.search(q, max_results=20, mode=args.mode,
                               _use_cache=not args.no_cache)
        if not results:
            print("  No results.")
            continue
        for i, r in enumerate(results, 1):
            conf_str = f"  [{r.get('confidence', 0):.2f}]" if args.confidence else ""
            print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title','')[:60]}")
            print(f"       {r['url']}")
        print("\n  Commands: <number> fetch page  |  new query = type it  |  'exit' quit")
        cmd = input("  > ").strip()
        if cmd.lower() in ("exit", "quit", "q"):
            print("Goodbye.")
            break
        if cmd.isdigit():
            idx = int(cmd) - 1
            if 0 <= idx < len(results):
                page = sicry.fetch(results[idx]["url"])
                if page["error"]:
                    print(f"  Error: {page['error']}")
                else:
                    print(f"\n  === {page['title']} ===")
                    print(page["text"][:4000])
    sys.exit(0)

# ── BUG-1: load checkpoint early so --resume can restore the query ────────
_checkpoint: dict = {}
_job_id = args.resume or str(uuid.uuid4())[:8]

if args.resume:
    try:
        from sicry import _db
        _checkpoint = _db().cache_get(
            f"pipeline_checkpoint:{args.resume}", "pipeline", ttl=86400 * 90
        ) or {}
        if _checkpoint:
            # Restore the original query from the checkpoint if caller omitted it
            if not args.query:
                args.query = (_checkpoint.get("data") or {}).get("__meta__", {}).get("query")
            print(f"[resume] Loaded checkpoint for job {args.resume!r}")
            print(f"         Steps already completed: {list(_checkpoint.get('steps', {}).keys())}")
            if args.query:
                print(f"         Query: {args.query!r}")
        else:
            # BUG-1/4: no checkpoint + no --query → clean error, not argparse noise
            if not args.query:
                print(f"ERROR: No checkpoint found for job {args.resume!r}.",
                      file=sys.stderr)
                print(f"       Either provide --query to start fresh, or check the job ID.",
                      file=sys.stderr)
                sys.exit(1)
            print(f"[resume] No checkpoint found for {args.resume!r} — starting fresh")
    except Exception as _re:
        print(f"[resume] Warning: could not load checkpoint — {_re}", file=sys.stderr)

# ── UX-2: clean error for empty --query before argparse prints the usage block
if args.query is not None and not args.query.strip():
    print("ERROR: --query cannot be empty.", file=sys.stderr)
    sys.exit(1)

# ── --query required from here ────────────────────────────────────────────
if not args.query:
    parser.error("--query is required")

# ── standalone: register watch job ────────────────────────────────
if args.watch:
    job_id = sicry.watch_add(args.query, mode=args.mode,
                             interval_hours=args.interval)
    print(f"Watch job registered: {job_id}")
    print(f"  Query   : {args.query!r}")
    print(f"  Mode    : {args.mode}")
    print(f"  Interval: every {args.interval}h")
    print(f"  Run 'python3 pipeline.py --watch-check' to check due jobs.")
    sys.exit(0)

# ── passive update notice ─────────────────────────────────────────
try:
    _u = sicry.check_update()
    if not _u["up_to_date"] and not _u["error"]:
        print(f"\n⚡ OnionClaw update available: "
              f"v{_u['current']} → v{_u['latest']}  "
              f"| run with --check-update for details\n")
except Exception:
    pass

NO_LLM = args.no_llm

def _step(n, total, label):
    print(f"\n[{n}/{total}] {label}")
    print("─" * 55)

TOTAL = 7  # 7 steps; LLM steps marked [skip N/7] with --no-llm

def _save_checkpoint(step: str, data):
    try:
        from sicry import _db
        _checkpoint.setdefault("steps", {})[step] = True
        _checkpoint.setdefault("data", {})[step] = data
        _db().cache_set(f"pipeline_checkpoint:{_job_id}", "pipeline", _checkpoint)
    except Exception:
        pass

def _ckpt(step: str):
    return _checkpoint.get("data", {}).get(step)

# ─────────────────────────────────────────────────────────────────
# Step 1: Verify Tor
# ─────────────────────────────────────────────────────────────────
_step(1, TOTAL, "Verify Tor connectivity")
status = sicry.check_tor()
if not status["tor_active"]:
    print(f"✗ Tor is not active: {status['error']}")
    print("  Start Tor first:  apt install tor && tor &")
    sys.exit(1)
print(f"✓ Tor active | exit IP: {status['exit_ip']}")

# ─────────────────────────────────────────────────────────────────
# Step 2: Health-check engines
# ─────────────────────────────────────────────────────────────────
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
        rel = alive[0].get("reliability")
        rel_str = f"  reliability={rel:.0%}" if rel is not None else ""
        print(f"  Fastest: {alive[0]['name']} ({alive[0].get('latency_ms')}ms){rel_str}")
    if not alive:
        print("✗ No engines alive — check your Tor connection")
        sys.exit(1)
    # Mode-based engine routing
    if args.mode in MODES:
        mc = sicry.mode_config(args.mode)
        mode_engines = mc.get("engines")
        if mode_engines:
            filtered = [n for n in live_names if n in mode_engines]
            if filtered:
                print(f"  Mode '{args.mode}' filter: using {len(filtered)} of {len(live_names)} engines")
                live_names = filtered
            else:
                print(f"  Mode '{args.mode}': no preferred engines alive — using all")
else:
    known = {e["name"].lower() for e in getattr(sicry, "SEARCH_ENGINES", [])}
    bad = [n for n in live_names if n.lower() not in known] if known else []
    if bad:
        print(f"WARN: unknown engine(s): {', '.join(bad)} — will be ignored by search()")
    _step(2, TOTAL, f"Using specified engines: {', '.join(live_names)}")

# ─────────────────────────────────────────────────────────────────
# Step 3: Refine query (LLM step — skipped with --no-llm)
# ─────────────────────────────────────────────────────────────────
raw_query = args.query
# Persist query in checkpoint so --resume <job_id> can re-run without --query
if not _ckpt("__meta__"):
    _save_checkpoint("__meta__", {"query": raw_query, "mode": args.mode})
    refined = raw_query
    print(f"\n[skip 3/{TOTAL}] Query refinement skipped (--no-llm)")
    print(f"    Query: {refined}")
else:
    cached_refined = _ckpt("refine")
    if cached_refined:
        refined = cached_refined
        print(f"\n[3/{TOTAL}] Query refinement (from checkpoint)")
        print(f"    Query: {refined}")
    else:
        _step(3, TOTAL, "Refine query")
        refined = sicry.refine_query(raw_query)
        if refined != raw_query:
            print(f"  Original : {raw_query}")
            print(f"  Refined  : {refined}")
        else:
            print(f"  Query    : {refined}  (no LLM key — using as-is)")
        _save_checkpoint("refine", refined)

# ─────────────────────────────────────────────────────────────────
# Step 4: Search
# ─────────────────────────────────────────────────────────────────
_step(4, TOTAL, f"Search {len(live_names)} engines for: \"{refined}\"")
cached_results = _ckpt("search")
if cached_results:
    raw_results = cached_results
    print(f"  (from checkpoint: {len(raw_results)} results)")
else:
    raw_results = sicry.search(
        refined,
        engines=live_names,
        max_results=args.max,
        mode=args.mode,
        _use_cache=not args.no_cache,
    )
    _save_checkpoint("search", raw_results)

print(f"✓ {len(raw_results)} raw results (deduplicated)")
if not raw_results:
    print("No results found. Try a broader query or different engines.")
    sys.exit(0)
for r in raw_results[:5]:
    conf_str = f"  [conf={r.get('confidence', 0):.2f}]" if args.confidence and "confidence" in r else ""
    print(f"  [{r.get('engine','?')}]{conf_str} {r.get('title', '?')[:65]}")
if len(raw_results) > 5:
    print(f"  ... and {len(raw_results) - 5} more")

# ─────────────────────────────────────────────────────────────────
# Step 5: Filter (LLM) or rank by confidence (--no-llm)
# ─────────────────────────────────────────────────────────────────
if NO_LLM:
    best = sorted(raw_results, key=lambda x: x.get("confidence", 0), reverse=True)[:20]
    print(f"\n[5/{TOTAL}] Ranked top {len(best)} results by BM25 confidence (--no-llm)")
    if args.confidence and best:
        for i, r in enumerate(best[:10], 1):
            print(f"  {i:>3}. [conf={r.get('confidence', 0):.4f}] "
                  f"[{r.get('engine','?')}] {r.get('title','?')[:55]}")
else:
    cached_best = _ckpt("filter")
    if cached_best:
        best = cached_best
        print(f"\n[5/{TOTAL}] Result filtering (from checkpoint: {len(best)} results)")
    else:
        _step(5, TOTAL, "Filter to most relevant results")
        best = sicry.filter_results(refined, raw_results)
        print(f"✓ {len(best)} most relevant results selected")
        if len(best) == len(raw_results[:20]):
            print("  (no LLM key — using top 20 by position)")
        _save_checkpoint("filter", best)

# ─────────────────────────────────────────────────────────────────
# Step 6: Batch scrape
# ─────────────────────────────────────────────────────────────────
scrape_count = min(args.scrape, len(best))
_step(6, TOTAL, f"Batch-scrape top {scrape_count} pages concurrently")

cached_pages = _ckpt("scrape")
if cached_pages:
    pages = cached_pages
    print(f"  (from checkpoint: {len(pages)} pages)")
else:
    pages = sicry.scrape_all(best[:scrape_count], max_workers=5)
    _save_checkpoint("scrape", pages)

print(f"✓ {len(pages)}/{scrape_count} pages scraped successfully")
if len(pages) < scrape_count:
    print(f"  {scrape_count - len(pages)} pages were unreachable (hidden services can be offline)")
total_chars = sum(len(v) for v in pages.values())
print(f"  Total content: {total_chars:,} chars")

if not pages:
    print("No pages could be scraped — all hidden services unreachable.")
    sys.exit(0)

# ─────────────────────────────────────────────────────────────────
# Step 7: Analysis
# ─────────────────────────────────────────────────────────────────
combined = "\n\n".join(f"[SOURCE: {url}]\n{text}" for url, text in pages.items())

if NO_LLM:
    _step(7, TOTAL, "No-LLM entity/keyword extraction (analyze_nollm)")
    report = sicry.analyze_nollm(combined, query=refined)
    header_label = "ANALYSIS REPORT (no-LLM)"
else:
    cached_report = _ckpt("ask")
    if cached_report:
        report = cached_report
        print(f"\n[7/{TOTAL}] LLM analysis (from checkpoint)")
        header_label = "INVESTIGATION REPORT"
    else:
        _step(7, TOTAL, f"OSINT analysis — mode: {args.mode}")
        report = sicry.ask(
            combined,
            query=refined,
            mode=args.mode,
            custom_instructions=args.custom,
        )
        _save_checkpoint("ask", report)
        header_label = "INVESTIGATION REPORT"

print()
if not NO_LLM and report.startswith("[SICRY:"):
    print("✗ LLM error:", report)
    print()
    print("  Set LLM_PROVIDER and API key in", os.path.join(_skill_dir, ".env"))
    print("  Tip: re-run with --no-llm for structured entity extraction without an API key.")
    print()
    print("  Scraped URLs:")
    for url in pages:
        print(f"    {url}")
    sys.exit(1)

print("=" * 55)
print(header_label)
print("=" * 55)
print(report)

# ─────────────────────────────────────────────────────────────────
# Output file: --format controls encoding
# ─────────────────────────────────────────────────────────────────
if args.out:
    fmt = args.format
    try:
        if fmt == "json":
            out_payload = json.dumps({
                "query": args.query,
                "refined_query": None if NO_LLM else refined,
                "mode": args.mode,
                "results": best,
                "report": report,
                "job_id": _job_id,
            }, indent=2)
        elif fmt == "csv":
            out_payload = sicry.to_csv(best)
        elif fmt == "stix":
            out_payload = json.dumps(
                sicry.to_stix(best, query=refined, report_text=report),
                indent=2,
            )
        else:  # md (default)
            kw_list = sicry.extract_keywords(combined, top_n=15)
            keywords = ", ".join(kw_list)
            import datetime
            out_payload = (
                f"# OnionClaw OSINT Report\n\n"
                f"**Query:** {args.query}  \n"
                + (f"**Refined:** {refined}  \n" if not NO_LLM and refined != raw_query else "")
                + f"**Mode:** {args.mode}  \n"
                f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n"
                f"**Job ID:** {_job_id}  \n\n"
                f"---\n\n"
                f"{report}\n\n"
                f"---\n\n"
                f"## Top Keywords\n\n{keywords}\n\n"
                f"## Sources ({len(best)} results)\n\n"
                + "\n".join(
                    f"- [{r.get('title','(no title)')[:80]}]({r['url']})"
                    + (f" — conf={r.get('confidence',0):.2f}" if args.confidence else "")
                    for r in best
                )
            )
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_payload)
        print(f"\nReport saved to: {args.out}  (format: {fmt})")
    except Exception as _we:
        print(f"\nERROR: could not write output file: {_we}", file=sys.stderr)
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Interactive follow-up drill-down (--interactive + --query)
# ─────────────────────────────────────────────────────────────────
if args.interactive:
    print("\n[interactive] Ask follow-up questions about the report above.")
    print("  Type 'exit' to quit, 'fetch N' to fetch result N.\n")
    while True:
        try:
            q = input("Follow-up > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break
        if q.lower() in ("exit", "quit", "q", ""):
            break
        if q.lower().startswith("fetch "):
            parts = q.split()
            if len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1]) - 1
                if 0 <= idx < len(best):
                    page = sicry.fetch(best[idx]["url"])
                    if page["error"]:
                        print(f"Error: {page['error']}")
                    else:
                        print(f"\n=== {page['title']} ===")
                        print(page["text"][:4000])
            continue
        follow_results = sicry.search(q, max_results=10, mode=args.mode)
        for i, r in enumerate(follow_results[:8], 1):
            conf_str = f"  [conf={r.get('confidence',0):.2f}]" if args.confidence else ""
            print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title','')[:65]}")
            print(f"       {r['url']}")

# ── Rotate identity when done ──────────────────────────────────────
sicry.renew_identity()
print("\n[+] Tor identity rotated.  Job ID:", _job_id)

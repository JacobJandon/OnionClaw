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
  python3 pipeline.py --query "QUERY" --format misp --out event.json --misp-threat-level 1
  python3 pipeline.py --watch-list
  python3 pipeline.py --modes
  python3 pipeline.py --engine-stats

TorPool (multi-circuit Tor):
  Set SICRY_POOL_SIZE=N in .env to use N isolated Tor circuits (see .env.example).
  pipeline.py prints pool status at step 1 when SICRY_POOL_SIZE > 0.
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
parser.add_argument("--format",       choices=["md", "json", "csv", "stix", "misp"], default="md",
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
parser.add_argument("--watch-list",   action="store_true",
                    help="List all active watch jobs and exit")
parser.add_argument("--watch-disable", default=None, metavar="JOB_ID",
                    help="Disable a watch job by ID and exit")
parser.add_argument("--resume",       default=None, metavar="JOB_ID",
                    help="Resume a previous pipeline run from its SQLite checkpoint")
parser.add_argument("--interactive",  action="store_true",
                    help="Interactive drill-down mode — ask follow-up questions after the report")
parser.add_argument("--no-cache",     action="store_true",
                    help="Skip search cache, force live queries")
parser.add_argument("--modes",         action="store_true",
                    help="List all modes and their engine routing, then exit")
parser.add_argument("--engine-stats",  action="store_true",
                    help="Print per-engine reliability / latency table and exit")
parser.add_argument("--watch-daemon",  action="store_true",
                    help="Run watch daemon as a foreground loop (Ctrl+C to stop)")
parser.add_argument("--daemon-poll",   type=int, default=None, metavar="SECONDS",
                    help="Daemon poll interval in seconds (default: 360). Overrides --interval for daemon tick rate.")
parser.add_argument("--misp-threat-level", type=int, default=2, choices=[1, 2, 3, 4],
                    help="MISP threat level (1=High 2=Medium 3=Low 4=Undefined; default 2)")
parser.add_argument("--misp-distribution", type=int, default=0,
                    choices=[0, 1, 2, 3, 4, 5],
                    help="MISP distribution setting (0=Organisation only … 5=All; default 0)")
parser.add_argument("--output-dir",    default=None, metavar="DIR",
                    help="Write output to DIR/<job_id>.<ext> instead of --out (batch-friendly)")
parser.add_argument("--watch-clear-all", action="store_true",
                    help="Disable ALL active watch jobs at once and exit")
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
    # IMPROVE-5: also check if bundled sicry.py is behind upstream SICRY™
    try:
        import urllib.request
        _sicry_api = "https://api.github.com/repos/JacobJandon/Sicry/tags?per_page=1"
        with urllib.request.urlopen(_sicry_api, timeout=4) as _sr:
            _stags = json.loads(_sr.read())
        if _stags:
            def _sver(v): 
                try: return tuple(int(x) for x in v.lstrip("v").split("."))
                except: return (0,)
            _latest_sicry = max(_stags, key=lambda t: _sver(t["name"]))['name'].lstrip('v')
            _bundled = getattr(sicry, "__version__", "0.0.0")
            if _sver(_bundled) < _sver(_latest_sicry):
                print(f"NOTICE: bundled sicry.py (v{_bundled}) is behind upstream SICRY™ (v{_latest_sicry}).")
                print(f"        Run: python3 {os.path.join(_skill_dir, 'sync_sicry.py')}")
    except Exception:
        pass
    sys.exit(0)

# ── standalone: watch-check ───────────────────────────────────────
if args.watch_check:
    print("[watch-check] Running all due watch jobs…")
    alerts = sicry.watch_check()
    _n_saved = 0
    if not alerts:
        print("  No due jobs.")
        if args.output_dir:
            print(f"  --output-dir: no files written (no due jobs).")
    else:
        import json as _json
        for a in alerts:
            new_flag = "[NEW]" if a.get("new") else "[unchanged]"
            last_run = a.get("last_run")
            last_str = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(last_run)) if last_run else "never"
            interval_h = a.get("interval_hours", 6)
            if last_run:
                next_ts  = last_run + interval_h * 3600
                next_str = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(next_ts))
            else:
                next_str = "overdue"
            print(f"  {new_flag} [{a['job_id']}] {a.get('result_count', 0)} results  "
                  f"last={last_str}  next={next_str}")
            print(f"       query: {a.get('query')!r}")
            # UX-2: show top-5 result titles/URLs so the operator can see what
            # triggered the alert without running a separate query
            if a.get("new") and a.get("results"):
                for _tr in a["results"][:5]:
                    _conf = _tr.get("confidence")
                    _tc   = f"[conf={_conf:.2f}] " if _conf is not None else ""
                    print(f"         {_tc}{_tr.get('title', '(no title)')[:70]}")
                    print(f"           {_tr.get('url', '')}")
            # [1] v2.1.10: --output-dir saves ALL due jobs (new or unchanged) so
            # automated pipelines always receive a file regardless of delta status.
            # Payload enriched with 'new', schedule fields, and 'mode'.
            if args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                _wout = os.path.join(args.output_dir, f"{a['job_id']}.json")
                with open(_wout, "w") as _wf:
                    _json.dump({
                        "job_id":       a["job_id"],
                        "query":        a.get("query", ""),
                        "new":          a.get("new", False),
                        "result_count": a.get("result_count", 0),
                        "mode":         a.get("mode", "threat_intel"),
                        "last_run":     last_str,
                        "last_run_ts":  last_run,
                        "next_run":     next_str,
                        "results":      a.get("results") or [],
                    }, _wf, indent=2)
                print(f"       saved → {_wout}")
                _n_saved += 1
        if args.output_dir:
            print(f"  Saved {_n_saved} file(s) to {args.output_dir!r}")
    # [2] v2.1.9: also list waiting (non-due) jobs so every job's health is
    # visible — not just the ones that ran today.
    _due_ids = {a["job_id"] for a in alerts}
    _waiting = [j for j in sicry.watch_list() if j["id"] not in _due_ids]
    if _waiting:
        print()
        print(f"Waiting jobs ({len(_waiting)}) — not yet due:")
        for _wj in _waiting:
            _wlast = _wj.get("last_run")
            _wint  = _wj.get("interval_hours", 6)
            _wlast_str = (_time.strftime("%Y-%m-%d %H:%M", _time.localtime(_wlast))
                          if _wlast else "never")
            if _wlast:
                _wnext_str = _time.strftime(
                    "%Y-%m-%d %H:%M", _time.localtime(_wlast + _wint * 3600))
            else:
                _wnext_str = "overdue (never run)"
            print(f"  [waiting] [{_wj['id']}] [{_wj['mode']}] every {_wint}h  "
                  f"last={_wlast_str}  next={_wnext_str}")
            print(f"       query: {_wj['query']!r}")
    sys.exit(0)

# ── standalone: watch-list ────────────────────────────────────────────
if args.watch_list:
    jobs = sicry.watch_list()
    if not jobs:
        print("No active watch jobs.")
    else:
        print(f"Active watch jobs ({len(jobs)}):")
        for j in jobs:
            last = j.get('last_run')
            last_str = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(last)) if last else "never"
            print(f"  {j['id']}  [{j['mode']}]  every {j['interval_hours']}h  "
                  f"last={last_str}  query={j['query']!r}")
    sys.exit(0)

# ── standalone: watch-disable ──────────────────────────────────────────
if args.watch_disable:
    _existing_ids = [j["id"] for j in sicry.watch_list()]
    if args.watch_disable not in _existing_ids:
        print(f"ERROR: no watch job with ID {args.watch_disable!r} — run --watch-list to see active jobs.",
              file=sys.stderr)
        sys.exit(1)
    sicry.watch_disable(args.watch_disable)
    print(f"Disabled watch job: {args.watch_disable}")
    sys.exit(0)

# ── standalone: --modes ───────────────────────────────────────────────
if args.modes:
    print("Available modes  (--mode <name>):")
    print()
    for _m in MODES:
        _mc = sicry.mode_config(_m)
        _engs = _mc.get("engines") or ["(all alive engines)"]
        _extra = len(_mc.get("extra_seeds") or [])
        print(f"  {_m:<22}  engines : {', '.join(_engs)}")
        print(f"  {'':22}  max_results={_mc.get('max_results', 30)}  "
              f"scrape={_mc.get('scrape', 8)}"
              + (f"  +{_extra} seed onion(s)" if _extra else ""))
        print()
    sys.exit(0)

# ── standalone: --engine-stats ───────────────────────────────────────
if args.engine_stats:
    _scores = sicry.engine_reliability_scores()
    _hist   = {_e: sicry.engine_health_history(_e, n=1) for _e in _scores}
    if not _scores:
        print("No engine history yet — run without --engine-stats first to trigger health checks.")
    else:
        print(f"  {'Engine':<24} {'Reliability':>12}  {'Last Latency':>14}  Last Seen")
        print("  " + "─" * 62)
        # UX-4 fix: _rel can be None (engine never checked); sort Nones last
        for _eng, _rel in sorted(_scores.items(), key=lambda x: (x[1] is None, -(x[1] or 0))):
            _last = (_hist.get(_eng) or [{}])[0]
            _lat  = f"{_last.get('latency_ms')}ms" if _last.get("latency_ms") else "—"
            _ts   = _last.get("ts")
            _ts_s = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(_ts)) if _ts else "—"
            _rel_str = f"{_rel:.0%}" if _rel is not None else "(no data)"
            print(f"  {_eng:<24} {_rel_str:>11}  {_lat:>14}  {_ts_s}")
    sys.exit(0)

# ── standalone: interactive mode (no --query required) ───────────
if args.interactive and not args.query:
    print("OnionClaw Interactive Mode  (type 'exit' to quit, 'help' for commands)")
    print("=" * 65)
    _session_history: list[str] = []
    _last_results: list[dict] = []
    _repl_format: str = "text"   # IMPROVE-8: format for drill-down output (text/json/stix/misp/csv)
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
        # UX-7: help / ? command inside REPL
        if q.lower() in ("help", "?"):
            print("  Commands:")
            print("    <query text>      Search the dark web")
            print("    <number>          Fetch page N from the last result set")
            print("    history           Show previous queries this session")
            print("    set format <fmt>  Set output format: text (default), json, stix, misp, csv")
            print(f"    Current format:   {_repl_format}")
            print("    exit / quit       Exit the REPL")
            print("    help / ?          Show this help")
            continue
        if q.lower() == "history":
            if not _session_history:
                print("  No queries yet.")
            else:
                for _i, _hq in enumerate(_session_history, 1):
                    print(f"  {_i}. {_hq}")
            continue
        # IMPROVE-8: set format <fmt> command
        if q.lower().startswith("set format "):
            _repl_format = q.split()[-1].lower()
            _valid_fmts = ("text", "json", "stix", "misp", "csv")
            if _repl_format not in _valid_fmts:
                print(f"  Unknown format {_repl_format!r}. Options: {', '.join(_valid_fmts)}")
                _repl_format = "text"
            else:
                print(f"  Output format set to: {_repl_format}")
            continue
        if q.isdigit():
            idx = int(q) - 1
            if _last_results and 0 <= idx < len(_last_results):
                page = sicry.fetch(_last_results[idx]["url"])
                if page["error"]:
                    print(f"  Error: {page['error']}")
                else:
                    print(f"\n  === {page['title']} ===")
                    # IMPROVE-8: honour _repl_format for drill-down output
                    if _repl_format == "json":
                        import json as _rj
                        print(_rj.dumps({"url": _last_results[idx]["url"],
                                         "title": page["title"],
                                         "text": page["text"][:4000]}, indent=2))
                    elif _repl_format in ("stix", "misp"):
                        _rfmt_result = [{"url": _last_results[idx]["url"],
                                         "title": page.get("title", ""),
                                         "confidence": _last_results[idx].get("confidence", 0.5),
                                         "engine": _last_results[idx].get("engine", "fetch")}]
                        if _repl_format == "stix":
                            import json as _rj
                            print(_rj.dumps(sicry.to_stix(_rfmt_result, query=q), indent=2)[:3000])
                        else:
                            import json as _rj
                            print(_rj.dumps(sicry.to_misp(_rfmt_result, query=q), indent=2)[:3000])
                    else:
                        # Default text mode
                        print(page["text"][:4000])
                    # UX-4 v2.1.8: structured entity extraction inline
                    if page.get("text") and _repl_format == "text":
                        import re as _re
                        _pt = page["text"]
                        _emails  = list(set(_re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", _pt)))
                        _onions  = list(set(_re.findall(r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", _pt)))
                        _btc     = list(set(_re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", _pt)))
                        _has_pgp = bool(_re.search(r"BEGIN PGP|END PGP", _pt))
                        if any([_emails, _onions, _btc, _has_pgp]):
                            print("\n  ── Extracted Entities ──")
                            if _emails:  print(f"  Emails     : {', '.join(_emails[:5])}")
                            if _onions:  print(f"  Onion links: {', '.join(_onions[:5])}")
                            if _btc:     print(f"  BTC addrs  : {', '.join(_btc[:3])}")
                            if _has_pgp: print("  PGP key    : detected")
                        _ents = sicry.analyze_nollm(
                            page["text"][:2000],
                            query=_last_results[idx].get("query", ""),
                        )
                        if _ents:
                            print("\n  --- Entities / Keywords ---")
                            print(_ents[:1200])
            else:
                print(f"  No result #{int(q)} — run a query first.")
            continue
        _session_history.append(q)
        _last_results = sicry.search(q, max_results=20, mode=args.mode,
                               _use_cache=not args.no_cache)
        if not _last_results:
            print("  No results.")
            continue
        for i, r in enumerate(_last_results, 1):
            # UX-4 v2.1.7: always show confidence in interactive mode — helps
            # the user decide which result to fetch without needing --confidence
            _iconf = r.get("confidence")
            conf_str = f" [{_iconf:.2f}]" if _iconf is not None else ""
            print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title','')[:60]}")
            print(f"       {r['url']}")
        print("\n  Type a number to fetch a page, a new query to search, or 'help'.")
    sys.exit(0)

# ── standalone: --watch-clear-all ─────────────────────────────────────
if args.watch_clear_all:
    _n_cleared = sicry.watch_clear_all()
    print(f"Cleared {_n_cleared} active watch job(s).")
    if _n_cleared == 0:
        print("  (no active watch jobs found — run --watch-list to check)")
    sys.exit(0)

# ── BUG-1: load checkpoint early so --resume can restore the query ────────
_checkpoint: dict = {}
_job_id = args.resume or str(uuid.uuid4())[:8]

# ── standalone: --watch-daemon ────────────────────────────────────────
if args.watch_daemon:
    import signal
    # IMPROVE-5: --daemon-poll overrides the computed tick interval
    if args.daemon_poll and args.daemon_poll > 0:
        _poll_s = args.daemon_poll
    else:
        _poll_s = max(int(args.interval * 60), 60)  # min 60 s
    print(f"[watch-daemon] Starting foreground daemon. Poll every {_poll_s}s. Ctrl+C to stop.")
    def _daemon_sig(s, f): print("\n[watch-daemon] Stopped."); sys.exit(0)
    signal.signal(signal.SIGINT, _daemon_sig)
    while True:
        _da = sicry.watch_check()
        if _da:
            for _a in _da:
                print(f"  [ALERT] [{_a['job_id']}] {_a.get('result_count',0)} results  "
                      f"query={_a.get('query')!r}")
        else:
            _nxt = _time.strftime("%H:%M:%S", _time.localtime(_time.time() + _poll_s))
            print(f"  [{_time.strftime('%H:%M:%S')}] No due jobs. Next check at {_nxt}.")
        _time.sleep(_poll_s)

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
# IMPROVE-1: show TorPool status so operator knows whether scrape workers
# use separate Tor circuits (SICRY_POOL_SIZE > 0) or share one circuit
_pool_sz = getattr(sicry, "TOR_POOL_SIZE", 0)
if _pool_sz > 0:
    _pool_base = getattr(sicry, "TOR_POOL_BASE_PORT", 9060)
    print(f"  TorPool: {_pool_sz} circuits active "
          f"(SICRY_POOL_SIZE={_pool_sz}, socks ports {_pool_base}–{_pool_base + _pool_sz - 1})")

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
    # UX-6: show mode routing note when --engines overrides mode selection
    if args.mode and args.mode != "threat_intel":
        mc = sicry.mode_config(args.mode)
        mode_engines = mc.get("engines")
        if mode_engines:
            print(f"  NOTE: --engines overrides mode '{args.mode}' routing "
                  f"(mode default: {', '.join(mode_engines)})")
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
# IMPROVE-7: show extra seed onions so the audit trail records exactly what was searched
_mc_s4 = sicry.mode_config(args.mode)
_s4_seeds = _mc_s4.get("extra_seeds") or []
if _s4_seeds:
    _seed_preview = ", ".join(_s4_seeds[:3])
    _seed_more = f" … +{len(_s4_seeds)-3} more" if len(_s4_seeds) > 3 else ""
    print(f"  + {len(_s4_seeds)} mode seed onion(s): {_seed_preview}{_seed_more}")
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
    # BUG-1 v2.1.7: re-score raw results with the refined query so the step-5
    # display never shows conf=0.0000.  Using score_results() (BM25 on title +
    # snippet + url) here replaces stale search-time values.  A second re-score
    # with scraped page texts happens after step 6 (line ~591).
    best = sicry.score_results(refined, raw_results)[:20]
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

# BUG-3: re-score `best` using scraped page content for richer BM25 weighting.
# Results with no scraped content keep their existing confidence score.
if best and pages:
    best = sicry.score_results(refined, best, texts=pages)
    # tag results that had no scraped text so the display can show conf=N/A
    _scraped_urls = set(pages.keys())
    for _br in best:
        if _br.get("url") not in _scraped_urls:
            _br.setdefault("_no_content", True)

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
if args.out or args.output_dir:
    # IMPROVE-8: --output-dir auto-names the file as <job_id>.<ext>
    fmt = args.format
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        _ext_map = {"json": "json", "csv": "csv", "stix": "json",
                    "misp": "json", "md": "md"}
        _out_path = os.path.join(args.output_dir,
                                 f"{_job_id}.{_ext_map.get(fmt, 'txt')}")
    else:
        _out_path = args.out
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
        elif fmt == "misp":
            out_payload = json.dumps(
                sicry.to_misp(best, query=refined, report_text=report,
                              threat_level=args.misp_threat_level,
                              distribution=args.misp_distribution),
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
        with open(_out_path, "w", encoding="utf-8") as fh:
            fh.write(out_payload)
        print(f"\nReport saved to: {_out_path}  (format: {fmt})")
    except Exception as _we:
        print(f"\nERROR: could not write output file: {_we}", file=sys.stderr)
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Interactive follow-up drill-down (--interactive + --query)
# ─────────────────────────────────────────────────────────────────
if args.interactive:
    print("\n[interactive] Ask follow-up questions about the report above.")
    print("  Type 'help' for commands, 'exit' to quit.\n")
    _ifollup_history: list[str] = []
    while True:
        try:
            q = input("Follow-up > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break
        if q.lower() in ("exit", "quit", "q", ""):
            break
        # UX-7: help and history inside follow-up REPL
        if q.lower() in ("help", "?"):
            print("  Commands:")
            print("    <question text>   Search for follow-up results")
            print("    fetch N           Fetch result N from the original search")
            print("    history           Show follow-up queries this session")
            print("    exit / quit       Exit")
            continue
        if q.lower() == "history":
            if not _ifollup_history:
                print("  No follow-up queries yet.")
            else:
                for _i, _hq in enumerate(_ifollup_history, 1):
                    print(f"  {_i}. {_hq}")
            continue
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
        _ifollup_history.append(q)
        follow_results = sicry.search(q, max_results=10, mode=args.mode)
        for i, r in enumerate(follow_results[:8], 1):
            conf_str = f"  [conf={r.get('confidence',0):.2f}]" if args.confidence else ""
            print(f"  {i:>3}.{conf_str} [{r['engine']}] {r.get('title','')[:65]}")
            print(f"       {r['url']}")

# ── Rotate identity when done ──────────────────────────────────────
sicry.renew_identity()
print("\n[+] Tor identity rotated.  Job ID:", _job_id)

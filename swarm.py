#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — swarm.py
Concurrent, persistent, read-only monitoring swarm.

A coordinator runs specialised collectors in parallel, records every run, and a
synthesizer fuses the resulting change events into one prioritised digest:

  leaksites   new ransomware victim disclosures (+ wallets in ransom notes)
  groupinfra  leak-site infrastructure going up / down / moving
  wallets     on-chain movement on wallets harvested from those notes
  onionsites  change monitoring on any .onion pages you point it at (needs Tor)

Collectors are passive observers. Nothing here contacts, negotiates with, or
deceives a threat actor.

Usage:
  python3 swarm.py                                # one sweep
  python3 swarm.py --watch healthcare --watch US  # flag matching events as PRIORITY
  python3 swarm.py --wallet bc1q...               # always track this address
  python3 swarm.py --onion http://xyz.onion       # monitor an onion page (Tor)
  python3 swarm.py --loop 900                     # sweep every 15 min, forever
  python3 swarm.py --json                         # machine-readable digest
  python3 swarm.py --llm                          # add an LLM narrative (needs LLM_PROVIDER)
"""
import sys, os, re, json, time, argparse, signal
from concurrent.futures import ThreadPoolExecutor, as_completed

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

from collectors import (CollectorUnavailable, GroupInfraCollector, KevCollector,
                        LeakSiteCollector, OnionSiteCollector, WalletCollector)
from store import Store
import alerts as alerts_mod

__version__ = "2.4.0"

# Higher = surfaced first.
_WEIGHT = {"wallet_state": 5, "onion_page": 4, "kev": 3, "victim": 3, "group_profile": 2, "dls": 2, "wallet": 1}


class Swarm:
    def __init__(self, store: Store, collectors, max_workers: int = 4,
                 timeout: float = 300.0):
        self.store = store
        self.collectors = list(collectors)
        self.max_workers = max_workers
        self.timeout = timeout

    def _run_one(self, c):
        last = self.store.last_ok_run(c.name)
        if c.min_interval and last and time.time() - last < c.min_interval:
            return c.name, "fresh", None, f"last ok run {int((time.time()-last)/60)}m ago (min interval {int(c.min_interval/60)}m)"
        run_id = self.store.start_run(c.name)
        try:
            res = c.collect(self.store)
            self.store.finish_run(run_id, True, res.items, res.events)
            return c.name, "ok", res, None
        except CollectorUnavailable as e:
            self.store.finish_run(run_id, True, 0, 0, f"skipped: {e}")
            return c.name, "skipped", None, str(e)
        except Exception as e:
            self.store.finish_run(run_id, False, 0, 0, repr(e))
            return c.name, "failed", None, repr(e)

    def sweep(self) -> dict:
        started = time.time()
        report = {}
        # Collectors that feed each other run in two waves: wallets are harvested
        # by `leaksites`, then `wallets` checks them in the same sweep.
        waves = [[c for c in self.collectors if c.name != "wallets"],
                 [c for c in self.collectors if c.name == "wallets"]]
        for wave in waves:
            if not wave:
                continue
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futs = {pool.submit(self._run_one, c): c for c in wave}
                for f in as_completed(futs, timeout=self.timeout):
                    name, status, res, err = f.result()
                    report[name] = {
                        "status": status, "error": err,
                        "items": res.items if res else 0,
                        "events": res.events if res else 0,
                        "skipped_unsafe_or_invalid": res.skipped if res else 0,
                        "notes": (res.notes[:10] if res else []),
                    }
        report["_started"] = started
        report["_elapsed"] = round(time.time() - started, 2)
        return report


# ── synthesizer ───────────────────────────────────────────────────
def synthesize(store: Store, since: float, run_report: dict, watch=()) -> dict:
    watch = [(w.lower(), re.compile(r"(?<![a-z0-9])" + re.escape(w.lower()) + r"(?![a-z0-9])"))
             for w in watch]
    events = store.events_since(since)
    items = []
    for e in events:
        # keys are searchable (wallet addresses, CVE ids, onion hosts) except victim keys,
        # which are tracker URLs and would make any term in the tracker's domain match everything
        hay = (e["detail"] if e["kind"] == "victim" else f"{e['detail']} {e['key']}").lower()
        hit = [w for w, rx in watch if rx.search(hay)]
        items.append({
            "ts": e["ts"], "source": e["source"], "kind": e["kind"], "change": e["change"],
            "key": e["key"], "detail": e["detail"], "priority": bool(hit), "matched": hit,
            "_w": _WEIGHT.get(e["kind"], 0) + (10 if hit else 0) + (2 if e["change"] == "changed" else 0)
                  + (4 if "[RANSOMWARE]" in e["detail"] else 0),
        })
    items.sort(key=lambda x: (-x["_w"], -x["ts"]))
    for i in items:
        del i["_w"]

    by_kind = {}
    for i in items:
        by_kind[i["kind"]] = by_kind.get(i["kind"], 0) + 1

    groups = {}
    for i in items:
        if i["kind"] == "victim":
            g = i["detail"].split(":", 1)[0]
            groups[g] = groups.get(g, 0) + 1

    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "since": since,
        "collectors": {k: v for k, v in run_report.items() if not k.startswith("_")},
        "elapsed_s": run_report.get("_elapsed"),
        "event_count": len(items),
        "events_by_kind": by_kind,
        "most_active_groups": sorted(groups.items(), key=lambda kv: -kv[1])[:5],
        "priority": [i for i in items if i["priority"]],
        "events": items,
        "totals": {k: store.count(k) for k in ("victim", "dls", "group_profile", "kev", "wallet", "wallet_state", "onion_page")},
    }


def render_text(d: dict, limit: int = 25) -> str:
    L = [f"OnionClaw swarm digest — {d['generated']}  ({d['elapsed_s']}s)", ""]
    for name, r in d["collectors"].items():
        mark = {"ok": "✓", "skipped": "–", "fresh": "·", "failed": "✗"}[r["status"]]
        extra = f"  [{r['error']}]" if r["error"] else ""
        L.append(f"  {mark} {name:<11} items={r['items']:<5} events={r['events']:<4} "
                 f"refused/invalid={r['skipped_unsafe_or_invalid']}{extra}")
    L += ["", f"{d['event_count']} new events: " +
          (", ".join(f"{k}={v}" for k, v in d["events_by_kind"].items()) or "none")]
    if d["most_active_groups"]:
        L.append("most active: " + ", ".join(f"{g} ({n})" for g, n in d["most_active_groups"]))
    if d["priority"]:
        L += ["", f"PRIORITY ({len(d['priority'])}):"]
        L += [f"  ★ {p['detail']}  [match: {', '.join(p['matched'])}]" for p in d["priority"][:limit]]
    rest = [e for e in d["events"] if not e["priority"]]
    if rest:
        L += ["", "events:"]
        L += [f"  {e['kind']:<12} {e['change']:<7} {e['detail'][:150]}" for e in rest[:limit]]
        if len(rest) > limit:
            L.append(f"  … {len(rest) - limit} more (use --json for all)")
    seen_notes = set()
    for name, r in d["collectors"].items():
        for n in r["notes"][:3]:
            if n not in seen_notes:                     # same notice from several collectors: once
                seen_notes.add(n)
                L.append(f"  note[{name}]: {n}")
    if "alerts" in d:
        al = d["alerts"]
        L += ["", f"alerts: {al['candidates']} candidate, {al['pending']} pending, "
                  f"{al['delivered']} delivered, {al['failed']} failed"
                  + (" (dry-run)" if al["dry_run"] else "")
                  + (f"  errors: {', '.join(al['errors'])}" if al["errors"] else "")]
    t = d["totals"]
    L += ["", "store: " + ", ".join(f"{k}={v}" for k, v in t.items())]
    return "\n".join(L)


def llm_narrative(digest: dict) -> str:
    import sicry
    top = digest["priority"][:10] + [e for e in digest["events"] if not e["priority"]][:20]
    brief = "\n".join(f"- [{e['kind']}/{e['change']}] {e['detail']}" for e in top)
    return sicry._call_llm(
        sicry.LLM_PROVIDER,
        "You are a threat-intelligence analyst. Write a concise defensive briefing from "
        "monitoring events. Use only the facts given; do not speculate beyond them.",
        f"Events from the latest monitoring sweep:\n{brief}\n\n"
        "Summarise key developments, name notable groups/sectors, and list recommended "
        "defensive actions in under 200 words.")


def main() -> int:
    ap = argparse.ArgumentParser(description="OnionClaw monitoring swarm (read-only)")
    ap.add_argument("--version", action="version", version=f"OnionClaw swarm {__version__}")
    ap.add_argument("--db", default=None, help="SQLite path (default: ./onionclaw.db or $ONIONCLAW_DB)")
    ap.add_argument("--watch", action="append", default=[], metavar="TERM",
                    help="flag events mentioning TERM as PRIORITY (repeatable)")
    ap.add_argument("--wallet", action="append", default=[], metavar="ADDR",
                    help="always track this BTC address (repeatable)")
    ap.add_argument("--onion", action="append", default=[], metavar="URL",
                    help="monitor this .onion page for changes (repeatable, needs Tor)")
    ap.add_argument("--only", action="append", default=[],
                    choices=["leaksites", "groupinfra", "kev", "wallets", "onionsites"],
                    help="run only these collectors")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="repeat every N seconds (default: single sweep)")
    ap.add_argument("--json", action="store_true", help="emit the digest as JSON")
    ap.add_argument("--llm", action="store_true", help="append an LLM narrative")
    ap.add_argument("--webhook", metavar="URL", help="POST alerts to this webhook")
    ap.add_argument("--webhook-format", choices=alerts_mod.FORMATS, default="generic")
    ap.add_argument("--webhook-secret", default=os.getenv("ONIONCLAW_WEBHOOK_SECRET"),
                    help="HMAC-SHA256 sign generic payloads (X-OnionClaw-Signature)")
    ap.add_argument("--alert-sector", action="append", default=None, metavar="SECTOR",
                    help="critical sector to alert on (repeatable; default healthcare, government, "
                         "defense, education, energy, utilities)")
    ap.add_argument("--alert-min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="MEDIUM")
    ap.add_argument("--alert-dry-run", action="store_true", help="show what would be sent")
    ap.add_argument("--alert-lookback-hours", type=float, default=24.0,
                    help="re-attempt undelivered alerts from this far back (default 24)")
    args = ap.parse_args()

    store = Store(args.db)
    collectors = [LeakSiteCollector(), GroupInfraCollector(), KevCollector(),
                  WalletCollector(extra_addresses=args.wallet)]
    if args.onion:
        collectors.append(OnionSiteCollector(args.onion, workers=args.workers))
    if args.only:
        collectors = [c for c in collectors if c.name in args.only]

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    swarm = Swarm(store, collectors, max_workers=args.workers)
    failed_any = False
    while True:
        since = time.time() - 0.001
        report = swarm.sweep()
        digest = synthesize(store, since, report, args.watch)
        if args.llm:
            try:
                digest["narrative"] = llm_narrative(digest)
            except Exception as e:
                digest["narrative_error"] = repr(e)
        if args.webhook:
            digest["alerts"] = alerts_mod.process(
                store, min(since, time.time() - args.alert_lookback_hours * 3600),
                args.webhook, args.webhook_format, args.watch,
                args.alert_sector or alerts_mod.DEFAULT_SECTORS, args.alert_min_severity,
                args.webhook_secret, args.alert_dry_run)
        print(json.dumps(digest, indent=2, default=str) if args.json else render_text(digest))
        if digest.get("narrative") and not args.json:
            print("\n" + digest["narrative"])
        failed_any = any(r["status"] == "failed" for r in digest["collectors"].values())
        if not args.loop or stop["flag"]:
            break
        for _ in range(args.loop):
            if stop["flag"]:
                break
            time.sleep(1)
        if stop["flag"]:
            break
    return 1 if failed_any else 0


if __name__ == "__main__":
    sys.exit(main())

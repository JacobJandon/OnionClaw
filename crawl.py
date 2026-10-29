#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — crawl.py
Deep-crawl an .onion site over Tor: follow links on the same hidden service,
harvest validated entities (BTC/ETH/XMR wallets, emails, .onion links, PGP keys),
and respect a per-site page budget. Where fetch.py reads one page, crawl.py
reads a site.

Usage:
  python3 crawl.py --url "http://example.onion"
  python3 crawl.py --url "http://example.onion" --depth 2 --max-pages 15
  python3 crawl.py --url "http://example.onion" --workers 4 --delay 1.0
  python3 crawl.py --url "http://example.onion" --json        # machine-readable only

The crawl proceeds level by level; pages within a level are fetched concurrently
(--workers), with a small per-request jitter (--delay) so a fragile hidden
service isn't hammered.

Safety:
  Abuse material is never crawled. Every refusal is reported (stderr, and the
  "refused" list in --json output) with its reason — nothing is dropped silently.
"""
import sys, os, time, json, random, argparse
from concurrent.futures import ThreadPoolExecutor

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

from entities import extract_entities, onion_host
from safety import is_safe

__version__ = "2.4.0"

_AGG_KEYS = ("btc_wallets", "eth_wallets", "xmr_wallets", "emails", "onion_links", "tox_ids")


def crawl(start_url: str, depth: int = 1, max_pages: int = 8, workers: int = 3,
          delay: float = 1.0, fetch=None, log=None) -> dict:
    """Crawl one hidden service. `fetch` and `log` are injectable for testing."""
    fetch = fetch or sicry.fetch
    log = log or (lambda *_: None)
    host = onion_host(start_url)

    visited, pages, refused, errors = set(), [], [], []
    agg = {k: set() for k in _AGG_KEYS}
    agg_pgp = False
    frontier = [start_url]

    def one(url):
        if delay:
            time.sleep(random.uniform(0, delay))
        try:
            return url, fetch(url), None
        except Exception as e:
            return url, None, e

    for level in range(depth + 1):
        batch = []
        for u in frontier:
            if u not in visited and len(pages) + len(batch) < max_pages:
                visited.add(u)
                batch.append(u)
        if not batch:
            break

        next_frontier = []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for url, page, err in pool.map(one, batch):
                if err or not page:
                    errors.append({"url": url, "error": str(err or "no response")})
                    log(f"  !  {url[:64]} → {err or 'no response'}")
                    continue
                if page.get("error") and not page.get("text"):
                    errors.append({"url": url, "error": page["error"]})
                    log(f"  !  {url[:64]} → {page['error']}")
                    continue

                title, text = page.get("title") or "", page.get("text") or ""
                verdict = is_safe(url, title, text)
                if not verdict:
                    refused.append({"url": url, "reason": verdict.reason})
                    log(f"  ⊘  refused {url[:64]}  ({verdict.reason})")
                    continue

                ent = extract_entities(text, page.get("links"), host)
                pages.append({"url": url, "status": page.get("status", 0),
                              "title": title[:120], "depth": level, "entities": ent})
                for k in _AGG_KEYS:
                    agg[k].update(ent[k])
                agg_pgp = agg_pgp or ent["pgp"]

                hit = ", ".join(f"{k.split('_')[0]}:{len(ent[k])}"
                                for k in ("btc_wallets", "emails", "onion_links") if ent[k])
                log(f"  {page.get('status', 0)}  d{level}  {url[:64]}")
                if hit:
                    log(f"        ⤷ {hit}{'  +PGP' if ent['pgp'] else ''}")

                if level < depth:
                    for ln in page.get("links") or []:
                        href = ln.get("href", "") if isinstance(ln, dict) else str(ln)
                        if onion_host(href) != host or href in visited:
                            continue
                        lv = is_safe(href, ln.get("text", "") if isinstance(ln, dict) else "")
                        if not lv:
                            refused.append({"url": href, "reason": lv.reason})
                            continue
                        next_frontier.append(href)
        frontier = list(dict.fromkeys(next_frontier))

    return {"start": start_url, "host": host, "pages_crawled": len(pages),
            "entities": {**{k: sorted(v) for k, v in agg.items()}, "pgp": agg_pgp},
            "refused": refused, "errors": errors, "pages": pages}


def main() -> int:
    ap = argparse.ArgumentParser(description="Deep-crawl an .onion site via Tor")
    ap.add_argument("--version", action="version",
                    version=f"OnionClaw crawl {__version__} (sicry {getattr(sicry, '__version__', '?')})")
    ap.add_argument("--url", required=True, help="Start .onion URL")
    ap.add_argument("--depth", type=int, default=1, help="Link-follow depth (default 1)")
    ap.add_argument("--max-pages", type=int, default=8, help="Page budget (default 8)")
    ap.add_argument("--workers", type=int, default=3, help="Concurrent fetches per level (default 3)")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Max random per-request jitter in seconds (default 1.0)")
    ap.add_argument("--json", action="store_true", help="Output raw JSON only")
    args = ap.parse_args()

    url = args.url if args.url.startswith(("http://", "https://")) else "http://" + args.url
    host = onion_host(url)
    if not host:
        print("ERROR: --url must be an .onion address", file=sys.stderr)
        return 1

    verdict = is_safe(url)
    if not verdict:
        print(f"REFUSED: start URL matches abuse filter ({verdict.reason})", file=sys.stderr)
        return 2

    if not getattr(sicry, "_tor_port_open", lambda: True)():
        h = getattr(sicry, "TOR_SOCKS_HOST", "127.0.0.1")
        p = getattr(sicry, "TOR_SOCKS_PORT", 9050)
        print(f"✗ Tor SOCKS port {h}:{p} is not reachable.", file=sys.stderr)
        print("  Start Tor first:  apt install tor && systemctl start tor", file=sys.stderr)
        return 1

    if not args.json:
        print(f"Crawling {host}  (depth={args.depth}, max-pages={args.max_pages}, "
              f"workers={args.workers})\n")

    out = crawl(url, args.depth, args.max_pages, args.workers, args.delay,
                log=None if args.json else print)

    for r in out["refused"]:
        print(f"refused: {r['url']}  ({r['reason']})", file=sys.stderr)

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    print(f"\nCrawled {out['pages_crawled']} page(s) on {host}  ·  "
          f"refused {len(out['refused'])}  ·  errors {len(out['errors'])}")
    shown = False
    for k, v in out["entities"].items():
        if v and k != "pgp":
            shown = True
            print(f"  {k:<13} {len(v):>3}   e.g. {', '.join(list(v)[:3])}")
    if out["entities"]["pgp"]:
        shown = True
        print("  pgp           yes")
    if not shown:
        print("  (no entities harvested)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

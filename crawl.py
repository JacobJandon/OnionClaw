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
from urllib.parse import urldefrag, urlsplit, urlunsplit

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

from entities import extract_entities, service_host, FULL_TEXT_CHARS, FULL_TEXT_LINKS
from safety import is_safe

from _version import __version__  # noqa: E402 — the toolkit version

_AGG_KEYS = ("btc_wallets", "eth_wallets", "xmr_wallets", "emails", "onion_links", "tox_ids")


def crawl(start_url: str, depth: int = 1, max_pages: int = 8, workers: int = 3,
          delay: float = 1.0, fetch=None, log=None) -> dict:
    """Crawl one hidden service. `fetch` and `log` are injectable for testing."""
    fetch = fetch or _full_fetch
    log = log or (lambda *_: None)
    host = service_host(start_url)

    visited, pages, refused, errors = set(), [], [], []
    refused_urls = set()
    agg = {k: set() for k in _AGG_KEYS}
    agg_pgp = False
    frontier = [_norm(start_url)]

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
                        href = _norm(ln.get("href", "") if isinstance(ln, dict) else str(ln))
                        # Same service means the URL's hostname, not an onion mentioned
                        # somewhere in it (a gateway, archive or tracker URL is clearnet).
                        if service_host(href) != host or href in visited or href in refused_urls:
                            continue
                        lv = is_safe(href, ln.get("text", "") if isinstance(ln, dict) else "")
                        if not lv:
                            refused_urls.add(href)
                            refused.append({"url": href, "reason": lv.reason})
                            continue
                        next_frontier.append(href)
        frontier = list(dict.fromkeys(next_frontier))

    return {"start": start_url, "host": host, "pages_crawled": len(pages),
            "entities": {**{k: sorted(v) for k, v in agg.items()}, "pgp": agg_pgp},
            "refused": refused, "errors": errors, "pages": pages}


def _full_fetch(url: str) -> dict:
    # sicry.fetch keeps 8,000 characters by default (sized for an LLM prompt), which
    # silently dropped wallets and PGP blocks lower down the page.
    return sicry.fetch(url, max_chars=FULL_TEXT_CHARS, max_links=FULL_TEXT_LINKS)


def _norm(url: str) -> str:
    """One spelling per page: no fragment, lower-case scheme and host, "/" for an empty
    path. /#about and /#top are the same document; fetching each one spent the page
    budget on copies."""
    try:
        p = urlsplit(urldefrag(url)[0])
    except ValueError:
        return url
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def _non_negative(kind):
    def parse(v):
        x = kind(v)
        if x < 0:
            raise argparse.ArgumentTypeError("must not be negative")
        return x
    return parse


def _positive_int(v):
    x = int(v)
    if x < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return x


def main() -> int:
    ap = argparse.ArgumentParser(description="Deep-crawl an .onion site via Tor")
    ap.add_argument("--version", action="version",
                    version=f"OnionClaw crawl {__version__} (sicry {getattr(sicry, '__version__', '?')})")
    ap.add_argument("--url", required=True, help="Start .onion URL")
    ap.add_argument("--depth", type=_non_negative(int), default=1, help="Link-follow depth (default 1)")
    ap.add_argument("--max-pages", type=_positive_int, default=8, help="Page budget (default 8)")
    ap.add_argument("--workers", type=_positive_int, default=3, help="Concurrent fetches per level (default 3)")
    ap.add_argument("--delay", type=_non_negative(float), default=1.0,
                    help="Max random per-request jitter in seconds (default 1.0)")
    ap.add_argument("--json", action="store_true", help="Output raw JSON only")
    args = ap.parse_args()

    url = args.url if args.url.startswith(("http://", "https://")) else "http://" + args.url
    host = service_host(url)
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

    # Nothing crawled is a failure, as it is for fetch.py: 1 when the pages could not
    # be fetched, 2 when every page that was fetched was refused.
    code = 0 if out["pages_crawled"] else (1 if out["errors"] or not out["refused"] else 2)
    if args.json:
        print(json.dumps(out, indent=2))
        return code

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
    return code


if __name__ == "__main__":
    sys.exit(main())

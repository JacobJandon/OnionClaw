# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""crawl() against a real local HTTP server. `.onion` hostnames are routed to it
by an injected fetcher, so link-following, depth, budget, safety refusals and
concurrency run for real. The Tor transport itself is not exercised here."""
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# crawl.py imports sicry at module load; a stub keeps these tests independent of
# the heavy dependency set.
import types
sys.modules.setdefault("sicry", types.SimpleNamespace(fetch=None, __version__="test"))
import crawl as crawl_mod

HOST = "a" * 56 + ".onion"
BASE = f"http://{HOST}"
BTC = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

PAGES = {
    "/": f'<html><title>Home</title><body>welcome <a href="/a">a</a> <a href="/b">b</a> '
         f'<a href="/bad">bad</a> <a href="/pthc-archive">files</a> '
         f'<a href="http://{"b" * 56}.onion/x">other</a></body></html>',
    "/a": f"<html><title>A</title><body>pay {BTC} contact ops@example.com "
          f'<a href="/c">c</a></body></html>',
    "/b": "<html><title>B</title><body>" + "filler " * 3000 + f" late wallet {BTC}</body></html>",
    "/c": "<html><title>C</title><body>deep page</body></html>",
    "/bad": "<html><title>pthc archive</title><body>x</body></html>",
    "/pthc-archive": "<html><title>x</title><body>x</body></html>",
}
_hits = []


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        _hits.append((self.path, time.time()))
        time.sleep(0.15)
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def fetch(server):
    from bs4 import BeautifulSoup

    def _fetch(url):
        path = urlparse(url).path or "/"
        r = requests.get(f"http://127.0.0.1:{server}{path}", timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [{"text": a.get_text(), "href": (f"{BASE}{a['href']}" if a["href"].startswith("/") else a["href"])}
                 for a in soup.find_all("a", href=True)]
        return {"status": r.status_code, "title": soup.title.string if soup.title else "",
                "text": soup.get_text(" "), "links": links, "error": None}
    _hits.clear()
    return _fetch


def run(fetch, **kw):
    return crawl_mod.crawl(BASE + "/", fetch=fetch, delay=0, **kw)


def test_follows_links_and_stays_on_host(fetch):
    out = run(fetch, depth=1, max_pages=20)
    urls = {p["url"] for p in out["pages"]}
    assert urls == {BASE + "/", BASE + "/a", BASE + "/b"}        # /c is depth 2; other host excluded
    assert not any("b" * 56 in u for u in urls)


def test_depth_two_reaches_deeper_page(fetch):
    out = run(fetch, depth=2, max_pages=20)
    assert BASE + "/c" in {p["url"] for p in out["pages"]}


def test_budget_is_respected(fetch):
    assert run(fetch, depth=2, max_pages=2)["pages_crawled"] == 2


def test_content_refusal_is_reported_and_page_not_recorded_or_followed(fetch):
    # Innocuous link text: only the fetched page's title reveals it, so it costs one request.
    out = run(fetch, depth=1, max_pages=20)
    assert any(r["url"].endswith("/bad") for r in out["refused"])
    assert all(not p["url"].endswith("/bad") for p in out["pages"])


def test_link_level_refusal_never_requests_the_page(fetch):
    # The URL reveals it, so the page is never fetched at all.
    out = run(fetch, depth=1, max_pages=20)
    assert any(r["url"].endswith("/pthc-archive") for r in out["refused"])
    assert not any(path == "/pthc-archive" for path, _ in _hits)


def test_wallet_below_old_8kb_cutoff_is_harvested(fetch):
    out = run(fetch, depth=1, max_pages=20)
    b = next(p for p in out["pages"] if p["url"].endswith("/b"))
    assert b["entities"]["btc_wallets"] == [BTC]
    assert out["entities"]["btc_wallets"] == [BTC]
    assert out["entities"]["emails"] == ["ops@example.com"]


def test_level_is_fetched_concurrently(fetch):
    run(fetch, depth=1, max_pages=20, workers=3)
    a = [t for p, t in _hits if p in ("/a", "/b")]
    assert len(a) == 2 and abs(a[0] - a[1]) < 0.14               # started together, not 0.15s apart


def test_fetch_errors_are_collected(server):
    def boom(url):
        raise TimeoutError("circuit timeout")
    out = crawl_mod.crawl(BASE + "/", fetch=boom, delay=0)
    assert out["pages_crawled"] == 0 and out["errors"][0]["error"] == "circuit timeout"

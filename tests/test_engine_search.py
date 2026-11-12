# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""The bundled engine's search path: caching, de-duplication, scraping, analysis input
and watch jobs. Offline: Tor sessions and the LLM are replaced, the DB is a temp file."""
import hashlib
import json
import os
import sys

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sicry  # noqa: E402

L = "l" * 56 + ".onion"
M = "m" * 56 + ".onion"


@pytest.fixture
def db(tmp_path, monkeypatch):
    d = sicry._DB(str(tmp_path / "sicry.db"))
    monkeypatch.setattr(sicry, "_db", lambda: d)
    monkeypatch.setattr(sicry, "_SEARCH_MEM_CACHE", {})
    monkeypatch.setattr(sicry, "_FETCH_CACHE", {})
    return d


class _Engines:
    """Every engine answers with one result page naming the engine."""
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None, timeout=None, **_):
        self.calls.append(url)
        host = url.split("/")[2]
        r = requests.models.Response()
        r.status_code, r.url, r.encoding = 200, url, "utf-8"
        tag = hashlib.sha1(host.encode()).hexdigest()[:8]
        r._content = (f'<div class="result"><a href="http://{tag * 7}.onion/page">'
                      f'lockbit result {tag}</a></div>').encode()
        return r


def test_search_cache_does_not_answer_another_mode(db, monkeypatch):
    """A ransomware-mode search (4 engines) answered a later threat_intel search
    (all 17) from the cache for 30 minutes."""
    s = _Engines()
    monkeypatch.setattr(sicry, "_pool_session", lambda: s)
    sicry.search("lockbit", mode="ransomware", max_results=10)
    first = len(s.calls)
    sicry.search("lockbit", mode="threat_intel", max_results=10)
    assert len(s.calls) > first


def test_dedup_keeps_distinct_pages_that_share_a_site_title():
    """Leak blogs give every post one title; the posts are different victims."""
    title = "LockBit 3.0 Leaked Data"
    rows = [{"url": f"http://{L}/post/{v}", "title": title} for v in ("acme", "globex", "initech")]
    rows.append({"url": f"http://{M}/post/acme", "title": title})      # a mirror copy
    kept = [r["url"] for r in sicry._deduplicate_results(rows)]
    assert kept == [f"http://{L}/post/acme", f"http://{L}/post/globex", f"http://{L}/post/initech"]


def test_dedup_drops_exact_repeats_but_never_merges_home_pages():
    rows = [{"url": f"http://{L}/", "title": "Login"}, {"url": f"HTTP://{L.upper()}", "title": "Login"},
            {"url": f"http://{M}/", "title": "Login"}]
    assert [r["url"] for r in sicry._deduplicate_results(rows)] == [f"http://{L}/", f"http://{M}/"]


class _Pages:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, headers=None, timeout=None, **_):
        page = self.pages[url]
        if isinstance(page, Exception):
            raise page
        status, body = page
        r = requests.models.Response()
        r.status_code, r.url, r.encoding, r._content = status, url, "utf-8", body.encode()
        return r


def test_scrape_all_returns_only_pages_that_downloaded(monkeypatch):
    """Failures came back as their title and blocked pages as '', so the pipeline
    counted every page as scraped and analysed titles as content."""
    pages = {f"http://{L}/ok": (200, "<p>real page text</p>"),
             f"http://{L}/down": requests.exceptions.ConnectionError("unreachable"),
             f"http://{L}/gone": (404, "<p>not found</p>")}
    monkeypatch.setattr(sicry, "_pool_session", lambda: _Pages(pages))
    out = sicry.scrape_all([{"url": u, "title": "t"} for u in pages])
    assert list(out) == [f"http://{L}/ok"] and "real page text" in out[f"http://{L}/ok"]


def test_ask_sends_every_source_up_to_its_own_limit(monkeypatch):
    seen = {}
    monkeypatch.setattr(sicry, "_call_llm", lambda p, system, prompt: seen.setdefault("p", prompt) and "REPORT")
    combined = "\n\n".join(f"[SOURCE: http://{L}/{i}]\n" + "x" * 2000 for i in range(8))
    assert sicry.ask(combined) == "REPORT"
    assert seen["p"].count("[SOURCE:") == 8               # was 4 of 8


def test_ask_says_when_content_was_left_out(monkeypatch):
    seen = {}
    monkeypatch.setattr(sicry, "ASK_MAX_CHARS", 5000)
    monkeypatch.setattr(sicry, "_call_llm", lambda p, system, prompt: seen.setdefault("p", prompt) and "REPORT")
    combined = "\n\n".join(f"[SOURCE: http://{L}/{i}]\n" + "x" * 2000 for i in range(4))
    report = sicry.ask(combined)
    assert seen["p"].count("[SOURCE:") == 2                # cut at a source boundary
    assert "covered the first" in report and "SICRY_ASK_MAX_CHARS" in report


# ── watch jobs ─────────────────────────────────────────────────────
def _results(*names):
    return [{"url": f"http://{L}/{n}", "title": n} for n in names]


@pytest.fixture
def watch(db, monkeypatch):
    feed = []
    monkeypatch.setattr(sicry, "search", lambda *a, **k: feed.pop(0))
    job = sicry.watch_add("lockbit leak", interval_hours=0)

    def check(results, callback=None):
        feed.append(results)
        return sicry.watch_check(callback=callback)[0]
    return job, check


def test_an_outage_is_not_reported_as_new(watch, db):
    job, check = watch
    assert check(_results("a", "b", "c"))["new"] is True       # first sighting
    out = check([])                                            # Tor down
    assert out["new"] is False and "unreachable" in out["error"]
    assert check(_results("a", "b", "c"))["new"] is False      # back: nothing new


def test_fewer_results_are_not_new_but_an_unseen_one_is(watch):
    job, check = watch
    check(_results("a", "b", "c"))
    assert check(_results("a", "b"))["new"] is False           # one engine timed out
    out = check(_results("a", "b", "d"))
    assert out["new"] is True and [r["title"] for r in out["new_results"]] == ["d"]


def test_a_failing_callback_keeps_the_alert_for_the_next_check(watch):
    job, check = watch
    check(_results("a"))

    def webhook_down(job, results):
        raise TimeoutError("webhook timed out")
    out = check(_results("a", "z"), callback=webhook_down)
    assert out["new"] is True and "callback failed" in out["error"]
    assert check(_results("a", "z"))["new"] is True            # was lost for good


def test_a_fingerprint_from_an_older_version_is_compared_once_the_old_way(watch, db):
    job, check = watch
    rows = _results("a", "b")
    legacy = hashlib.md5("|".join(sorted(r["url"] + r["title"] for r in rows)).encode(),
                         usedforsecurity=False).hexdigest()
    db.watch_update(job, legacy, 0)
    assert check(rows)["new"] is False                         # no spurious upgrade alert
    assert check(_results("a", "b", "c"))["new"] is True

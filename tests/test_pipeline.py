# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""pipeline.py end to end: the real script and engine module, with the engine's network
calls and the LLM replaced, and checkpoints in a temp database."""
import os
import runpy
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import sicry  # noqa: E402

V3 = "p" * 56 + ".onion"
RESULTS = [{"url": f"http://{V3}/t{i}", "title": f"Acme leak thread {i}", "engine": "Ahmia",
            "confidence": 0.5} for i in range(3)]


class Engine:
    """Records what the pipeline asked of the engine."""
    def __init__(self):
        self.refined, self.asked, self.watch_checked = [], [], 0
        self.ask_reply = "REPORT: findings"
        self.scraped = {r["url"]: f"{r['title']} - page text" for r in RESULTS}
        self.renew = {"success": True, "error": None}
        self.tor_up = True
        self.watch_alerts = []
        self.interrupt_scrape = False


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    db = sicry._DB(str(tmp_path / "sicry.db"))
    e = Engine()
    patches = {
        "_db": lambda: db,
        "_tor_port_open": lambda *a, **k: e.tor_up,
        "check_tor": lambda: {"tor_active": True, "exit_ip": "192.0.2.1", "error": None},
        "check_update": lambda *a, **k: {"up_to_date": True, "current": "x", "latest": "x",
                                         "url": None, "error": None},
        "check_search_engines": lambda *a, **k: [{"name": "Ahmia", "status": "up", "latency_ms": 5}],
        "search": lambda *a, **k: [dict(r) for r in RESULTS],
        "filter_results": lambda q, results, *a, **k: results,
        "refine_query": lambda q, *a, **k: e.refined.append(q) or q + " refined",
        "renew_identity": lambda: e.renew,
        "watch_check": lambda *a, **k: (setattr(e, "watch_checked", e.watch_checked + 1)
                                        or e.watch_alerts),
        "watch_list": lambda: [],
    }

    def scrape_all(items, *a, **k):
        if e.interrupt_scrape:
            raise KeyboardInterrupt
        return {u: t for u, t in e.scraped.items() if u in {i["url"] for i in items}}

    def ask(content, query="", mode="threat_intel", *a, **k):
        e.asked.append(mode)
        return e.ask_reply

    patches.update(scrape_all=scrape_all, ask=ask)
    for name, fn in patches.items():
        monkeypatch.setattr(sicry, name, fn)

    def go(*argv):
        monkeypatch.setattr(sys, "argv", ["pipeline.py", *argv])
        code = 0
        try:
            runpy.run_path(os.path.join(ROOT, "pipeline.py"), run_name="__main__")
        except SystemExit as x:
            code = x.code if isinstance(x.code, int) else 1
        except KeyboardInterrupt:
            code = 130
        return code, capsys.readouterr().out
    return e, go


def test_a_fresh_run_refines_the_query(run):
    """Every fresh run skipped refinement and printed '(--no-llm)'."""
    e, go = run
    code, out = go("--query", "find leaked credentials for employees of acme corporation")
    assert code == 0 and e.refined == ["find leaked credentials for employees of acme corporation"]
    assert "(--no-llm)" not in out


def test_no_llm_never_sends_the_query_to_the_llm_even_on_resume(run):
    """--resume --no-llm called refine_query, sending the query to the LLM provider."""
    e, go = run
    go("--query", "acme leak", "--resume", "job1", "--no-llm")
    go("--resume", "job1", "--no-llm")
    assert e.refined == []


def test_unreachable_pages_are_reported_as_unreachable(run):
    e, go = run
    e.scraped = {RESULTS[0]["url"]: "Acme - page text"}
    code, out = go("--query", "acme leak", "--no-llm")
    assert "1/3 pages scraped successfully" in out and "2 pages were unreachable" in out


def test_nothing_scraped_is_a_failure(run):
    e, go = run
    e.scraped = {}
    code, out = go("--query", "acme leak", "--no-llm")
    assert code == 1 and "No pages could be scraped" in out


def test_an_llm_error_is_not_saved_so_resume_can_retry(run):
    """The 429 was checkpointed as the finished analysis; --resume replayed it forever."""
    e, go = run
    e.ask_reply = "[SICRY: LLM call failed — Error code: 429]"
    code, _ = go("--query", "acme leak", "--resume", "job2")
    assert code == 1
    e.ask_reply = "REPORT: findings"
    code, _ = go("--resume", "job2")
    assert code == 0 and len(e.asked) == 2


def test_the_job_id_is_printed_before_anything_can_fail(run):
    e, go = run
    e.ask_reply = "[SICRY: LLM call failed — outage]"
    code, out = go("--query", "acme leak")
    assert code == 1 and "[job] " in out and "--resume " in out


def test_resume_keeps_the_jobs_mode(run):
    """--resume restored the query but ran the default threat_intel mode."""
    e, go = run
    e.interrupt_scrape = True
    go("--query", "lockbit acme victim", "--mode", "ransomware", "--resume", "rw1")
    e.interrupt_scrape = False
    go("--resume", "rw1")
    assert e.asked == ["ransomware"]


def test_an_explicit_mode_overrides_the_resumed_one(run):
    e, go = run
    e.interrupt_scrape = True
    go("--query", "lockbit acme victim", "--mode", "ransomware", "--resume", "rw2")
    e.interrupt_scrape = False
    go("--resume", "rw2", "--mode", "corporate")
    assert e.asked == ["corporate"]


def test_a_failed_tor_rotation_is_not_reported_as_done(run):
    e, go = run
    e.renew = {"success": False, "error": "Connection refused"}
    code, out = go("--query", "acme leak", "--no-llm")
    assert "Tor identity rotated." not in out and "NOT rotated" in out


def test_watch_check_does_not_run_jobs_without_tor(run):
    """Every search came back empty and was stored as the job's new result."""
    e, go = run
    e.tor_up = False
    code, _ = go("--watch-check")
    assert code == 1 and e.watch_checked == 0


def test_watch_check_shows_failed_jobs_and_exits_non_zero(run):
    e, go = run
    e.watch_alerts = [{"job_id": "abc", "query": "q", "new": False, "result_count": 0,
                       "results": [], "error": "no results: Tor or the search engines may be unreachable",
                       "last_run": None, "interval_hours": 6}]
    code, out = go("--watch-check")
    assert code == 1 and "[error]" in out and "unreachable" in out

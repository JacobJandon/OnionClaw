# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""The observation store under concurrent writers, and fetch.py's output."""
import json
import os
import runpy
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import sicry  # noqa: E402
from store import CHANGED, NEW, Store  # noqa: E402


def test_concurrent_writers_on_one_key_do_not_collide(tmp_path):
    """Two processes running one collector both saw 'no row' and hit
    UNIQUE constraint failed, or logged the same change twice."""
    path = str(tmp_path / "t.db")
    Store(path)
    errors, results = [], []
    start = threading.Barrier(8)

    def writer(i):
        st = Store(path)              # its own connection, like a second process
        start.wait()
        for n in range(25):
            try:
                results.append(st.observe("kev", "kev", "CVE-2099-1", {"n": n % 3}, "d"))
            except Exception as e:     # noqa: BLE001
                errors.append(repr(e))
    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert results.count(NEW) == 1
    events = Store(path).events_since(0)
    assert len(events) == results.count(NEW) + results.count(CHANGED)


@pytest.fixture
def fetch_cli(monkeypatch, capsys):
    def go(*argv, text="x" * 6000, truncated=False):
        monkeypatch.setattr(sicry, "_tor_port_open", lambda *a, **k: True)
        monkeypatch.setattr(sicry, "clear_cache", lambda: 3)
        monkeypatch.setattr(sicry, "fetch", lambda url, **k: {
            "url": url, "is_onion": True, "status": 200, "title": "t", "text": text,
            "links": [], "truncated": truncated, "error": None})
        monkeypatch.setattr(sys, "argv", ["fetch.py", *argv])
        try:
            runpy.run_path(os.path.join(ROOT, "fetch.py"), run_name="__main__")
        except SystemExit:
            pass
        return capsys.readouterr()
    return go


def test_fetch_prints_the_whole_text_it_got(fetch_cli):
    """Pages between 4,000 and SICRY_MAX_CHARS were cut at 4,000 with no notice."""
    out = fetch_cli("--url", "http://" + "f" * 56 + ".onion/").out
    assert "x" * 6000 in out


def test_fetch_json_stays_valid_with_clear_cache(fetch_cli):
    out = fetch_cli("--url", "http://" + "f" * 56 + ".onion/", "--json", "--clear-cache")
    json.loads(out.out)
    assert "Cleared 3" in out.err

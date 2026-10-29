# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Alerting against a real local HTTP receiver (genuine network delivery, signing, retry)."""
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import alerts
from collectors import KevCollector, LeakSiteCollector
from store import Store


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


class Receiver:
    def __init__(self):
        self.posts, self.fail_next = [], 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n)
                if outer.fail_next > 0:
                    outer.fail_next -= 1
                    self.send_response(503); self.end_headers(); return
                outer.posts.append((dict(self.headers), body))
                self.send_response(204); self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"

    def close(self):
        self.srv.shutdown()


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    monkeypatch.setattr(alerts.time, "sleep", lambda s: None)


@pytest.fixture
def rx():
    r = Receiver()
    yield r
    r.close()


@pytest.fixture
def store(tmp_path):
    st = Store(str(tmp_path / "a.db"))
    LeakSiteCollector(fetch_json=lambda u: fx("recentvictims.json")).collect(st)
    return st


def test_critical_sector_victims_alert_at_medium(store):
    al = alerts.build_alerts(store, store.events_since(0))
    kinds = {a.type for a in al}
    assert "CRITICAL_VICTIM" in kinds
    assert all(a.severity == "MEDIUM" for a in al if a.type == "CRITICAL_VICTIM")
    assert all(a.matched for a in al if a.type == "CRITICAL_VICTIM")


def test_watch_hit_upgrades_to_high_and_whole_word_only(store):
    hospitality = [a for a in alerts.build_alerts(store, store.events_since(0), watch=["hospital"])
                   if "hospitality" in a.message.lower() and "hospital" in a.matched]
    assert hospitality == []                                       # 'Hospitality' is not 'hospital'
    al = alerts.build_alerts(store, store.events_since(0), watch=["healthcare"])
    assert any(a.severity == "HIGH" and "healthcare" in a.matched for a in al)


def test_kev_ransomware_alert_is_high(tmp_path):
    st = Store(str(tmp_path / "k.db"))
    feed = fx("kev.json")
    c = KevCollector(fetch_json=lambda u: feed)
    c.collect(st)
    feed["vulnerabilities"].append({"cveID": "CVE-2099-1", "vendorProject": "A", "product": "B",
                                    "vulnerabilityName": "x", "dateAdded": "2099-01-01",
                                    "knownRansomwareCampaignUse": "Known", "cwes": []})
    c.collect(st)
    al = alerts.build_alerts(st, st.events_since(0))
    assert [(a.type, a.severity) for a in al] == [("KEV_RANSOMWARE", "HIGH")]


def test_delivery_exactly_once_per_sink(store, rx):
    r1 = alerts.process(store, 0, rx.url, "generic")
    assert r1["delivered"] > 0 and r1["failed"] == 0
    n = len(rx.posts)
    r2 = alerts.process(store, 0, rx.url, "generic")
    assert r2["pending"] == 0 and len(rx.posts) == n               # nothing re-sent


def test_failed_delivery_is_retried_not_lost(store, rx):
    rx.fail_next = 99                                              # receiver down
    r1 = alerts.process(store, 0, rx.url, "generic")
    assert r1["delivered"] == 0 and r1["failed"] > 0 and r1["errors"]
    rx.fail_next = 0                                               # receiver back
    r2 = alerts.process(store, 0, rx.url, "generic")
    assert r2["delivered"] == r1["failed"] and r2["failed"] == 0


def test_two_sinks_tracked_independently(store, rx):
    """Regression: alerts_sent keyed on event_id alone made the second sink re-send forever."""
    a = alerts.process(store, 0, rx.url + "?a", "generic")
    b = alerts.process(store, 0, rx.url + "?b", "generic")
    assert a["delivered"] == b["delivered"] > 0
    assert alerts.process(store, 0, rx.url + "?b", "generic")["pending"] == 0


def test_hmac_signature_verifies(store, rx):
    alerts.process(store, 0, rx.url, "generic", secret="s3cret")
    headers, body = rx.posts[0]
    expect = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["X-OnionClaw-Signature"] == expect


def test_client_error_is_not_retried(store, monkeypatch):
    calls = []

    class R:
        status_code = 404; headers = {}

    class S:
        def post(self, *a, **k):
            calls.append(1); return R()
    ok, info = alerts.deliver("http://x", {}, session=S())
    assert not ok and info == "HTTP 404" and len(calls) == 1


@pytest.mark.parametrize("fmt,key", [("slack", "text"), ("discord", "content"), ("generic", "alerts")])
def test_formats(store, fmt, key):
    al = alerts.build_alerts(store, store.events_since(0))
    p = alerts.format_payload(al, fmt)
    assert key in p
    if fmt == "discord":
        assert len(p["content"]) <= 2000


def test_min_severity_filters(store, rx):
    r = alerts.process(store, 0, rx.url, "generic", min_severity="HIGH", dry_run=True)
    assert r["candidates"] == 0                                    # only MEDIUM alerts exist here


def test_dry_run_sends_and_records_nothing(store, rx):
    r = alerts.process(store, 0, rx.url, "generic", dry_run=True)
    assert r["pending"] > 0 and rx.posts == []
    assert alerts.process(store, 0, rx.url, "generic", dry_run=True)["pending"] == r["pending"]


def test_watch_term_in_tracker_domain_does_not_match_every_victim(store):
    """Regression: victim keys are ransomware.live URLs, so --watch ransomware matched all of them."""
    assert [a for a in alerts.build_alerts(store, store.events_since(0), watch=["ransomware"])
            if "ransomware" in a.matched] == []

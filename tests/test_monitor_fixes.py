# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Monitoring fixes from the post-release audit: alert delivery, KEV alert rule, wallet
history stability and the HTTP client's retry policy. Fixtures are real captured data."""
import copy
import json
import os
import sys

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import alerts  # noqa: E402
import collectors  # noqa: E402
from collectors import KevCollector, LeakSiteCollector, http_get_json  # noqa: E402
from store import Store  # noqa: E402


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "t.db"))


class _Sink:
    def __init__(self):
        self.posts = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.posts.append(json.loads(data))
        r = requests.models.Response()
        r.status_code = 204
        return r


def _kev_with_new_ransomware_cves(n):
    kev = fx("kev.json")
    base = next(v for v in kev["vulnerabilities"] if v.get("knownRansomwareCampaignUse") == "Known")
    for i in range(n):
        v = dict(base, cveID=f"CVE-2099-{10000 + i}",
                 vulnerabilityName=f"{base.get('vulnerabilityName', '')} variant {i} " + "x" * 40)
        kev["vulnerabilities"].append(v)
    return kev


def test_discord_batches_are_split_so_no_alert_is_cut_off(store):
    """Discord's 2,000-char cap cut whole alert lines, yet every alert in the batch
    was recorded as delivered and never retried."""
    kev = fx("kev.json")
    c = KevCollector(fetch_json=lambda u: kev)
    c.collect(store)                                        # silent baseline
    kev2 = _kev_with_new_ransomware_cves(20)
    KevCollector(fetch_json=lambda u: kev2).collect(store)
    sink = _Sink()
    res = alerts.process(store, 0, "https://discord.test/hook", "discord", session=sink)
    assert res["delivered"] == 20 and len(sink.posts) > 1
    assert all(len(p["content"]) <= 2000 for p in sink.posts)
    sent_text = "\n".join(p["content"] for p in sink.posts)
    assert all(f"CVE-2099-{10000 + i}" in sent_text for i in range(20))


def _kev_alerts(store, mutate):
    kev = fx("kev.json")
    KevCollector(fetch_json=lambda u: kev).collect(store)  # baseline
    kev2 = copy.deepcopy(kev)
    mutate(kev2["vulnerabilities"])
    KevCollector(fetch_json=lambda u: kev2).collect(store)
    return [a for a in alerts.build_alerts(store, store.events_since(0)) if a.type == "KEV_RANSOMWARE"]


def test_a_metadata_edit_to_a_known_entry_is_not_a_ransomware_alert(store):
    """CISA correcting dueDate / backfilling CWEs fired a HIGH alert per entry."""
    def edit(vulns):
        for v in [v for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"][:5]:
            v["dueDate"] = "2099-01-01"
            v["cwes"] = ["CWE-787"]
    assert _kev_alerts(store, edit) == []


def test_a_cve_newly_linked_to_ransomware_still_alerts(store):
    def flip(vulns):
        v = next(v for v in vulns if v.get("knownRansomwareCampaignUse") != "Known")
        v["knownRansomwareCampaignUse"] = "Known"
    hits = _kev_alerts(store, flip)
    assert len(hits) == 1 and "now linked to ransomware" in hits[0].message


def test_an_edit_names_the_fields_that_changed(store):
    kev = fx("kev.json")
    KevCollector(fetch_json=lambda u: kev).collect(store)
    kev2 = copy.deepcopy(kev)
    v = next(v for v in kev2["vulnerabilities"] if v.get("knownRansomwareCampaignUse") == "Known")
    v["dueDate"] = "2099-01-01"
    KevCollector(fetch_json=lambda u: kev2).collect(store)
    ev = [e for e in store.events_since(0) if e["kind"] == "kev"]
    assert len(ev) == 1 and "updated (due)" in ev[0]["detail"] and "[RANSOMWARE]" not in ev[0]["detail"]


def test_a_wallet_shared_by_two_victims_does_not_change_every_sweep(store):
    """seen_in was reordered on every pass, so an unchanged feed logged phantom
    'wallet changed' events each sweep."""
    victims = copy.deepcopy(fx("recentvictims.json")[:2])
    for i, v in enumerate(victims):
        v["group"] = "lockbit3"
        v["url"] = f"https://tracker.test/id/{i}"
        v["description"] = "Pay to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 72h"
    for _ in range(4):
        LeakSiteCollector(fetch_json=lambda u: victims).collect(store)
    wallet_events = [e for e in store.events_since(0) if e["kind"] == "wallet"]
    assert len(wallet_events) <= 2                          # first sightings only


class _Responses:
    def __init__(self, *statuses, retry_after=None):
        self.statuses, self.calls, self.retry_after = list(statuses), 0, retry_after

    def get(self, url, timeout=None, headers=None):
        self.calls += 1
        r = requests.models.Response()
        r.status_code = self.statuses.pop(0) if self.statuses else 200
        if self.retry_after:
            r.headers["Retry-After"] = self.retry_after
        r._content = b"{}"
        return r


def test_a_429_is_not_retried(monkeypatch):
    """Per-minute limits cannot be met seconds later; retrying spent the allowance."""
    monkeypatch.setattr(collectors.time, "sleep", lambda s: None)
    s = _Responses(429, 429, 429)
    with pytest.raises(RuntimeError, match="rate limited"):
        http_get_json("https://api.ransomware.live/v2/recentvictims", session=s)
    assert s.calls == 1


def test_retry_after_is_capped_and_never_slept_after_the_last_try(monkeypatch):
    """A 503 with Retry-After: 3600 slept three hours, the last after the final attempt."""
    slept = []
    monkeypatch.setattr(collectors.time, "sleep", slept.append)
    s = _Responses(503, 503, 503, retry_after="3600")
    with pytest.raises(RuntimeError):
        http_get_json("https://www.cisa.gov/kev.json", session=s)
    assert s.calls == 3 and len(slept) == 2 and max(slept) <= collectors.RETRY_AFTER_CAP


def test_one_ransomware_live_claim_is_one_request(monkeypatch, store):
    calls = []

    def fake(url, **kw):
        calls.append(kw.get("retries", 3))
        return []
    monkeypatch.setattr(collectors, "http_get_json", fake)
    LeakSiteCollector().collect(store)
    assert calls == [1]

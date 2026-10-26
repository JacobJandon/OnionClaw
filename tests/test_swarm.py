# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Tests for the monitoring swarm. Fixtures under tests/fixtures are REAL captured
ransomware.live responses, not synthetic data."""
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import safety
from collectors import (GroupInfraCollector, LeakSiteCollector, OnionSiteCollector,
                        WalletCollector, CollectorUnavailable)
from entities import extract_entities, valid_btc
from store import CHANGED, NEW, UNCHANGED, Store
from swarm import Swarm, synthesize


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "t.db"))


# ── safety ────────────────────────────────────────────────────────
@pytest.mark.parametrize("text", [
    "LockBit — Boston Children's Hospital — 400GB exfiltrated",
    "St. Jude Children's Research Hospital",
    "Middlesex County school district",
    "Snuff tobacco distributor breach",
])
def test_safety_allows_legitimate_victims(text):
    assert safety.is_safe("", text)


@pytest.mark.parametrize("text", [
    "pthc archive", "CSAM forum", "child porn videos", "underage nude collection",
])
def test_safety_blocks_abuse_vocabulary(text):
    v = safety.is_safe("", text)
    assert not v and v.reason != "ok"


# ── entities ──────────────────────────────────────────────────────
def test_btc_checksums():
    assert valid_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert valid_btc("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    assert valid_btc("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")  # BIP-350
    assert not valid_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert not valid_btc("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlj")


def test_entities_found_below_old_8kb_cutoff():
    text = "filler " * 4000 + " pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh now"
    assert len(text) > 8000
    assert extract_entities(text)["btc_wallets"] == ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]


def test_entities_reject_checksum_failures():
    assert extract_entities("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")["btc_wallets"] == []


# ── store ─────────────────────────────────────────────────────────
def test_store_new_changed_unchanged(store):
    assert store.observe("s", "k", "a", {"v": 1}) == NEW
    assert store.observe("s", "k", "a", {"v": 1}) == UNCHANGED
    assert store.observe("s", "k", "a", {"v": 2}) == CHANGED
    assert [e["change"] for e in store.events_since(0)] == [NEW, CHANGED]


def test_store_quiet_baseline_logs_no_event_but_later_change_does(store):
    assert store.observe("s", "k", "a", {"v": 1}, quiet=True) == NEW
    assert store.events_since(0) == []
    assert store.observe("s", "k", "a", {"v": 2}) == CHANGED
    assert len(store.events_since(0)) == 1


# ── leak-site collector (real fixture) ────────────────────────────
def test_leaksites_then_idempotent(store):
    c = LeakSiteCollector(fetch_json=lambda u: fixture("recentvictims.json"))
    r1 = c.collect(store)
    assert r1.items == 40 and r1.events >= 40
    r2 = c.collect(store)
    assert r2.items == 40 and r2.events == 0
    assert store.count("victim") == 40


def test_leaksites_do_not_refuse_childrens_hospital(store):
    v = dict(fixture("recentvictims.json")[0])
    v.update(victim="Boston Children's Hospital", url="https://x/id/hosp")
    r = LeakSiteCollector(fetch_json=lambda u: [v]).collect(store)
    assert r.items == 1 and r.skipped == 0


def test_leaksites_harvest_valid_wallets_only(store):
    v = dict(fixture("recentvictims.json")[0])
    v.update(url="https://x/id/w", description=(
        "Pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh not 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))
    LeakSiteCollector(fetch_json=lambda u: [v]).collect(store)
    assert store.count("wallet") == 1


# ── group infra: regression for shared-host key collision ─────────
def test_groupinfra_shared_hosts_do_not_flap(store):
    groups = fixture("groups.json")
    total = sum(len(g.get("locations") or []) for g in groups)
    c = GroupInfraCollector(fetch_json=lambda u: groups)
    r1 = c.collect(store)
    assert r1.items == total and r1.events == 0            # silent baseline
    assert store.count("dls") == total                     # no overwritten rows
    r2 = c.collect(store)
    assert r2.events == 0                                  # no phantom CHANGED


def test_groupinfra_detects_going_dark(store):
    groups = fixture("groups.json")
    c = GroupInfraCollector(fetch_json=lambda u: groups)
    c.collect(store)
    loc = next(l for g in groups for l in (g.get("locations") or []) if l.get("available"))
    loc["available"] = False
    assert c.collect(store).events == 1


# ── wallets ───────────────────────────────────────────────────────
def _addr(tx, recv, spent, mp=0):
    return {"chain_stats": {"tx_count": tx, "funded_txo_sum": recv, "spent_txo_sum": spent},
            "mempool_stats": {"tx_count": mp}}


def test_wallet_movement_detected(store):
    addr = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    state = {"v": _addr(10, 100_000_000, 0)}
    c = WalletCollector([addr], pause=0, fetch_json=lambda u: state["v"])
    assert c.collect(store).events == 0                    # baseline
    assert c.collect(store).events == 0                    # unchanged
    state["v"] = _addr(11, 100_000_000, 40_000_000)
    r = c.collect(store)
    assert r.events == 1
    ev = store.events_since(0, ["wallet_state"])[-1]
    assert "-0.40000000" in ev["detail"] and "+1 tx" in ev["detail"]


def test_wallet_invalid_address_skipped_not_fetched(store):
    called = []
    c = WalletCollector(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"], pause=0,
                        fetch_json=lambda u: called.append(u))
    r = c.collect(store)
    assert r.skipped == 1 and not called


# ── onion collector (fetch injected; live Tor path not exercised here) ──
def _page(text, status=200):
    return {"status": status, "title": "t", "text": text, "links": [], "error": None}


def test_onion_page_change_reports_new_wallet(store):
    url = "http://" + "a" * 56 + ".onion"
    pages = {"p": _page("hello")}
    c = OnionSiteCollector([url], fetch=lambda u: pages["p"])
    assert c.collect(store).events == 0                    # baseline
    pages["p"] = _page("hello pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    assert c.collect(store).events == 1
    assert "btc_wallets" in store.events_since(0, ["onion_page"])[-1]["detail"]


def test_onion_collector_unavailable_without_tor(store, monkeypatch):
    import types
    fake = types.SimpleNamespace(_tor_port_open=lambda: False, TOR_SOCKS_HOST="h", TOR_SOCKS_PORT=1)
    monkeypatch.setitem(sys.modules, "sicry", fake)
    with pytest.raises(CollectorUnavailable):
        OnionSiteCollector(["http://x.onion"]).collect(store)


def test_onion_refuses_unsafe_page(store):
    url = "http://" + "b" * 56 + ".onion"
    c = OnionSiteCollector([url], fetch=lambda u: _page("pthc archive"))
    r = c.collect(store)
    assert r.skipped == 1 and r.items == 0


# ── swarm / synthesizer ───────────────────────────────────────────
class _Boom:
    name = "boom"
    min_interval = 0

    def collect(self, store):
        raise RuntimeError("source down")


def test_swarm_isolates_failures_and_synthesizes(store):
    ok = LeakSiteCollector(fetch_json=lambda u: fixture("recentvictims.json"))
    swarm = Swarm(store, [ok, _Boom()])
    t0 = time.time() - 0.001
    rep = swarm.sweep()
    assert rep["boom"]["status"] == "failed" and rep["leaksites"]["status"] == "ok"
    d = synthesize(store, t0, rep, watch=["healthcare"])
    assert d["event_count"] >= 40
    assert all("healthcare" in p["detail"].lower() or p["matched"] for p in d["priority"])


def test_watch_uses_word_boundaries(store):
    v = dict(fixture("recentvictims.json")[0])
    v.update(victim="Seaside Hospitality Group", url="https://x/id/h", activity="Hospitality")
    swarm = Swarm(store, [LeakSiteCollector(fetch_json=lambda u: [v])])
    t0 = time.time() - 0.001
    d = synthesize(store, t0, swarm.sweep(), watch=["hospital"])
    assert d["priority"] == []


def test_min_interval_skips_fresh_collector(store):
    g = GroupInfraCollector(fetch_json=lambda u: fixture("groups.json"))
    swarm = Swarm(store, [g])
    assert swarm.sweep()["groupinfra"]["status"] == "ok"
    assert swarm.sweep()["groupinfra"]["status"] == "fresh"


# ── CISA KEV (real fixture) ───────────────────────────────────────
from collectors import KevCollector
import collectors as collectors_mod


def test_kev_baseline_then_new_cve_event(store):
    feed = fixture("kev.json")
    c = KevCollector(fetch_json=lambda u: feed)
    r = c.collect(store)
    assert r.items == 40 and r.events == 0                       # silent baseline
    assert store.count("kev") == 40
    feed["vulnerabilities"].append({"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget",
                                    "vulnerabilityName": "Acme RCE", "dateAdded": "2099-01-01",
                                    "knownRansomwareCampaignUse": "Known", "cwes": []})
    r = c.collect(store)
    assert r.events == 1
    ev = store.events_since(0, ["kev"])[-1]
    assert "CVE-2099-0001" in ev["detail"] and "[RANSOMWARE]" in ev["detail"]


def test_kev_flags_cve_newly_linked_to_ransomware(store):
    feed = fixture("kev.json")
    c = KevCollector(fetch_json=lambda u: feed)
    c.collect(store)
    target = next(v for v in feed["vulnerabilities"] if v["knownRansomwareCampaignUse"] != "Known")
    target["knownRansomwareCampaignUse"] = "Known"
    assert c.collect(store).events == 1
    assert "now linked to ransomware" in store.events_since(0, ["kev"])[-1]["detail"]


def test_kev_ransomware_events_rank_first(store):
    feed = fixture("kev.json")
    c = KevCollector(fetch_json=lambda u: feed)
    c.collect(store)
    feed["vulnerabilities"] += [
        {"cveID": "CVE-2099-0002", "vendorProject": "A", "product": "B", "vulnerabilityName": "x",
         "dateAdded": "2099-01-01", "knownRansomwareCampaignUse": "Unknown", "cwes": []},
        {"cveID": "CVE-2099-0003", "vendorProject": "A", "product": "B", "vulnerabilityName": "y",
         "dateAdded": "2099-01-01", "knownRansomwareCampaignUse": "Known", "cwes": []}]
    t0 = time.time() - 0.001
    swarm = Swarm(store, [c]); c.min_interval = 0
    d = synthesize(store, t0, swarm.sweep())
    assert [e["key"] for e in d["events"]][0] == "CVE-2099-0003"


# ── ransomware.live guard: throttle, key header, free-tier notice ──
def test_ransomware_live_throttle_blocks_second_poll(store, monkeypatch):
    calls = []
    monkeypatch.setattr(collectors_mod, "http_get_json", lambda url, **kw: calls.append((url, kw)) or [])
    c = LeakSiteCollector()                                        # default = guarded live path
    c.collect(store)
    with pytest.raises(CollectorUnavailable, match="rate-limit guard"):
        c.collect(store)
    assert len(calls) == 1                                         # second poll never hit the API


def test_ransomware_live_free_tier_notice_and_key_header(store, monkeypatch):
    seen = {}
    monkeypatch.setattr(collectors_mod, "http_get_json",
                        lambda url, **kw: seen.update(kw) or [])
    monkeypatch.setattr(collectors_mod, "RL_API_KEY", "")
    r = LeakSiteCollector().collect(store)
    assert any("personal use" in n for n in r.notes) and not seen.get("headers")

    monkeypatch.setattr(collectors_mod, "RL_API_KEY", "secret")
    monkeypatch.setattr(collectors_mod, "RL_KEY_HEADER", "X-API-KEY")
    r = GroupInfraCollector().collect(store)
    assert seen["headers"] == {"X-API-KEY": "secret"} and not any("personal use" in n for n in r.notes)


def test_same_wallet_in_two_groups_notes_is_accumulated_not_overwritten(store):
    """Regression: the second group used to silently overwrite the first, hiding the very
    evidence shared-wallet correlation depends on."""
    base = dict(fixture("recentvictims.json")[0])
    a = dict(base, url="https://x/id/1", group="alpha",
             description="pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    b = dict(base, url="https://x/id/2", group="beta",
             description="pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    c = LeakSiteCollector(fetch_json=lambda u: [a])
    c.collect(store)
    LeakSiteCollector(fetch_json=lambda u: [b]).collect(store)
    p = store.get("leaksites", "wallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    assert p["groups"] == ["alpha", "beta"]
    assert any("now linked to 2 groups" in e["detail"] for e in store.events_since(0, ["wallet"]))

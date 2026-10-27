# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Unified indicator view (iocs.py), adapted from PRISM-Intel's IoC tracker.
Fixtures are REAL captured ransomware.live and CISA KEV responses."""
import csv
import io
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import iocs
from collectors import GroupInfraCollector, KevCollector, LeakSiteCollector
from store import Store

ONION = "a" * 56 + ".onion"
BTC = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "i.db"))


@pytest.fixture
def live(store):
    GroupInfraCollector(fetch_json=lambda u: fx("groups.json")).collect(store)
    LeakSiteCollector(fetch_json=lambda u: fx("recentvictims.json")).collect(store)
    KevCollector(fetch_json=lambda u: fx("kev.json")).collect(store)
    return store


def by_type(rows):
    out = {}
    for r in rows:
        out.setdefault(r["type"], []).append(r)
    return out


# ── derivation from real observations ─────────────────────────────
def test_leak_site_hosts_and_cves_derived_from_real_data(live):
    t = by_type(iocs.collect(live))
    assert t["onion_host"] and t["cve"]
    assert all(r["value"].endswith(".onion") for r in t["onion_host"])
    assert all(iocs._CVE_RE.match(r["value"]) for r in t["cve"])
    assert any("ransomware" in r["flags"] for r in t["cve"])
    assert any(r["groups"] for r in t["onion_host"])          # attributed to a group


def test_available_leak_sites_are_flagged_live(live):
    hosts = [r for r in iocs.collect(live) if r["type"] == "onion_host" and "live" in r["flags"]]
    assert hosts and all(r["groups"] for r in hosts)


def test_ransom_note_wallets_and_emails_are_extracted(store):
    v = dict(fx("recentvictims.json")[0], url="https://x/id/w", group="qilin", victim="Acme",
             description=f"Pay {BTC} or write to ops@example.com. Mirror: http://{ONION}/x")
    LeakSiteCollector(fetch_json=lambda u: [v]).collect(store)
    t = by_type(iocs.collect(store))
    assert [r["value"] for r in t["btc_wallet"]] == [BTC]
    assert [r["value"] for r in t["email"]] == ["ops@example.com"]
    assert ONION in [r["value"] for r in t["onion_host"]]
    assert t["btc_wallet"][0]["groups"] == ["qilin"]
    assert "Acme" in t["btc_wallet"][0]["context"]


def test_invalid_wallet_is_not_reported(store):
    store.observe("leaksites", "wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
                  {"chain": "btc", "groups": ["x"]})
    assert not [r for r in iocs.collect(store) if r["type"] == "btc_wallet"]


def test_same_value_from_two_sources_is_one_row(store):
    """A wallet in a ransom note and in the wallet collector is one indicator, not two."""
    v = dict(fx("recentvictims.json")[0], url="https://x/id/d", group="alpha",
             description=f"pay {BTC}")
    LeakSiteCollector(fetch_json=lambda u: [v]).collect(store)
    store.observe("leaksites", "wallet", BTC, {"chain": "btc", "groups": ["alpha", "beta"]})
    rows = [r for r in iocs.collect(store) if r["type"] == "btc_wallet"]
    assert len(rows) == 1
    assert rows[0]["groups"] == ["alpha", "beta"]              # merged attribution


def test_onion_page_entities_are_included(store):
    store.observe("onionsites", "onion_page", f"http://{ONION}/",
                  {"status": 200, "title": "t", "text_sha256": "x",
                   "entities": {"btc_wallets": [BTC], "emails": ["a@b.co"], "tox_ids": ["F" * 76],
                                "onion_links": ["b" * 56 + ".onion"], "xmr_wallets": [], "eth_wallets": [],
                                "pgp": False}})
    t = by_type(iocs.collect(store))
    assert BTC in [r["value"] for r in t["btc_wallet"]]
    assert "F" * 76 in [r["value"] for r in t["tox"]]
    assert all("onionsites" in r["sources"] for r in t["tox"])


# ── presentation ──────────────────────────────────────────────────
def test_values_are_defanged_by_default_and_fangable(live):
    rows = iocs.filter_rows(iocs.collect(live), types=["onion_host"])
    out = list(iocs.to_rows(rows[:1]))[0]["value"]
    assert ".onion" not in out and "[.]onion" in out
    assert list(iocs.to_rows(rows[:1], fanged=True))[0]["value"].endswith(".onion")


def test_defang_leaves_wallets_and_cves_alone():
    assert iocs.defang(BTC, "btc_wallet") == BTC
    assert iocs.defang("CVE-2021-1234", "cve") == "CVE-2021-1234"
    assert iocs.defang("http://x.onion", "onion_host") == "hxxp://x[.]onion"


def test_attributed_and_live_rows_sort_first(live):
    """Regression: sorting by date alone buried leak-site hosts under the whole KEV
    catalogue, which shares one timestamp."""
    rows = iocs.collect(live)
    assert rows[0]["groups"]
    first_unattributed = next(i for i, r in enumerate(rows) if not r["groups"])
    assert all(rows[i]["groups"] for i in range(first_unattributed))


def test_render_states_attribution_is_a_lead(live):
    text = iocs.render(iocs.collect(live), limit=3)
    assert "treat it as a lead" in text and "defanged" in text


def test_render_handles_empty_store(store):
    assert "No indicators yet" in iocs.render(iocs.collect(store))


# ── filters and export ────────────────────────────────────────────
def test_filters(live):
    rows = iocs.collect(live)
    assert all(r["type"] == "cve" for r in iocs.filter_rows(rows, types=["cve"]))
    assert all("ransomware" in r["flags"] for r in iocs.filter_rows(rows, flag="ransomware"))
    g = next(r["groups"][0] for r in rows if r["groups"])
    assert all(g in r["groups"] for r in iocs.filter_rows(rows, group=g))
    assert iocs.filter_rows(rows, group="no-such-group") == []
    newest = max(r["last_seen"] for r in rows)
    assert iocs.filter_rows(rows, since=newest + 86400) == []


def test_csv_export_is_well_formed(live):
    rows = iocs.filter_rows(iocs.collect(live), types=["onion_host"])[:5]
    buf = io.StringIO()
    fields = ["type", "value", "first_seen", "last_seen", "groups", "sources", "flags", "context"]
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows(iocs.to_rows(rows, fanged=True))
    parsed = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert len(parsed) == len(rows)
    assert all(p["value"].endswith(".onion") for p in parsed)
    assert all(len(p["first_seen"]) == 10 for p in parsed)     # ISO date

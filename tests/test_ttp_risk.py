# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""ATT&CK profiles (ttp.py) and group risk scores (risk.py), both adapted from PRISM-Intel.
Group fixtures are REAL captured ransomware.live responses."""
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import alerts
import risk
import ttp
from collectors import GroupInfraCollector, LeakSiteCollector
from store import Store


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "t.db"))


def iso(days_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - days_ago * 86400))


# ── ttp: profiles from real data ──────────────────────────────────
def test_profiles_recorded_from_real_groups(store):
    groups = fx("groups.json")
    GroupInfraCollector(fetch_json=lambda u: groups).collect(store)
    want = sum(1 for g in groups if ttp.normalize_profile(g))
    assert want >= 7 and store.count("group_profile") == want
    med = ttp.group_ttps(store, "medusa")
    ids = {t["id"] for t in med["techniques"]}
    assert {"T1078", "T1133"} <= ids
    assert all(t["confidence"] == "high" for t in med["techniques"])
    assert all(ttp.TECHNIQUE_RE.fullmatch(i) for i in ids)


def test_profile_details_strip_citations_and_keep_tactics(store):
    med = next(g for g in fx("groups.json") if g["name"] == "medusa")
    prof = ttp.normalize_profile(med)
    t = next(x for x in prof["techniques"] if x["id"] == "T1078")
    assert t["tactics"] and t["tactics"][0]["id"].startswith("TA")
    assert all("(Citation:" not in x["detail"] for x in prof["techniques"])


def test_group_without_ttps_or_tools_has_no_profile():
    assert ttp.normalize_profile({"name": "x", "ttps": [], "tools": []}) is None


def test_attack_url_handles_subtechniques():
    assert ttp.attack_url("T1021.001") == "https://attack.mitre.org/techniques/T1021/001/"


# ── ttp: keyword fallback, regression for PRISM's substring matching ──
@pytest.mark.parametrize("text", [
    "We monitor every sector of the victor's storage.",       # PRISM's "tor" matched all three
    "Your password policy is weak.",                           # PRISM mapped this to brute force
    "Contact our recovery team for details.",
])
def test_keywords_do_not_fire_on_substrings_or_unsound_mappings(text):
    assert ttp.keyword_ttps(text) == []


def test_keywords_whole_word_with_evidence():
    found = {t["id"]: t for t in ttp.keyword_ttps(
        "All files were encrypted. 400GB was exfiltrated before that. See T1490 notes.")}
    assert {"T1486", "T1041", "T1490"} <= set(found)
    assert found["T1486"]["evidence"] == "All files were encrypted."


def test_keyword_hits_are_low_confidence_behind_published_data(store):
    groups = fx("groups.json")
    GroupInfraCollector(fetch_json=lambda u: groups).collect(store)
    v = dict(fx("recentvictims.json")[0], url="https://x/id/k", group="medusa",
             description="All your data was exfiltrated by our team.")   # T1041: medusa doesn't publish it
    LeakSiteCollector(fetch_json=lambda u: [v]).collect(store)
    techs = ttp.group_ttps(store, "medusa")["techniques"]
    kw = [t for t in techs if t["confidence"] == "low"]
    assert [t["id"] for t in kw] == ["T1041"] and kw[0]["source"] == "ransom note keyword"
    assert techs[0]["confidence"] == "high"                         # published data sorts first


def test_republished_identical_profile_is_not_an_event(store):
    groups = fx("groups.json")
    c = GroupInfraCollector(fetch_json=lambda u: groups)
    c.collect(store)
    c.collect(store)
    assert not store.events_since(0, ["group_profile"])


def test_ttp_change_is_an_event_and_a_medium_alert(store):
    groups = fx("groups.json")
    c = GroupInfraCollector(fetch_json=lambda u: groups)
    c.collect(store)                                                # baseline: silent
    assert not store.events_since(0, ["group_profile"])
    med = next(g for g in groups if g["name"] == "medusa")
    assert "T1041" not in {t["id"] for t in ttp.normalize_profile(med)["techniques"]}
    med["ttps"][0]["techniques"].append({"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
                                        "technique_details": "new"})
    c.collect(store)
    ev = store.events_since(0, ["group_profile"])
    assert len(ev) == 1 and "+1 ATT&CK technique(s): T1041" in ev[0]["detail"]
    al = alerts.build_alerts(store, ev)
    assert [(a.type, a.severity) for a in al] == [("TTP_CHANGE", "MEDIUM")]


def test_technique_usage_ranks_by_groups(store):
    GroupInfraCollector(fetch_json=lambda u: fx("groups.json")).collect(store)
    rows = ttp.technique_usage(store)
    assert rows and len(rows[0]["groups"]) >= len(rows[-1]["groups"])


# ── risk: adapted PRISM scoring + decay ──────────────────────────
def victim(store, group, n, days_ago=1, activity="Manufacturing", country="US"):
    for k in range(n):
        store.observe("leaksites", "victim", f"u/{group}/{k}/{activity}",
                      {"group": group, "victim": f"{group}-v{k}-{activity}", "attackdate": iso(days_ago),
                       "activity": activity, "country": country})


@pytest.mark.parametrize("days,mult", [(5, 1.02), (60, 1.0), (120, 0.95), (300, 0.88), (400, 0.78), (900, 0.65)])
def test_decay_matches_prism_curve(days, mult):
    assert risk.decay(days)[0] == mult


def test_more_victims_score_higher(store):
    victim(store, "big", 20)
    victim(store, "small", 2)
    s = {r["group"]: r["score"] for r in risk.score_groups(store)}
    assert s["big"] > s["small"]


def test_critical_sectors_raise_the_score(store):
    victim(store, "hosp", 5, activity="Healthcare")
    victim(store, "shop", 5, activity="Retail & E-Commerce")
    s = {r["group"]: r for r in risk.score_groups(store)}
    assert s["hosp"]["score"] > s["shop"]["score"]
    assert s["hosp"]["evidence"]["critical_victims"] == 5


def test_quiet_groups_decay(store):
    victim(store, "fresh", 8, days_ago=3)
    victim(store, "stale", 8, days_ago=700)
    s = {r["group"]: r for r in risk.score_groups(store)}
    assert s["fresh"]["score"] > s["stale"]["score"]
    assert "defunct" in s["stale"]["decay"]["reason"]


def test_published_ttps_count_as_capability(store):
    GroupInfraCollector(fetch_json=lambda u: fx("groups.json")).collect(store)
    victim(store, "medusa", 3)
    victim(store, "nottp", 3)
    s = {r["group"]: r for r in risk.score_groups(store)}
    assert s["medusa"]["evidence"]["techniques"] > 0
    assert s["medusa"]["components"]["capability"] > s["nottp"]["components"]["capability"]


def test_every_score_is_explained_and_bounded(store):
    LeakSiteCollector(fetch_json=lambda u: fx("recentvictims.json")).collect(store)
    rows = risk.score_groups(store)
    assert rows
    for r in rows:
        assert 0 <= r["score"] <= 1 and r["tier"] in ("HIGH", "MEDIUM", "LOW")
        assert set(r["components"]) == set(risk.WEIGHTS)
    text = risk.explain(rows[0])
    assert "not an attribution" in text and "observed victims" in text

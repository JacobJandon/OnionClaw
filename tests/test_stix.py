# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""STIX 2.1 export, validated with OASIS's reference library (stix2 + stix2-patterns)."""
import json
import os
import sys
import uuid

import pytest

stix2 = pytest.importorskip("stix2")
from stix2patterns.validator import run_validator

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from collectors import GroupInfraCollector, KevCollector, LeakSiteCollector
from store import Store
import stix as stix_mod

WALLET = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    st = Store(str(tmp_path_factory.mktemp("s") / "s.db"))
    victims = fx("recentvictims.json")
    LeakSiteCollector(fetch_json=lambda u: victims).collect(st)
    GroupInfraCollector(fetch_json=lambda u: fx("groups.json")).collect(st)
    KevCollector(fetch_json=lambda u: fx("kev.json")).collect(st)
    st.observe("leaksites", "wallet", WALLET,
               {"chain": "btc", "groups": [victims[0]["group"]], "seen_in": ["u"]})
    return stix_mod.build_bundle(st), st, victims


def test_every_object_parses_with_reference_library(bundle):
    b, *_ = bundle
    stix2.parse(b, allow_custom=True)                              # whole bundle
    for o in b["objects"]:
        stix2.parse(o, allow_custom=True)


def test_all_ids_are_rfc4122_uuids_and_unique(bundle):
    b, *_ = bundle
    ids = [o["id"] for o in b["objects"]]
    assert len(ids) == len(set(ids))
    for i in ids:
        u = uuid.UUID(i.split("--", 1)[1])
        assert u.version in (4, 5) and u.variant == uuid.RFC_4122
    assert stix_mod.NAMESPACE != uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # reserved SCO ns


def test_no_dangling_references(bundle):
    """Regression for the PRISM defect: created_by_ref pointed at a non-existent/invalid id."""
    b, *_ = bundle
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        for k in ("created_by_ref", "source_ref", "target_ref"):
            if k in o:
                assert o[k] in ids, f"{o['id']} has dangling {k}={o[k]}"


def test_all_indicator_patterns_are_valid(bundle):
    b, *_ = bundle
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    assert inds
    for o in inds:
        assert run_validator(o["pattern"]) == [], o["pattern"]


def test_wallet_pattern_is_not_a_meaningless_file_hash(bundle):
    b, *_ = bundle
    w = next(o for o in b["objects"] if o["type"] == "indicator" and WALLET in o["pattern"])
    assert w["pattern"] == f"[x-cryptocurrency-wallet:address = '{WALLET}']"
    assert "hashes" not in w["pattern"]


def test_export_is_deterministic(bundle):
    b, st, _ = bundle
    assert {o["id"] for o in stix_mod.build_bundle(st)["objects"]} == {o["id"] for o in b["objects"]}


def test_victim_identity_targets_and_sector_mapping(bundle):
    b, _, victims = bundle
    health = next((v for v in victims if v.get("activity") == "Healthcare"), None)
    assert health, "fixture should contain a healthcare victim"
    ident = next(o for o in b["objects"] if o["type"] == "identity" and o["name"] == health["victim"])
    assert ident["sectors"] == ["healthcare"] and ident["identity_class"] == "organization"
    rels = [o for o in b["objects"] if o["type"] == "relationship"
            and o["relationship_type"] == "targets" and o["target_ref"] == ident["id"]]
    assert len(rels) == 1 and rels[0]["start_time"].endswith("Z")


def test_group_filter_limits_output(bundle):
    b, st, victims = bundle
    g = victims[0]["group"]
    sub = stix_mod.build_bundle(st, group=g)
    names = {o["name"] for o in sub["objects"] if o["type"] == "threat-actor"}
    assert names == {g}
    assert not any(o["type"] == "vulnerability" for o in sub["objects"])


def test_only_ransomware_known_kevs_exported(bundle):
    b, *_ = bundle
    vulns = [o for o in b["objects"] if o["type"] == "vulnerability"]
    assert len(vulns) == 15 and all(v["name"].startswith("CVE-") for v in vulns)


def test_attack_patterns_and_tools_from_group_profiles(bundle):
    b, *_ = bundle
    aps = [o for o in b["objects"] if o["type"] == "attack-pattern"]
    tools = [o for o in b["objects"] if o["type"] == "tool"]
    assert aps and tools
    for o in aps:
        ref = o["external_references"][0]
        assert ref["source_name"] == "mitre-attack" and ref["external_id"].startswith("T")
        assert ref["url"].startswith("https://attack.mitre.org/techniques/")
        for ph in o.get("kill_chain_phases", []):
            assert ph["kill_chain_name"] == "mitre-attack" and ph["phase_name"] == ph["phase_name"].lower()
    ids = {o["id"] for o in b["objects"]}
    uses = [o for o in b["objects"] if o["type"] == "relationship" and o["relationship_type"] == "uses"]
    assert uses and all(u["source_ref"] in ids and u["target_ref"] in ids for u in uses)
    assert {o["type"] for o in b["objects"] if o["id"] in {u["target_ref"] for u in uses}} == {"attack-pattern", "tool"}


def test_one_attack_pattern_per_technique_across_groups(bundle):
    b, *_ = bundle
    ext = [o["external_references"][0]["external_id"] for o in b["objects"] if o["type"] == "attack-pattern"]
    assert len(ext) == len(set(ext))       # shared techniques are one object, linked to many groups

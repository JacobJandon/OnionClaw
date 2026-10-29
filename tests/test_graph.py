# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Group correlation. Shared-host tests use REAL captured ransomware.live data; wallet and
double-claim cases are synthetic (they don't occur naturally in a small real sample)."""
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import graph
from collectors import GroupInfraCollector
from store import Store


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "g.db"))


def dls(store, group, host):
    store.observe("groupinfra", "dls", f"{group}|{host}",
                  {"group": group, "type": "DLS", "available": True, "enabled": True})


def victim(store, group, name, attack="2026-10-25T00:00:00+00:00"):
    store.observe("leaksites", "victim", f"u/{group}/{name}",
                  {"group": group, "victim": name, "attackdate": attack})


def test_real_fixture_finds_known_shared_infrastructure(store):
    with open(os.path.join(HERE, "fixtures", "groups.json")) as f:
        groups = json.load(f)
    GroupInfraCollector(fetch_json=lambda u: groups).collect(store)
    pairs = {frozenset((c["groups"][0], c["groups"][1])) if len(c["groups"]) == 2 else frozenset(c["groups"])
             for c in graph.clusters(graph.build_edges(store), 0.6)}
    assert frozenset({"cyclops", "knight"}) in pairs
    assert frozenset({"embargo", "radar"}) in pairs


def test_host_shared_by_two_is_stronger_than_by_three(store):
    dls(store, "a", "x.onion"); dls(store, "b", "x.onion")
    for g in ("c", "d", "e"):
        dls(store, g, "platform.onion")
    edges = {(e["a"], e["b"]): e["confidence"] for e in graph.build_edges(store)}
    assert edges[("a", "b")] == 0.80
    assert edges[("c", "d")] == 0.50


def test_platform_hosts_do_not_form_clusters_at_default_threshold(store):
    for g in ("c", "d", "e"):
        dls(store, g, "platform.onion")
    assert graph.clusters(graph.build_edges(store), 0.6) == []
    assert len(graph.clusters(graph.build_edges(store), 0.4)) == 1


def test_alias_names_collapse(store):
    victim(store, "The Green Blood Group", "v1")
    victim(store, "thegreenbloodgroup", "v2")
    edges = graph.build_edges(store)
    assert [e["kind"] for e in edges] == ["alias-name"] and edges[0]["confidence"] == 0.95
    act = graph.activity(store)
    assert len(act) == 1 and act[0]["victims"] == 2                # counts merged, not split


def test_shared_wallet_links_groups(store):
    store.observe("leaksites", "wallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                  {"chain": "btc", "groups": ["alpha", "beta"]})
    e = graph.build_edges(store)
    assert e[0]["kind"] == "shared-wallet" and e[0]["confidence"] == 0.85


def test_shared_victim_is_weak_lead_only(store):
    victim(store, "alpha", "Acme Corp"); victim(store, "beta", "ACME CORP ")
    e = graph.build_edges(store)
    assert e[0]["kind"] == "shared-victim" and e[0]["confidence"] == 0.30
    assert graph.clusters(e, 0.6) == []


def test_edge_confidence_is_strongest_evidence_regardless_of_order(store):
    """Regression: confidence used to depend on which evidence was inserted first."""
    for order in (["weak", "strong"], ["strong", "weak"]):
        s = Store(str(store.path) + "-" + "".join(order))
        for kind in order:
            if kind == "strong":
                dls(s, "a", "pair.onion"); dls(s, "b", "pair.onion")
            else:
                for g in ("a", "b", "c"):
                    dls(s, g, "plat.onion")
        e = next(x for x in graph.build_edges(s) if (x["a"], x["b"]) == ("a", "b"))
        assert e["confidence"] == 0.80


def test_activity_decays_with_age(store):
    now = time.time()
    victim(store, "fresh", "v", time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 86400)))
    victim(store, "stale", "v", time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 365 * 86400)))
    rows = {r["group"]: r for r in graph.activity(store, half_life_days=90, now=now)}
    assert rows["fresh"]["decayed_activity"] > 0.98
    assert rows["stale"]["decayed_activity"] < 0.1

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Correctness of the intelligence OnionClaw derives: group correlation, risk links,
the IoC view and STIX indicators. Uses the real captured ransomware.live feeds."""
import json
import os
import sys
import time
from datetime import datetime, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import entities  # noqa: E402
import graph  # noqa: E402
import iocs  # noqa: E402
import risk  # noqa: E402
import stix  # noqa: E402
import ttp  # noqa: E402
from collectors import GroupInfraCollector  # noqa: E402
from store import Store  # noqa: E402


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "t.db"))


@pytest.fixture
def groups(store):
    GroupInfraCollector(fetch_json=lambda u: fx("groups.json")).collect(store)
    return store


def _recent():
    return datetime.fromtimestamp(time.time() - 2 * 86400, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _green_blood_victims(store, n=1):
    for k in range(n):
        store.observe("leaksites", "victim", f"https://tracker.test/gb{k}",
                      {"group": "thegreenbloodgroup", "victim": f"V{k}", "activity": "Healthcare",
                       "country": "US", "attackdate": _recent()}, "v")


# ── names ──────────────────────────────────────────────────────────
def test_names_in_other_scripts_stay_distinct():
    """Everything outside a-z0-9 was stripped, so these all became '' and merged."""
    assert len({graph.norm(n) for n in ("Медуза", "Кракен", "龙", "???", "!!!")}) == 5


def test_names_still_match_across_case_accents_and_punctuation():
    assert graph.norm("LockBit 3.0") == graph.norm("lockbit30")
    assert graph.norm("Ransomwaré") == graph.norm("RANSOMWARE")


def test_unrelated_groups_in_other_scripts_are_not_aliases(store):
    for g, host in (("Медуза", "m" * 56 + ".onion"), ("Кракен", "k" * 56 + ".onion")):
        store.observe("groupinfra", "dls", f"{g}|{host}", {"group": g, "available": True}, "dls")
    assert [e for e in graph.build_edges(store) if e["kind"] == "alias-name"] == []


def test_a_host_listed_with_and_without_a_path_is_one_shared_host(store):
    host = "s" * 56 + ".onion"
    store.observe("groupinfra", "dls", f"alpha|{host}", {"group": "alpha", "available": True}, "d")
    store.observe("groupinfra", "dls", f"beta|{host}/leaks", {"group": "beta", "available": True}, "d")
    assert any(e["kind"] == "shared-host" for e in graph.build_edges(store))


def test_graph_rejects_a_zero_half_life(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["graph.py", "--half-life", "0"])
    with pytest.raises(SystemExit) as e:
        graph.main()
    assert e.value.code == 2


# ── risk ───────────────────────────────────────────────────────────
def test_a_group_is_not_linked_to_its_own_alias(groups):
    """The alias edge between two spellings made the group 'linked' to itself."""
    _green_blood_victims(groups)
    row = next(r for r in risk.score_groups(groups) if "green" in r["group"].lower())
    assert row["evidence"]["linked_groups"] == [] and row["components"]["links"] == 0


def test_risk_group_filter_accepts_any_spelling(groups, monkeypatch, capsys):
    _green_blood_victims(groups)
    for spelling in ("thegreenbloodgroup", "The Green Blood Group"):
        monkeypatch.setattr(sys, "argv", ["risk.py", "--db", groups.path, "--group", spelling])
        assert risk.main() == 0
    capsys.readouterr()


# ── IoC view ───────────────────────────────────────────────────────
def test_leak_sites_with_a_path_or_port_are_listed(groups):
    """D1R's only leak site is 'dirone...onion/items'; IP-hosted sites carry ports."""
    values = {(r["type"], r["value"]) for r in iocs.collect(groups)}
    assert ("onion_host", "dirone3rl3vvq64ckcnrvhe2ogrhjrwu5u7hqzrlotu3rfvmqmmbsuqd.onion") in values
    assert ("ipv4", "95.143.191.148") in values


def test_ioc_group_filter_survives_the_display_name_flipping(groups):
    """After posts by 'thegreenbloodgroup' the canonical name flipped and the documented
    blocklist export went from 2 rows to 0."""
    before = len(iocs.filter_rows(iocs.collect(groups), group="The Green Blood Group"))
    _green_blood_victims(groups, n=2)
    rows = iocs.collect(groups)
    assert before > 0
    for spelling in ("The Green Blood Group", "thegreenbloodgroup"):
        assert len(iocs.filter_rows(rows, group=spelling)) >= before


def test_no_match_is_not_reported_as_an_empty_store(groups, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["iocs.py", "--db", groups.path, "--type", "tox"])
    iocs.main()
    out = capsys.readouterr().out
    assert "No indicators match these filters" in out and "Run swarm.py" not in out


def test_ttp_unknown_technique_is_not_reported_as_no_data(groups, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ttp.py", "--db", groups.path, "--technique", "T9999"])
    ttp.main()
    assert "No group is recorded using T9999" in capsys.readouterr().out


# ── STIX indicators ────────────────────────────────────────────────
def _value(pattern):
    return pattern.split("'")[1]


def test_leak_site_indicators_use_the_right_observable(groups):
    pats = [o["pattern"] for o in stix.build_bundle(groups)["objects"] if o["type"] == "indicator"]
    bad = [p for p in pats if p.startswith("[domain-name:")
           and ("/" in _value(p) or ":" in _value(p) or entities.IPV4_RE.match(_value(p)))]
    assert bad == []
    assert any(p.startswith("[url:value = 'http://dirone3rl3") and "/items" in p for p in pats)
    assert "[ipv4-addr:value = '95.143.191.148']" in pats


def test_the_bundle_still_validates(groups):
    stix2 = pytest.importorskip("stix2")
    validator = pytest.importorskip("stix2patterns.validator")
    b = stix.build_bundle(groups)
    stix2.parse(json.dumps(b), allow_custom=True)
    assert [o for o in b["objects"] if o["type"] == "indicator"
            and validator.run_validator(o["pattern"])] == []


def test_stix_rejects_a_malformed_since_cleanly(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stix.py", "--db", str(tmp_path / "x.db"), "--since", "yesterday"])
    assert stix.main() == 2


# ── entities ───────────────────────────────────────────────────────
def test_eth_spellings_of_one_wallet_are_one_wallet():
    a = "0x52908400098527886E0F7030069857D2E4169EE7"
    assert entities.extract_entities(f"{a} and {a.lower()}")["eth_wallets"] == [a.lower()]


def test_site_host_strips_scheme_port_and_path():
    v3 = "d" * 56 + ".onion"
    assert entities.site_host(f"{v3}/items") == v3
    assert entities.site_host("95.143.191.148:3000") == "95.143.191.148"
    assert entities.site_host("92.118.36.204.") == "92.118.36.204"
    assert entities.site_host("https://crpx0.su/affiliate") == "crpx0.su"

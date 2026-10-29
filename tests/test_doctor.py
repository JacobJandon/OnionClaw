# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Setup check (doctor.py), adapted from PRISM-Intel's doctor command."""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import doctor


@pytest.fixture
def rep():
    return doctor.build(deep=False)


def test_every_check_is_well_formed(rep):
    assert rep.groups and rep.rows
    for r in rep.rows:
        assert r["state"] in (doctor.OK, doctor.WARN, doctor.FAIL)
        assert r["check"] and isinstance(r["required"], bool)
        if r["state"] != doctor.OK and r["required"]:
            assert r["fix"], f"a required failure must say how to fix it: {r['check']}"


def test_core_dependencies_are_required_and_present(rep):
    core = dict((r["check"], r) for n, rows in rep.groups if n == "Core" for r in rows)
    for name in ("requests", "beautifulsoup4", "python-dotenv"):
        assert core[name]["required"] and core[name]["state"] == doctor.OK


def test_tor_and_llm_are_optional_so_doctor_passes_without_them(rep):
    """Search, fetch, crawl and the clearnet collectors work with no Tor and no LLM key,
    so neither may fail the run."""
    optional = {r["check"] for n, rows in rep.groups if n in ("Tor", "Configuration") for r in rows}
    assert {"SOCKS port", "ControlPort", "LLM provider"} <= optional
    for n, rows in rep.groups:
        if n in ("Tor", "Configuration"):
            assert all(not r["required"] for r in rows)


def test_missing_tor_does_not_make_the_run_fail(monkeypatch):
    monkeypatch.setattr(doctor, "_port_open", lambda *a, **k: False)
    rep = doctor.build(deep=False)
    tor = [r for n, rows in rep.groups if n == "Tor" for r in rows]
    assert tor and all(r["state"] == doctor.WARN for r in tor)
    assert all(r["fix"] for r in tor)
    assert rep.failures() == []            # exit code stays 0


def test_a_missing_required_dependency_fails_the_run(monkeypatch):
    real = doctor.importlib.import_module

    def boom(name, *a, **k):
        if name == "requests":
            raise ImportError("simulated")
        return real(name, *a, **k)

    monkeypatch.setattr(doctor.importlib, "import_module", boom)
    rep = doctor.build(deep=False)
    fails = rep.failures()
    assert [r["check"] for r in fails] == ["requests"]
    assert "pip install" in fails[0]["fix"]


def test_render_names_the_fix_for_every_problem(rep):
    text = doctor.render(rep, deep=False)
    assert "OnionClaw doctor" in text
    for r in rep.rows:
        if r["state"] != doctor.OK and r["fix"]:
            assert r["fix"] in text


def test_json_output_is_machine_readable(rep, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["doctor.py", "--json"])
    code = doctor.main()
    data = json.loads(capsys.readouterr().out)
    assert code in (0, 1)
    assert data["ready"] is (code == 0)
    assert data["groups"] and all("checks" in g for g in data["groups"])

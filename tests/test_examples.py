# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""The CrewAI and LangChain examples, with stand-ins for the frameworks (neither is a
dependency) and for the engine's network calls."""
import importlib
import os
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sicry  # noqa: E402

URL = "http://" + "r" * 56 + ".onion/thread/7"
RESULTS = [{"url": URL, "title": "Leak thread", "engine": "Ahmia", "confidence": 0.7}]


class _Rec:
    made = []

    def __init__(self, *a, **k):
        self.kw = k
        _Rec.made.append(self)


@pytest.fixture
def crew_example(monkeypatch):
    class Crew(_Rec):
        def kickoff(self):
            return "REPORT"
    fake = types.SimpleNamespace(Agent=type("Agent", (_Rec,), {}), Task=type("Task", (_Rec,), {}),
                                 Crew=Crew)
    monkeypatch.setitem(sys.modules, "crewai", fake)
    sys.modules.pop("examples_crewai", None)
    calls = {"search": 0}

    def search(q, **k):
        calls["search"] += 1
        return [dict(r) for r in RESULTS]
    monkeypatch.setattr(sicry, "search", search)
    monkeypatch.setattr(sicry, "scrape_all", lambda items, **k: {URL: "Leak thread - page text"})
    monkeypatch.setattr(sicry, "check_tor", lambda: {"tor_active": True})
    return importlib.import_module("examples_crewai"), calls


def test_crewai_example_works_from_real_sicry_results(crew_example):
    """The researcher had no tools and was asked for 15-20 results, so the
    'investigation report' was invented by the model."""
    mod, calls = crew_example
    _Rec.made.clear()
    assert mod.run_dark_web_investigation("acme leak") == "REPORT"
    assert calls["search"] == 1
    research = next(t for t in _Rec.made if "RESULTS" in t.kw.get("description", ""))
    assert URL in research.kw["description"] and "do not add results" in research.kw["description"]


def test_crewai_example_stops_when_tor_is_down(crew_example, monkeypatch):
    mod, calls = crew_example
    monkeypatch.setattr(sicry, "check_tor", lambda: {"tor_active": False, "error": "refused"})
    assert mod.run_dark_web_investigation("acme leak").startswith("ERROR")
    assert calls["search"] == 0


def test_crewai_example_does_not_run_agents_on_no_results(crew_example, monkeypatch):
    mod, _ = crew_example
    monkeypatch.setattr(sicry, "search", lambda q, **k: [])
    assert "nothing to analyse" in mod.run_dark_web_investigation("acme leak")


@pytest.fixture
def chain_example(monkeypatch):
    built = {}

    class Tool:
        def __init__(self, name, func, description):
            self.name, self.func = name, func

        def run(self, text):          # LangChain calls func with exactly one string
            return self.func(text)

    lc = types.ModuleType("langchain")
    tools = types.SimpleNamespace(Tool=Tool)
    agents = types.SimpleNamespace(AgentType=types.SimpleNamespace(OPENAI_FUNCTIONS="f"),
                                   initialize_agent=lambda **k: built.setdefault("tools", k["tools"]))
    memory = types.SimpleNamespace(ConversationBufferMemory=lambda **k: None)
    for name, mod in (("langchain", lc), ("langchain.tools", tools), ("langchain.agents", agents),
                      ("langchain.memory", memory),
                      ("langchain_openai", types.SimpleNamespace(ChatOpenAI=lambda **k: None))):
        monkeypatch.setitem(sys.modules, name, mod)
    sys.modules.pop("examples_langchain", None)
    monkeypatch.setattr(sicry, "check_tor", lambda: {"tor_active": True})
    monkeypatch.setattr(sicry, "check_search_engines", lambda *a, **k: [{"name": "Ahmia", "status": "up"}])
    return importlib.import_module("examples_langchain"), built


def test_every_langchain_tool_accepts_one_string(chain_example):
    """check_engine_health (no arguments) and analyze_results (two) crashed on their
    first call."""
    mod, built = chain_example
    mod.create_dark_web_agent()
    tools = {t.name: t for t in built["tools"]}
    assert "Online: 1/1" in tools["check_engine_health"].run("")
    assert tools["analyze_results"].run("[]") == "No results to analyze."


def test_langchain_example_refuses_to_start_without_tor(chain_example, monkeypatch):
    mod, _ = chain_example
    monkeypatch.setattr(sicry, "check_tor", lambda: {"tor_active": False})
    with pytest.raises(RuntimeError, match="Tor is not running"):
        mod.create_dark_web_agent()

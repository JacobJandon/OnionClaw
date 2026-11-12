# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""setup.py must never destroy or spread the user's keys, and must not trust files in
directories other users can write. Every test runs against a scratch directory."""
import json
import os
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import setup  # noqa: E402

TEMPLATE = ("LLM_PROVIDER=openai\nOPENAI_API_KEY=sk-...\nANTHROPIC_API_KEY=sk-ant-...\n"
            "TOR_SOCKS_PORT=9050\n")
EXISTING = ("LLM_PROVIDER=anthropic\nOPENAI_API_KEY=sk-real-openai-key\n"
            "ANTHROPIC_API_KEY=sk-ant-real-key\nTOR_CONTROL_PASSWORD=hunter2\n"
            "TOR_SOCKS_PORT=9150\nSICRY_CACHE_TTL=60\n")


@pytest.fixture
def install(tmp_path, monkeypatch):
    """An OnionClaw install at <tmp>/.openclaw/skills/onionclaw with an existing .env."""
    d = tmp_path / ".openclaw" / "skills" / "onionclaw"
    d.mkdir(parents=True)
    (d / ".env.example").write_text(TEMPLATE)
    (d / ".env").write_text(EXISTING)
    for name, value in (("_DIR", str(d)), ("_ENV", str(d / ".env")),
                        ("_EXAMPLE", str(d / ".env.example")),
                        ("_EXAMPLE_PARENT", str(d.parent / ".env.example"))):
        monkeypatch.setattr(setup, name, value)
    return d


def _answers(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it, ""))


def _env(path):
    from dotenv import dotenv_values
    return dict(dotenv_values(path))


def test_pressing_enter_through_setup_keeps_every_key(install, monkeypatch):
    """Re-configure used to default to Yes and copy the template over .env."""
    _answers(monkeypatch)                                  # Enter at every prompt
    setup.setup_env()
    assert (install / ".env").read_text() == EXISTING


def test_reconfiguring_changes_only_what_is_typed(install, monkeypatch):
    _answers(monkeypatch, "y", "", "")                     # re-configure, keep provider, keep key
    setup.setup_env()
    after = _env(install / ".env")
    assert after["LLM_PROVIDER"] == "anthropic"
    assert after["ANTHROPIC_API_KEY"] == "sk-ant-real-key"
    assert after["OPENAI_API_KEY"] == "sk-real-openai-key"
    assert after["TOR_CONTROL_PASSWORD"] == "hunter2"
    assert after["TOR_SOCKS_PORT"] == "9150" and after["SICRY_CACHE_TTL"] == "60"
    backups = list(install.glob(".env.bak-*"))
    assert len(backups) == 1 and backups[0].read_text() == EXISTING
    assert oct(backups[0].stat().st_mode & 0o777) == "0o600"


def test_a_new_key_replaces_only_that_key(install, monkeypatch):
    _answers(monkeypatch, "y", "1", "sk-new-openai")
    setup.setup_env()
    after = _env(install / ".env")
    assert after["LLM_PROVIDER"] == "openai" and after["OPENAI_API_KEY"] == "sk-new-openai"
    assert after["ANTHROPIC_API_KEY"] == "sk-ant-real-key"


def test_keys_are_never_copied_outside_the_install(install, monkeypatch):
    """Setup copied .env into the parent directory, ~/.openclaw/skills/.env here, where
    any other skill's load_dotenv() would pick the keys up."""
    os.remove(install / ".env")
    _answers(monkeypatch, "1", "sk-fresh-key", "y", "y", "y")
    setup.setup_env()
    assert not (install.parent / ".env").exists()


def test_copy_to_a_sicry_checkout_is_opt_in(install, monkeypatch):
    (install.parent / "sicry.py").write_text("# the SICRY repo\n")
    os.remove(install / ".env")
    _answers(monkeypatch, "1", "sk-fresh-key")              # Enter at the copy question
    setup.setup_env()
    assert not (install.parent / ".env").exists()


def test_custom_torrc_lives_in_a_private_directory(tmp_path, monkeypatch, install):
    d = tmp_path / "home" / ".onionclaw" / "tor"
    monkeypatch.setattr(setup, "CUSTOM_TORRC_DIR", str(d))
    monkeypatch.setattr(setup, "CUSTOM_TORRC_PATH", str(d / "torrc"))
    setup._write_custom_torrc()
    assert "ControlPort" in (d / "torrc").read_text()
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    assert oct((d / "torrc").stat().st_mode & 0o777) == "0o600"


def test_custom_torrc_refuses_a_planted_symlink(tmp_path, monkeypatch, install):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    planted = tmp_path / "planted"
    planted.symlink_to(tmp_path)                           # a directory someone else prepared
    monkeypatch.setattr(setup, "CUSTOM_TORRC_DIR", str(planted))
    monkeypatch.setattr(setup, "CUSTOM_TORRC_PATH", str(planted / "victim.txt"))
    setup._write_custom_torrc()
    assert victim.read_text() == "precious"


def test_the_default_torrc_location_is_private_to_the_user():
    assert setup.CUSTOM_TORRC_DIR == os.path.join(os.path.expanduser("~"), ".onionclaw", "tor")


@pytest.mark.parametrize("exc,code", [(KeyboardInterrupt, 130), (EOFError, 1)])
def test_an_interrupted_setup_does_not_exit_successfully(monkeypatch, exc, code):
    def boom(prompt=""):
        raise exc
    monkeypatch.setattr("builtins.input", boom)
    with pytest.raises(SystemExit) as e:
        setup._ask("anything")
    assert e.value.code == code


def test_engine_check_cache_is_per_user(tmp_path):
    """The cache was a fixed file in shared /tmp that another user could pre-fill."""
    cache = tmp_path / ".onionclaw" / "engines_cache.json"
    cache.parent.mkdir()
    cache.write_text(json.dumps({"_timestamp": time.time(),
                                 "results": [{"name": "PlantedEngine", "status": "up"}]}))
    env = {**os.environ, "HOME": str(tmp_path)}
    out = subprocess.run([sys.executable, os.path.join(ROOT, "check_engines.py"), "--cached", "60",
                          "--json"], capture_output=True, text=True, env=env, timeout=60)
    assert "PlantedEngine" in out.stdout

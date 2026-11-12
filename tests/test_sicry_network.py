# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""Privacy guarantees of the bundled engine's network layer: nothing leaves outside Tor."""
import os
import sys

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sicry  # noqa: E402

ONION = "http://" + "a" * 56 + ".onion/"


def _effective_proxy(session, url):
    proxies = session.merge_environment_settings(url, {}, None, None, None)["proxies"]
    return requests.utils.select_proxy(url, proxies)


@pytest.mark.parametrize("url", ["https://ahmia.fi/search/?q=x", ONION])
def test_environment_proxies_cannot_replace_tor(monkeypatch, url):
    """requests gives HTTP(S)_PROXY priority over session.proxies, so a corporate proxy
    setting silently sent every request, onion and clearnet, outside Tor."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(var, "http://corp-proxy.example:3128")
    tor = f"socks5h://{sicry.TOR_SOCKS_HOST}:{sicry.TOR_SOCKS_PORT}"
    assert _effective_proxy(sicry._build_tor_session(), url) == tor


def test_pool_sessions_ignore_environment_proxies_too(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy.example:3128")
    pool = sicry.TorPool(size=1)
    proxy = _effective_proxy(pool.session(), "https://ahmia.fi/")
    assert proxy.startswith("socks5h://127.0.0.1:")


def test_server_errors_with_content_are_returned_not_raised():
    """A hidden service's 503 queue page has real content; raising RetryError lost it."""
    retry = sicry._build_tor_session().get_adapter("http://x.onion/").max_retries
    assert retry.raise_on_status is False


class _Session:
    def __init__(self, status=200, body=None):
        self.calls, self.status, self.body = [], status, body or {}

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers or {}))
        r = requests.models.Response()
        r.status_code, r.url = self.status, url
        r._content = requests.compat.json.dumps(self.body).encode()
        return r


@pytest.fixture
def tor(monkeypatch):
    def use(up=True, **kw):
        s = _Session(**kw)
        monkeypatch.setattr(sicry, "_tor_port_open", lambda *a, **k: up)
        monkeypatch.setattr(sicry, "_build_tor_session", lambda: s)
        monkeypatch.setattr(sicry.requests, "get",
                            lambda *a, **k: pytest.fail("update check went outside Tor"))
        return s
    return use


def test_update_check_is_skipped_not_sent_directly_when_tor_is_down(tor):
    s = tor(up=False)
    r = sicry.check_update()
    assert r["up_to_date"] is None and "Tor" in r["error"]
    assert s.calls == []


def test_update_check_compares_the_repo_it_was_asked_about(tor):
    """It compared OnionClaw's release tags with the engine's own version number, so
    publishing OnionClaw v2.4.0 would announce an update on every run."""
    s = tor(body={"tag_name": "v2.4.0", "html_url": "https://example.test/r"})
    r = sicry.check_update(repo="JacobJandon/OnionClaw", current="2.4.1")
    assert r["up_to_date"] is True and r["latest"] == "2.4.0"
    assert s.calls[0][0].endswith("/repos/JacobJandon/OnionClaw/releases/latest")
    assert sicry.check_update(repo="JacobJandon/OnionClaw", current="2.3.9")["up_to_date"] is False


def test_update_check_does_not_announce_itself(tor):
    s = tor(body={"tag_name": "v1.0.0"})
    sicry.check_update()
    agent = s.calls[0][1].get("User-Agent", "")
    assert agent in sicry._USER_AGENTS and "OnionClaw" not in agent and "SICRY" not in agent


@pytest.mark.parametrize("status", [404, 500])
def test_a_failed_update_check_is_unknown_not_up_to_date(tor, status):
    tor(status=status)
    assert sicry.check_update()["up_to_date"] is None

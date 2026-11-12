# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""The bundled engine's exports, agent integrations, storage, circuit pool, ranking and
error reporting. Offline throughout."""
import hashlib
import json
import os
import subprocess
import sys
import types

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import sicry  # noqa: E402

V3 = "q" * 56 + ".onion"
RESULT = {"url": f"http://{V3}/a", "title": "t", "engine": "Ahmia", "confidence": 0.5}


# ── exports ────────────────────────────────────────────────────────
def test_stix_bundle_is_accepted_by_the_oasis_parser():
    """A bundle-level spec_version reads as STIX 2.0, so every export was rejected."""
    stix2 = pytest.importorskip("stix2")
    bundle = sicry.to_stix([RESULT], query="q", report_text="r")
    stix2.parse(json.dumps(bundle), allow_custom=True)


@pytest.mark.parametrize("export", ["to_stix", "to_misp", "to_csv"])
def test_exports_accept_untitled_pages(export):
    """fetch() returns title None for untitled pages; the exports crashed on it."""
    getattr(sicry, export)([{"url": f"http://{V3}/", "title": None, "confidence": None}])


def test_misp_flags_only_onion_hosts_as_indicators():
    event = sicry.to_misp([RESULT, {"url": "https://news.example/story", "title": "n"}])
    attrs = event["Event"]["Attribute"] if "Event" in event else event["Attribute"]
    hosts = {a["value"]: a["to_ids"] for a in attrs if a["type"] in ("domain", "hostname")}
    assert hosts == {V3: True, "news.example": False}


# ── agent integrations ─────────────────────────────────────────────
def _arrays_without_items(node, path=()):
    if isinstance(node, dict):
        if node.get("type") == "array" and "items" not in node:
            yield path
        for k, v in node.items():
            yield from _arrays_without_items(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _arrays_without_items(v, path + (i,))


@pytest.mark.parametrize("schema", ["TOOLS", "TOOLS_OPENAI", "TOOLS_GEMINI"])
def test_every_array_parameter_declares_its_items(schema):
    """OpenAI and Gemini reject a tool list with an array lacking items, so no
    SICRY tool worked with them at all."""
    assert list(_arrays_without_items(getattr(sicry, schema))) == []


def test_mcp_server_starts_and_registers_its_tools(monkeypatch):
    """FastMCP(description=...) raised TypeError on current mcp releases."""
    fastmcp = pytest.importorskip("mcp.server.fastmcp")
    ran = {}
    monkeypatch.setattr(fastmcp.FastMCP, "run",
                        lambda self, *a, **k: ran.setdefault("tools", len(self._tool_manager.list_tools())))
    sicry._start_mcp_server()
    assert ran["tools"] == len(sicry.TOOLS)


# ── storage ────────────────────────────────────────────────────────
def test_crawling_a_site_again_keeps_earlier_jobs(tmp_path):
    db = sicry._DB(str(tmp_path / "s.db"))
    for u in ("/", "/a", "/b"):
        db.crawl_save_page(f"http://{V3}{u}", "monday", 0, "t", "x", {})
    db.crawl_save_page(f"http://{V3}/a", "tuesday", 0, "t", "y", {})
    assert len(db.crawl_export("monday")["pages"]) == 3
    assert len(db.crawl_export("tuesday")["pages"]) == 1


def test_a_database_from_an_older_version_is_migrated_with_its_pages(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE crawl_pages (url TEXT PRIMARY KEY, job_id TEXT, depth INTEGER, "
                  "ts REAL, title TEXT, text TEXT, entities TEXT)")
        c.execute("INSERT INTO crawl_pages VALUES (?,?,?,?,?,?,?)",
                  (f"http://{V3}/", "old-job", 0, 1.0, "t", "x", "{}"))
    db = sicry._DB(path)
    assert len(db.crawl_export("old-job")["pages"]) == 1
    db.crawl_save_page(f"http://{V3}/", "new-job", 0, "t", "y", {})
    assert len(db.crawl_export("old-job")["pages"]) == 1


def test_a_bare_filename_works_as_the_database_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sicry._DB("sicry.db")


def test_clear_cache_keeps_resume_checkpoints_and_empties_memory(tmp_path, monkeypatch):
    db = sicry._DB(str(tmp_path / "s.db"))
    monkeypatch.setattr(sicry, "_db", lambda: db)
    db.cache_set("pipeline_checkpoint:job42", "pipeline", {"steps": {"search": 1}})
    db.cache_set("q|x|10|", "search", [RESULT])
    monkeypatch.setattr(sicry, "_SEARCH_MEM_CACHE", {"q|x|10|": (9e18, [RESULT])})
    sicry.clear_cache()
    assert db.cache_get("pipeline_checkpoint:job42", "pipeline", 86400) is not None
    assert db.cache_get("q|x|10|", "search", 86400) is None and sicry._SEARCH_MEM_CACHE == {}


# ── circuit pool ───────────────────────────────────────────────────
def test_pool_without_tor_installed_cleans_up_and_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(sicry.tempfile, "tempdir", str(tmp_path))

    def no_tor(*a, **k):
        raise FileNotFoundError("tor")
    monkeypatch.setattr(sicry.subprocess, "Popen", no_tor)
    with pytest.raises(RuntimeError, match="could not start tor"):
        sicry.TorPool(size=2).start()
    assert not list(tmp_path.glob("tor_pool_*"))
    monkeypatch.setattr(sicry, "TOR_POOL_SIZE", 2)
    monkeypatch.setattr(sicry, "_pool_instance", None)
    monkeypatch.setattr(sicry, "_pool_disabled", False)
    assert sicry._get_pool() is None and sicry._pool_disabled is True   # no retry per request


def test_an_on_demand_pool_is_stopped_at_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(sicry.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(sicry.subprocess, "Popen", lambda *a, **k: types.SimpleNamespace(
        poll=lambda: None, terminate=lambda: None, wait=lambda timeout=None: 0, kill=lambda: None))

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(sicry.socket, "create_connection", lambda *a, **k: _Conn())
    registered = []
    monkeypatch.setattr(sicry.atexit, "register", registered.append)
    monkeypatch.setattr(sicry, "TOR_POOL_SIZE", 2)
    monkeypatch.setattr(sicry, "_pool_instance", None)
    monkeypatch.setattr(sicry, "_pool_disabled", False)
    pool = sicry._get_pool()
    assert pool is not None and registered == [pool.stop]
    pool.stop()


# ── ranking ────────────────────────────────────────────────────────
def test_reading_a_page_does_not_demote_it():
    """A fixed avgdl of 12 ranked a scraped on-topic page below an unscraped
    off-topic one."""
    a = {"url": f"http://{V3}/victims", "title": "LockBit ransomware leak site - victims list"}
    b = {"url": f"http://{V3}/vpn", "title": "Cheap VPN accounts ransomware"}
    text = a["title"] + " " + " ".join(f"victim{i} corp data published" for i in range(60))
    ranked = sicry.score_results("lockbit ransomware leak", [a, b], texts={a["url"]: text})
    assert ranked[0]["url"] == a["url"]


# ── error messages ─────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expect", [
    ("SOCKSHTTPConnectionPool(host='x.onion', port=80): Max retries exceeded "
     "(Caused by ProxyError(SOCKS5Error('0x04: Host unreachable')))", "Hidden service unreachable"),
    ("SOCKSHTTPConnectionPool(host='x.onion', port=80): Read timed out. (read timeout=45)",
     "timed out"),
    ("SOCKSHTTPConnectionPool(host='x.onion', port=80): Max retries exceeded (Caused by "
     "NewConnectionError('<SOCKSConnection>: Failed to establish a new connection: "
     "[Errno 111] Connection refused'))", "is `tor` running"),
])
def test_errors_say_whether_tor_or_the_hidden_service_failed(raw, expect):
    """Every http:// Tor error used to read "is tor running?"."""
    assert expect in sicry._friendly_error(raw)


# ── no-LLM analysis ────────────────────────────────────────────────
def test_only_checksummed_bitcoin_addresses_are_reported():
    md5 = "1" + hashlib.md5(b"x").hexdigest()[1:].replace("0", "a")      # base58-shaped, no checksum
    taproot = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
    legacy = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    report = sicry.analyze_nollm(f"pay {legacy} or {taproot}. hash {md5}", query="q")
    btc = next(line for line in report.splitlines() if line.startswith("**BTC addresses**"))
    assert legacy in btc and taproot in btc and md5 not in btc


# ── the engine's crawler and its downloads ─────────────────────────
def test_engine_crawler_fetches_each_document_once_within_its_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(sicry, "_db", lambda: sicry._DB(str(tmp_path / "c.db")))
    calls = []
    links = [{"href": f"http://{V3}/t/1#p{i}"} for i in range(5)] + \
            [{"href": f"http://{V3}/p{i}"} for i in range(12)]

    def fetch(url, **kw):
        calls.append(url)
        return {"url": url, "status": 200, "title": "t", "text": "x",
                "links": links if url.rstrip("/") == f"http://{V3}" else [], "error": None}
    monkeypatch.setattr(sicry, "fetch", fetch)
    out = sicry.crawl(f"http://{V3}/", max_depth=2, max_pages=6)
    assert len(calls) == len(set(calls)) and len(calls) <= 6
    assert out.pages_found <= 6


class _Stream:
    def __init__(self, ctype, size):
        self.ctype, self.size = ctype, size

    def get(self, url, headers=None, timeout=None, stream=False, **_):
        r = requests.models.Response()
        r.status_code, r.url, r.encoding = 200, url, "utf-8"
        r.headers["Content-Type"] = self.ctype
        r.raw = types.SimpleNamespace(read=lambda *a, **k: b"", stream=None)
        r.iter_content = lambda chunk_size=1: iter([b"<p>" + b"x" * 65536] * (self.size // 65536))
        r.close = lambda: None
        return r


def test_a_binary_download_is_not_fetched(monkeypatch):
    monkeypatch.setattr(sicry, "_pool_session", lambda: _Stream("application/zip", 4 * 1024 * 1024))
    out = sicry.fetch(f"http://{V3}/dump.zip", _use_cache=False)
    assert "not a web page" in out["error"]


def test_a_huge_page_is_capped_not_read_whole(monkeypatch):
    monkeypatch.setattr(sicry, "MAX_DOWNLOAD_BYTES", 256 * 1024)
    monkeypatch.setattr(sicry, "_pool_session", lambda: _Stream("text/html", 4 * 1024 * 1024))
    out = sicry.fetch(f"http://{V3}/huge", _use_cache=False, max_chars=0)
    assert out["truncated"] is True and len(out["text"]) <= 256 * 1024


def test_disabling_an_unknown_watch_job_is_an_error(tmp_path):
    env = {**os.environ, "HOME": str(tmp_path), "SICRY_DB_PATH": str(tmp_path / "w.db")}
    r = subprocess.run([sys.executable, os.path.join(ROOT, "sicry.py"), "watch", "disable", "nope"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1 and "No active watch job" in r.stderr

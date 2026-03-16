# SPDX-License-Identifier: MIT
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/Sicry
from __future__ import annotations

__version__ = "2.1.0"

"""
SICRY — Tor/Onion Network Access Layer for AI Agents
=====================================================
One file. No Robin install needed. Robin's patterns are baked in.

  pip install requests[socks] beautifulsoup4 python-dotenv stem
  apt install tor && tor &
  echo LLM_PROVIDER=ollama > .env   # or add OPENAI_API_KEY / ANTHROPIC_API_KEY

Five core tools — same interface as regular-internet equivalents:
  check_tor()                     — ping / verify Tor
  check_search_engines()          — ping all 12 engines, get latency
  search(query)                   — web_search() but for .onion
  fetch(url)                      — fetch_url() but via Tor
  ask(content, mode, ...)         — analyze() / LLM OSINT report
  renew_identity()                — rotate Tor circuit

Robin-powered quality tools (major improvement on dark web indexes):
  refine_query(query)             — LLM trims query to ≤5 focused words
  filter_results(query, results)  — LLM picks top-20 most relevant
  scrape_all(urls)                — batch fetch → {url: text} dict

Drop into any agent framework:
  Anthropic   →  tools=sicry.TOOLS,         sicry.dispatch(name, input)
  OpenAI      →  tools=sicry.TOOLS_OPENAI,  sicry.dispatch(name, input)
  Gemini      →  tools=sicry.TOOLS_GEMINI,  sicry.dispatch(name, input)
  LangChain   →  see examples.py
  CrewAI      →  see examples.py
  MCP server  →  python sicry.py serve
  OpenClaw    →  cp openclaw_skill/SKILL.md ~/.openclaw/workspace/skills/sicry/

MCP server config (Claude Desktop / Cursor / Zed / any MCP client):
  ~/.config/claude/claude_desktop_config.json:
    { "mcpServers": { "sicry": { "command": "python",
      "args": ["/absolute/path/to/sicry.py", "serve"] } } }

Powered by Robin's engine catalogue (github.com/apurvsinghgautam/robin, MIT).
Use responsibly and lawfully.
"""

import csv
import dataclasses
import hashlib
import io
import json
import logging
import math
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator, Optional
from urllib.parse import urljoin, urlparse, quote_plus, parse_qs, unquote

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress urllib3 retry noise — expected when some .onion nodes are unreachable
import warnings
warnings.filterwarnings("ignore", message=".*Retry.*", category=Warning)
warnings.filterwarnings("ignore", module="urllib3")
import logging as _ul3_log
_ul3_log.getLogger("urllib3").setLevel(_ul3_log.ERROR)
_ul3_log.getLogger("urllib3.connectionpool").setLevel(_ul3_log.ERROR)

# Kill stem logs completely — stem writes DEBUG/INFO during every control port
# interaction; propagate=False + NullHandler prevents them reaching any handler.
def _silence_stem():
    _s = _ul3_log.getLogger("stem")
    _s.setLevel(_ul3_log.CRITICAL)
    if not _s.handlers:
        _s.addHandler(_ul3_log.NullHandler())
    _s.propagate = False
    for _child in ("stem.control", "stem.response", "stem.socket",
                   "stem.connection", "stem.util"):
        _c = _ul3_log.getLogger(_child)
        _c.setLevel(_ul3_log.CRITICAL)
        _c.propagate = False
_silence_stem()
del _silence_stem

load_dotenv()
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("sicry")

# ─────────────────────────────────────────────────────────────────
# CONFIG  (all overridable via environment variables)
# ─────────────────────────────────────────────────────────────────

TOR_SOCKS_HOST     = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT     = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_HOST   = os.getenv("TOR_CONTROL_HOST", "127.0.0.1")
TOR_CONTROL_PORT   = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASS   = os.getenv("TOR_CONTROL_PASSWORD")
TOR_DATA_DIR       = os.getenv("TOR_DATA_DIR")   # optional: path to Tor DataDirectory for cookie auth
TOR_TIMEOUT        = int(os.getenv("TOR_TIMEOUT", "45"))
MAX_CONTENT_CHARS  = int(os.getenv("SICRY_MAX_CHARS", "8000"))
FETCH_CACHE_TTL    = int(os.getenv("SICRY_CACHE_TTL", "600"))  # seconds; 0 disables
_FETCH_CACHE: dict = {}   # in-memory TTL cache: key → (timestamp, result)
SEARCH_CACHE_TTL   = int(os.getenv("SICRY_SEARCH_CACHE_TTL", "1800"))  # cache search results 30 min
ENGINE_CACHE_TTL   = int(os.getenv("SICRY_ENGINE_CACHE_TTL", "3600"))  # engine health history TTL

# SQLite persistent store (replaces /tmp JSON cache — queryable, persistent, TTL per record type)
SICRY_DB_PATH      = os.getenv("SICRY_DB_PATH", os.path.expanduser("~/.sicry/sicry.db"))

# Tor circuit pool — multiple simultaneous identities
TOR_POOL_SIZE      = int(os.getenv("SICRY_POOL_SIZE", "0"))   # 0 = disabled (single circuit)
TOR_POOL_BASE_PORT = int(os.getenv("SICRY_POOL_BASE_PORT", "9060"))  # socks ports: 9060,9061...

# Watch/alert mode
WATCH_INTERVAL_DEFAULT = int(os.getenv("SICRY_WATCH_INTERVAL", "6"))  # hours between re-runs

# Update-check: GitHub Tags API (all git tags, not only formal Releases)
GITHUB_TAGS_URL = (
    "https://api.github.com/repos/JacobJandon/OnionClaw/tags?per_page=20"
)

OPENAI_API_KEY     = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL       = os.getenv("OPENAI_MODEL", "gpt-4o")
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL    = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-5")
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL       = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
OLLAMA_URL         = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL       = os.getenv("OLLAMA_MODEL", "llama3.2")
LLAMACPP_URL       = os.getenv("LLAMACPP_BASE_URL", "http://127.0.0.1:8080")
LLM_PROVIDER       = os.getenv("LLM_PROVIDER", "openai")

# ─────────────────────────────────────────────────────────────────
# SQLITE PERSISTENT STORE
# Replaces the old JSON file cache. Three tables:
#   cache       — URL/query fetches (type: fetch | search | engine)
#   engine_history — rolling health checks per engine
#   watch_jobs  — persistent watch/alert jobs
# All TTLs are per record-type and configurable via env vars.
# ─────────────────────────────────────────────────────────────────

class _DB:
    """Thread-safe SQLite wrapper. One connection per thread (check_same_thread=False
    is safe here because we use a lock around every write operation)."""

    def __init__(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._local = threading.local()
        self._lock  = threading.Lock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        with self._lock:
            c = self._conn()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS cache (
                    key       TEXT    NOT NULL,
                    cache_type TEXT   NOT NULL,
                    ts        REAL    NOT NULL,
                    data      TEXT    NOT NULL,
                    PRIMARY KEY (key, cache_type)
                );
                CREATE TABLE IF NOT EXISTS engine_history (
                    engine    TEXT  NOT NULL,
                    ts        REAL  NOT NULL,
                    status    TEXT  NOT NULL,
                    latency_ms INTEGER,
                    error     TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_eh_engine ON engine_history(engine, ts);
                CREATE TABLE IF NOT EXISTS watch_jobs (
                    id        TEXT PRIMARY KEY,
                    query     TEXT NOT NULL,
                    mode      TEXT NOT NULL DEFAULT 'threat_intel',
                    interval_hours REAL NOT NULL DEFAULT 6,
                    fingerprint TEXT,
                    last_run  REAL,
                    created   REAL NOT NULL,
                    enabled   INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS crawl_pages (
                    url       TEXT PRIMARY KEY,
                    job_id    TEXT,
                    depth     INTEGER,
                    ts        REAL,
                    title     TEXT,
                    text      TEXT,
                    entities  TEXT
                );
                CREATE TABLE IF NOT EXISTS crawl_links (
                    src   TEXT NOT NULL,
                    dst   TEXT NOT NULL,
                    PRIMARY KEY (src, dst)
                );
            """)
            c.commit()

    # ── cache ──────────────────────────────────────────────────────
    def cache_get(self, key: str, cache_type: str, ttl: int) -> dict | list | None:
        if ttl <= 0:
            return None
        row = self._conn().execute(
            "SELECT ts, data FROM cache WHERE key=? AND cache_type=?", (key, cache_type)
        ).fetchone()
        if row and (time.time() - row["ts"]) < ttl:
            try:
                return json.loads(row["data"])
            except Exception:
                return None
        return None

    def cache_set(self, key: str, cache_type: str, data: dict | list) -> None:
        with self._lock:
            self._conn().execute(
                "INSERT OR REPLACE INTO cache(key,cache_type,ts,data) VALUES(?,?,?,?)",
                (key, cache_type, time.time(), json.dumps(data, default=str)),
            )
            self._conn().commit()

    def cache_clear(self, cache_type: str | None = None) -> int:
        with self._lock:
            if cache_type:
                n = self._conn().execute(
                    "SELECT COUNT(*) FROM cache WHERE cache_type=?", (cache_type,)
                ).fetchone()[0]
                self._conn().execute("DELETE FROM cache WHERE cache_type=?", (cache_type,))
            else:
                n = self._conn().execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                self._conn().execute("DELETE FROM cache")
            self._conn().commit()
            return n

    def cache_prune(self) -> int:
        """Delete all expired records based on type-appropriate TTL."""
        now = time.time()
        with self._lock:
            n = 0
            for ctype, ttl in (("fetch", FETCH_CACHE_TTL),
                               ("search", SEARCH_CACHE_TTL),
                               ("engine", ENGINE_CACHE_TTL)):
                if ttl > 0:
                    cur = self._conn().execute(
                        "DELETE FROM cache WHERE cache_type=? AND ?-ts > ?",
                        (ctype, now, ttl),
                    )
                    n += cur.rowcount
            self._conn().commit()
        return n

    # ── engine health history ──────────────────────────────────────
    def engine_history_add(self, engine: str, status: str,
                           latency_ms: int | None, error: str | None) -> None:
        with self._lock:
            self._conn().execute(
                "INSERT INTO engine_history(engine,ts,status,latency_ms,error) VALUES(?,?,?,?,?)",
                (engine, time.time(), status, latency_ms, error),
            )
            # Keep only last 20 checks per engine
            self._conn().execute(
                """DELETE FROM engine_history WHERE engine=? AND ts NOT IN (
                    SELECT ts FROM engine_history WHERE engine=? ORDER BY ts DESC LIMIT 20
                )""",
                (engine, engine),
            )
            self._conn().commit()

    def engine_history_get(self, engine: str, n: int = 5) -> list[dict]:
        rows = self._conn().execute(
            "SELECT ts,status,latency_ms,error FROM engine_history "
            "WHERE engine=? ORDER BY ts DESC LIMIT ?",
            (engine, n),
        ).fetchall()
        return [dict(r) for r in rows]

    def engine_reliability(self, engine: str, window: int = 5) -> float:
        """Fraction of last `window` checks where engine was up. Returns 1.0 if no history."""
        rows = self.engine_history_get(engine, window)
        if not rows:
            return 1.0
        up = sum(1 for r in rows if r["status"] == "up")
        return up / len(rows)

    # ── watch jobs ─────────────────────────────────────────────────
    def watch_add(self, query: str, mode: str = "threat_intel",
                  interval_hours: float = 6) -> str:
        job_id = str(uuid.uuid4())[:8]
        with self._lock:
            self._conn().execute(
                "INSERT INTO watch_jobs(id,query,mode,interval_hours,created) "
                "VALUES(?,?,?,?,?)",
                (job_id, query, mode, interval_hours, time.time()),
            )
            self._conn().commit()
        return job_id

    def watch_list(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM watch_jobs WHERE enabled=1 ORDER BY created DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def watch_update(self, job_id: str, fingerprint: str, last_run: float) -> None:
        with self._lock:
            self._conn().execute(
                "UPDATE watch_jobs SET fingerprint=?, last_run=? WHERE id=?",
                (fingerprint, last_run, job_id),
            )
            self._conn().commit()

    def watch_disable(self, job_id: str) -> None:
        with self._lock:
            self._conn().execute(
                "UPDATE watch_jobs SET enabled=0 WHERE id=?", (job_id,)
            )
            self._conn().commit()

    def watch_due(self) -> list[dict]:
        """Return jobs that are due for a re-run."""
        now = time.time()
        rows = self._conn().execute(
            "SELECT * FROM watch_jobs WHERE enabled=1 AND "
            "(last_run IS NULL OR ?-last_run >= interval_hours*3600)",
            (now,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── crawl store ────────────────────────────────────────────────
    def crawl_save_page(self, url: str, job_id: str, depth: int, title: str,
                        text: str, entities: dict) -> None:
        with self._lock:
            self._conn().execute(
                "INSERT OR REPLACE INTO crawl_pages(url,job_id,depth,ts,title,text,entities) "
                "VALUES(?,?,?,?,?,?,?)",
                (url, job_id, depth, time.time(), title or "", text[:10000],
                 json.dumps(entities, default=str)),
            )
            self._conn().commit()

    def crawl_save_link(self, src: str, dst: str) -> None:
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO crawl_links(src,dst) VALUES(?,?)", (src, dst)
            )
            self._conn().commit()

    def crawl_export(self, job_id: str) -> dict:
        pages = [dict(r) for r in self._conn().execute(
            "SELECT url,depth,ts,title,entities FROM crawl_pages WHERE job_id=?", (job_id,)
        ).fetchall()]
        links = [dict(r) for r in self._conn().execute(
            "SELECT src,dst FROM crawl_links WHERE src IN "
            "(SELECT url FROM crawl_pages WHERE job_id=?)", (job_id,)
        ).fetchall()]
        return {"job_id": job_id, "pages": pages, "links": links}


# Module-level DB singleton (lazy: only created when used)
_db_instance: _DB | None = None
_db_lock = threading.Lock()


def _db() -> _DB:
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = _DB(SICRY_DB_PATH)
    return _db_instance


# ─────────────────────────────────────────────────────────────────
# BACKWARD-COMPAT: clear_cache() now delegates to SQLite store
# ─────────────────────────────────────────────────────────────────

def clear_cache() -> int:
    """Delete all cached fetch/search results.

    Returns the number of entries evicted.

    Example:
        >>> n = sicry.clear_cache()
        >>> print(f"Cleared {n} cached entries")
    """
    mem_count = len(_FETCH_CACHE)
    _FETCH_CACHE.clear()
    return mem_count + _db().cache_clear()


# ─────────────────────────────────────────────────────────────────
# CONTENT SAFETY  — keyword blacklist (SAFETY-1)
# Applied to every search result and fetched page before returning to caller.
# Zero tolerance: results matching any term are silently dropped; fetch()
# returns an error dict rather than displaying illegal content.
# ─────────────────────────────────────────────────────────────────
_CONTENT_BLACKLIST: frozenset[str] = frozenset({
    # child sexual abuse material (CSAM)
    "child porn", "childporn", "cp porn", "pedo", "paedo",
    "lolita", "loli ", "lolicon", "shotacon",
    "preteen sex", "preteen nude", "preteens sex",
    "underage sex", "underage nude", "underage porn",
    "jailbait", "jail bait",
    "teen porn", "teenporn", "teens sex", "teen nude",
    "child erotica", "child sex", "child nude", "child model",
    "boy lover", "girl lover", "boylover", "girllover",
    "toddler sex", "infant sex", "baby sex",
    "incest child", "minor sex", "minors sex",
    "hurtcore",
    # other hard illegal content
    "snuff film", "snuff video",
    "red room",
    # standalone violent/sexual terms (SAFETY-1 gap fix — token-pair bypass)
    " rape ", "rape video", "rape film", "rape porn", "rape site",
    "torture porn", "torture murder", "torture video",
    "kids sex", "kids porn", "kids nude",
    "child rape", "child torture", "child murder",
    "minor rape",
})

# Token pairs: if BOTH words appear anywhere in the text, block it.
# Catches titles like "KIDS - CHILD - RAPE" that bypass phrase matching.
_TOKEN_PAIR_BLACKLIST: tuple[tuple[str, str], ...] = (
    ("child",  "rape"),
    ("child",  "torture"),
    ("minor",  "rape"),
    ("minor",  "torture"),
    ("kids",   "rape"),
    ("kids",   "sex"),
    ("kids",   "porn"),
    ("baby",   "rape"),
    ("infant", "rape"),
    ("teen",   "rape"),
    ("snuff",  "live"),
)


def _is_content_safe(text: str) -> bool:
    """Return False if text contains any blacklisted phrase or token pair (case-insensitive)."""
    lower = text.lower()
    # 1. exact phrase match
    if any(term in lower for term in _CONTENT_BLACKLIST):
        return False
    # 2. standalone "rape" not caught above (prefix/suffix boundary)
    if re.search(r'\brake\b', lower) or re.search(r'\brape\b', lower):
        # allow criminology/news context terms like "date rape statistics"
        # but block if combined with any sexual/minor context word
        if re.search(r'\brake\b', lower):
            pass  # "brake" is safe
        elif any(kw in lower for kw in ("video", "film", "porn", "site", "photo",
                                        "image", "upload", "stream", "dark web",
                                        "onion", "market", "child", "minor",
                                        "teen", "kids", "baby", "infant")):
            return False
    # 3. token-pair check — blocks evasive titles like "KIDS — CHILD — RAPE"
    tokens = set(re.findall(r"[a-z]+", lower))
    if any(a in tokens and b in tokens for a, b in _TOKEN_PAIR_BLACKLIST):
        return False
    return True


# ─────────────────────────────────────────────────────────────────
# FRIENDLY ERROR MESSAGES  (issue #8)
# Maps raw socket/urllib3 noise to actionable user-facing strings.
# ─────────────────────────────────────────────────────────────────

_FRIENDLY_ERROR_MAP = [
    # SOCKS / Tor circuit
    (r"SOCKS5|SOCKSHTTPConnection|SOCKS proxy",
     "Tor circuit unavailable — is `tor` running? (`apt install tor && tor &`)"),
    (r"Max retries exceeded",
     "Tor circuit slow or overloaded — renew identity with `sicry.renew_identity()` and retry"),
    (r"timed out|Read timed out",
     "Tor circuit timed out — hidden service may be offline, or try renewing identity"),
    (r"Connection refused|ConnectionRefused",
     "Connection refused — hidden service is likely down"),
    (r"RemoteDisconnected|ConnectionReset",
     "Connection reset by hidden service — site may be overloaded"),
    (r"Name or service not known|Failed to resolve",
     "DNS/hostname not resolved — only .onion URLs work over Tor"),
    # Auth / crypto
    (r"SSL|certificate|cert verify",
     "TLS/SSL error on hidden service — try HTTP instead of HTTPS for this .onion"),
    # Network generic
    (r"Network is unreachable|No route to host",
     "Network unreachable — check your internet connection"),
    # Tor control port
    (r"control port|stem|authentication",
     "Tor control port auth failed — set TOR_CONTROL_PASSWORD or TOR_DATA_DIR in .env"),
]


def _friendly_error(exc: Exception | str) -> str:
    """Convert a raw exception into a human-readable, actionable error message."""
    msg = str(exc)
    for pattern, friendly in _FRIENDLY_ERROR_MAP:
        if re.search(pattern, msg, re.IGNORECASE):
            return friendly
    # Fall-through: return truncated original message
    return msg[:200] if len(msg) > 200 else msg


# ─────────────────────────────────────────────────────────────────
# ROTATING USER AGENTS  (same pool Robin uses)
# ─────────────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
]

# ─────────────────────────────────────────────────────────────────
# SEARCH ENGINES  (12 verified-live .onion indexes)
# Removed permanently-dead engines: Torgle, Kaizer, Anima, Tornado,
# TorNet, FindTor (all ceased responding as of 2026-Q1).
# Source: github.com/apurvsinghgautam/robin — MIT License
# ─────────────────────────────────────────────────────────────────

SEARCH_ENGINES = [
    {"name": "Ahmia",            "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "OnionLand",        "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Amnesia",          "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"},
    {"name": "Torland",          "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "Excavator",        "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    {"name": "Onionway",         "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66",            "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
    {"name": "OSS",              "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol",           "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "TheDeepSearches",  "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},
    # dark.fail PGP-verified live addresses (March 13 2026):
    {"name": "DuckDuckGo-Tor",   "url": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q={query}&ia=web"},
    {"name": "Ahmia-clearnet",   "url": "https://ahmia.fi/search/?q={query}"},
]

# ─────────────────────────────────────────────────────────────────
# TOR SESSION
# ─────────────────────────────────────────────────────────────────

def _build_tor_session() -> requests.Session:
    """Create a requests.Session that routes all traffic through Tor SOCKS5."""
    session = requests.Session()
    retry = Retry(total=3, read=3, connect=3, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    proxy = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    session.proxies = {"http": proxy, "https": proxy}
    return session


# ─────────────────────────────────────────────────────────────────
# TOR CIRCUIT POOL  (issue #3)
# Manages N simultaneous Tor processes on consecutive SOCKS ports
# (TOR_POOL_BASE_PORT … TOR_POOL_BASE_PORT + size - 1).
# Round-robin distributes requests so each identity scrapes different engines.
# When TOR_POOL_SIZE=0 (default), everything falls back to the system Tor.
# ─────────────────────────────────────────────────────────────────

class TorPool:
    """Spawn and manage a pool of independent Tor processes.

    Usage::

        pool = TorPool(size=5)
        pool.start()
        session = pool.session()   # round-robin across circuits
        pool.renew_all()           # rotate all circuits at once
        pool.stop()

    Environment override: ``SICRY_POOL_SIZE`` (0 = disabled, use main Tor).
    """

    def __init__(self, size: int = 5, base_port: int = TOR_POOL_BASE_PORT) -> None:
        self.size = size
        self.base_port = base_port
        self._procs: list[subprocess.Popen] = []
        self._data_dirs: list[str] = []
        self._lock = threading.Lock()
        self._rr_idx = 0  # round-robin index
        self._running = False

    def _socks_port(self, i: int) -> int:
        return self.base_port + i

    def _ctl_port(self, i: int) -> int:
        return self.base_port + 100 + i   # control port 100 above socks

    def start(self) -> None:
        """Launch all Tor processes in the pool. Waits until each SOCKS port accepts connections."""
        if self._running:
            return
        self._data_dirs = [tempfile.mkdtemp(prefix=f"tor_pool_{i}_") for i in range(self.size)]
        for i, ddir in enumerate(self._data_dirs):
            sp = self._socks_port(i)
            cp = self._ctl_port(i)
            torrc = os.path.join(ddir, "torrc")
            with open(torrc, "w") as f:
                f.write(
                    f"SocksPort {sp}\nControlPort {cp}\nDataDirectory {ddir}\n"
                    f"CookieAuthentication 1\nSafeSocks 1\n"
                )
            proc = subprocess.Popen(
                ["tor", "-f", torrc],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._procs.append(proc)
        # Wait up to 30 s for each socks port to become available
        deadline = time.time() + 30
        for i in range(self.size):
            sp = self._socks_port(i)
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", sp), timeout=1):
                        break
                except OSError:
                    time.sleep(0.5)
        self._running = True

    def stop(self) -> None:
        """Terminate all pool processes and clean up temp dirs."""
        for proc in self._procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._procs.clear()
        for ddir in self._data_dirs:
            shutil.rmtree(ddir, ignore_errors=True)
        self._data_dirs.clear()
        self._running = False

    def session(self) -> requests.Session:
        """Return a requests.Session routed through the next pool circuit (round-robin)."""
        if not self._running or not self.size:
            return _build_tor_session()
        with self._lock:
            i = self._rr_idx % self.size
            self._rr_idx += 1
        sp = self._socks_port(i)
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        proxy = f"socks5h://127.0.0.1:{sp}"
        s.proxies = {"http": proxy, "https": proxy}
        return s

    def renew_all(self) -> list[dict]:
        """Send NEWNYM to every pool process via its control port."""
        results = []
        for i in range(self.size):
            cp = self._ctl_port(i)
            ddir = self._data_dirs[i] if i < len(self._data_dirs) else ""
            cookie_path = os.path.join(ddir, "control_auth_cookie") if ddir else ""
            try:
                from stem import Signal
                from stem.control import Controller
                with Controller.from_port(address="127.0.0.1", port=cp) as c:
                    if os.path.isfile(cookie_path):
                        with open(cookie_path, "rb") as fh:
                            c.authenticate(password=fh.read())
                    else:
                        c.authenticate()
                    c.signal(Signal.NEWNYM)
                results.append({"port": cp, "success": True})
            except Exception as e:
                results.append({"port": cp, "success": False, "error": str(e)})
        return results

    def __enter__(self) -> "TorPool":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()


# Module-level pool singleton (only active when TOR_POOL_SIZE > 0)
_pool_instance: TorPool | None = None
_pool_lock = threading.Lock()


def _get_pool() -> TorPool | None:
    global _pool_instance
    if TOR_POOL_SIZE <= 0:
        return None
    if _pool_instance is None or not _pool_instance._running:
        with _pool_lock:
            if _pool_instance is None or not _pool_instance._running:
                _pool_instance = TorPool(size=TOR_POOL_SIZE)
                _pool_instance.start()
    return _pool_instance


def _pool_session() -> requests.Session:
    """Get a session from the pool if active, else fall back to standard Tor."""
    pool = _get_pool()
    return pool.session() if pool else _build_tor_session()


# ─────────────────────────────────────────────────────────────────
# NO-LLM INTELLIGENCE LAYER  (issue #1)
# keyword extraction · BM25-lite relevance scoring · content dedup
# Works 100% offline — no API key needed.
# ─────────────────────────────────────────────────────────────────

_STOPWORDS: frozenset[str] = frozenset({
    "the","and","or","in","on","at","to","a","an","of","for","is","are","was",
    "were","be","been","being","have","has","had","do","does","did","will","would",
    "could","should","may","might","can","this","that","these","those","it","its",
    "from","with","as","by","about","into","through","during","before","after",
    "above","below","between","each","all","both","few","more","most","no","not",
    "only","same","so","than","too","very","just","but","if","then","because","so",
    "our","your","their","my","his","her","we","you","they","i","who","which","www",
    "com","http","https","onion","html","page","site","click","here","link","home",
    # dark web noise
    "forum","thread","reply","post","message","user","admin","login","register",
})


def extract_keywords(text: str, top_n: int = 20) -> list[str]:
    """Extract the top-N keywords from `text` using TF-IDF-like scoring.
    Requires no external libraries — pure stdlib.

    Args:
        text:  Plain text to analyse.
        top_n: Number of top keywords to return (default 20).

    Returns:
        Ordered list of keyword strings, highest-scoring first.
    """
    words = re.findall(r"[a-z0-9]{3,}", text.lower())
    word_freq: dict[str, int] = {}
    for w in words:
        if w not in _STOPWORDS:
            word_freq[w] = word_freq.get(w, 0) + 1
    if not word_freq:
        return []
    total = sum(word_freq.values())
    # Boost rare but present terms (IDF proxy: penalise very common words)
    scored = {w: (cnt / total) * (1 / math.log(cnt + 2)) for w, cnt in word_freq.items()}
    return sorted(scored, key=scored.__getitem__, reverse=True)[:top_n]


def score_results(query: str, results: list[dict]) -> list[dict]:
    """Score each result by keyword overlap with `query` using BM25-lite.
    Adds a ``"score"`` key (0.0–1.0) to each result dict and returns them
    sorted descending. Safe to call without an LLM — all stdlib.

    Args:
        query:   The investigation query.
        results: List of {title, url, engine, ...} dicts.

    Returns:
        Same dicts, each with ``"score": float``, sorted best-first.
    """
    if not results:
        return []
    q_terms = set(re.findall(r"[a-z0-9]{3,}", query.lower())) - _STOPWORDS
    if not q_terms:
        for r in results:
            r.setdefault("score", 0.5)
        return results[:]

    scored: list[tuple[float, dict]] = []
    for result in results:
        # Include snippet/description if available for richer scoring
        doc = " ".join(filter(None, [
            result.get("title", ""),
            result.get("snippet", "") or result.get("description", ""),
            result.get("url", ""),
        ])).lower()
        doc_terms = re.findall(r"[a-z0-9]{3,}", doc)
        term_count = {t: doc_terms.count(t) for t in q_terms if t in doc_terms}
        dl = max(len(doc_terms), 1)
        avgdl = 12.0  # realistic average for onion title+url+snippet combos
        k1, b = 1.5, 0.75
        score = sum(
            (cnt * (k1 + 1))
            / (cnt + k1 * (1 - b + b * dl / avgdl))
            for cnt in term_count.values()
        )
        # Normalise to 0-1 loosely
        norm_score = min(score / (len(q_terms) * 2 + 1), 1.0)
        r_copy = dict(result)
        r_copy["score"] = round(norm_score, 4)
        scored.append((norm_score, r_copy))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [r for _, r in scored]


def _content_fingerprint(text: str) -> str:
    """Fast content fingerprint for near-duplicate detection.
    Normalises whitespace, removes boilerplate, returns MD5 hex."""
    normalised = re.sub(r"\s+", " ", text.lower()).strip()
    normalised = re.sub(r"(copy|copyright|all rights reserved|terms|privacy)[^.]*\.", "", normalised)
    return hashlib.md5(normalised[:4096].encode(), usedforsecurity=False).hexdigest()


def deduplicate_results(results: list[dict], texts: dict[str, str] | None = None) -> list[dict]:
    """Remove near-duplicate results by content fingerprint (not just URL).
    When `texts` ({url: page_text}) is provided, fingerprinting is done on
    content; otherwise falls back to URL+title normalisation.

    Args:
        results: List of result dicts with at least ``"url"`` key.
        texts:   Optional dict mapping URL → scraped text for deep dedup.

    Returns:
        Deduplicated list (preserves first occurrence of each unique fingerprint).
    """
    seen: set[str] = set()
    unique: list[dict] = []
    for r in results:
        url = r.get("url", "")
        if texts and url in texts:
            fp = _content_fingerprint(texts[url])
        else:
            # Shallow fingerprint: normalise URL + lowercased title
            combined = url.lower().rstrip("/") + "|" + r.get("title", "").lower()
            fp = hashlib.md5(combined.encode(), usedforsecurity=False).hexdigest()
        if fp not in seen:
            seen.add(fp)
            unique.append(r)
    return unique


# ─────────────────────────────────────────────────────────────────
# MODE CONFIG  (issue #6)
# Each mode optionally targets specific engines and overrides defaults.
# Ransomware mode adds known RW blog .onions to seed the search.
# ─────────────────────────────────────────────────────────────────

# Known ransomware leak-site .onion addresses (dark.fail / public OSINT verified)
_RANSOMWARE_ONIONS: list[str] = [
    "http://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion",   # AlphV/BlackCat
    "http://lockbit7ouvrsdgtojeoj5hvu6bljqtghitekwpdy3b6y62ixtsu5jqd.onion",   # LockBit 3
    "http://ransomwareuauudfvtj44g426w45pgjfvbwp64wfrypyjzn3jq3muxd.onion",    # generic placeholder
]

_MODE_CONFIG: dict[str, dict] = {
    "threat_intel": {
        "engines": None,          # use all alive engines
        "max_results": 30,
        "scrape": 8,
        "extra_seeds": [],
    },
    "ransomware": {
        "engines": ["Ahmia", "Tor66", "Excavator", "Ahmia-clearnet"],
        "max_results": 40,
        "scrape": 12,
        "extra_seeds": _RANSOMWARE_ONIONS,
    },
    "personal_identity": {
        "engines": ["Ahmia", "OnionLand", "Tor66", "DuckDuckGo-Tor", "Ahmia-clearnet"],
        "max_results": 30,
        "scrape": 8,
        "extra_seeds": [],
    },
    "corporate": {
        "engines": ["Ahmia", "Excavator", "Tor66", "TheDeepSearches", "Ahmia-clearnet"],
        "max_results": 30,
        "scrape": 10,
        "extra_seeds": [],
    },
}


def mode_config(mode: str) -> dict:
    """Return the engine/depth config for the given analysis mode.

    Returns:
        Dict with keys: ``engines``, ``max_results``, ``scrape``, ``extra_seeds``.
    """
    return dict(_MODE_CONFIG.get(mode, _MODE_CONFIG["threat_intel"]))


# Mirrors exactly how AI agents access the clearnet internet,
# just now for .onion and the full Tor network.
# ─────────────────────────────────────────────────────────────────

def check_tor() -> dict:
    """
    Verify Tor is running and confirm exit IP is a Tor node.

    Returns:
        {"tor_active": bool, "exit_ip": str|None, "error": str|None}

    Example:
        >>> sicry.check_tor()
        {"tor_active": True, "exit_ip": "185.220.101.5", "error": None}
    """
    try:
        s = _build_tor_session()
        r = s.get("https://check.torproject.org/api/ip", timeout=TOR_TIMEOUT)
        d = r.json()
        return {"tor_active": d.get("IsTor", False), "exit_ip": d.get("IP"), "error": None}
    except Exception as e:
        return {"tor_active": False, "exit_ip": None, "error": str(e)}


def check_update() -> dict:
    """
    Check whether a newer OnionClaw tag is available on GitHub (clearnet).

    Uses the GitHub Tags API (all git tags, not only formal Releases) with a
    4-second timeout.  Silently returns an error dict on any network failure —
    callers can ignore the ``error`` field to suppress noise.

    Returns::

        {
            "up_to_date": bool,          # True  → already on latest
            "current":    str,           # e.g. "1.2.1"
            "latest":     str,           # e.g. "1.3.0"
            "url":        str | None,    # GitHub tag/release page
            "error":      str | None,    # set when the check itself failed
        }

    Upgrade with::

        git -C /path/to/OnionClaw pull     # if cloned
        python3 sync_sicry.py              # keep sicry.py up-to-date

    Example::

        >>> r = sicry.check_update()
        >>> if not r["up_to_date"]:
        ...     print(f"Update available: {r['current']} → {r['latest']}")
    """
    def _ver(v: str) -> tuple:
        try:
            return tuple(int(x) for x in v.lstrip("v").split("."))
        except Exception:
            return (0,)

    try:
        r = requests.get(
            GITHUB_TAGS_URL,
            headers={"User-Agent": f"OnionClaw/{__version__}"},
            timeout=4,
        )
        r.raise_for_status()
        tags = r.json()  # list of {"name": "v1.2.1", "commit": {...}, ...}
        semver_tags = [
            t["name"].lstrip("v") for t in tags
            if re.match(r"^\d+\.\d+\.\d+", t.get("name", "").lstrip("v"))
        ]
        if not semver_tags:
            return {"up_to_date": True, "current": __version__,
                    "latest": __version__, "url": None,
                    "error": "no semver tags found in repository"}
        latest = max(semver_tags, key=_ver)
        up_to_date = _ver(latest) <= _ver(__version__)
        url = f"https://github.com/JacobJandon/OnionClaw/releases/tag/v{latest}"
        return {
            "up_to_date": up_to_date,
            "current":    __version__,
            "latest":     latest,
            "url":        url,
            "error":      None,
        }
    except Exception as e:
        return {"up_to_date": True, "current": __version__,
                "latest": __version__, "url": None, "error": str(e)}


def renew_identity() -> dict:
    """
    Rotate the Tor circuit — get a new exit node / new identity.
    Equivalent to clicking 'New Identity' in Tor Browser.

    Auth is attempted in order:
      1. TOR_CONTROL_PASSWORD env var (HashedControlPassword)
      2. Cookie file from TOR_DATA_DIR env var
      3. Cookie file from common system paths (/tmp/tor_data, /var/lib/tor, ~/.tor)
      4. Empty-string / null auth (no password Tor)

    Returns:
        {"success": bool, "error": str|None}

    Example:
        >>> sicry.renew_identity()
        {"success": True, "error": None}
    """
    _COOKIE_PATHS = [
        # explicit override
        os.path.join(TOR_DATA_DIR, "control_auth_cookie") if TOR_DATA_DIR else None,
        # custom sicry torrc default
        "/tmp/tor_data/control_auth_cookie",
        # system Tor (Linux/Debian)
        "/var/lib/tor/control_auth_cookie",
        "/run/tor/control.authcookie",
        # user Tor
        os.path.expanduser("~/.tor/control_auth_cookie"),
        # macOS homebrew
        "/usr/local/var/db/tor/control_auth_cookie",
    ]

    def _find_cookie() -> bytes | None:
        for path in _COOKIE_PATHS:
            if path and os.path.isfile(path):
                try:
                    with open(path, "rb") as _fh:
                        return _fh.read()
                except Exception:
                    continue
        return None

    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(address=TOR_CONTROL_HOST, port=TOR_CONTROL_PORT) as c:
            authed = False
            last_err = "all auth methods failed"

            # 1. explicit password
            if TOR_CONTROL_PASS and not authed:
                try:
                    c.authenticate(password=TOR_CONTROL_PASS)
                    authed = True
                except Exception as e:
                    last_err = str(e)

            # 2 & 3. cookie file
            if not authed:
                cookie = _find_cookie()
                if cookie is not None:
                    try:
                        c.authenticate(password=cookie)
                        authed = True
                    except Exception as e:
                        last_err = str(e)

            # 4. null / empty-string auth
            if not authed:
                for pw in ("", None):
                    try:
                        c.authenticate(password=pw) if pw is not None else c.authenticate()
                        authed = True
                        break
                    except Exception as e:
                        last_err = str(e)

            if not authed:
                return {"success": False, "error": f"Control port auth failed ({last_err}). See .env.example for TOR_CONTROL_PASSWORD / TOR_DATA_DIR."}

            c.signal(Signal.NEWNYM)
        time.sleep(1.5)
        return {"success": True, "error": None}
    except Exception as e:
        return {"success": False, "error": str(e)}


def fetch(url: str, _use_cache: bool = True) -> dict:
    """
    Fetch any URL through Tor — clearnet OR .onion.
    The exact same as calling fetch_url() or browser_read_page() in a
    clearnet AI agent, but now works for hidden services.

    Improvements over a plain requests.get:
      - TTL cache (SICRY_CACHE_TTL env var, default 10 min) — avoids redundant
        Tor round-trips for the same URL within a session.
      - HTTPS → HTTP automatic fallback for .onion addresses that don't serve
        TLS (most hidden services are HTTP-only).
      - SOCKS-level retry — if a SOCKS5 handshake or circuit times out, the
        function builds a fresh session and retries once before giving up.

    Args:
        url:        Any http/https URL or .onion address.
        _use_cache: Set False to bypass the TTL cache (e.g. forced refresh).

    Returns:
        {
          "url": str,
          "is_onion": bool,
          "status": int,
          "title": str|None,
          "text": str,          # clean plain text, HTML stripped
          "links": list[dict],  # [{text, href}, ...]
          "error": str|None
        }

    Example:
        >>> sicry.fetch("http://somemarket.onion/listings")
        {"url": "...", "is_onion": True, "status": 200, "title": "...", "text": "...", ...}
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    is_onion = ".onion" in (urlparse(url).hostname or "")

    # ── TTL cache check ──────────────────────────────────────────
    cache_key = url.lower().rstrip("/")
    if _use_cache and FETCH_CACHE_TTL > 0 and cache_key in _FETCH_CACHE:
        _cached_ts, _cached_result = _FETCH_CACHE[cache_key]
        if time.time() - _cached_ts < FETCH_CACHE_TTL:
            return _cached_result

    headers = {"User-Agent": random.choice(_USER_AGENTS)}

    # ── URL attempt list: try HTTPS first, then fall back to HTTP for .onion ─
    urls_to_try: list[str] = [url]
    if url.startswith("https://") and is_onion:
        urls_to_try.append("http://" + url[8:])

    last_err: str = "unknown error"

    def _parse_response(resp: requests.Response, final_url: str) -> dict:
        """Extract title / text / links from a successful HTTP response."""
        # UX-1: fix mojibake — if server reported ISO-8859-1 (HTTP default) but
        # content is actually UTF-8 or another encoding, use apparent_encoding.
        if resp.encoding and resp.encoding.upper() in ("ISO-8859-1", "LATIN-1"):
            resp.encoding = resp.apparent_encoding or "utf-8"
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")

        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # SAFETY-1: block pages with illegal titles before emitting any content
        check_str = (title or "") + " " + final_url
        if not _is_content_safe(check_str):
            return {
                "url": final_url, "is_onion": is_onion, "status": resp.status_code,
                "title": "[content blocked]", "text": "",
                "links": [], "truncated": False,
                "error": "SICRY safety filter: content matches illegal-content blacklist",
            }

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        raw_text = re.sub(r"\n{3,}", "\n\n", soup.get_text(separator="\n")).strip()
        # BUG-3: record whether content was truncated (exposed in return dict)
        truncated = len(raw_text) > MAX_CONTENT_CHARS
        body_text = raw_text[:MAX_CONTENT_CHARS]

        base = urlparse(final_url)
        links: list[dict] = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("/"):
                href = f"{base.scheme}://{base.netloc}{href}"
            if href.startswith(("http://", "https://")):
                links.append({"text": a.get_text(strip=True), "href": href})

        return {
            "url": final_url, "is_onion": is_onion, "status": resp.status_code,
            "title": title, "text": body_text, "links": links[:80],
            "truncated": truncated, "error": None,
        }

    for attempt_url in urls_to_try:
        # ── SOCKS-level retry: 2 attempts per URL variant ────────
        for socks_attempt in range(2):
            try:
                session = _pool_session()
                resp = session.get(attempt_url, headers=headers, timeout=TOR_TIMEOUT)
                # SECURITY: block .onion → clearnet redirect (de-anonymization risk)
                # resp.url is the final URL after redirects (a string in real requests;
                # fall back to attempt_url if not a string, e.g. in mocked tests).
                raw_final = resp.url
                final_url = raw_final if isinstance(raw_final, str) else attempt_url
                if is_onion and ".onion" not in (urlparse(final_url).hostname or ""):
                    logging.warning(
                        "SICRY security: .onion URL %s redirected to clearnet %s — blocked",
                        attempt_url, final_url,
                    )
                    return {
                        "url": attempt_url, "is_onion": True, "status": resp.status_code,
                        "title": None, "text": "", "links": [], "truncated": False,
                        "error": (
                            f"SICRY security: .onion URL redirected to clearnet "
                            f"({final_url}) — blocked to prevent de-anonymization"
                        ),
                    }
                result = _parse_response(resp, final_url)
                # Store in both in-memory and SQLite cache on success
                if _use_cache and FETCH_CACHE_TTL > 0:
                    _FETCH_CACHE[cache_key] = (time.time(), result)
                    _db().cache_set(cache_key, "fetch", result)
                return result
            except Exception as exc:
                last_err = _friendly_error(exc)
                _is_socks_err = any(kw in str(exc) for kw in
                                    ("SOCKS", "timed out", "Connection refused",
                                     "RemoteDisconnected", "ConnectionError"))
                if socks_attempt == 0 and _is_socks_err:
                    # Brief pause, then retry on a fresh circuit
                    time.sleep(1.5)
                    continue
                # Non-retryable error or second attempt — move to next URL variant
                break

    return {
        "url": url, "is_onion": is_onion, "status": 0,
        "title": None, "text": "", "links": [], "truncated": False, "error": last_err,
    }


def scrape_all(urls: list[dict], max_workers: int = 5) -> dict:
    """Batch-fetch multiple .onion pages concurrently.
    Robin pattern: returns {url: "title - content"} dict ready for LLM.

    Args:
        urls:        List of {"title": str, "url": str} dicts (output of search()).
        max_workers: Parallel threads. Default 5.

    Returns:
        {url_str: "Page Title - page text (up to 2000 chars)"}
    """
    def _scrape_one(item: dict) -> tuple[str, str]:
        u = item.get("url", item.get("link", ""))
        t = item.get("title", "")
        if not u:
            return u, t
        # SAFETY-1: skip URLs/titles matching the blacklist
        if not _is_content_safe(u + " " + t):
            return u, ""  # return empty so it won't be included
        try:
            session = _pool_session()
            session.headers["User-Agent"] = random.choice(_USER_AGENTS)
            resp = session.get(u, timeout=TOR_TIMEOUT)
            # UX-1: fix mojibake from servers that report ISO-8859-1 by default
            if resp.encoding and resp.encoding.upper() in ("ISO-8859-1", "LATIN-1"):
                resp.encoding = resp.apparent_encoding or "utf-8"
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            text = " ".join(soup.get_text(separator=" ").split())
            # SAFETY-1: also check page body
            if not _is_content_safe(text[:500]):
                return u, ""
            content = f"{t} - {text}"
            if len(content) > 2000:
                content = content[:2000] + "...(truncated)"
            return u, content
        except Exception:
            return u, t

    results: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for fut in as_completed({ex.submit(_scrape_one, item): item for item in urls}):
            try:
                url, content = fut.result()
                if url:
                    results[url] = content
            except Exception:
                continue
    return results


def refine_query(query: str, provider: Optional[str] = None) -> str:
    """LLM-refine a query for dark web search engines (Robin pattern).
    Removes stop words, focuses intent, keeps to ≤5 words.
    Use before search() to significantly improve result relevance.

    Args:
        query:    Natural-language investigation goal.
        provider: LLM backend override (defaults to LLM_PROVIDER).

    Returns:
        Refined short query string (≤5 words), or original on LLM failure.
    """
    system = (
        "You are a Cybercrime Threat Intelligence Expert. "
        "Refine the user query for use as a dark web search engine query. "
        "Rules: 1) Improve it to return best dark web results. "
        "2) No logical operators (AND, OR, etc.). "
        "3) Keep the final query 5 words or less. "
        "4) Output ONLY the refined query text, nothing else."
    )
    try:
        result = _call_llm((provider or LLM_PROVIDER).lower(), system, query).strip()
        # If _call_llm returned a SICRY error tag (no key / LLM failed), fall back silently
        if result.startswith("[SICRY:"):
            return query
        return result
    except Exception:
        return query


def _generate_final_string(results: list[dict], truncate: bool = False) -> str:
    """Format search results as a numbered string for LLM processing (Robin pattern).
    When truncate=True, trims titles to 30 chars and omits links — used as a
    rate-limit fallback that sends far less tokens to the LLM.
    """
    max_title_length = 30 if truncate else 120
    max_link_length  = 0  if truncate else 80
    final_str = []
    for i, res in enumerate(results):
        url_stem = re.sub(r"(?<=\.onion).*", "", res.get("url", res.get("link", "")))
        title    = re.sub(r"[^0-9a-zA-Z\-\.]", " ",  res.get("title", ""))
        if not url_stem and not title:
            continue
        if truncate:
            title    = (title[:max_title_length] + "..." if len(title) > max_title_length else title)
            url_stem = ""
        else:
            url_stem = (url_stem[:max_link_length] + "..." if len(url_stem) > max_link_length else url_stem)
        final_str.append(f"{i + 1}. {url_stem} - {title}".strip(" -"))
    return "\n".join(final_str)


def filter_results(
    query: str,
    results: list[dict],
    provider: Optional[str] = None,
) -> list[dict]:
    """LLM-filter search results to keep only the most relevant (Robin pattern).
    Reduces noise, picks top-20 matches from all raw results.
    Falls back to truncated titles if the LLM rate-limits on large payloads.

    Args:
        query:    The original search query (for relevance context).
        results:  Output of search() — list of {title, url, engine} dicts.
        provider: LLM backend override.

    Returns:
        Filtered list of up to 20 most relevant results.
    """
    if not results:
        return []
    formatted = _generate_final_string(results)
    if not formatted.strip():
        return results[:20]
    system = (
        "You are a Cybercrime Threat Intelligence Expert. "
        "Given a dark web search query and numbered results (index, link, title), "
        f'select the top 20 most relevant for: "{query}". '
        "Output ONLY a comma-separated list of indices (e.g. 1,3,7). Nothing else."
    )
    _provider = (provider or LLM_PROVIDER).lower()
    try:
        raw = _call_llm(_provider, system, formatted).strip()
        # If _call_llm returned a SICRY error tag (no key / LLM failed), fall back silently
        if raw.startswith("[SICRY:"):
            return results[:20]
    except Exception as e:
        # Rate-limit or token-limit — retry with heavily truncated titles only
        if "rate" in str(e).lower() or "limit" in str(e).lower() or "token" in str(e).lower():
            try:
                truncated = _generate_final_string(results, truncate=True)
                raw = _call_llm(_provider, system, truncated).strip()
            except Exception:
                return results[:20]
        else:
            return results[:20]
    indices, seen_i = [], set()
    for m in re.findall(r"\d+", raw):
        idx = int(m)
        if 1 <= idx <= len(results) and idx not in seen_i:
            seen_i.add(idx)
            indices.append(idx)
    if indices:
        return [results[i - 1] for i in indices[:20]]
    return results[:20]


def check_search_engines(max_workers: int = 8, _cached: bool = False) -> list[dict]:
    """Ping all 12 active search engines via Tor and return per-engine status with latency.
    Robin health.py pattern — tells you which engines are alive before you search.

    Results are stored in the SQLite health history so ``engine_health_history()`` and
    automatic reliability weighting work over multiple runs.

    Args:
        max_workers: Parallel threads. Default 8.
        _cached:     If True, return the last stored results (skip live ping).

    Returns:
        List of dicts ordered by original engine index:
        [{"name": str, "status": "up"|"down", "latency_ms": int|None,
          "reliability": float, "error": str|None}, ...]
    """
    if _cached:
        # Return most recent stored health check from SQLite
        rows = []
        for eng in SEARCH_ENGINES:
            history = _db().engine_history_get(eng["name"], 1)
            rel = _db().engine_reliability(eng["name"])
            if history:
                r = dict(history[0])
                r["name"] = eng["name"]
                r["reliability"] = round(rel, 3)
            else:
                r = {"name": eng["name"], "status": "unknown",
                     "latency_ms": None, "error": "no history", "reliability": 1.0}
            rows.append(r)
        return rows

    def _ping(engine: dict) -> dict:
        url = engine["url"].format(query="test")
        try:
            session = _pool_session()
            session.headers["User-Agent"] = random.choice(_USER_AGENTS)
            start = time.time()
            resp = session.get(url, timeout=20)
            latency_ms = round((time.time() - start) * 1000)
            status = "up" if resp.status_code == 200 else "down"
            err = None if resp.status_code == 200 else f"HTTP {resp.status_code}"
            _db().engine_history_add(engine["name"], status, latency_ms, err)
            return {
                "name": engine["name"],
                "status": status,
                "latency_ms": latency_ms,
                "reliability": round(_db().engine_reliability(engine["name"]), 3),
                "error": err,
            }
        except Exception as exc:
            # Use a compact engine-specific message — do NOT blame Tor globally
            # (other engines may be working fine; this one is just unreachable)
            exc_str = str(exc)
            if any(kw in exc_str for kw in ("timed out", "Read timed out", "Timeout")):
                err = f"engine timed out (hidden service unreachable or slow)"
            elif any(kw in exc_str for kw in ("SOCKS", "Connection refused", "ConnectionRefused")):
                err = f"engine unreachable via Tor circuit"
            elif "HTTP" in exc_str or "4" in exc_str[:5] or "5" in exc_str[:5]:
                err = exc_str[:120]
            else:
                err = exc_str[:120]
            _db().engine_history_add(engine["name"], "down", None, err)
            return {
                "name": engine["name"],
                "status": "down",
                "latency_ms": None,
                "reliability": round(_db().engine_reliability(engine["name"]), 3),
                "error": err,
            }

    results_map: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_engine = {ex.submit(_ping, eng): eng for eng in SEARCH_ENGINES}
        for fut in as_completed(future_to_engine):
            try:
                r = fut.result()
                results_map[r["name"]] = r
            except Exception:
                continue

    # Return in original engine order
    return [results_map.get(e["name"], {"name": e["name"], "status": "down",
            "latency_ms": None, "reliability": 0.0, "error": "no result"})
            for e in SEARCH_ENGINES]


def engine_health_history(engine_name: str, n: int = 5) -> list[dict]:
    """Return the last `n` health checks for a specific engine.

    Args:
        engine_name: Engine name exactly as it appears in SEARCH_ENGINES.
        n:           Number of past checks to return (default 5).

    Returns:
        List of ``{"ts": float, "status": str, "latency_ms": int|None, "error": str|None}``
        ordered newest-first.

    Example::

        >>> sicry.engine_health_history("Ahmia", n=3)
        [{"ts": 1741000000, "status": "up", "latency_ms": 842, "error": None}, ...]
    """
    return _db().engine_history_get(engine_name, n)


def engine_reliability_scores() -> dict[str, float]:
    """Return a dict of engine_name → reliability (fraction up over last 5 checks).
    Engines with no history default to 1.0.

    Example::

        >>> sicry.engine_reliability_scores()
        {"Ahmia": 1.0, "Excavator": 0.6, "Torland": 0.2, ...}
    """
    return {e["name"]: _db().engine_reliability(e["name"]) for e in SEARCH_ENGINES}




def search(
    query: str,
    engines: Optional[list[str]] = None,
    max_results: int = 20,
    max_workers: int = 8,
    mode: Optional[str] = None,
    _use_cache: bool = True,
) -> list[dict]:
    """
    Search the Tor network across 12 verified-live dark web search indexes simultaneously.
    The onion equivalent of web_search() or brave_search().
    All results are passed through a content safety filter before being returned.

    Results are automatically scored by relevance (issue #10) and cached per query
    in SQLite for 30 minutes (``SICRY_SEARCH_CACHE_TTL``).  When ``mode`` is set,
    engine selection and search depth are automatically tuned for that investigation
    type (issue #6).

    Args:
        query:       What to search for (natural language or keywords).
        engines:     Optional explicit engine list. Overrides mode defaults.
                     Options: Ahmia, OnionLand, Amnesia, Torland,
                              Excavator, Onionway, Tor66, OSS, Torgol,
                              TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet
        max_results: Max unique results returned after dedup. Default 20.
        max_workers: Parallel search threads. Default 8.
        mode:        If set, applies mode-specific engine routing (``mode_config()``).
                     Options: threat_intel | ransomware | personal_identity | corporate
        _use_cache:  Set False to bypass the 30-min search result cache.

    Returns:
        List of dicts: [{"title": str, "url": str, "engine": str, "confidence": float}, ...]
        Results are sorted by ``confidence`` (BM25-lite relevance score) descending.

    Example:
        >>> sicry.search("leaked database credentials")
        [{"title": "...", "url": "http://...onion/...", "engine": "Ahmia",
          "confidence": 0.72}, ...]
    """
    # ── search result cache (SQLite, TTL=SEARCH_CACHE_TTL) ────────
    cache_key = f"{query.lower().strip()}|{','.join(sorted(engines or []))}|{max_results}"
    if _use_cache and SEARCH_CACHE_TTL > 0:
        _cached = _db().cache_get(cache_key, "search", SEARCH_CACHE_TTL)
        if _cached is not None:
            # BUG-2: normalize legacy cached results that stored "score" not "confidence"
            for _r in _cached:
                if "score" in _r and "confidence" not in _r:
                    _r["confidence"] = _r.pop("score")
            return _cached

    # ── mode-based engine routing (issue #6) ─────────────────────
    if mode and not engines:
        cfg = mode_config(mode)
        engines = cfg.get("engines")  # None means use all

    selected = SEARCH_ENGINES
    if engines:
        names = {e.lower() for e in engines}
        selected = [e for e in SEARCH_ENGINES if e["name"].lower() in names]

    results: list[dict] = []
    lock_seen: set[str] = set()

    def _fetch_engine(engine: dict) -> list[dict]:
        url = engine["url"].format(query=quote_plus(query))
        # Compute engine's own hostname so we can exclude self-referential links
        _eng_host_m = re.findall(r"https?://([^/]+)", engine["url"])
        _eng_host = _eng_host_m[0] if _eng_host_m else ""
        # Transient errors that are safe to retry (circuit hiccup / throttle)
        _TRANSIENT_KW = ("timed out", "SOCKS", "Connection refused",
                         "RemoteDisconnected", "ConnectionError",
                         "ConnectionReset", "ProxyError")
        found = []
        for _attempt in range(3):        # initial attempt + up to 2 retries
            headers = {"User-Agent": random.choice(_USER_AGENTS)}
            session = _pool_session()
            try:
                resp = session.get(url, headers=headers, timeout=TOR_TIMEOUT)
                if resp.status_code != 200:
                    return []
                soup = BeautifulSoup(resp.text, "html.parser")
                # Try to find result containers first (more precise)
                result_links = (
                    soup.select(".result a, .results a, li.result a, div.result a,"
                                " .search-result a, .web-result a, td.result a") or
                    soup.find_all("a")
                )
                for a in result_links:
                    try:
                        href  = a.get("href", "")
                        title = a.get_text(strip=True)
                        if len(title) < 4:
                            continue
                        # Decode redirect wrappers (Ahmia /redirect/?redirect_url=... or ?url=...)
                        if "redirect_url=" in href or ("redirect" in href and "?" in href):
                            _qs = parse_qs(urlparse(href).query)
                            for _param in ("redirect_url", "url"):
                                if _param in _qs:
                                    href = unquote(_qs[_param][0])
                                    break
                        # Primary: .onion dark web result URLs
                        onion = re.findall(r"https?://[a-z0-9.\-]+\.onion[^\s\"'<>]*", href)
                        onion = [u for u in onion if _eng_host not in u]
                        # Fallback: clearnet HTTPS results (DuckDuckGo-Tor, Ahmia-clearnet, etc.)
                        clearnet: list[str] = []
                        if not onion:
                            clearnet = re.findall(r"https?://[a-z0-9.\-]+\.[a-z]{2,}[^\s\"'<>]*", href)
                            clearnet = [u for u in clearnet if _eng_host not in u and ".onion" not in u]
                        picked = onion or clearnet
                        if not picked:
                            continue
                        found.append({"title": title, "url": picked[0].rstrip("/"), "engine": engine["name"]})
                    except Exception:
                        continue
                return found            # success — don't retry
            except Exception as _exc:
                _is_transient = any(kw in str(_exc) for kw in _TRANSIENT_KW)
                if _is_transient and _attempt < 2:
                    time.sleep(2 ** _attempt)   # 1 s, then 2 s
                    continue
                break
        return found

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_engine, eng): eng for eng in selected}
        for future in as_completed(futures):
            for item in future.result():
                clean = item["url"].rstrip("/")
                if clean not in lock_seen:
                    # SAFETY-1: filter illegal content before returning
                    safe_str = item.get("title", "") + " " + item.get("url", "")
                    if not _is_content_safe(safe_str):
                        continue
                    lock_seen.add(clean)
                    results.append(item)

    # ── confidence scoring (issue #10) ───────────────────────────
    scored = score_results(query, results)
    # BUG-2: score_results() adds "score" key; rename to "confidence" for API
    for r in scored:
        if "score" in r and "confidence" not in r:
            r["confidence"] = r.pop("score")
    final = scored[:max_results]

    # ── store in SQLite search cache ──────────────────────────────
    if _use_cache and SEARCH_CACHE_TTL > 0 and final:
        _db().cache_set(cache_key, "search", final)

    return final




def ask(
    content: str,
    query: str = "",
    mode: str = "threat_intel",
    custom_instructions: str = "",
    provider: Optional[str] = None,
) -> str:
    """Analyse dark web content with an LLM — returns a structured OSINT report.
    Dark web equivalent of analyze() / summarize().

    Args:
        content:             Raw text from .onion pages or search results.
        query:               Original investigation goal (for LLM context).
        mode:                Analysis profile:
                               "threat_intel"      — general OSINT (default)
                               "ransomware"        — malware/C2/MITRE TTPs
                               "personal_identity" — PII/breach exposure
                               "corporate"         — data leaks/espionage
        custom_instructions: Optional extra focus area appended to the prompt.
        provider:            LLM backend override.

    Returns:
        Structured OSINT report string.
    """
    # Accept Robin's verbose mode names as aliases
    _MODE_ALIASES = {
        "ransomware_malware": "ransomware",
        "corporate_espionage": "corporate",
    }
    mode = _MODE_ALIASES.get(mode, mode)
    _provider = (provider or LLM_PROVIDER).lower()
    system = _SYSTEM_PROMPTS.get(mode, _SYSTEM_PROMPTS["threat_intel"])
    if custom_instructions and custom_instructions.strip():
        system = system.rstrip() + f"\n\nAdditionally focus on: {custom_instructions.strip()}"
    prompt = f"Investigation Query: {query}\n\nContent:\n---\n{content[:MAX_CONTENT_CHARS]}\n---"
    return _call_llm(_provider, system, prompt)


# ─────────────────────────────────────────────────────────────────
# NO-LLM ANALYSIS  (issue #1)
# Produces a structured OSINT report using only heuristics — no API key.
# ─────────────────────────────────────────────────────────────────

def analyze_nollm(
    content: str,
    query: str = "",
    results: Optional[list[dict]] = None,
) -> str:
    """Produce a structured OSINT report without an LLM.

    Uses keyword extraction + BM25-lite scoring + entity regex to turn raw
    scraped dark web text into an actionable summary.  Works offline, zero cost.

    Args:
        content:  Raw concatenated text from fetched pages.
        query:    Original investigation query (used for keyword scoring).
        results:  Optional search result list — adds source attribution.

    Returns:
        Plain-text OSINT summary report string.
    """
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    lines: list[str] = [
        f"# OnionClaw OSINT Report (no-LLM)",
        f"**Query:** {query}",
        f"**Generated:** {ts}",
        "",
    ]

    # ── entity extraction ─────────────────────────────────────────
    emails = sorted(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)))
    onion_links = sorted(set(re.findall(r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", content)))
    btc_addrs = sorted(set(re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", content)))
    xmr_addrs = sorted(set(re.findall(r"\b4[0-9AB][0-9a-zA-Z]{93}\b", content)))
    pgp_keys = bool(re.search(r"BEGIN PGP|END PGP|-----BEGIN", content))
    # Crypto wallet addresses (ETH format)
    eth_addrs = sorted(set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", content)))

    lines.append("## Extracted Entities")
    if emails:
        lines.append(f"**Email addresses** ({len(emails)}):")
        for e in emails[:20]:
            lines.append(f"  - {e}")
    if onion_links:
        lines.append(f"**Onion links** ({len(onion_links)}):")
        for o in onion_links[:30]:
            lines.append(f"  - {o}")
    if btc_addrs:
        lines.append(f"**BTC addresses** ({len(btc_addrs)}): " + ", ".join(btc_addrs[:10]))
    if xmr_addrs:
        lines.append(f"**XMR addresses** ({len(xmr_addrs)}): " + ", ".join(xmr_addrs[:5]))
    if eth_addrs:
        lines.append(f"**ETH addresses** ({len(eth_addrs)}): " + ", ".join(eth_addrs[:10]))
    if pgp_keys:
        lines.append("**PGP key detected** in content")
    if not any([emails, onion_links, btc_addrs, xmr_addrs, eth_addrs, pgp_keys]):
        lines.append("*No entities auto-extracted.*")

    # ── keyword analysis ──────────────────────────────────────────
    keywords = extract_keywords(content, top_n=25)
    lines.append("")
    lines.append("## Top Keywords")
    lines.append(", ".join(keywords) if keywords else "*None extracted.*")

    # ── relevance-scored source attribution ───────────────────────
    if results:
        scored = score_results(query, results) if query else results
        lines.append("")
        lines.append("## Source Links (by relevance)")
        for r in scored[:20]:
            conf = r.get("confidence", r.get("score", 0))
            lines.append(f"  [{r.get('engine','?')}] confidence={conf:.2f}  {r.get('url','')}  — {r.get('title','')[:80]}")

    # ── content excerpt ───────────────────────────────────────────
    lines.append("")
    lines.append("## Content Excerpt")
    lines.append(content[:3000].strip() or "*No content available.*")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by OnionClaw analyze_nollm() — no LLM required.*")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# STRUCTURED OUTPUT FORMATS  (issue #4)
# to_stix()   — STIX 2.1 Bundle JSON
# to_csv()    — flat CSV string
# to_report() — timestamped report dict with confidence scores
# ─────────────────────────────────────────────────────────────────

def to_stix(
    results: list[dict],
    query: str = "",
    report_text: str = "",
) -> dict:
    """Generate a STIX 2.1 Bundle from search results.

    Each result becomes a ``location``-free ``report`` + ``url`` observable.
    Suitable for import into OpenCTI, MISP, Maltego, or any STIX-aware platform.

    Args:
        results:     List of {title, url, engine, confidence} dicts.
        query:       Investigation query string.
        report_text: Optional full LLM/nollm report text to embed as a Note.

    Returns:
        STIX 2.1 Bundle dict (JSON-serialisable).

    Example::

        bundle = sicry.to_stix(results, query="ransomware leak")
        with open("report.stix2", "w") as f:
            json.dump(bundle, f, indent=2)
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    objects: list[dict] = []

    # Identity (tool as threat actor)
    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": ts, "modified": ts, "name": f"OnionClaw v{__version__}",
        "identity_class": "system",
        "description": "Automated dark web OSINT collection system",
    })

    # Report object (the investigation itself)
    report_id = f"report--{uuid.uuid4()}"
    object_refs: list[str] = [identity_id]

    # URL observables for each result
    for r in results[:50]:
        url_id = f"url--{uuid.uuid4()}"
        url_val = r.get("url", "")
        if not url_val:
            continue
        objects.append({
            "type": "url", "spec_version": "2.1", "id": url_id,
            "value": url_val,
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": ts, "modified": ts,
            "relationship_type": "related-to",
            "source_ref": report_id,
            "target_ref": url_id,
            "description": (
                f"[engine:{r.get('engine','?')}] "
                f"[confidence:{r.get('confidence', r.get('score', 0)):.2f}] "
                f"{r.get('title', '')[:120]}"
            ),
        })
        object_refs.append(url_id)

    # Optional note with full report text
    if report_text:
        note_id = f"note--{uuid.uuid4()}"
        objects.append({
            "type": "note", "spec_version": "2.1", "id": note_id,
            "created": ts, "modified": ts,
            "abstract": f"OnionClaw OSINT Report: {query}",
            "content": report_text[:20000],
            "object_refs": [report_id],
            "created_by_ref": identity_id,
        })
        object_refs.append(note_id)

    objects.insert(1, {
        "type": "report", "spec_version": "2.1", "id": report_id,
        "created": ts, "modified": ts,
        "name": f"OnionClaw OSINT: {query or 'Investigation'}",
        "description": f"Dark web OSINT investigation — {len(results)} results collected",
        "labels": ["threat-intelligence", "dark-web", "osint"],
        "published": ts,
        "created_by_ref": identity_id,
        "object_refs": object_refs,
    })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def to_csv(results: list[dict]) -> str:
    """Serialise search or crawl results to a CSV string.

    Columns: title, url, engine, confidence, timestamp

    Args:
        results: List of result dicts (from ``search()`` or ``crawl()``).

    Returns:
        UTF-8 CSV string (include header row).

    Example::

        csv_data = sicry.to_csv(results)
        with open("results.csv", "w") as f:
            f.write(csv_data)
    """
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["title", "url", "engine", "confidence", "timestamp"],
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    for r in results:
        writer.writerow({
            "title":      r.get("title", ""),
            "url":        r.get("url", ""),
            "engine":     r.get("engine", ""),
            "confidence": r.get("confidence", r.get("score", "")),
            "timestamp":  ts,
        })
    return buf.getvalue()


def to_misp(
    results: list[dict],
    query: str = "",
    report_text: str = "",
    threat_level: int = 2,
    distribution: int = 0,
) -> dict:
    """Generate a MISP 2.4 event dict from search results.

    No external dependency — returns a plain dict that is directly
    JSON-serialisable and importable into any MISP instance via the REST API
    (``POST /events/add``) or the free-text import interface.

    Args:
        results:      List of {title, url, engine, confidence} dicts.
        query:        Investigation query string.
        report_text:  Full LLM/nollm report text to embed as a comment attribute.
        threat_level: MISP threat level (1=High 2=Medium 3=Low 4=Undefined). Default 2.
        distribution: MISP distribution level (0=Your org only … 3=All). Default 0.

    Returns:
        MISP 2.4 event dict — ``{"Event": {...}}`` ready for JSON serialisation.

    Example::

        event = sicry.to_misp(results, query="ransomware leak")
        import json
        with open("investigation.misp.json", "w") as f:
            json.dump(event, f, indent=2)
    """
    ts_unix  = str(int(time.time()))
    date_str = time.strftime("%Y-%m-%d", time.gmtime())
    event_uuid = str(uuid.uuid4())
    event_info = f"OnionClaw OSINT: {query or 'Dark web investigation'}"
    dist_str   = str(distribution)

    attributes: list[dict] = []

    for r in results[:50]:
        url_val = r.get("url", "")
        if not url_val:
            continue
        conf    = r.get("confidence", r.get("score", 0)) or 0
        comment = (
            f"[engine: {r.get('engine', '?')}] "
            f"[confidence: {conf:.4f}] "
            f"{r.get('title', '')[:120]}"
        )
        attributes.append({
            "uuid":         str(uuid.uuid4()),
            "type":         "url",
            "category":     "External analysis",
            "value":        url_val,
            "comment":      comment,
            "to_ids":       False,
            "distribution": dist_str,
            "timestamp":    ts_unix,
        })
        # Also emit the hostname/domain as a network indicator
        hostname = urlparse(url_val).hostname or ""
        if hostname:
            attr_type = "domain" if "." in hostname else "hostname"
            attributes.append({
                "uuid":         str(uuid.uuid4()),
                "type":         attr_type,
                "category":     "Network activity",
                "value":        hostname,
                "comment":      f"Extracted from: {r.get('title', '')[:80]}",
                "to_ids":       True,
                "distribution": dist_str,
                "timestamp":    ts_unix,
            })

    # Full report as a comment attribute
    if report_text:
        attributes.append({
            "uuid":         str(uuid.uuid4()),
            "type":         "comment",
            "category":     "Attribution",
            "value":        report_text[:65536],
            "comment":      f"OnionClaw v{__version__} OSINT report",
            "to_ids":       False,
            "distribution": dist_str,
            "timestamp":    ts_unix,
        })

    # Original query as a text attribute
    if query:
        attributes.append({
            "uuid":         str(uuid.uuid4()),
            "type":         "text",
            "category":     "Other",
            "value":        query,
            "comment":      "Original investigation query",
            "to_ids":       False,
            "distribution": dist_str,
            "timestamp":    ts_unix,
        })

    tags = [
        {"name": "tlp:amber"},
        {"name": "dark-web"},
        {"name": "osint"},
        {"name": 'osint:source-scale="i"'},
        {"name": f'onionclaw:version="{__version__}"'},
    ]
    if query:
        tags.append({"name": f'onionclaw:query="{query[:100]}"'})

    return {
        "Event": {
            "uuid":            event_uuid,
            "info":            event_info,
            "date":            date_str,
            "timestamp":       ts_unix,
            "threat_level_id": str(threat_level),
            "analysis":        "1",   # Ongoing
            "distribution":    dist_str,
            "published":       False,
            "Attribute":       attributes,
            "Tag":             tags,
            "Object":          [],
        }
    }


def to_report(
    results: list[dict],
    query: str = "",
    mode: str = "threat_intel",
    report_text: str = "",
    keywords: Optional[list[str]] = None,
) -> dict:
    """Generate a structured report dict with metadata, timestamps, and confidence scores.

    Designed to be serialised to JSON and loaded into threat intel platforms.

    Args:
        results:     Search/crawl results.
        query:       Investigation query.
        mode:        Analysis mode string.
        report_text: Full LLM or analyze_nollm() report text.
        keywords:    Top keywords extracted from content.

    Returns:
        Dict with keys: query, mode, timestamp, version, result_count, keywords,
        sources (with confidence + engine per URL), report, source_attribution.
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    avg_conf = (
        sum(r.get("confidence", r.get("score", 0.0)) for r in results) / len(results)
        if results else 0.0
    )
    return {
        "query":           query,
        "mode":            mode,
        "timestamp":       ts,
        "version":         __version__,
        "result_count":    len(results),
        "avg_confidence":  round(avg_conf, 4),
        "keywords":        keywords or [],
        "sources": [
            {
                "title":      r.get("title", ""),
                "url":        r.get("url", ""),
                "engine":     r.get("engine", ""),
                "confidence": round(r.get("confidence", r.get("score", 0.0)), 4),
            }
            for r in results[:50]
        ],
        "report": report_text,
        "source_attribution": "OnionClaw dark web OSINT — collected via Tor network",
    }


# ─────────────────────────────────────────────────────────────────
# WATCH / ALERT MODE  (issue #7)
# Store a query fingerprint. Re-run every N hours.
# Alert when new results appear that weren't in the last run.
# ─────────────────────────────────────────────────────────────────

def watch_add(
    query: str,
    mode: str = "threat_intel",
    interval_hours: float = WATCH_INTERVAL_DEFAULT,
) -> str:
    """Register a persistent watch job.

    Persisted in SQLite (``SICRY_DB_PATH``).  Check for new results with
    ``watch_check()``; list all jobs with ``watch_list()``.

    Args:
        query:          The search query to monitor.
        mode:           Analysis mode (default ``threat_intel``).
        interval_hours: How often to re-check. Default ``SICRY_WATCH_INTERVAL`` (6 h).

    Returns:
        Job ID string (short UUID prefix, e.g. ``"a1b2c3d4"``).

    Example::

        jid = sicry.watch_add("ransomware blackcat", mode="ransomware", interval_hours=4)
        print(f"Monitoring started — job {jid}")
    """
    return _db().watch_add(query, mode, interval_hours)


def watch_list() -> list[dict]:
    """Return all active watch jobs.

    Returns:
        List of job dicts with keys: id, query, mode, interval_hours,
        fingerprint, last_run, created, enabled.
    """
    return _db().watch_list()


def watch_disable(job_id: str) -> None:
    """Disable a watch job (soft delete — keeps history)."""
    _db().watch_disable(job_id)


def watch_check(
    callback: Optional[object] = None,
) -> list[dict]:
    """Check all due watch jobs for new results.

    A job is "due" when ``now - last_run >= interval_hours * 3600``.

    For each due job:
    1. Run ``search(query, mode=mode)``
    2. Compute a content fingerprint of result URLs + titles
    3. If fingerprint changed vs last run → "new results" event
    4. Store new fingerprint + timestamp

    Args:
        callback: Optional callable(job, new_results) invoked when new results
                  are detected. Signature: ``callback(job: dict, results: list[dict]) -> None``

    Returns:
        List of alert dicts::

            [{"job_id": str, "query": str, "new": bool,
              "result_count": int, "results": list[dict]}, ...]

    Example::

        def on_alert(job, results):
            print(f"[ALERT] New results for {job['query']}: {len(results)}")

        sicry.watch_check(callback=on_alert)
    """
    due_jobs = _db().watch_due()
    alerts: list[dict] = []
    for job in due_jobs:
        try:
            results = search(job["query"], mode=job["mode"], max_results=30, _use_cache=False)
            # Fingerprint: sorted URL+title hash
            fp_source = "|".join(
                sorted(r.get("url", "") + r.get("title", "") for r in results)
            )
            fp = hashlib.md5(fp_source.encode(), usedforsecurity=False).hexdigest()
            is_new = fp != job.get("fingerprint")
            _db().watch_update(job["id"], fp, time.time())
            alert = {
                "job_id":       job["id"],
                "query":        job["query"],
                "new":          is_new,
                "result_count": len(results),
                "results":      results,
            }
            alerts.append(alert)
            if is_new and callback and callable(callback):
                callback(job, results)
        except Exception as e:
            alerts.append({
                "job_id": job["id"], "query": job["query"],
                "new": False, "result_count": 0, "results": [], "error": str(e),
            })
    return alerts


def watch_daemon(
    callback: Optional[object] = None,
    poll_interval_s: int = 300,
) -> threading.Thread:
    """Start a background daemon thread that continuously polls due watch jobs.

    The thread runs until the process exits (daemon=True).

    Args:
        callback:        Callable(job, results) for alerts. See ``watch_check()``.
        poll_interval_s: How often to check for due jobs (seconds). Default 300 (5 min).

    Returns:
        The started ``threading.Thread`` object.

    Example::

        t = sicry.watch_daemon(callback=lambda j, r: print(f"Alert: {j['query']}"))
        # thread runs in background automatically
    """
    def _loop():
        while True:
            try:
                watch_check(callback=callback)
            except Exception:
                pass
            time.sleep(poll_interval_s)

    t = threading.Thread(target=_loop, name="sicry-watch-daemon", daemon=True)
    t.start()
    return t


# ─────────────────────────────────────────────────────────────────
# ONION SPIDER — depth-first .onion crawler  (the big one)
# Follows links, maps site structure, extracts entities,
# stores everything in SQLite (crawl_pages + crawl_links tables).
# ─────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class CrawlResult:
    """Summary of a completed crawl job."""
    job_id:       str
    seed_url:     str
    pages_found:  int
    links_found:  int
    entities:     dict       # aggregated across all pages
    db_path:      str


def crawl(
    seed_url: str,
    max_depth: int = 3,
    max_pages: int = 100,
    stay_on_domain: bool = True,
    extract_entities: bool = True,
    max_workers: int = 4,
    job_id: Optional[str] = None,
    on_page: Optional[object] = None,
) -> CrawlResult:
    """Depth-first .onion spider.

    Follows links from `seed_url`, maps site structure, extracts entities
    (emails, crypto addresses, PGP keys, onion links, usernames), and stores
    everything in the SQLite database under a single ``job_id``.

    Args:
        seed_url:         Starting .onion URL.
        max_depth:        Maximum link-follow depth from seed (default 3).
        max_pages:        Hard cap on total pages visited (default 100).
        stay_on_domain:   Only follow links that stay on the same .onion host (default True).
        extract_entities: Run entity extraction on each page (default True).
        max_workers:      Concurrent fetch workers (default 4, capped at 4 for Tor).
        job_id:           Optional custom job ID for resuming. Auto-generated if None.
        on_page:          Optional callback(url, depth, result_dict) called after each page.

    Returns:
        ``CrawlResult`` dataclass with summary and ``db_path`` pointing to SQLite store.

    Example::

        result = sicry.crawl("http://examplemarket.onion", max_depth=2, max_pages=50)
        print(f"Crawled {result.pages_found} pages, found {len(result.entities)} entities")
        export = sicry.crawl_export(result.job_id)
        with open("crawl.json", "w") as f:
            json.dump(export, f, indent=2)
    """
    if not seed_url.startswith(("http://", "https://")):
        seed_url = "http://" + seed_url

    job_id = job_id or str(uuid.uuid4())[:12]
    parsed_seed = urlparse(seed_url)
    seed_host = parsed_seed.netloc

    visited:  set[str] = set()
    # queue: (url, depth)
    queue: list[tuple[str, int]] = [(seed_url, 0)]
    all_entities: dict = {
        "emails": [], "onion_links": [], "btc_addresses": [],
        "xmr_addresses": [], "eth_addresses": [], "pgp_keys": 0,
        "usernames": [],
    }
    pages_crawled = 0
    links_found = 0

    _lock = threading.Lock()

    def _extract_entities_from_text(text: str, url: str) -> dict:
        ents: dict = {}
        ents["emails"]        = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)
        ents["onion_links"]   = re.findall(r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", text)
        ents["btc_addresses"] = re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", text)
        ents["xmr_addresses"] = re.findall(r"\b4[0-9AB][0-9a-zA-Z]{93}\b", text)
        ents["eth_addresses"] = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
        ents["pgp_keys"]      = 1 if re.search(r"BEGIN PGP|END PGP", text) else 0
        # Simple username heuristics: "user: <word>" or "username: <word>"
        ents["usernames"]     = re.findall(r"(?:username|user|handle|nick)\s*:\s*([^\s<>\"']{3,32})", text, re.IGNORECASE)
        return {k: list(set(v)) if isinstance(v, list) else v for k, v in ents.items()}

    def _process_page(url: str, depth: int) -> list[tuple[str, int]]:
        nonlocal pages_crawled, links_found
        result = fetch(url)
        if result.get("error") or not result.get("text"):
            return []

        text  = result["text"]
        title = result.get("title", "")
        entities = _extract_entities_from_text(text, url) if extract_entities else {}
        _db().crawl_save_page(url, job_id, depth, title, text, entities)

        with _lock:
            pages_crawled += 1
            if extract_entities:
                for k, v in entities.items():
                    if isinstance(v, list):
                        all_entities[k].extend(v)
                    elif isinstance(v, int):
                        all_entities[k] = all_entities.get(k, 0) + v

        if on_page and callable(on_page):
            try:
                on_page(url, depth, result)
            except Exception:
                pass

        # Collect child links
        child_links: list[tuple[str, int]] = []
        if depth < max_depth:
            for link in result.get("links", []):
                href = link.get("href", "")
                if not href:
                    continue
                # Must be .onion
                if ".onion" not in href:
                    continue
                # Domain restriction
                if stay_on_domain and urlparse(href).netloc != seed_host:
                    continue
                clean = href.rstrip("/")
                with _lock:
                    if clean not in visited:
                        visited.add(clean)
                        links_found += 1
                        _db().crawl_save_link(url, clean)
                        child_links.append((clean, depth + 1))
        return child_links

    # BFS with ThreadPoolExecutor for concurrent sibling-page fetching
    visited.add(seed_url.rstrip("/"))
    while queue and pages_crawled < max_pages:
        batch = []
        while queue and len(batch) < max_workers:
            item = queue.pop(0)
            batch.append(item)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(batch))) as ex:
            future_map = {ex.submit(_process_page, url, depth): (url, depth)
                          for url, depth in batch}
            for fut in as_completed(future_map):
                try:
                    children = fut.result()
                    queue.extend(children)
                except Exception:
                    pass
        if pages_crawled >= max_pages:
            break

    # Deduplicate entities
    for k, v in all_entities.items():
        if isinstance(v, list):
            all_entities[k] = sorted(set(v))

    return CrawlResult(
        job_id=job_id,
        seed_url=seed_url,
        pages_found=pages_crawled,
        links_found=links_found,
        entities=all_entities,
        db_path=SICRY_DB_PATH,
    )


def crawl_export(job_id: str) -> dict:
    """Export all crawled pages and links for a given job to a dict.

    Returns:
        Dict with ``job_id``, ``pages`` (list), and ``links`` (list).
    """
    return _db().crawl_export(job_id)


def search_and_crawl(
    query: str,
    top_n: int = 3,
    max_depth: int = 2,
    max_pages: int = 30,
    engines: Optional[list[str]] = None,
    max_results: int = 20,
    mode: Optional[str] = None,
    stay_on_domain: bool = True,
    _use_cache: bool = True,
) -> dict:
    """Search dark web engines then automatically spider the top-N results.

    Closes the most common manual loop — search → pick top URLs → crawl each one
    — in a single call. All crawls run concurrently (one thread per seed URL, up
    to ``top_n`` threads, capped at 4 to be gentle on Tor circuits).

    Args:
        query:          Search query.
        top_n:          Number of top search results to crawl. Default 3.
        max_depth:      Crawl depth per seed URL. Default 2.
        max_pages:      Max pages visited per crawl job. Default 30.
        engines:        Engine list override (passed to search()).
        max_results:    Max search results to collect before picking top_n. Default 20.
        mode:           OSINT mode (threat_intel|ransomware|personal_identity|corporate).
        stay_on_domain: Only follow same-host links during crawls. Default True.
        _use_cache:     Use search result cache. Crawl results are never cached. Default True.

    Returns::

        {
          "query":          str,
          "search_results": [...],           # full scored list from search()
          "crawls":         {url: dict, ...}, # one CrawlResult dict per crawled URL
        }

    Example::

        result = sicry.search_and_crawl("LockBit ransomware hospital", top_n=3)
        for url, crawl in result["crawls"].items():
            print(url, crawl["pages_found"], "pages")
    """
    search_results = search(
        query,
        engines=engines,
        max_results=max_results,
        mode=mode,
        _use_cache=_use_cache,
    )
    seeds = [r["url"] for r in search_results[:top_n] if r.get("url")]
    crawl_results: dict = {}
    _lock = threading.Lock()

    def _do_crawl(url: str) -> None:
        try:
            cr = crawl(url, max_depth=max_depth, max_pages=max_pages,
                       stay_on_domain=stay_on_domain)
            with _lock:
                crawl_results[url] = dataclasses.asdict(cr)
        except Exception:
            with _lock:
                crawl_results[url] = {"error": "crawl failed"}

    workers = min(len(seeds), 4) if seeds else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_do_crawl, seeds))

    return {
        "query":          query,
        "search_results": search_results,
        "crawls":         crawl_results,
    }


# ─────────────────────────────────────────────────────────────────
# LLM BACKENDS
# ─────────────────────────────────────────────────────────────────

def _call_llm(provider: str, system: str, prompt: str) -> str:
    """Call the configured LLM backend. Returns an error string (never raises)
    if the API key is missing or the call fails, so agent tool loops stay alive."""
    try:
        if provider == "openai":
            if not OPENAI_API_KEY:
                return "[SICRY: OPENAI_API_KEY not set. Add it to .env or set LLM_PROVIDER=ollama for local inference.]"
            from openai import OpenAI
            c = OpenAI(api_key=OPENAI_API_KEY)
            r = c.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                max_tokens=4096,
            )
            return r.choices[0].message.content or ""

        if provider == "anthropic":
            if not ANTHROPIC_API_KEY:
                return "[SICRY: ANTHROPIC_API_KEY not set. Add it to .env or set LLM_PROVIDER=ollama for local inference.]"
            import anthropic
            c = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            r = c.messages.create(
                model=ANTHROPIC_MODEL, max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            return r.content[0].text if r.content else ""

        if provider == "gemini":
            if not GEMINI_API_KEY:
                return "[SICRY: GEMINI_API_KEY not set. Add it to .env or set LLM_PROVIDER=ollama for local inference.]"
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            m = genai.GenerativeModel(model_name=GEMINI_MODEL, system_instruction=system)
            return m.generate_content(prompt).text or ""

        if provider == "ollama":
            r = requests.post(f"{OLLAMA_URL}/api/generate", json={
                "model": OLLAMA_MODEL, "prompt": prompt, "system": system, "stream": False,
            }, timeout=180)
            r.raise_for_status()
            return r.json().get("response", "")

        if provider == "llamacpp":
            r = requests.post(f"{LLAMACPP_URL}/v1/chat/completions", json={
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                "max_tokens": 4096,
            }, timeout=180)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"] or ""

        return f"[SICRY: Unknown LLM provider {provider!r}. Use: openai, anthropic, gemini, ollama, llamacpp]"
    except Exception as e:
        return f"[SICRY: LLM call failed — {e}]"


# ─────────────────────────────────────────────────────────────────
# SYSTEM PROMPTS  (Robin's actual prompts, extended)
# ─────────────────────────────────────────────────────────────────

_SYSTEM_PROMPTS = {
    "threat_intel": """You are a Cybercrime Threat Intelligence Expert analysing Tor network OSINT data.

Rules:
1. Analyse the dark web OSINT data using the links and raw text provided.
2. Output the Source Links referenced for the analysis.
3. Provide detailed, contextual, evidence-based technical analysis.
4. Extract intelligence artifacts with context: names, emails, phones, crypto addresses,
   domains, dark web markets, forum names, threat actor info, malware names, TTPs.
5. Generate 3-5 key insights — specific, actionable, data-driven.
6. Include suggested next steps and follow-up search queries.
7. Be objective. Ignore NSFW content.

Output format:
1. Input Query: {query}
2. Source Links Referenced
3. Investigation Artifacts
4. Key Insights
5. Next Steps

INPUT:""",

    "ransomware": """You are a Malware and Ransomware Intelligence Expert analysing dark web data.

Rules:
1. Analyse the dark web OSINT data using links and raw text.
2. Output Source Links referenced.
3. Focus on ransomware groups, malware families, exploit kits, attack infrastructure.
4. Identify: file hashes, C2 domains/IPs, staging URLs, payload names, obfuscation techniques.
5. Map TTPs to MITRE ATT&CK where possible.
6. Identify victim organisations, sectors, or geographies mentioned.
7. Generate 3-5 insights on threat actor behaviour and malware evolution.
8. Include next steps: containment, detection, hunting.
9. Be objective. Ignore NSFW content.

Output format:
1. Input Query: {query}
2. Source Links Referenced
3. Malware / Ransomware Indicators (hashes, C2s, payload names, TTPs)
4. Threat Actor Profile (group, aliases, known victims, sector targeting)
5. Key Insights
6. Next Steps (hunting queries, detection rules, further investigation)

INPUT:""",

    "personal_identity": """You are a Personal Threat Intelligence Expert analysing dark web PII exposure.

Rules:
1. Analyse the dark web OSINT data using links and raw text.
2. Output Source Links referenced.
3. Focus on PII: names, emails, phones, addresses, SSNs, passport data, financial details.
4. Identify breach sources, data brokers, and marketplaces selling personal data.
5. Assess exposure severity: what data is available and how actionable for a threat actor.
6. Generate 3-5 insights on individual exposure risk.
7. Include protective actions and further investigation queries.
8. Handle all personal data with discretion.

Output format:
1. Input Query: {query}
2. Source Links Referenced
3. Exposed PII Artifacts (type, value, source context)
4. Breach / Marketplace Sources Identified
5. Exposure Risk Assessment
6. Key Insights
7. Next Steps (protective actions, further queries)

INPUT:""",

    "corporate": """You are a Corporate Intelligence Expert analysing dark web data for corporate threats.

Rules:
1. Analyse the dark web OSINT data using links and raw text.
2. Output Source Links referenced.
3. Focus on leaked corporate data: credentials, source code, internal docs, financials, customer DBs.
4. Identify threat actors, insider threat indicators, data broker activity.
5. Assess business impact: operational and competitive damage from the exposure.
6. Generate 3-5 insights on corporate risk posture.
7. Include IR steps and further investigation queries.
8. Be objective. Ignore NSFW content.

Output format:
1. Input Query: {query}
2. Source Links Referenced
3. Leaked Corporate Artifacts (credentials, documents, source code, databases)
4. Threat Actor / Broker Activity
5. Business Impact Assessment
6. Key Insights
7. Next Steps (IR actions, legal considerations, further queries)

INPUT:""",
}


# ─────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# Drop these directly into any AI framework's tool registration.
# ─────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "sicry_check_tor",
        "description": "Verify Tor is running and confirm the machine is routing traffic through the Tor network. Call this before any dark web operations.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "sicry_renew_identity",
        "description": "Rotate the Tor circuit to get a new exit node and new identity. Use this to avoid fingerprinting between investigation sessions.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "sicry_fetch",
        "description": "Fetch any URL through Tor — works for both normal websites (clearnet via Tor exit node) and .onion hidden services. Returns the page title, full clean text, and all hyperlinks found on the page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch. Can be http/https or a .onion address."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sicry_search",
        "description": "Search the Tor network / dark web across up to 12 .onion search engines simultaneously. Returns results with confidence scores (BM25-lite relevance). Results are cached per query for 30 minutes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query":       {"type": "string", "description": "Search query — keywords or short phrase."},
                "max_results": {"type": "integer", "description": "Max unique results. Default 20.", "default": 20},
                "engines":     {"type": "array", "items": {"type": "string"},
                                "description": "Optional engine list. Available: Ahmia, OnionLand, Amnesia, Torland, Excavator, Onionway, Tor66, OSS, Torgol, TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet."},
                "mode":        {"type": "string", "enum": ["threat_intel", "ransomware", "personal_identity", "corporate"],
                                "description": "Mode-based engine routing. Overrides engines if set."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "sicry_ask",
        "description": "Analyze dark web content with an LLM. Returns a structured OSINT report. Use after sicry_fetch or sicry_search.",
        "input_schema": {
            "type": "object",
            "properties": {
                "content":             {"type": "string", "description": "Raw text to analyze."},
                "query":               {"type": "string", "description": "The investigation goal."},
                "mode":                {"type": "string",
                                        "enum": ["threat_intel", "ransomware", "ransomware_malware",
                                                 "personal_identity", "corporate", "corporate_espionage"],
                                        "default": "threat_intel"},
                "custom_instructions": {"type": "string", "description": "Extra focus area."},
            },
            "required": ["content"],
        },
    },
    {
        "name": "sicry_analyze_nollm",
        "description": "Analyze dark web content WITHOUT an LLM. Uses keyword extraction, entity regex, and BM25 scoring. Works fully offline. Call instead of sicry_ask when no API key is configured.",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Raw text from fetched pages."},
                "query":   {"type": "string", "description": "Investigation query for relevance scoring."},
            },
            "required": ["content"],
        },
    },
    {
        "name": "sicry_check_engines",
        "description": "Ping all 12 dark web search engines via Tor. Returns per-engine status, latency, and rolling reliability score (from health history). Use before searching to find out which engines are alive.",
        "input_schema": {
            "type": "object",
            "properties": {
                "max_workers": {"type": "integer", "description": "Parallel ping threads. Default 8.", "default": 8},
                "cached":      {"type": "boolean", "description": "Return last stored results instead of live ping.", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "sicry_crawl",
        "description": "Depth-first spider that crawls a .onion site. Follows links, maps structure, extracts emails/crypto addresses/PGP keys/onion links, stores everything in SQLite. Call sicry_crawl_export to get results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "seed_url":          {"type": "string", "description": "Starting .onion URL."},
                "max_depth":         {"type": "integer", "description": "Max link-follow depth. Default 3.", "default": 3},
                "max_pages":         {"type": "integer", "description": "Hard page cap. Default 100.", "default": 100},
                "stay_on_domain":    {"type": "boolean", "description": "Only follow same-host links. Default True.", "default": True},
            },
            "required": ["seed_url"],
        },
    },
    {
        "name": "sicry_crawl_export",
        "description": "Export all pages and links for a completed crawl job as a structured dict.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID returned by sicry_crawl."},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "sicry_watch_add",
        "description": "Register a persistent watch/alert job. Re-runs the query every N hours and alerts when new results appear. Stored in SQLite — survives process restarts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query":          {"type": "string", "description": "The search query to monitor."},
                "mode":           {"type": "string", "default": "threat_intel"},
                "interval_hours": {"type": "number",
                                   "description": "Re-check interval in hours. Default 6.", "default": 6},
            },
            "required": ["query"],
        },
    },
    {
        "name": "sicry_watch_list",
        "description": "List all active watch jobs.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "sicry_watch_check",
        "description": "Check all due watch jobs now. Returns list of alerts with new/changed results.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "sicry_to_stix",
        "description": "Export search results to a STIX 2.1 Bundle JSON. Import into OpenCTI, MISP, Maltego, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "results":     {"type": "array",  "description": "Search result list from sicry_search."},
                "query":       {"type": "string", "description": "Investigation query."},
                "report_text": {"type": "string", "description": "Optional report text to embed as STIX Note."},
            },
            "required": ["results"],
        },
    },
    {
        "name": "sicry_to_csv",
        "description": "Export search results to CSV string. Columns: title, url, engine, confidence, timestamp.",
        "input_schema": {
            "type": "object",
            "properties": {
                "results": {"type": "array", "description": "Search result list from sicry_search."},
            },
            "required": ["results"],
        },
    },
    {
        "name": "sicry_extract_keywords",
        "description": "Extract the top keywords from text using TF-IDF-like scoring. No LLM needed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text":  {"type": "string", "description": "Plain text to analyze."},
                "top_n": {"type": "integer", "description": "Number of keywords. Default 20.", "default": 20},
            },
            "required": ["text"],
        },
    },
]

# OpenAI function-calling format
TOOLS_OPENAI = [
    {"type": "function", "function": {"name": t["name"], "description": t["description"],
                                      "parameters": t["input_schema"]}}
    for t in TOOLS
]

# Google Gemini function declarations
TOOLS_GEMINI = [
    {"name": t["name"], "description": t["description"],
     "parameters": {"type": "object",
                    "properties": t["input_schema"].get("properties", {}),
                    "required":   t["input_schema"].get("required", [])}}
    for t in TOOLS
]


# ─────────────────────────────────────────────────────────────────
# TOOL DISPATCHER
# Call this from your agent loop to execute any SICRY tool call.
# ─────────────────────────────────────────────────────────────────

def dispatch(tool_name: str, tool_input: dict) -> dict | list | str:
    """Execute a SICRY tool by name. Plug into any agent framework's tool loop.

    Example::

        result = sicry.dispatch(tool_call.name, tool_call.input)
    """
    if tool_name == "sicry_check_tor":
        return check_tor()
    if tool_name == "sicry_renew_identity":
        return renew_identity()
    if tool_name == "sicry_fetch":
        return fetch(tool_input["url"])
    if tool_name == "sicry_search":
        return search(
            tool_input["query"],
            engines=tool_input.get("engines"),
            max_results=tool_input.get("max_results", 20),
            mode=tool_input.get("mode"),
        )
    if tool_name == "sicry_ask":
        return ask(
            tool_input["content"],
            query=tool_input.get("query", ""),
            mode=tool_input.get("mode", "threat_intel"),
            custom_instructions=tool_input.get("custom_instructions", ""),
        )
    if tool_name == "sicry_analyze_nollm":
        return analyze_nollm(
            tool_input["content"],
            query=tool_input.get("query", ""),
        )
    if tool_name == "sicry_check_engines":
        return check_search_engines(
            max_workers=tool_input.get("max_workers", 8),
            _cached=tool_input.get("cached", False),
        )
    if tool_name == "sicry_crawl":
        result = crawl(
            tool_input["seed_url"],
            max_depth=tool_input.get("max_depth", 3),
            max_pages=tool_input.get("max_pages", 100),
            stay_on_domain=tool_input.get("stay_on_domain", True),
        )
        return dataclasses.asdict(result)
    if tool_name == "sicry_crawl_export":
        return crawl_export(tool_input["job_id"])
    if tool_name == "sicry_watch_add":
        return {"job_id": watch_add(
            tool_input["query"],
            mode=tool_input.get("mode", "threat_intel"),
            interval_hours=tool_input.get("interval_hours", 6),
        )}
    if tool_name == "sicry_watch_list":
        return watch_list()
    if tool_name == "sicry_watch_check":
        return watch_check()
    if tool_name == "sicry_to_stix":
        return to_stix(
            tool_input["results"],
            query=tool_input.get("query", ""),
            report_text=tool_input.get("report_text", ""),
        )
    if tool_name == "sicry_to_csv":
        return to_csv(tool_input["results"])
    if tool_name == "sicry_to_misp":
        return to_misp(
            tool_input["results"],
            query=tool_input.get("query", ""),
            report_text=tool_input.get("report_text", ""),
            threat_level=tool_input.get("threat_level", 2),
            distribution=tool_input.get("distribution", 0),
        )
    if tool_name == "sicry_search_and_crawl":
        return search_and_crawl(
            tool_input["query"],
            top_n=tool_input.get("top_n", 3),
            max_depth=tool_input.get("max_depth", 2),
            max_pages=tool_input.get("max_pages", 30),
            engines=tool_input.get("engines"),
            max_results=tool_input.get("max_results", 20),
            mode=tool_input.get("mode"),
            stay_on_domain=tool_input.get("stay_on_domain", True),
        )
    if tool_name == "sicry_extract_keywords":
        return extract_keywords(tool_input["text"], top_n=tool_input.get("top_n", 20))
    raise ValueError(f"Unknown SICRY tool: {tool_name!r}")


# ─────────────────────────────────────────────────────────────────
# MCP SERVER  —  python sicry.py serve
# Model Context Protocol — plugs into Claude Desktop, Cursor, Zed,
# and any other MCP-compatible client. Requires: pip install mcp
# ─────────────────────────────────────────────────────────────────

def _start_mcp_server():
    """Start SICRY as a Model Context Protocol server.

    Installation (works on PEP 668 / Debian locked systems)::

        pip install mcp --user              # user install
        pipx install mcp                    # isolated
        pip install mcp --break-system-packages   # override system guard

    Claude Desktop config (``~/.config/claude/claude_desktop_config.json``)::

        { "mcpServers": { "sicry": {
            "command": "python",
            "args": ["/absolute/path/to/sicry.py", "serve"]
        } } }

    Cursor settings.json::

        "mcp.servers": { "sicry": {
            "command": "python /absolute/path/to/sicry.py serve"
        } }

    Available MCP tools (15 total):
      sicry_check_tor, sicry_renew_identity, sicry_fetch, sicry_search,
      sicry_ask, sicry_analyze_nollm, sicry_check_engines,
      sicry_crawl, sicry_crawl_export,
      sicry_watch_add, sicry_watch_list, sicry_watch_check,
      sicry_to_stix, sicry_to_csv, sicry_extract_keywords
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "MCP not installed.\n"
            "  pip install mcp --user          # user install (works on PEP 668 systems)\n"
            "  pipx install mcp                # per-tool isolated install\n"
            "  pip install mcp --break-system-packages  # override system guard (Debian/Ubuntu)\n"
            "\n"
            "After installing, restart with: python sicry.py serve\n"
            "Then configure in Claude Desktop / Cursor / Zed — see docstring for details.",
            file=sys.stderr,
        )
        sys.exit(1)

    mcp = FastMCP("sicry", description="Tor/Onion dark web OSINT platform for AI agents")

    @mcp.tool(description="Verify Tor is running. Call before any dark web operation.")
    def sicry_check_tor() -> dict:
        return check_tor()

    @mcp.tool(description="Rotate Tor circuit — new exit node, fresh identity.")
    def sicry_renew_identity() -> dict:
        return renew_identity()

    @mcp.tool(description="Search 12 .onion search engines. Results include BM25 confidence score. Results cached 30 min.")
    def sicry_search(query: str, max_results: int = 20, mode: str = "threat_intel") -> list:
        return search(query, max_results=max_results, mode=mode)

    @mcp.tool(description="Fetch any URL through Tor (.onion or clearnet). Returns title, text, links.")
    def sicry_fetch(url: str) -> dict:
        return fetch(url)

    @mcp.tool(description="Analyse dark web content with LLM. Returns structured OSINT report.")
    def sicry_ask(content: str, query: str = "", mode: str = "threat_intel",
                  custom_instructions: str = "") -> str:
        return ask(content, query=query, mode=mode, custom_instructions=custom_instructions)

    @mcp.tool(description="Analyse dark web content WITHOUT an LLM. Uses keyword extraction + entity regex. Works offline.")
    def sicry_analyze_nollm(content: str, query: str = "") -> str:
        return analyze_nollm(content, query=query)

    @mcp.tool(description="Ping 12 dark web search engines. Returns status + rolling reliability score.")
    def sicry_check_engines(max_workers: int = 8, cached: bool = False) -> list:
        return check_search_engines(max_workers=max_workers, _cached=cached)

    @mcp.tool(description="Spider a .onion site depth-first. Extracts entities, stores in SQLite.")
    def sicry_crawl(seed_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        result = crawl(seed_url, max_depth=max_depth, max_pages=max_pages)
        return dataclasses.asdict(result)

    @mcp.tool(description="Export all pages and links for a crawl job as structured dict.")
    def sicry_crawl_export(job_id: str) -> dict:
        return crawl_export(job_id)

    @mcp.tool(description="Register a persistent watch/alert job. Re-checks every N hours, alerts on new results.")
    def sicry_watch_add(query: str, mode: str = "threat_intel", interval_hours: float = 6) -> dict:
        return {"job_id": watch_add(query, mode=mode, interval_hours=interval_hours)}

    @mcp.tool(description="List all active watch jobs.")
    def sicry_watch_list() -> list:
        return watch_list()

    @mcp.tool(description="Check all due watch jobs now. Returns new/changed result alerts.")
    def sicry_watch_check() -> list:
        return watch_check()

    @mcp.tool(description="Export results as STIX 2.1 Bundle JSON for OpenCTI/MISP/Maltego.")
    def sicry_to_stix(results: list, query: str = "", report_text: str = "") -> dict:
        return to_stix(results, query=query, report_text=report_text)

    @mcp.tool(description="Export results as CSV string.")
    def sicry_to_csv(results: list) -> str:
        return to_csv(results)

    @mcp.tool(description="Extract top keywords from text using TF-IDF-like scoring. No LLM needed.")
    def sicry_extract_keywords(text: str, top_n: int = 20) -> list:
        return extract_keywords(text, top_n=top_n)

    mcp.run()


# ─────────────────────────────────────────────────────────────────
# CLI  —  python sicry.py <command>
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="sicry",
        description=f"SICRY v{__version__} — Tor/Onion Network Access Layer + Dark Web OSINT Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  check                              verify Tor is running
  renew                              rotate Tor circuit
  serve                              start MCP server (15 tools)
  clear-cache                        wipe all cached results
  engines [--cached]                 ping all search engines
  engine-history <name> [--n N]      show rolling health history for an engine
  search "query" [options]           search dark web
  fetch <url>                        fetch URL through Tor
  analyze-nollm <file|-> [options]   no-LLM entity/keyword extraction
  crawl <url> [options]              spider a .onion site
  crawl-export <job_id>              export crawl pages+links as JSON
  watch add "query" [options]        register a persistent watch/alert job
  watch list                         list all active watch jobs
  watch disable <job_id>             disable a watch job
  watch check                        run all due watch jobs now
  export --from <file.json> [--format stix|csv]   convert results to STIX/CSV
  pool start [--size N]              launch TorPool (N circuits)
  pool stop                          stop TorPool
  pool status                        show pool info
  tools [--format anthropic|openai|gemini]   print tool schemas as JSON

Examples:
  python sicry.py check
  python sicry.py search "ransomware data leak" --max 15 --mode ransomware --format csv
  python sicry.py fetch http://example.onion
  python sicry.py crawl http://example.onion --depth 3 --pages 150 --out crawl.json
  python sicry.py crawl-export abc123 > graph.json
  python sicry.py analyze-nollm report.txt --query "LockBit"
  python sicry.py watch add "LockBit victims" --mode ransomware --interval 4
  python sicry.py watch list
  python sicry.py watch check
  python sicry.py export --from results.json --format stix > bundle.json
  python sicry.py pool start --size 3
  python sicry.py engines --cached
  python sicry.py engine-history Ahmia --n 10
  python sicry.py tools --format openai
  python sicry.py serve
        """,
    )
    parser.add_argument("--version", action="version", version=f"SICRY {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    # ── simple commands ────────────────────────────────────────────
    sub.add_parser("check",       help="Verify Tor is running")
    sub.add_parser("renew",       help="Rotate Tor circuit")
    sub.add_parser("serve",       help="Start MCP server")
    sub.add_parser("clear-cache", help="Wipe all cached results")

    # ── engines ────────────────────────────────────────────────────
    p_eng = sub.add_parser("engines", help="Ping all search engines")
    p_eng.add_argument("--cached", action="store_true",
                       help="Return last stored check instead of pinging live")
    p_eng.add_argument("--workers", type=int, default=8, dest="max_workers")

    p_eh = sub.add_parser("engine-history", help="Show rolling health history for one engine")
    p_eh.add_argument("name", help="Engine name (e.g. Ahmia)")
    p_eh.add_argument("--n", type=int, default=5, help="Number of recent records")

    # ── search ─────────────────────────────────────────────────────
    p_s = sub.add_parser("search", help="Search dark web")
    p_s.add_argument("query")
    p_s.add_argument("--max", type=int, default=10, dest="max_results")
    p_s.add_argument("--engine", action="append", dest="engines", metavar="NAME")
    p_s.add_argument("--mode", default="threat_intel",
                     choices=list(_MODE_CONFIG.keys()),
                     help="Routing mode (selects optimal engines)")
    p_s.add_argument("--no-cache", action="store_true", help="Skip cache, force live search")
    p_s.add_argument("--format", choices=["text", "json", "csv", "stix"], default="text",
                     help="Output format")
    p_s.add_argument("--out", metavar="FILE", help="Write output to file instead of stdout")

    # ── fetch ──────────────────────────────────────────────────────
    p_f = sub.add_parser("fetch", help="Fetch URL through Tor")
    p_f.add_argument("url")

    # ── analyze-nollm ──────────────────────────────────────────────
    p_an = sub.add_parser("analyze-nollm",
                          help="No-LLM entity/keyword extraction from text")
    p_an.add_argument("content", metavar="FILE|-",
                      help="Path to text file, or '-' to read from stdin")
    p_an.add_argument("--query", default="", help="Optional focus query for relevance scoring")
    p_an.add_argument("--out", metavar="FILE", help="Write report to file")

    # ── crawl ──────────────────────────────────────────────────────
    p_c = sub.add_parser("crawl", help="Spider a .onion site")
    p_c.add_argument("url", help="Seed URL")
    p_c.add_argument("--depth", type=int, default=3, help="Max crawl depth")
    p_c.add_argument("--pages", type=int, default=100, help="Max pages to fetch")
    p_c.add_argument("--stay-domain", action="store_true", dest="stay_domain",
                     help="Restrict to same .onion host")
    p_c.add_argument("--job-id", default=None, metavar="ID",
                     help="Reuse / resume a crawl job ID")
    p_c.add_argument("--out", metavar="FILE",
                     help="Write JSON export to file (default: stdout)")

    p_ce = sub.add_parser("crawl-export", help="Export crawl pages+links as JSON")
    p_ce.add_argument("job_id")

    # ── watch ──────────────────────────────────────────────────────
    p_w = sub.add_parser("watch", help="Manage watch/alert jobs")
    sub_w = p_w.add_subparsers(dest="watch_cmd")

    p_wa = sub_w.add_parser("add", help="Register a watch job")
    p_wa.add_argument("query")
    p_wa.add_argument("--mode", default="threat_intel", choices=list(_MODE_CONFIG.keys()))
    p_wa.add_argument("--interval", type=float, default=6.0, dest="interval_hours",
                      help="Re-check interval in hours")

    sub_w.add_parser("list", help="List active watch jobs")

    p_wd = sub_w.add_parser("disable", help="Disable a watch job")
    p_wd.add_argument("job_id")

    sub_w.add_parser("check", help="Run all due watch jobs now")

    # ── export ─────────────────────────────────────────────────────
    p_ex = sub.add_parser("export", help="Convert a results JSON file to STIX or CSV")
    p_ex.add_argument("--from", dest="infile", required=True, metavar="FILE",
                      help="JSON file containing a list of result dicts")
    p_ex.add_argument("--format", choices=["stix", "csv"], default="stix")
    p_ex.add_argument("--query", default="")
    p_ex.add_argument("--out", metavar="FILE", help="Write to file instead of stdout")

    # ── pool ───────────────────────────────────────────────────────
    p_pool_root = sub.add_parser("pool", help="Manage TorPool")
    sub_pool = p_pool_root.add_subparsers(dest="pool_cmd")

    p_ps = sub_pool.add_parser("start", help="Start N Tor circuits")
    p_ps.add_argument("--size", type=int, default=3)
    p_ps.add_argument("--base-port", type=int, default=TOR_POOL_BASE_PORT)

    sub_pool.add_parser("stop",   help="Stop TorPool")
    sub_pool.add_parser("status", help="Show TorPool info")

    # ── tools ──────────────────────────────────────────────────────
    p_t = sub.add_parser("tools", help="Print MCP tool schemas as JSON")
    p_t.add_argument("--format", choices=["anthropic", "openai", "gemini"], default="anthropic")

    # ──────────────────────────────────────────────────────────────
    args = parser.parse_args()

    def _write_out(text: str, path: str | None = None) -> None:
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"Wrote: {path}")
        else:
            print(text)

    # ── dispatch ───────────────────────────────────────────────────
    if args.cmd == "check":
        r = check_tor()
        ok = "CONNECTED via Tor" if r["tor_active"] else "NOT through Tor"
        print(f"{ok}  |  exit IP: {r['exit_ip']}  |  error: {r['error']}")

    elif args.cmd == "renew":
        r = renew_identity()
        print("Identity rotated" if r["success"] else f"Failed: {r['error']}")

    elif args.cmd == "engines":
        results = check_search_engines(max_workers=args.max_workers, _cached=args.cached)
        for e in results:
            sym = "✓" if e["reachable"] else "✗"
            print(f"  {sym} {e['engine']:<30} {e.get('latency_ms', 0):>6.0f}ms  "
                  f"reliability={e.get('reliability', 0):.0%}  {e.get('error') or ''}")

    elif args.cmd == "engine-history":
        hist = engine_health_history(args.name, n=args.n)
        if not hist:
            print(f"No history for '{args.name}'.")
        for row in hist:
            sym = "✓" if row["reachable"] else "✗"
            print(f"  {sym}  {row['ts']}  {row.get('latency_ms', 0):.0f}ms")

    elif args.cmd == "search":
        results = search(
            args.query,
            engines=args.engines,
            max_results=args.max_results,
            mode=args.mode,
            _use_cache=not args.no_cache,
        )
        if not results:
            print("No results. Tor may be down or engines unreachable.")
        else:
            fmt = args.format
            if fmt == "json":
                out_text = json.dumps(results, indent=2)
            elif fmt == "csv":
                out_text = to_csv(results)
            elif fmt == "stix":
                out_text = json.dumps(to_stix(results, query=args.query), indent=2)
            else:  # text
                lines = []
                for i, r in enumerate(results, 1):
                    conf = f"  conf={r.get('confidence', 0):.2f}" if "confidence" in r else ""
                    lines.append(f"{i:>3}. [{r['engine']}]{conf}  {r['title']}")
                    lines.append(f"      {r['url']}")
                out_text = "\n".join(lines)
            _write_out(out_text, args.out)

    elif args.cmd == "fetch":
        r = fetch(args.url)
        if r["error"]:
            print(f"Error: {r['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"Title:  {r['title']}")
        print(f"Status: {r['status']}  |  .onion: {r['is_onion']}  |  links: {len(r['links'])}")
        print("-" * 60)
        print(r["text"][:3000])

    elif args.cmd == "analyze-nollm":
        if args.content == "-":
            raw = sys.stdin.read()
        else:
            with open(args.content, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        report = analyze_nollm(raw, query=args.query)
        _write_out(report, args.out)

    elif args.cmd == "crawl":
        print(f"Starting crawl: {args.url}  depth={args.depth}  pages={args.pages}")
        result = crawl(
            args.url,
            max_depth=args.depth,
            max_pages=args.pages,
            stay_on_domain=args.stay_domain,
            job_id=args.job_id,
            on_page=lambda p: print(f"  [{p.get('depth',0)}] {p.get('url','')}"),
        )
        print(f"\nJob: {result.job_id}")
        print(f"Pages found : {result.pages_found}")
        print(f"Links found : {result.links_found}")
        print(f"Entities    : {json.dumps(result.entities, indent=2)}")
        if args.out:
            export = crawl_export(result.job_id)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(export, fh, indent=2)
            print(f"Exported to {args.out}")

    elif args.cmd == "crawl-export":
        print(json.dumps(crawl_export(args.job_id), indent=2))

    elif args.cmd == "watch":
        wc = getattr(args, "watch_cmd", None)
        if wc == "add":
            job_id = watch_add(args.query, mode=args.mode, interval_hours=args.interval_hours)
            print(f"Watch job registered: {job_id}")
        elif wc == "list":
            jobs = watch_list()
            if not jobs:
                print("No active watch jobs.")
            for j in jobs:
                print(f"  {j['job_id']}  [{j['mode']}]  every {j['interval_hours']}h  "
                      f"next={j.get('next_run','')}  query={j['query']!r}")
        elif wc == "disable":
            watch_disable(args.job_id)
            print(f"Disabled: {args.job_id}")
        elif wc == "check":
            alerts = watch_check()
            if not alerts:
                print("No due jobs or no new results.")
            for a in alerts:
                print(f"  [{a['job_id']}] {a.get('new_count', 0)} new results for {a.get('query')!r}")
        else:
            p_w.print_help()

    elif args.cmd == "export":
        with open(args.infile, encoding="utf-8") as fh:
            data = json.load(fh)
        if args.format == "stix":
            out_text = json.dumps(to_stix(data, query=args.query), indent=2)
        else:
            out_text = to_csv(data)
        _write_out(out_text, args.out)

    elif args.cmd == "pool":
        pc = getattr(args, "pool_cmd", None)
        if pc == "start":
            pool = _get_pool(size=args.size, base_port=args.base_port)
            pool.start()
            print(f"TorPool started: {args.size} circuits on ports "
                  f"{args.base_port}–{args.base_port + args.size - 1}")
            print("Run 'pool stop' or Ctrl-C to stop.")
            try:
                import time as _time
                while True:
                    _time.sleep(60)
            except KeyboardInterrupt:
                pool.stop()
                print("Pool stopped.")
        elif pc == "stop":
            _p = _get_pool()
            if _p:
                _p.stop()
                print("TorPool stopped.")
            else:
                print("No pool running.")
        elif pc == "status":
            _p = _get_pool()
            if _p and _p._procs:
                alive = sum(1 for p in _p._procs if p.poll() is None)
                print(f"TorPool: {alive}/{len(_p._procs)} circuits alive  "
                      f"base_port={_p.base_port}")
            else:
                print("No TorPool running (TOR_POOL_SIZE=0 or not started).")
        else:
            p_pool_root.print_help()

    elif args.cmd == "tools":
        schema_map = {"anthropic": TOOLS, "openai": TOOLS_OPENAI, "gemini": TOOLS_GEMINI}
        print(json.dumps(schema_map[args.format], indent=2))

    elif args.cmd == "serve":
        _start_mcp_server()

    elif args.cmd == "clear-cache":
        n = clear_cache()
        print(f"Cleared {n} cached result(s).")

    else:
        parser.print_help()

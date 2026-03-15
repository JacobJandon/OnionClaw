# SPDX-License-Identifier: MIT
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/Sicry
from __future__ import annotations

__version__ = "1.2.3"

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

import json
import logging
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
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
# FETCH CACHE  (keyed by normalised URL; evicted after FETCH_CACHE_TTL)
# Two-layer: in-process dict (fast) + /tmp file (survives between runs).
# ─────────────────────────────────────────────────────────────────
_FETCH_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_FILE: str = os.getenv("SICRY_CACHE_FILE", "/tmp/onionclaw_cache.json")


def _load_disk_cache() -> None:
    """Load the persistent file cache into the in-memory dict (once per process)."""
    global _FETCH_CACHE
    if not _CACHE_FILE or not os.path.exists(_CACHE_FILE):
        return
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        now = time.time()
        # Discard expired entries while loading
        _FETCH_CACHE = {k: (ts, v) for k, (ts, v) in data.items()
                        if now - ts < FETCH_CACHE_TTL}
    except Exception:
        pass  # corrupt cache — ignore, will be overwritten


def _save_disk_cache() -> None:
    """Flush the in-memory cache to the file-based persistent store."""
    if not _CACHE_FILE:
        return
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_FETCH_CACHE, f)
    except Exception:
        pass  # read-only fs or permission error — silently skip


def clear_cache() -> int:
    """Delete all cached fetch results (memory + disk).

    Returns the number of entries that were evicted.

    Example:
        >>> n = sicry.clear_cache()
        >>> print(f"Cleared {n} cached entries")
    """
    global _FETCH_CACHE
    n = len(_FETCH_CACHE)
    _FETCH_CACHE = {}
    if _CACHE_FILE and os.path.exists(_CACHE_FILE):
        try:
            os.remove(_CACHE_FILE)
        except OSError:
            pass
    return n


# Load disk cache eagerly so the first call in a new process gets warm cache hits.
_load_disk_cache()

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
# PUBLIC API — 5 functions,  that's it.
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
                session = _build_tor_session()
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
                # Store in cache on success (memory + disk)
                if _use_cache and FETCH_CACHE_TTL > 0:
                    _FETCH_CACHE[cache_key] = (time.time(), result)
                    _save_disk_cache()
                return result
            except Exception as exc:
                last_err = str(exc)
                _is_socks_err = any(kw in last_err for kw in
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
            session = _build_tor_session()
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


def check_search_engines(max_workers: int = 8) -> list[dict]:
    """Ping all 12 active search engines via Tor and return per-engine status with latency.
    Robin health.py pattern — tells you which engines are alive before you search.

    Args:
        max_workers: Parallel threads. Default 8.

    Returns:
        List of dicts ordered by original engine index:
        [{"name": str, "status": "up"|"down", "latency_ms": int|None, "error": str|None}, ...]
    """
    def _ping(engine: dict) -> dict:
        url = engine["url"].format(query="test")
        try:
            session = _build_tor_session()
            session.headers["User-Agent"] = random.choice(_USER_AGENTS)
            start = time.time()
            resp = session.get(url, timeout=20)
            latency_ms = round((time.time() - start) * 1000)
            return {
                "name": engine["name"],
                "status": "up" if resp.status_code == 200 else "down",
                "latency_ms": latency_ms,
                "error": None if resp.status_code == 200 else f"HTTP {resp.status_code}",
            }
        except Exception as exc:
            return {
                "name": engine["name"],
                "status": "down",
                "latency_ms": None,
                "error": str(exc)[:80],
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
    return [results_map.get(e["name"], {"name": e["name"], "status": "down", "latency_ms": None, "error": "no result"}) for e in SEARCH_ENGINES]


def search(
    query: str,
    engines: Optional[list[str]] = None,
    max_results: int = 20,
    max_workers: int = 8,
) -> list[dict]:
    """
    Search the Tor network across 12 verified-live dark web search indexes simultaneously.
    The onion equivalent of web_search() or brave_search().
    All results are passed through a content safety filter before being returned.

    Args:
        query:       What to search for (natural language or keywords).
        engines:     Optional list of specific engine names to use.
                     Defaults to ALL 12 engines in parallel.
                     Options: Ahmia, OnionLand, Amnesia, Torland,
                              Excavator, Onionway, Tor66, OSS, Torgol,
                              TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet
        max_results: Max unique results returned after dedup. Default 20.
        max_workers: Parallel search threads. Default 8.

    Returns:
        List of dicts: [{"title": str, "url": str, "engine": str}, ...]

    Example:
        >>> sicry.search("leaked database credentials")
        [{"title": "...", "url": "http://...onion/...", "engine": "Ahmia"}, ...]
    """
    selected = SEARCH_ENGINES
    if engines:
        names = {e.lower() for e in engines}
        selected = [e for e in SEARCH_ENGINES if e["name"].lower() in names]

    results: list[dict] = []
    lock_seen: set[str] = set()

    def _fetch_engine(engine: dict) -> list[dict]:
        url = engine["url"].format(query=quote_plus(query))
        headers = {"User-Agent": random.choice(_USER_AGENTS)}
        session = _build_tor_session()
        # Compute engine's own hostname so we can exclude self-referential links
        _eng_host_m = re.findall(r"https?://([^/]+)", engine["url"])
        _eng_host = _eng_host_m[0] if _eng_host_m else ""
        found = []
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
        except Exception:
            pass
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

    return results[:max_results]


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
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "sicry_renew_identity",
        "description": "Rotate the Tor circuit to get a new exit node and new identity. Use this to avoid fingerprinting between investigation sessions.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "sicry_fetch",
        "description": "Fetch any URL through Tor — works for both normal websites (clearnet via Tor exit node) and .onion hidden services. Returns the page title, full clean text, and all hyperlinks found on the page. Use this to read specific .onion pages the same way you'd use fetch_url() or browser_read_page() for normal websites.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch. Can be a normal http/https URL or a .onion address. Example: 'http://example.onion/page'",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "sicry_search",
        "description": "Search the Tor network / dark web for the given query across up to 18 .onion search engines simultaneously (Ahmia, Tor66, Excavator, Torgle, and 12 more). Returns a deduplicated list of {title, url, engine} results. Use this the same way you'd call web_search() or brave_search() for the regular internet.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query — keywords or short phrase. Keep under 5 words for best results across onion search engines.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of unique results to return. Default 20.",
                    "default": 20,
                },
                "engines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: limit to specific engines by name. Available: Ahmia, OnionLand, Amnesia, Torland, Excavator, Onionway, Tor66, OSS, Torgol, TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet. Omit to query all 12.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "sicry_ask",
        "description": "Analyze and summarize dark web content using an LLM. Pass scraped text from .onion sites and get a structured OSINT investigation report back. Use after sicry_fetch or sicry_search to process raw dark web content into actionable intelligence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw text content from a dark web page or search results to analyze.",
                },
                "query": {
                    "type": "string",
                    "description": "The original investigation goal or query for context.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["threat_intel", "ransomware", "ransomware_malware", "personal_identity", "corporate", "corporate_espionage"],
                    "description": "Analysis mode. 'threat_intel' is the default general-purpose mode. 'ransomware'/'ransomware_malware' and 'corporate'/'corporate_espionage' are accepted aliases.",
                    "default": "threat_intel",
                },
                "custom_instructions": {
                    "type": "string",
                    "description": "Optional: extra focus area or constraints appended to the analysis prompt.",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "sicry_check_engines",
        "description": "Ping all 12 active dark web search engines via Tor and return per-engine status with latency in ms. Use this to find out which engines are alive before running a search, or to diagnose slow queries. Robin health-check pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "max_workers": {
                    "type": "integer",
                    "description": "Number of parallel ping workers. Default 8.",
                    "default": 8,
                },
            },
            "required": [],
        },
    },
]

# OpenAI function-calling format
TOOLS_OPENAI = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    }
    for t in TOOLS
]

# Google Gemini function declarations
TOOLS_GEMINI = [
    {
        "name": t["name"],
        "description": t["description"],
        "parameters": {
            "type": "object",
            "properties": t["input_schema"].get("properties", {}),
            "required": t["input_schema"].get("required", []),
        },
    }
    for t in TOOLS
]


# ─────────────────────────────────────────────────────────────────
# TOOL DISPATCHER
# Call this from your agent loop to execute any SICRY tool call.
# ─────────────────────────────────────────────────────────────────

def dispatch(tool_name: str, tool_input: dict) -> dict | list | str:
    """
    Execute a SICRY tool by name with the given input dict.
    Plug this into any agent framework's tool execution loop.

    Args:
        tool_name:  One of the tool names from TOOLS above.
        tool_input: Dict matching the tool's input_schema.

    Returns:
        The tool's return value (dict, list, or string).

    Example (in an agent loop):
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
        )
    if tool_name == "sicry_ask":
        return ask(
            tool_input["content"],
            query=tool_input.get("query", ""),
            mode=tool_input.get("mode", "threat_intel"),
            custom_instructions=tool_input.get("custom_instructions", ""),
        )
    if tool_name == "sicry_check_engines":
        return check_search_engines(max_workers=tool_input.get("max_workers", 8))
    raise ValueError(f"Unknown SICRY tool: {tool_name!r}")


# ─────────────────────────────────────────────────────────────────
# MCP SERVER  —  python sicry.py serve
# Model Context Protocol — plugs into Claude Desktop, Cursor, Zed,
# and any other MCP-compatible client. Requires: pip install mcp
# ─────────────────────────────────────────────────────────────────

def _start_mcp_server():
    """Start SICRY as a Model Context Protocol server.

    Claude Desktop (~/.config/claude/claude_desktop_config.json):
        { "mcpServers": { "sicry": {
            "command": "python",
            "args": ["/absolute/path/to/sicry.py", "serve"]
        } } }

    Cursor (settings.json):
        "mcp.servers": { "sicry": {
            "command": "python /absolute/path/to/sicry.py serve"
        } }
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "MCP not installed.\n"
            "  pip install mcp --user          # user install (works on PEP 668 systems)\n"
            "  pipx install mcp                # per-tool isolated install\n"
            "  pip install mcp --break-system-packages  # override system guard (Debian/Ubuntu)",
            file=sys.stderr,
        )
        sys.exit(1)

    mcp = FastMCP("sicry", description="Tor/Onion dark web access for AI agents")

    @mcp.tool(description="Verify Tor is running. Call before any dark web operation.")
    def sicry_check_tor() -> dict:
        return check_tor()

    @mcp.tool(description="Rotate Tor circuit — new exit node, fresh identity.")
    def sicry_renew_identity() -> dict:
        return renew_identity()

    @mcp.tool(description="Search 18 .onion search engines in parallel. Dark web equivalent of web_search().")
    def sicry_search(query: str, max_results: int = 20) -> list:
        return search(query, max_results=max_results)

    @mcp.tool(description="Fetch any URL through Tor (.onion or clearnet). Returns title, text, links.")
    def sicry_fetch(url: str) -> dict:
        return fetch(url)

    @mcp.tool(description="Analyse dark web content with LLM. Returns structured OSINT report.")
    def sicry_ask(content: str, query: str = "", mode: str = "threat_intel",
                  custom_instructions: str = "") -> str:
        return ask(content, query=query, mode=mode, custom_instructions=custom_instructions)

    @mcp.tool(description="Ping all 12 active dark web search engines via Tor. Returns per-engine status and latency. Use to check which engines are alive before searching.")
    def sicry_check_engines(max_workers: int = 8) -> list:
        return check_search_engines(max_workers=max_workers)

    mcp.run()


# ─────────────────────────────────────────────────────────────────
# CLI  —  python sicry.py <command>
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=f"SICRY v{__version__} — Tor/Onion Network Access Layer for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  check                          verify Tor is running
  search "query" [--max N]       search dark web (12 engines)
  fetch <url>                    fetch any URL through Tor
  tools [--format openai|gemini] print tool schemas as JSON
  serve                          start MCP server
  renew                          rotate Tor circuit
  clear-cache                    delete all cached fetch results

Examples:
  python sicry.py --version
  python sicry.py check
  python sicry.py search "ransomware data leak" --max 15
  python sicry.py fetch http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion
  python sicry.py tools --format openai
  python sicry.py serve
  python sicry.py clear-cache
        """,
    )
    parser.add_argument("--version", action="version", version=f"SICRY {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("check")
    sub.add_parser("renew")
    sub.add_parser("serve")
    sub.add_parser("clear-cache", help="Delete all cached fetch results (memory + disk)")

    p_s = sub.add_parser("search")
    p_s.add_argument("query")
    p_s.add_argument("--max", type=int, default=10, dest="max_results")
    p_s.add_argument("--engine", action="append", dest="engines", metavar="NAME")

    p_f = sub.add_parser("fetch")
    p_f.add_argument("url")

    p_t = sub.add_parser("tools")
    p_t.add_argument("--format", choices=["anthropic", "openai", "gemini"], default="anthropic")

    args = parser.parse_args()

    if args.cmd == "check":
        r = check_tor()
        ok = "CONNECTED via Tor" if r["tor_active"] else "NOT through Tor"
        print(f"{ok}  |  exit IP: {r['exit_ip']}  |  error: {r['error']}")

    elif args.cmd == "renew":
        r = renew_identity()
        print("Identity rotated" if r["success"] else f"Failed: {r['error']}")

    elif args.cmd == "search":
        results = search(args.query, engines=args.engines, max_results=args.max_results)
        if not results:
            print("No results. Tor may be down or engines unreachable.")
        for i, r in enumerate(results, 1):
            print(f"{i:>3}. [{r['engine']}] {r['title']}")
            print(f"      {r['url']}")

    elif args.cmd == "fetch":
        r = fetch(args.url)
        if r["error"]:
            print(f"Error: {r['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"Title:  {r['title']}")
        print(f"Status: {r['status']}  |  .onion: {r['is_onion']}  |  links: {len(r['links'])}")
        print("-" * 60)
        print(r["text"][:3000])

    elif args.cmd == "tools":
        schema_map = {"anthropic": TOOLS, "openai": TOOLS_OPENAI, "gemini": TOOLS_GEMINI}
        print(json.dumps(schema_map[args.format], indent=2))

    elif args.cmd == "serve":
        _start_mcp_server()

    elif args.cmd == "clear-cache":
        n = clear_cache()
        print(f"Cleared {n} cached fetch result(s).")

    else:
        parser.print_help()

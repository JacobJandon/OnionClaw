# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — collectors.py
Read-only intelligence collectors used by the swarm.

Every collector is a passive observer: it reads public data and records what it
sees in the Store. None of them post, message, register, negotiate or otherwise
interact with threat actors or third-party services beyond plain GETs.

  LeakSiteCollector   ransomware.live victim disclosures  -> kind "victim"
                      (also harvests ransom-note wallets  -> kind "wallet")
  GroupInfraCollector ransomware.live group leak-site infra -> kind "dls"
  WalletCollector     mempool.space on-chain movement     -> kind "wallet_state"
  OnionSiteCollector  .onion page change monitoring (Tor) -> kind "onion_page"
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

import requests

import safety
from entities import extract_entities, onion_host, valid_btc
from store import CHANGED, NEW, Store

USER_AGENT = "OnionClaw/2.4 (threat-intel monitor; read-only)"
MEMPOOL = "https://mempool.space/api"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ransomware.live — free v2 tier: 1 request/minute/endpoint, victims delayed vs PRO, and
# "personal use only, not for corporate or business use" per https://www.ransomware.live/api.
# A PRO key is supported via env. NOTE: the PRO auth header name and paths could not be
# verified from public docs; RANSOMWARE_LIVE_KEY_HEADER defaults to X-API-KEY (UNVERIFIED —
# confirm in the PRO docs) and RANSOMWARE_LIVE_BASE lets you point at the PRO host.
RANSOMWARE_LIVE = os.getenv("RANSOMWARE_LIVE_BASE", "https://api.ransomware.live/v2").rstrip("/")
RL_API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY", "")
RL_KEY_HEADER = os.getenv("RANSOMWARE_LIVE_KEY_HEADER", "X-API-KEY")
RL_MIN_GAP = float(os.getenv("RANSOMWARE_LIVE_MIN_GAP", "60"))
FREE_TIER_NOTICE = ("ransomware.live free tier in use: limited to personal use (not corporate/"
                    "business), 1 req/min/endpoint, victims delayed vs PRO. For business use set "
                    "RANSOMWARE_LIVE_API_KEY (and RANSOMWARE_LIVE_BASE).")


class CollectorUnavailable(Exception):
    """Dependency (e.g. Tor) missing. The collector is skipped, not failed."""


@dataclass
class Result:
    items: int = 0
    events: int = 0
    skipped: int = 0            # unsafe / invalid items dropped (always counted, never silent)
    notes: list[str] = field(default_factory=list)


def http_get_json(url: str, *, timeout: float = 25, retries: int = 3,
                  session: Optional[requests.Session] = None,
                  headers: Optional[dict] = None):
    """GET JSON with backoff on 429/5xx and transient network errors."""
    s = session or requests
    delay = 1.5
    last: Optional[Exception] = None
    for _ in range(retries):
        try:
            r = s.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT, **(headers or {})})
            if r.status_code in (429, 500, 502, 503, 504):
                retry_after = r.headers.get("Retry-After")
                time.sleep(float(retry_after) if retry_after and retry_after.isdigit() else delay)
                delay *= 2
                last = RuntimeError(f"HTTP {r.status_code} from {url}")
                continue
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            last = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"GET {url} failed after {retries} attempts: {last}")


class Collector:
    name = "collector"
    min_interval = 0.0      # seconds; swarm skips the collector while its last run is fresher

    def collect(self, store: Store) -> Result:  # pragma: no cover - interface
        raise NotImplementedError


class _RansomwareLiveMixin:
    """Throttled (cross-process), key-aware access to ransomware.live."""
    _get = None   # injected fetcher (tests); None => guarded live HTTP

    def _rl(self, store: Store, path: str, res: "Result"):
        if self._get is not None:
            return self._get(f"{RANSOMWARE_LIVE}{path}")
        wait = store.claim(f"ransomware.live{path}", RL_MIN_GAP)
        if wait:
            raise CollectorUnavailable(f"rate-limit guard: {path} polled {int(RL_MIN_GAP - wait)}s ago, "
                                       f"wait {int(wait)}s (ransomware.live allows 1 req/min/endpoint)")
        if not RL_API_KEY:
            res.notes.append(FREE_TIER_NOTICE)
        headers = {RL_KEY_HEADER: RL_API_KEY} if RL_API_KEY else None
        return http_get_json(f"{RANSOMWARE_LIVE}{path}", headers=headers)


# ── 1. leak-site victim disclosures ───────────────────────────────────────────
class LeakSiteCollector(_RansomwareLiveMixin, Collector):
    name = "leaksites"

    def __init__(self, fetch_json: Optional[Callable[[str], object]] = None):
        self._get = fetch_json

    def collect(self, store: Store) -> Result:
        res = Result()
        victims = self._rl(store, "/recentvictims", res)
        if not isinstance(victims, list):
            raise RuntimeError("unexpected ransomware.live payload (not a list)")
        for v in victims:
            key = v.get("url")
            if not key:
                res.skipped += 1
                continue
            # Safety applies to the structured identity fields only, not the long
            # extortion text, so a children's hospital victim is not dropped.
            verdict = safety.is_safe(
                "", f"{v.get('victim','')} {v.get('group','')}", v.get("domain") or "")
            if not verdict:
                res.skipped += 1
                res.notes.append(f"refused {key}: {verdict.reason}")
                continue

            payload = {k: v.get(k) for k in (
                "victim", "group", "country", "activity", "attackdate",
                "discovered", "domain", "claim_url", "data_size", "ransom")}
            payload["description"] = (v.get("description") or "")[:2000]
            detail = f"{v.get('group')}: {v.get('victim')} ({v.get('country') or '??'}, {v.get('activity') or 'n/a'})"
            change = store.observe(self.name, "victim", key, payload, detail)
            res.items += 1
            res.events += change in (NEW, CHANGED)

            # Ransom-note wallets are the bridge to the wallet collector.
            ents = extract_entities(v.get("description") or "")
            for addr in ents["btc_wallets"]:
                prev = store.get(self.name, "wallet", addr) or {}
                groups = sorted(set(prev.get("groups", [])) | {v.get("group")} - {None})
                seen_in = sorted(set(prev.get("seen_in", [])) | {key})[:50]
                shared = len(groups) > 1 and v.get("group") not in prev.get("groups", [])
                detail = (f"BTC wallet {addr} now linked to {len(groups)} groups: {', '.join(groups)}"
                          if shared else f"BTC wallet in {v.get('group')} note: {addr}")
                ch = store.observe(self.name, "wallet", addr,
                                   {"chain": "btc", "groups": groups, "seen_in": seen_in}, detail)
                res.events += ch in (NEW, CHANGED)
        return res


# ── 2. leak-site infrastructure ───────────────────────────────────────────────
class GroupInfraCollector(_RansomwareLiveMixin, Collector):
    name = "groupinfra"
    min_interval = 6 * 3600   # leak-site infrastructure moves slowly; be a good API neighbour

    def __init__(self, fetch_json: Optional[Callable[[str], object]] = None):
        self._get = fetch_json

    def collect(self, store: Store) -> Result:
        res = Result()
        baseline = store.count("dls") == 0     # first run: record silently, no event flood
        groups = self._rl(store, "/groups", res)
        if not isinstance(groups, list):
            raise RuntimeError("unexpected ransomware.live payload (not a list)")
        for g in groups:
            for loc in g.get("locations") or []:
                fqdn = (loc.get("fqdn") or "").lower()
                if not fqdn:
                    res.skipped += 1
                    continue
                payload = {"group": g.get("name"), "enabled": loc.get("enabled"),
                           "available": loc.get("available"), "title": loc.get("title"),
                           "type": loc.get("type")}
                detail = (f"{g.get('name')} {loc.get('type')} {fqdn} "
                          f"available={loc.get('available')} enabled={loc.get('enabled')}")
                change = store.observe(self.name, "dls", f"{g.get('name')}|{fqdn}", payload, detail,
                                       quiet=baseline)
                res.items += 1
                res.events += (change in (NEW, CHANGED)) and not baseline
        if baseline:
            res.notes.append(f"baseline recorded: {res.items} leak-site locations")
        return res


# ── 2b. CISA Known Exploited Vulnerabilities ──────────────────────────────────
class KevCollector(Collector):
    """New CVEs added to CISA KEV, and — the high-value signal — existing CVEs whose
    knownRansomwareCampaignUse flips from Unknown to Known."""
    name = "kev"
    min_interval = 3600

    def __init__(self, fetch_json: Callable[[str], object] = http_get_json):
        self._get = fetch_json

    def collect(self, store: Store) -> Result:
        res = Result()
        baseline = store.count("kev") == 0
        feed = self._get(CISA_KEV)
        vulns = feed.get("vulnerabilities") if isinstance(feed, dict) else None
        if not isinstance(vulns, list):
            raise RuntimeError("unexpected CISA KEV payload")
        for v in vulns:
            cve = v.get("cveID")
            if not cve:
                res.skipped += 1
                continue
            ransom = v.get("knownRansomwareCampaignUse") == "Known"
            payload = {"vendor": v.get("vendorProject"), "product": v.get("product"),
                       "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"),
                       "due": v.get("dueDate"), "ransomware_known": ransom,
                       "cwes": v.get("cwes") or []}
            prev = store.get(self.name, "kev", cve)
            tag = " [RANSOMWARE]" if ransom else ""
            if prev and not prev["ransomware_known"] and ransom:
                detail = f"{cve} now linked to ransomware campaigns: {v.get('vendorProject')} {v.get('product')}{tag}"
            else:
                detail = f"{cve} {v.get('vendorProject')} {v.get('product')} — {v.get('vulnerabilityName')}{tag}"
            change = store.observe(self.name, "kev", cve, payload, detail, quiet=baseline)
            res.items += 1
            res.events += (change in (NEW, CHANGED)) and not baseline
        if baseline:
            res.notes.append(f"baseline recorded: {res.items} KEV entries "
                             f"({store.count('kev')} stored)")
        return res


# ── 3. on-chain wallet movement ───────────────────────────────────────────────
class WalletCollector(Collector):
    name = "wallets"

    def __init__(self, extra_addresses: Iterable[str] = (), max_per_run: int = 25,
                 pause: float = 0.4,
                 fetch_json: Callable[[str], object] = http_get_json):
        self.extra = [a for a in extra_addresses]
        self.max_per_run = max_per_run
        self.pause = pause
        self._get = fetch_json

    def _targets(self, store: Store) -> list[str]:
        addrs, seen = [], set()
        for a in self.extra:
            if a not in seen:
                addrs.append(a); seen.add(a)
        with store._conn() as c:   # harvested wallets, least-recently-checked first
            rows = c.execute(
                "SELECT o.key FROM observations o "
                "LEFT JOIN observations s ON s.kind='wallet_state' AND s.key=o.key "
                "WHERE o.kind='wallet' ORDER BY COALESCE(s.last_seen,0) ASC").fetchall()
        for r in rows:
            if r["key"] not in seen:
                addrs.append(r["key"]); seen.add(r["key"])
        return addrs

    def collect(self, store: Store) -> Result:
        res = Result()
        for addr in self._targets(store)[: self.max_per_run]:
            if not valid_btc(addr):
                res.skipped += 1
                res.notes.append(f"invalid address skipped: {addr}")
                continue
            try:
                info = self._get(f"{MEMPOOL}/address/{addr}")
            except RuntimeError as e:
                res.notes.append(str(e))
                continue
            cs, ms = info["chain_stats"], info["mempool_stats"]
            balance = cs["funded_txo_sum"] - cs["spent_txo_sum"]
            payload = {"tx_count": cs["tx_count"], "received_sat": cs["funded_txo_sum"],
                       "spent_sat": cs["spent_txo_sum"], "balance_sat": balance,
                       "mempool_tx": ms["tx_count"]}
            prev = store.get(self.name, "wallet_state", addr)
            if prev is None:
                detail = f"{addr} first seen: balance {balance/1e8:.8f} BTC, {cs['tx_count']} tx"
            else:
                delta = balance - prev["balance_sat"]
                detail = (f"{addr} balance {prev['balance_sat']/1e8:.8f} -> {balance/1e8:.8f} BTC "
                          f"({delta/1e8:+.8f}), +{cs['tx_count']-prev['tx_count']} tx, "
                          f"{ms['tx_count']} in mempool")
            change = store.observe(self.name, "wallet_state", addr, payload, detail,
                                   quiet=prev is None)
            res.items += 1
            res.events += change == CHANGED
            time.sleep(self.pause)
        return res


# ── 4. .onion page monitoring (needs Tor) ─────────────────────────────────────
_VOLATILE = re.compile(r"\b\d{1,2}:\d{2}(:\d{2})?\b|\b\d{4}-\d{2}-\d{2}\b")


class OnionSiteCollector(Collector):
    name = "onionsites"

    def __init__(self, urls: Iterable[str], workers: int = 4, fetch=None):
        self.urls = [u if u.startswith("http") else "http://" + u for u in urls]
        self.workers = workers
        self._fetch = fetch

    def _resolve_fetch(self):
        if self._fetch:
            return self._fetch
        try:
            import sicry
        except Exception as e:
            raise CollectorUnavailable(f"sicry import failed: {e}")
        if not sicry._tor_port_open():
            raise CollectorUnavailable(
                f"Tor SOCKS {sicry.TOR_SOCKS_HOST}:{sicry.TOR_SOCKS_PORT} not reachable")
        return sicry.fetch

    def collect(self, store: Store) -> Result:
        res = Result()
        fetch = self._resolve_fetch()

        def one(url):
            try:
                return url, fetch(url), None
            except Exception as e:
                return url, None, e

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for url, page, err in pool.map(one, self.urls):
                if err or not page or page.get("error") or not page.get("status"):
                    res.notes.append(f"{url}: {err or (page or {}).get('error') or 'no response'}")
                    continue
                title, text = page.get("title") or "", page.get("text") or ""
                verdict = safety.is_safe(url, title, text)
                if not verdict:
                    res.skipped += 1
                    res.notes.append(f"refused {url}: {verdict.reason}")
                    continue
                host = onion_host(url)
                ents = extract_entities(text, page.get("links"), host)
                norm = _VOLATILE.sub("", text)
                payload = {"status": page["status"], "title": title[:160],
                           "text_sha256": hashlib.sha256(norm.encode()).hexdigest(),
                           "entities": ents}
                prev = store.get(self.name, "onion_page", url)
                detail = f"{url} status={page['status']}"
                if prev:
                    parts = []
                    for k in ("btc_wallets", "xmr_wallets", "eth_wallets", "emails", "onion_links"):
                        added = sorted(set(ents[k]) - set(prev["entities"].get(k, [])))
                        if added:
                            parts.append(f"+{len(added)} {k}: {', '.join(added[:3])}")
                    if prev["text_sha256"] != payload["text_sha256"]:
                        parts.insert(0, "content changed")
                    if parts:
                        detail += " — " + "; ".join(parts)
                change = store.observe(self.name, "onion_page", url, payload, detail,
                                       quiet=prev is None)
                res.items += 1
                res.events += change == CHANGED
        return res

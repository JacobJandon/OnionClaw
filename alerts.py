# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — alerts.py
Turn monitoring events into prioritised alerts and deliver them to a webhook.

Rules (severity):
  KEV_RANSOMWARE   HIGH    CVE added to CISA KEV with known ransomware use, or newly linked to it
  WALLET_MOVEMENT  HIGH    balance / transactions changed on a tracked ransom wallet
  WALLET_LINK      HIGH    one wallet now linked to more than one group
  WATCHLIST_HIT    HIGH    event mentions a --watch term (whole word)
  CRITICAL_VICTIM  MEDIUM  new victim in a critical sector (healthcare, government, ... configurable)
  TTP_CHANGE       MEDIUM  a group's published ATT&CK techniques changed
  ONION_CHANGE     MEDIUM  a monitored .onion page changed
  INFRA_CHANGE     LOW     a leak-site location went up / down

Delivery guarantees
  * An event is marked delivered only after the receiver answers 2xx, so a failed
    delivery is retried on the next run and never silently lost.
  * An event is delivered at most once per sink (alerts_sent table).
  * generic payloads can be HMAC-SHA256 signed (X-OnionClaw-Signature) so the receiver
    can verify they came from you.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

import requests

from store import Store

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
DEFAULT_SECTORS = ("healthcare", "government", "defense", "education", "energy", "utilities")
FORMATS = ("generic", "slack", "discord")


@dataclass
class Alert:
    event_id: int
    type: str
    severity: str
    message: str
    key: str
    ts: float
    matched: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"alert_type": self.type, "severity": self.severity, "message": self.message,
                "key": self.key, "event_id": self.event_id, "matched": self.matched,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts))}


def _word_rx(term: str):
    return re.compile(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])")


def build_alerts(store: Store, events: Iterable[dict], watch: Iterable[str] = (),
                 sectors: Iterable[str] = DEFAULT_SECTORS) -> list[Alert]:
    watch_rx = [(w, _word_rx(w)) for w in watch]
    sector_rx = [(s, _word_rx(s)) for s in sectors]
    out: list[Alert] = []
    for e in events:
        kind, change, detail = e["kind"], e["change"], e["detail"]
        hay = (detail if kind == "victim" else f"{detail} {e['key']}").lower()
        hits = [w for w, rx in watch_rx if rx.search(hay)]
        a: Optional[Alert] = None

        if kind == "kev" and "[RANSOMWARE]" in detail:
            a = Alert(e["id"], "KEV_RANSOMWARE", "HIGH", detail, e["key"], e["ts"])
        elif kind == "wallet_state" and change == "changed":
            a = Alert(e["id"], "WALLET_MOVEMENT", "HIGH", detail, e["key"], e["ts"])
        elif kind == "wallet" and "now linked to" in detail:
            a = Alert(e["id"], "WALLET_LINK", "HIGH", detail, e["key"], e["ts"])
        elif kind == "onion_page" and change == "changed":
            a = Alert(e["id"], "ONION_CHANGE", "MEDIUM", detail, e["key"], e["ts"])
        elif kind == "victim" and change == "new":
            p = store.get(e["source"], "victim", e["key"]) or {}
            activity = (p.get("activity") or "").lower()
            crit = [s for s, rx in sector_rx if rx.search(activity)]
            if crit:
                a = Alert(e["id"], "CRITICAL_VICTIM", "MEDIUM", detail, e["key"], e["ts"], crit)
        elif kind == "group_profile" and change == "changed" and "ATT&CK technique" in detail:
            a = Alert(e["id"], "TTP_CHANGE", "MEDIUM", detail, e["key"], e["ts"])
        elif kind == "dls" and change == "changed":
            a = Alert(e["id"], "INFRA_CHANGE", "LOW", detail, e["key"], e["ts"])

        if hits:
            if a is None:
                a = Alert(e["id"], "WATCHLIST_HIT", "HIGH", detail, e["key"], e["ts"], hits)
            else:
                a.matched = sorted(set(a.matched) | set(hits))
                if SEVERITY_ORDER[a.severity] < SEVERITY_ORDER["HIGH"]:
                    a.severity = "HIGH"
        if a:
            out.append(a)
    out.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], -a.ts))
    return out


def format_payload(alerts: list[Alert], fmt: str, source: str = "OnionClaw") -> dict:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "⚪"}
    lines = [f"{icon[a.severity]} [{a.severity}] {a.type}: {a.message}" for a in alerts]
    text = f"{source}: {len(alerts)} alert(s)\n" + "\n".join(lines)
    if fmt == "slack":
        return {"text": text[:39000]}                      # Slack caps messages near 40k chars
    if fmt == "discord":
        return {"content": text[:1990]}                    # Discord caps content at 2000 chars
    return {"source": source, "count": len(alerts), "alerts": [a.as_dict() for a in alerts]}


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(url: str, payload: dict, secret: Optional[str] = None, retries: int = 3,
            timeout: float = 15.0, session=None) -> tuple[bool, str]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "OnionClaw/2.4"}
    if secret:
        headers["X-OnionClaw-Signature"] = sign(body, secret)
    s = session or requests
    delay, last = 1.0, "no attempt"
    for _ in range(retries):
        try:
            r = s.post(url, data=body, headers=headers, timeout=timeout)
            if 200 <= r.status_code < 300:
                return True, f"HTTP {r.status_code}"
            last = f"HTTP {r.status_code}"
            if r.status_code == 429:
                ra = r.headers.get("Retry-After", "")
                time.sleep(min(float(ra), 30) if ra.replace(".", "", 1).isdigit() else delay)
            elif 400 <= r.status_code < 500:
                return False, last                          # client error: retrying won't help
            else:
                time.sleep(delay)
        except requests.RequestException as e:
            last = type(e).__name__
            time.sleep(delay)
        delay *= 2
    return False, last


def process(store: Store, since: float, url: str, fmt: str = "generic",
            watch: Iterable[str] = (), sectors: Iterable[str] = DEFAULT_SECTORS,
            min_severity: str = "MEDIUM", secret: Optional[str] = None,
            dry_run: bool = False, batch: int = 20, session=None) -> dict:
    """Build alerts from events since `since`, drop already-delivered ones, send the rest."""
    floor = SEVERITY_ORDER[min_severity]
    alerts = [a for a in build_alerts(store, store.events_since(since), watch, sectors)
              if SEVERITY_ORDER[a.severity] >= floor]
    sink = f"{fmt}:{url}"
    with store._conn() as c:
        sent = {r["event_id"] for r in c.execute(
            "SELECT event_id FROM alerts_sent WHERE sink=?", (sink,))}
    pending = [a for a in alerts if a.event_id not in sent]
    result = {"candidates": len(alerts), "pending": len(pending), "delivered": 0,
              "failed": 0, "dry_run": dry_run, "errors": []}
    if dry_run or not pending:
        result["preview"] = [a.as_dict() for a in pending[:batch]]
        return result

    for i in range(0, len(pending), batch):
        chunk = pending[i:i + batch]
        ok, info = deliver(url, format_payload(chunk, fmt), secret, session=session)
        if ok:
            with store._conn() as c:
                c.executemany("INSERT OR IGNORE INTO alerts_sent (event_id,sink,ts) VALUES (?,?,?)",
                              [(a.event_id, sink, time.time()) for a in chunk])
            result["delivered"] += len(chunk)
        else:
            result["failed"] += len(chunk)
            result["errors"].append(info)
    return result

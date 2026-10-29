# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — store.py
Persistent observation store with change detection.

Every collector reports observations as (source, kind, key, payload). The store
hashes the payload and answers the one question monitoring cares about:
is this NEW, CHANGED, or UNCHANGED since the last time we looked?

SQLite in WAL mode, safe for concurrent collector threads (one connection per
call, short transactions, busy timeout).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterable, Optional

DEFAULT_DB = os.getenv(
    "ONIONCLAW_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "onionclaw.db"),
)

NEW, CHANGED, UNCHANGED = "new", "changed", "unchanged"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    source       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    key          TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    payload      TEXT NOT NULL,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    seen_count   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (source, kind, key)
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    source  TEXT NOT NULL,
    kind    TEXT NOT NULL,
    key     TEXT NOT NULL,
    change  TEXT NOT NULL,
    detail  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    collector TEXT NOT NULL,
    started   REAL NOT NULL,
    finished  REAL,
    ok        INTEGER,
    items     INTEGER DEFAULT 0,
    events    INTEGER DEFAULT 0,
    error     TEXT
);
CREATE TABLE IF NOT EXISTS throttle (
    endpoint  TEXT PRIMARY KEY,
    last_call REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts_sent (
    event_id INTEGER NOT NULL,
    sink     TEXT NOT NULL,
    ts       REAL NOT NULL,
    PRIMARY KEY (event_id, sink)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_obs_kind  ON observations(kind);
"""


def content_hash(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_DB
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=30000")
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def observe(self, source: str, kind: str, key: str, payload: Any,
                detail: Optional[str] = None, quiet: bool = False) -> str:
        """Record one observation. Returns NEW / CHANGED / UNCHANGED and logs an
        event for NEW and CHANGED. quiet=True records a first sighting without an
        event (baselining), so the first run doesn't flood the event log."""
        now = time.time()
        h = content_hash(payload)
        body = json.dumps(payload, sort_keys=True, default=str)
        with self._conn() as c:
            row = c.execute(
                "SELECT content_hash FROM observations WHERE source=? AND kind=? AND key=?",
                (source, kind, key),
            ).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO observations VALUES (?,?,?,?,?,?,?,1)",
                    (source, kind, key, h, body, now, now),
                )
                change = NEW
                if quiet:
                    return NEW
            elif row["content_hash"] != h:
                c.execute(
                    "UPDATE observations SET content_hash=?, payload=?, last_seen=?, "
                    "seen_count=seen_count+1 WHERE source=? AND kind=? AND key=?",
                    (h, body, now, source, kind, key),
                )
                change = CHANGED
            else:
                c.execute(
                    "UPDATE observations SET last_seen=?, seen_count=seen_count+1 "
                    "WHERE source=? AND kind=? AND key=?",
                    (now, source, kind, key),
                )
                return UNCHANGED
            c.execute(
                "INSERT INTO events (ts,source,kind,key,change,detail) VALUES (?,?,?,?,?,?)",
                (now, source, kind, key, change, detail or ""),
            )
            return change

    def get(self, source: str, kind: str, key: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute(
                "SELECT payload FROM observations WHERE source=? AND kind=? AND key=?",
                (source, kind, key),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def events_since(self, ts: float, kinds: Optional[Iterable[str]] = None) -> list[dict]:
        q, args = "SELECT * FROM events WHERE ts>=?", [ts]
        if kinds:
            kinds = list(kinds)
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += kinds
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY ts, id", args)]

    def count(self, kind: Optional[str] = None) -> int:
        with self._conn() as c:
            if kind:
                return c.execute("SELECT COUNT(*) FROM observations WHERE kind=?", (kind,)).fetchone()[0]
            return c.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

    def start_run(self, collector: str) -> int:
        with self._conn() as c:
            return c.execute(
                "INSERT INTO runs (collector, started) VALUES (?,?)", (collector, time.time())
            ).lastrowid

    def finish_run(self, run_id: int, ok: bool, items: int, events: int,
                   error: Optional[str] = None) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE runs SET finished=?, ok=?, items=?, events=?, error=? WHERE id=?",
                (time.time(), int(ok), items, events, error, run_id),
            )

    def claim(self, endpoint: str, min_gap: float) -> float:
        """Cross-process rate-limit guard. Returns 0.0 and records the call if at least
        `min_gap` seconds have passed since the last claim; otherwise returns the
        seconds still to wait (and records nothing). Atomic via BEGIN IMMEDIATE."""
        now = time.time()
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            c.execute("PRAGMA busy_timeout=30000")
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT last_call FROM throttle WHERE endpoint=?", (endpoint,)).fetchone()
            if row and now - row[0] < min_gap:
                c.execute("ROLLBACK")
                return min_gap - (now - row[0])
            c.execute("INSERT INTO throttle (endpoint,last_call) VALUES (?,?) "
                      "ON CONFLICT(endpoint) DO UPDATE SET last_call=excluded.last_call", (endpoint, now))
            c.execute("COMMIT")
            return 0.0
        finally:
            c.close()

    def last_ok_run(self, collector: str) -> Optional[float]:
        """Finish time of the last run that completed and actually did work."""
        with self._conn() as c:
            row = c.execute(
                "SELECT MAX(finished) FROM runs WHERE collector=? AND ok=1 AND error IS NULL",
                (collector,)).fetchone()
        return row[0] if row and row[0] else None

    def recent_runs(self, limit: int = 20) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

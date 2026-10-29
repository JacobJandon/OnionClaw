#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — iocs.py
One queryable list of every indicator the swarm has observed.

Adapted from PRISM-Intel's IoC tracker. PRISM kept a separate `ioc_entries` table that
had to be seeded and could drift from the data it described. Here the list is derived
from the observations the collectors already store, so it can never disagree with them
and needs no extra writes:

  onion_host   leak-site hosts (groupinfra), victim claim URLs, links found while crawling
  domain       leak sites on the clearnet, victim domains
  btc_wallet   checksum-validated addresses from ransom notes
  cve          CISA KEV entries, flagged when tied to ransomware campaigns
  email / tox  contact addresses found on monitored .onion pages

Every row carries first/last seen, the groups it is attributed to, and the observation
it came from, so each one can be traced back. Values are defanged by default
(hxxp://, [.]), the usual convention for passing indicators around safely; pass --fanged
for machine-readable output.

Attribution comes from what a leak site published, not from analysis: treat it as a lead.

Usage:
  python3 iocs.py                            # everything, newest first
  python3 iocs.py --type btc_wallet --type cve
  python3 iocs.py --group qilin              # indicators attributed to one group
  python3 iocs.py --search acme              # substring match on value or context
  python3 iocs.py --since 2026-10-01
  python3 iocs.py --format csv -o iocs.csv   # table | json | csv
"""
from __future__ import annotations

import sys, os, re, csv, json, time, argparse
from datetime import datetime, timezone

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

from store import Store
from entities import extract_entities, onion_host, valid_btc
import graph

__version__ = "2.4.0"

TYPES = ("onion_host", "domain", "btc_wallet", "cve", "email", "tox")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)


def defang(value: str, kind: str) -> str:
    """Standard analyst defanging, so indicators can be pasted into a ticket or chat
    without becoming a live link."""
    if kind in ("onion_host", "domain", "email"):
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    return value


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


class _Table:
    """Collects rows, merging duplicates of the same (type, value)."""

    def __init__(self):
        self.rows: dict[tuple, dict] = {}

    def add(self, kind, value, *, first, last, group=None, source="", context="", flags=()):
        if not value:
            return
        value = value.strip()
        if not value:
            return
        key = (kind, value.lower())
        r = self.rows.get(key)
        if r is None:
            r = self.rows[key] = {"type": kind, "value": value, "first_seen": first, "last_seen": last,
                                  "groups": set(), "sources": set(), "context": context, "flags": set()}
        r["first_seen"] = min(r["first_seen"], first)
        r["last_seen"] = max(r["last_seen"], last)
        if group:
            r["groups"].add(group)
        if source:
            r["sources"].add(source)
        if context and not r["context"]:
            r["context"] = context
        r["flags"].update(flags)


def collect(store: Store) -> list[dict]:
    """Every indicator currently derivable from the observation store."""
    t = _Table()
    data = graph._load(store)
    _, canon = graph._canonical(data)
    name = lambda g: canon.get(graph.norm(g or ""), g) if g else None

    # leak-site infrastructure: the host is in the observation key, "group|fqdn"
    for key, p, first, last in data["dls"]:
        host = key.split("|", 1)[-1].lower()
        g = name(p.get("group"))
        kind = "onion_host" if host.endswith(".onion") else ("domain" if _DOMAIN_RE.match(host) else None)
        if not kind:
            continue
        flags = {"live"} if p.get("available") else set()
        t.add(kind, host, first=first, last=last, group=g, source="groupinfra",
              context=f"{p.get('type') or 'leak site'} for {g}", flags=flags)

    # victims: claim URL, victim domain, and anything in the published extortion text
    for _, p, first, last in data["victim"]:
        g = name(p.get("group"))
        ctx = f"victim {p.get('victim')}" if p.get("victim") else "victim post"
        host = onion_host(p.get("claim_url") or "")
        if host:
            t.add("onion_host", host, first=first, last=last, group=g, source="leaksites",
                  context=f"claim URL, {ctx}")
        dom = (p.get("domain") or "").strip().lower().rstrip(".")
        if dom and _DOMAIN_RE.match(dom):
            t.add("domain", dom, first=first, last=last, group=g, source="leaksites",
                  context=f"{ctx} domain", flags={"victim"})
        ents = extract_entities(p.get("description") or "")
        for addr in ents["btc_wallets"]:
            t.add("btc_wallet", addr, first=first, last=last, group=g, source="leaksites",
                  context=f"ransom note, {ctx}")
        for em in ents["emails"]:
            t.add("email", em, first=first, last=last, group=g, source="leaksites",
                  context=f"ransom note, {ctx}")
        for h in ents["onion_links"]:
            t.add("onion_host", h, first=first, last=last, group=g, source="leaksites",
                  context=f"linked in {ctx}")

    # wallets harvested by the collector (may list several groups)
    for key, p, first, last in data["wallet"]:
        if not valid_btc(key):
            continue
        groups = p.get("groups") or ([p["group"]] if p.get("group") else [])
        for g in groups or [None]:
            t.add("btc_wallet", key, first=first, last=last, group=name(g), source="leaksites",
                  context="ransom-note wallet")

    with store._conn() as c:
        # CISA KEV
        for r in c.execute("SELECT key, payload, first_seen, last_seen FROM observations WHERE kind='kev'"):
            p = json.loads(r["payload"])
            if not _CVE_RE.match(r["key"]):
                continue
            t.add("cve", r["key"].upper(), first=r["first_seen"], last=r["last_seen"], source="kev",
                  context=f"{p.get('vendor')} {p.get('product')}".strip(),
                  flags={"ransomware"} if p.get("ransomware_known") else set())
        # monitored .onion pages
        for r in c.execute("SELECT key, payload, first_seen, last_seen FROM observations WHERE kind='onion_page'"):
            p = json.loads(r["payload"])
            ents = p.get("entities") or {}
            page = onion_host(r["key"]) or r["key"]
            for kind, field in (("btc_wallet", "btc_wallets"), ("email", "emails"),
                                ("tox", "tox_ids"), ("onion_host", "onion_links")):
                for v in ents.get(field) or []:
                    t.add(kind, v, first=r["first_seen"], last=r["last_seen"], source="onionsites",
                          context=f"seen on {page}")

    rows = []
    for r in t.rows.values():
        rows.append({**r, "groups": sorted(x for x in r["groups"] if x),
                     "sources": sorted(r["sources"]), "flags": sorted(r["flags"])})
    # Most actionable first: indicators tied to a group, then live infrastructure and
    # ransomware-linked CVEs, then recency. Sorting by date alone buries 900 leak-site
    # hosts under the whole KEV catalogue, which all carries the same timestamp.
    def rank(r):
        return (0 if r["groups"] else 1,
                0 if ({"live", "ransomware"} & set(r["flags"])) else 1,
                -r["last_seen"], r["type"], r["value"].lower())
    rows.sort(key=rank)
    return rows


def filter_rows(rows, types=None, group=None, search=None, since=None, flag=None):
    out = rows
    if types:
        want = set(types)
        out = [r for r in out if r["type"] in want]
    if group:
        g = group.lower()
        out = [r for r in out if any(x.lower() == g for x in r["groups"])]
    if search:
        s = search.lower()
        out = [r for r in out if s in r["value"].lower() or s in (r["context"] or "").lower()]
    if since is not None:
        out = [r for r in out if r["last_seen"] >= since]
    if flag:
        out = [r for r in out if flag in r["flags"]]
    return out


def to_rows(rows, fanged=False):
    """Flatten for CSV/JSON: dates as ISO, lists joined, value defanged unless asked."""
    for r in rows:
        yield {
            "type": r["type"],
            "value": r["value"] if fanged else defang(r["value"], r["type"]),
            "first_seen": _iso(r["first_seen"]),
            "last_seen": _iso(r["last_seen"]),
            "groups": "; ".join(r["groups"]),
            "sources": "; ".join(r["sources"]),
            "flags": "; ".join(r["flags"]),
            "context": r["context"],
        }


def render(rows, fanged=False, limit=40) -> str:
    if not rows:
        return "No indicators yet. Run swarm.py first."
    flat = list(to_rows(rows[:limit], fanged))
    w = max((len(r["value"]) for r in flat), default=20)
    w = min(max(w, 14), 58)
    L = [f"{'type':<11}{'value':<{w + 2}}{'last seen':<12}{'groups':<22}flags",
         "-" * (11 + w + 2 + 12 + 22 + 10)]
    for r in flat:
        v = r["value"] if len(r["value"]) <= w else r["value"][: w - 1] + "…"
        L.append(f"{r['type']:<11}{v:<{w + 2}}{r['last_seen']:<12}{(r['groups'] or '—')[:21]:<22}{r['flags']}")
    if len(rows) > limit:
        L.append(f"… {len(rows) - limit} more (use --limit or --format csv/json)")
    L.append("")
    L.append(f"{len(rows)} indicator(s). Values defanged; --fanged for machine-readable."
             if not fanged else f"{len(rows)} indicator(s).")
    L.append("Attribution is what a leak site published, not analysis — treat it as a lead.")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Unified view of every observed indicator")
    ap.add_argument("--version", action="version", version=f"OnionClaw iocs {__version__}")
    ap.add_argument("--db", default=None)
    ap.add_argument("--type", action="append", choices=TYPES, dest="types", help="repeatable")
    ap.add_argument("--group", help="only indicators attributed to this group")
    ap.add_argument("--search", help="substring match on value or context")
    ap.add_argument("--since", help="only seen since YYYY-MM-DD")
    ap.add_argument("--flag", help="only rows with this flag (live, ransomware, victim)")
    ap.add_argument("--fanged", action="store_true", help="do not defang values")
    ap.add_argument("--format", choices=("table", "json", "csv"), default="table")
    ap.add_argument("--limit", type=int, default=40, help="rows in table output (default 40)")
    ap.add_argument("-o", "--output", help="write to this file instead of stdout")
    args = ap.parse_args()

    since = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            print(f"--since must be YYYY-MM-DD, got {args.since!r}", file=sys.stderr)
            return 2

    rows = filter_rows(collect(Store(args.db)), args.types, args.group, args.search, since, args.flag)

    if args.format == "json":
        text = json.dumps(list(to_rows(rows, args.fanged)), indent=2)
    elif args.format == "csv":
        import io
        buf = io.StringIO()
        flat = list(to_rows(rows, args.fanged))
        fields = ["type", "value", "first_seen", "last_seen", "groups", "sources", "flags", "context"]
        wtr = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
        wtr.writeheader()
        wtr.writerows(flat)
        text = buf.getvalue()
    else:
        text = render(rows, args.fanged, args.limit)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {len(rows)} indicator(s) to {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

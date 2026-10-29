#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — graph.py
Evidence-based correlation of ransomware groups from the monitoring store.

Groups are linked ONLY through hard, observable identifiers — never by guessing:

  alias-name      same name after normalisation ("The Green Blood Group" == "thegreenbloodgroup")
  shared-wallet   a ransom-note wallet published by both groups
  shared-host     both groups list the same leak-site host. Strong when exactly two groups
                  share it (rebrand / affiliate lineage); weak when three or more do, because
                  that pattern usually means a shared platform or marketplace, not one operator
  shared-victim   the same victim name claimed by both (re-post, resale or affiliate overlap)

Every edge carries its evidence and a confidence, and clusters are reported with the
evidence behind them so an analyst can judge, not just trust. Correlation is a lead,
not an attribution.

Also reports group activity with time-decayed weighting (half-life configurable), so a
group silent for a year ranks below one active this week.

Usage:
  python3 graph.py                      # clusters at confidence >= 0.6
  python3 graph.py --min-confidence 0.3
  python3 graph.py --json
  python3 graph.py --activity           # decayed group activity ranking
"""
from __future__ import annotations

import sys, os, re, json, time, argparse
from collections import defaultdict
from datetime import datetime, timezone
from itertools import combinations

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

from store import Store

__version__ = "2.4.0"

CONF = {"alias-name": 0.95, "shared-wallet": 0.85, "shared-host-2": 0.80,
        "shared-host-n": 0.50, "shared-victim": 0.30}


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _load(store: Store):
    with store._conn() as c:
        rows = {k: [(r["key"], json.loads(r["payload"]), r["first_seen"], r["last_seen"])
                    for r in c.execute("SELECT key,payload,first_seen,last_seen FROM observations "
                                       "WHERE kind=?", (k,))]
                for k in ("dls", "wallet", "victim")}
    return rows


def _canonical(data) -> tuple[dict, dict]:
    """norm -> set of raw spellings, and norm -> one canonical display name (most frequent
    spelling, ties broken alphabetically) so aliases collapse everywhere consistently."""
    counts = defaultdict(lambda: defaultdict(int))
    for kind in data:
        for _, p, _, _ in data[kind]:
            for grp in (p.get("groups") or ([p["group"]] if p.get("group") else [])):
                counts[norm(grp)][grp] += 1
    raw = {n: set(c) for n, c in counts.items()}
    canon = {n: sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] for n, c in counts.items()}
    return raw, canon


def build_edges(store: Store) -> list[dict]:
    data = _load(store)
    edges: dict[tuple, dict] = {}

    def add(a, b, kind, conf, evidence):
        if a == b:
            return
        key = tuple(sorted((a, b))) + (kind,)
        e = edges.setdefault(key, {"a": key[0], "b": key[1], "kind": kind,
                                   "confidence": conf, "evidence": []})
        e["confidence"] = max(e["confidence"], conf)
        if evidence not in e["evidence"]:
            e["evidence"].append(evidence)

    groups, by_norm = _canonical(data)

    # alias-name: different raw spellings of the same normalised name
    for n, names in groups.items():
        if len(names) > 1:
            names = sorted(names)
            for a, b in combinations(names, 2):
                add(a, b, "alias-name", CONF["alias-name"], f"normalise to '{n}'")

    def canon(g):  # edges are expressed on canonical names so aliases collapse
        return by_norm[norm(g)]

    hosts = defaultdict(set)
    for key, p, _, _ in data["dls"]:
        if p.get("group"):
            hosts[key.split("|", 1)[-1]].add(canon(p["group"]))
    for host, gs in hosts.items():
        if len(gs) < 2:
            continue
        conf = CONF["shared-host-2"] if len(gs) == 2 else CONF["shared-host-n"]
        for a, b in combinations(sorted(gs), 2):
            add(a, b, "shared-host", conf,
                f"{host} (listed by {len(gs)} groups)")

    wallets = defaultdict(set)
    for key, p, _, _ in data["wallet"]:
        for grp in p.get("groups") or ([p["group"]] if p.get("group") else []):
            wallets[key].add(canon(grp))
    for w, gs in wallets.items():
        for a, b in combinations(sorted(gs), 2):
            add(a, b, "shared-wallet", CONF["shared-wallet"], f"wallet {w}")

    victims = defaultdict(set)
    for _, p, _, _ in data["victim"]:
        if p.get("group") and p.get("victim"):
            victims[p["victim"].strip().lower()].add(canon(p["group"]))
    for v, gs in victims.items():
        for a, b in combinations(sorted(gs), 2):
            add(a, b, "shared-victim", CONF["shared-victim"], f"victim '{v}'")

    return sorted(edges.values(), key=lambda e: (-e["confidence"], e["a"], e["b"]))


def clusters(edges: list[dict], min_conf: float = 0.6) -> list[dict]:
    uf = _UF()
    use = [e for e in edges if e["confidence"] >= min_conf]
    for e in use:
        uf.union(e["a"], e["b"])
    members = defaultdict(set)
    for e in use:
        for g in (e["a"], e["b"]):
            members[uf.find(g)].add(g)
    out = []
    for root, ms in members.items():
        es = [e for e in use if uf.find(e["a"]) == root]
        kinds = sorted({e["kind"] for e in es})
        out.append({"groups": sorted(ms),
                    "confidence": max(e["confidence"] for e in es),
                    "weakest_link": min(e["confidence"] for e in es),
                    "evidence_types": kinds, "edges": es})
    return sorted(out, key=lambda c: (-c["confidence"], -len(c["groups"])))


def activity(store: Store, half_life_days: float = 90.0, now: float | None = None) -> list[dict]:
    """Group activity weighted by exponential time decay of each victim's attack date."""
    now = now or time.time()
    per = defaultdict(lambda: {"victims": 0, "weighted": 0.0, "last": 0.0})
    data = _load(store)
    _, by_norm = _canonical(data)
    for _, p, first_seen, _ in data["victim"]:
        g = by_norm.get(norm(p.get("group") or ""))
        if not g:
            continue
        try:
            d = datetime.fromisoformat((p.get("attackdate") or "").replace("Z", "+00:00"))
            t = (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
        except ValueError:
            t = first_seen
        age = max(0.0, (now - t) / 86400)
        s = per[g]
        s["victims"] += 1
        s["weighted"] += 0.5 ** (age / half_life_days)
        s["last"] = max(s["last"], t)
    rows = [{"group": g, "victims": s["victims"], "decayed_activity": round(s["weighted"], 3),
             "days_since_last": round((now - s["last"]) / 86400, 1)} for g, s in per.items()]
    return sorted(rows, key=lambda r: -r["decayed_activity"])


def render(cs: list[dict], min_conf: float) -> str:
    if not cs:
        return f"No group correlations at confidence >= {min_conf}."
    L = [f"{len(cs)} correlated cluster(s) at confidence >= {min_conf}  "
         "(leads for an analyst, not attribution)\n"]
    for i, c in enumerate(cs, 1):
        L.append(f"[{i}] {' ~ '.join(c['groups'])}   confidence {c['confidence']:.2f}"
                 f" (weakest link {c['weakest_link']:.2f})  via {', '.join(c['evidence_types'])}")
        for e in c["edges"]:
            L.append(f"      {e['a']} — {e['b']}  [{e['kind']} {e['confidence']:.2f}]  "
                     + "; ".join(e["evidence"][:3]))
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Evidence-based group correlation")
    ap.add_argument("--version", action="version", version=f"OnionClaw graph {__version__}")
    ap.add_argument("--db", default=None)
    ap.add_argument("--min-confidence", type=float, default=0.6)
    ap.add_argument("--activity", action="store_true", help="show decayed group activity ranking")
    ap.add_argument("--half-life", type=float, default=90.0, help="activity half-life in days")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    store = Store(args.db)
    if args.activity:
        rows = activity(store, args.half_life)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'group':<24}{'victims':>8}{'decayed':>10}{'days since last':>17}")
            for r in rows[:25]:
                print(f"{r['group']:<24}{r['victims']:>8}{r['decayed_activity']:>10}{r['days_since_last']:>17}")
        return 0

    cs = clusters(build_edges(store), args.min_confidence)
    print(json.dumps(cs, indent=2) if args.json else render(cs, args.min_confidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())

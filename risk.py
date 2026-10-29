#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — risk.py
Transparent priority scores for ransomware groups, from what the swarm has observed.

Adapted from PRISM-Intel's risk_scorer and confidence_decay. PRISM's ransomware path
started from a hand-picked list of "high-severity" groups and added a capped victim
bonus. Here every point of the score comes from observed data, and every factor is
reported with the numbers behind it:

  volume      0.25  observed victims, log-scaled (50 victims = 1.0)
  critical    0.25  share of victims in critical sectors (healthcare, government, …)
  reach       0.15  distinct countries and sectors hit
  capability  0.20  ATT&CK techniques + tools on record, active leak-site hosts
  links       0.15  other groups linked by hard evidence (graph.py)

The weighted sum is then multiplied by PRISM's decay curve on days since the group's
latest observed victim (≤30 d ×1.02 … >18 months ×0.65), so a group that went quiet
a year ago ranks below one active this week.

This is a triage order for defenders, not an attribution or a threat verdict: it only
knows what the configured sources published.

Usage:
  python3 risk.py                 # ranked table
  python3 risk.py --group qilin   # one group, every factor explained
  python3 risk.py --json
"""
from __future__ import annotations

import sys, os, re, json, math, time, argparse
from collections import defaultdict
from datetime import datetime, timezone

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

from store import Store
import graph

__version__ = "2.4.0"

WEIGHTS = {"volume": 0.25, "critical": 0.25, "reach": 0.15, "capability": 0.20, "links": 0.15}
CRITICAL = ("healthcare", "government", "defense", "education", "energy", "utilities",
            "water", "transportation", "financial")
TIERS = ((0.65, "HIGH"), (0.40, "MEDIUM"), (0.0, "LOW"))
_CRIT_RE = re.compile(r"(?<![a-z])(" + "|".join(CRITICAL) + r")(?![a-z])")


def decay(days: float | None) -> tuple[float, str]:
    """PRISM-Intel's confidence-decay curve (confidence_decay.compute_decay)."""
    if days is None:
        return 0.85, "no activity date"
    if days <= 30:
        return 1.02, "active in the last 30 days"
    if days <= 90:
        return 1.0, "active this quarter"
    if days <= 180:
        return 0.95, f"quiet {int(days)} days"
    if days <= 365:
        return 0.88, f"quiet {int(days)} days"
    if days <= 548:
        return 0.78, f"dormant {int(days)} days"
    return 0.65, f"presumed defunct ({int(days)} days)"


def _ts(s) -> float | None:
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    except (TypeError, ValueError):
        return None


def score_groups(store: Store, now: float | None = None) -> list[dict]:
    now = now or time.time()
    data = graph._load(store)
    _, canon = graph._canonical(data)
    name = lambda g: canon.get(graph.norm(g or ""), g)

    victims = defaultdict(list)
    for _, p, first_seen, _ in data["victim"]:
        if p.get("group"):
            victims[name(p["group"])].append((p, _ts(p.get("attackdate")) or first_seen))

    hosts = defaultdict(int)
    for _, p, _, _ in data["dls"]:
        if p.get("group") and p.get("available"):
            hosts[name(p["group"])] += 1

    profiles = {}
    with store._conn() as c:
        for r in c.execute("SELECT payload FROM observations WHERE kind='group_profile'"):
            p = json.loads(r["payload"])
            if p.get("group"):
                profiles[name(p["group"])] = p

    links = defaultdict(set)
    for e in graph.build_edges(store):
        if e["confidence"] >= 0.6:
            links[e["a"]].add(e["b"])
            links[e["b"]].add(e["a"])

    out = []
    for g in set(victims) | set(profiles):
        vs = victims.get(g, [])
        n = len(vs)
        crit = sum(1 for p, _ in vs if _CRIT_RE.search((p.get("activity") or "").lower()))
        countries = {p.get("country") for p, _ in vs if p.get("country")}
        sectors = {p.get("activity") for p, _ in vs if p.get("activity") and p.get("activity") != "Not Found"}
        prof = profiles.get(g, {})
        n_tech = len(prof.get("techniques", []))
        n_tools = sum(len(v) for v in prof.get("tools", {}).values())

        comp = {
            "volume": min(1.0, math.log1p(n) / math.log1p(50)),
            "critical": (crit / n) if n else 0.0,
            "reach": min(1.0, (len(countries) + len(sectors)) / 16),
            "capability": min(1.0, math.log1p(n_tech + n_tools + hosts.get(g, 0)) / math.log1p(40)),
            "links": min(1.0, len(links.get(g, ())) / 3),
        }
        base = sum(WEIGHTS[k] * v for k, v in comp.items())
        last = max((t for _, t in vs if t), default=None)
        days = (now - last) / 86400 if last else None
        mult, why = decay(days)
        score = round(min(1.0, base * mult), 4)
        tier = next(t for cut, t in TIERS if score >= cut)
        out.append({
            "group": g, "score": score, "tier": tier,
            "components": {k: round(v, 3) for k, v in comp.items()},
            "decay": {"multiplier": mult, "reason": why, "days_since_last": None if days is None else round(days, 1)},
            "evidence": {
                "victims": n, "critical_victims": crit, "countries": len(countries), "sectors": len(sectors),
                "techniques": n_tech, "tools": n_tools, "active_hosts": hosts.get(g, 0),
                "linked_groups": sorted(links.get(g, ())),
            },
        })
    return sorted(out, key=lambda r: (-r["score"], r["group"].lower()))


def explain(r: dict) -> str:
    e, c, d = r["evidence"], r["components"], r["decay"]
    L = [f"{r['group']}  score {r['score']:.2f}  [{r['tier']}]", ""]
    L.append(f"  volume      {c['volume']:.2f} × {WEIGHTS['volume']}   {e['victims']} observed victims")
    L.append(f"  critical    {c['critical']:.2f} × {WEIGHTS['critical']}   {e['critical_victims']} in critical sectors")
    L.append(f"  reach       {c['reach']:.2f} × {WEIGHTS['reach']}   {e['countries']} countries, {e['sectors']} sectors")
    L.append(f"  capability  {c['capability']:.2f} × {WEIGHTS['capability']}   {e['techniques']} ATT&CK techniques, "
             f"{e['tools']} tools, {e['active_hosts']} active leak-site hosts")
    L.append(f"  links       {c['links']:.2f} × {WEIGHTS['links']}   "
             + (", ".join(e["linked_groups"]) if e["linked_groups"] else "no evidence-linked groups"))
    L.append(f"  decay       × {d['multiplier']}   {d['reason']}")
    L.append("\n  A triage order from observed data, not an attribution or threat verdict.")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Transparent priority scores for ransomware groups")
    ap.add_argument("--version", action="version", version=f"OnionClaw risk {__version__}")
    ap.add_argument("--db", default=None)
    ap.add_argument("--group", help="explain one group's score")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = score_groups(Store(args.db))
    if args.group:
        rows = [r for r in rows if r["group"].lower() == args.group.lower()]
        if not rows:
            print(f"No observations for {args.group!r}. Run swarm.py first.")
            return 1
        print(json.dumps(rows[0], indent=2) if args.json else explain(rows[0]))
        return 0
    if args.json:
        print(json.dumps(rows[: args.top], indent=2))
        return 0
    if not rows:
        print("No observations yet. Run swarm.py first.")
        return 0
    print(f"{'group':<22}{'score':>6}  {'tier':<7}{'victims':>8}{'crit':>6}{'TTPs':>6}  activity")
    for r in rows[: args.top]:
        e = r["evidence"]
        print(f"{r['group'][:21]:<22}{r['score']:>6.2f}  {r['tier']:<7}{e['victims']:>8}{e['critical_victims']:>6}"
              f"{e['techniques']:>6}  {r['decay']['reason']}")
    print("\nTriage order from observed data, not an attribution. Explain one: risk.py --group NAME")
    return 0


if __name__ == "__main__":
    sys.exit(main())

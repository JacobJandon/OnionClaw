#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — stix.py
Export the monitoring store as a STIX 2.1 bundle (MISP / OpenCTI / TAXII-ready).

Objects produced
  identity        producer ("OnionClaw", class system) + one per victim organisation
  threat-actor    one per ransomware group
  relationship    threat-actor --targets--> victim identity   (start_time = attack date)
                  indicator    --indicates--> threat-actor
  indicator       leak-site .onion URLs   [url:value = '...']
                  ransom-note wallets     [x-cryptocurrency-wallet:address = '...']
  vulnerability   CISA KEV CVEs with known ransomware-campaign use

IDs are deterministic UUIDv5 (stable across exports, so re-importing updates rather
than duplicates). They use a private namespace, never the reserved SCO namespace.

NOTE on wallets: STIX 2.1 core has no cryptocurrency-wallet observable. Wallets are
expressed with a custom `x-cryptocurrency-wallet` object path, which STIX patterns
permit; consumers that don't know it will simply never match it.

Usage:
  python3 stix.py                       # bundle to stdout
  python3 stix.py -o bundle.json
  python3 stix.py --group qilin --since 2026-10-01
"""
from __future__ import annotations

import sys, os, re, json, uuid, argparse
from datetime import datetime, timezone

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

from store import Store
from ttp import attack_url

__version__ = "2.4.0"

# Private namespace for all OnionClaw-generated ids (derived, documented, stable).
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/JacobJandon/OnionClaw")
_PRODUCER_CREATED = "2026-01-01T00:00:00.000Z"

# ransomware.live "activity" → STIX industry-sector-ov. Unmapped values are omitted
# rather than guessed.
_SECTORS = [
    (("healthcare",), "healthcare"),
    (("financial",), "financial-services"),
    (("insurance",), "insurance"),
    (("government", "defense"), "government"),
    (("education",), "education"),
    (("energy", "utilit"), "energy"),
    (("manufactur",), "manufacturing"),
    (("retail", "e-commerce"), "retail"),
    (("hospitality",), "hospitality-leisure"),
    (("technology",), "technology"),
    (("telecom",), "telecommunications"),
    (("transport",), "transportation"),
    (("agricultur", "food"), "agriculture"),
    (("construction",), "construction"),
    (("non-profit", "nonprofit"), "non-profit"),
]


def sid(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(NAMESPACE, f'{type_}:{key}')}"


def ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{int((epoch % 1) * 1000):03d}Z"


def _iso(s) -> str | None:
    """Normalise an ISO-ish timestamp from a feed to STIX form, or None."""
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return ts(d.timestamp())
    except ValueError:
        return None


def _sector(activity: str | None) -> list:
    a = (activity or "").lower()
    out = []
    for needles, sector in _SECTORS:
        if any(n in a for n in needles) and sector not in out:
            out.append(sector)
    return out


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


class _Bundle:
    def __init__(self):
        self.objs: dict[str, dict] = {}

    def add(self, obj: dict):
        self.objs.setdefault(obj["id"], obj)
        return obj["id"]


def _rows(store: Store, kind: str):
    with store._conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT key, payload, first_seen, last_seen FROM observations WHERE kind=?", (kind,))]


def build_bundle(store: Store, group: str | None = None, since: float = 0.0,
                 include_kev: bool = True) -> dict:
    b = _Bundle()
    producer = b.add({
        "type": "identity", "spec_version": "2.1", "id": sid("identity", "onionclaw-producer"),
        "created": _PRODUCER_CREATED, "modified": _PRODUCER_CREATED,
        "name": "OnionClaw", "identity_class": "system",
        "description": "OnionClaw read-only dark-web monitoring (https://github.com/JacobJandon/OnionClaw)"})

    actors: dict[str, str] = {}

    def actor(name: str, first: float, last: float) -> str:
        key = name.lower()
        if key not in actors:
            actors[key] = b.add({
                "type": "threat-actor", "spec_version": "2.1", "id": sid("threat-actor", key),
                "created": ts(first), "modified": ts(last), "created_by_ref": producer,
                "name": name, "threat_actor_types": ["crime-syndicate"],
                "description": "Ransomware / extortion group observed on a public leak site."})
        return actors[key]

    # victims → identity + targets relationship
    for r in _rows(store, "victim"):
        p = json.loads(r["payload"])
        if r["last_seen"] < since or not p.get("group") or not p.get("victim"):
            continue
        if group and p["group"].lower() != group.lower():
            continue
        a = actor(p["group"], r["first_seen"], r["last_seen"])
        vid = sid("identity", f"victim:{p['group'].lower()}:{p['victim'].lower()}")
        ident = {"type": "identity", "spec_version": "2.1", "id": vid,
                 "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
                 "created_by_ref": producer, "name": p["victim"], "identity_class": "organization",
                 "x_onionclaw_country": p.get("country"), "x_onionclaw_activity": p.get("activity")}
        sectors = _sector(p.get("activity"))
        if sectors:
            ident["sectors"] = sectors
        ident = {k: v for k, v in ident.items() if v not in (None, "")}
        b.add(ident)
        rel = {"type": "relationship", "spec_version": "2.1",
               "id": sid("relationship", f"{a}:targets:{vid}"),
               "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
               "created_by_ref": producer, "relationship_type": "targets",
               "source_ref": a, "target_ref": vid}
        start = _iso(p.get("attackdate"))
        if start:
            rel["start_time"] = start
        b.add(rel)

    # leak-site infrastructure → URL indicators
    for r in _rows(store, "dls"):
        p = json.loads(r["payload"])
        g = p.get("group")
        if not g or r["last_seen"] < since or (group and g.lower() != group.lower()):
            continue
        host = r["key"].split("|", 1)[-1]
        a = actor(g, r["first_seen"], r["last_seen"])
        ind = {"type": "indicator", "spec_version": "2.1",
               "id": sid("indicator", f"url:{g.lower()}:{host}"),
               "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
               "created_by_ref": producer, "name": f"{g} leak site {host}",
               "indicator_types": ["malicious-activity"], "pattern_type": "stix",
               "pattern": f"[url:value = '{_esc('http://' + host)}']" if host.endswith(".onion")
                          else f"[domain-name:value = '{_esc(host)}']",
               "valid_from": ts(r["first_seen"]),
               "description": f"{p.get('type') or 'site'} for {g}; "
                              f"available={p.get('available')} enabled={p.get('enabled')}"}
        iid = b.add(ind)
        b.add({"type": "relationship", "spec_version": "2.1",
               "id": sid("relationship", f"{iid}:indicates:{a}"),
               "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
               "created_by_ref": producer, "relationship_type": "indicates",
               "source_ref": iid, "target_ref": a})

    # ransom-note wallets (one indicator; a relationship to every group that used it)
    for r in _rows(store, "wallet"):
        p = json.loads(r["payload"])
        gs = p.get("groups") or ([p["group"]] if p.get("group") else [])
        if group:
            gs = [g for g in gs if g.lower() == group.lower()]
            if not gs:
                continue
        if r["last_seen"] < since:
            continue
        who = ", ".join(gs) if gs else "ransomware"
        ind = {"type": "indicator", "spec_version": "2.1",
               "id": sid("indicator", f"wallet:{r['key']}"),
               "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
               "created_by_ref": producer, "name": f"Ransom wallet {r['key']}",
               "indicator_types": ["malicious-activity"], "pattern_type": "stix",
               "pattern": f"[x-cryptocurrency-wallet:address = '{_esc(r['key'])}']",
               "valid_from": ts(r["first_seen"]),
               "x_onionclaw_chain": p.get("chain", "btc"),
               "description": f"Wallet published in a {who} ransom note."}
        iid = b.add(ind)
        for g in gs:
            a = actor(g, r["first_seen"], r["last_seen"])
            b.add({"type": "relationship", "spec_version": "2.1",
                   "id": sid("relationship", f"{iid}:indicates:{a}"),
                   "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
                   "created_by_ref": producer, "relationship_type": "indicates",
                   "source_ref": iid, "target_ref": a})

    # ATT&CK techniques and tools each group uses (ransomware.live group profiles)
    for r in _rows(store, "group_profile"):
        p = json.loads(r["payload"])
        g = p.get("group")
        if not g or r["last_seen"] < since or (group and g.lower() != group.lower()):
            continue
        a = actor(g, r["first_seen"], r["last_seen"])
        for t in p.get("techniques", []):
            ap = {"type": "attack-pattern", "spec_version": "2.1", "id": sid("attack-pattern", t["id"]),
                  "created": _PRODUCER_CREATED, "modified": _PRODUCER_CREATED, "created_by_ref": producer,
                  "name": t.get("name") or t["id"],
                  "external_references": [{"source_name": "mitre-attack", "external_id": t["id"],
                                           "url": attack_url(t["id"])}]}
            phases = [{"kill_chain_name": "mitre-attack",
                       "phase_name": re.sub(r"[^a-z0-9]+", "-", x["name"].lower()).strip("-")}
                      for x in t.get("tactics", []) if x.get("name")]
            if phases:
                ap["kill_chain_phases"] = phases
            apid = b.add(ap)
            b.add({"type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{a}:uses:{apid}"),
                   "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]), "created_by_ref": producer,
                   "relationship_type": "uses", "source_ref": a, "target_ref": apid,
                   **({"description": t["detail"]} if t.get("detail") else {})})
        for category, names in p.get("tools", {}).items():
            for n in names:
                tid = b.add({"type": "tool", "spec_version": "2.1", "id": sid("tool", n.lower()),
                             "created": _PRODUCER_CREATED, "modified": _PRODUCER_CREATED,
                             "created_by_ref": producer, "name": n,
                             "x_onionclaw_category": category})
                b.add({"type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{a}:uses:{tid}"),
                       "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]), "created_by_ref": producer,
                       "relationship_type": "uses", "source_ref": a, "target_ref": tid})

    # KEV CVEs with known ransomware use
    if include_kev and not group:
        for r in _rows(store, "kev"):
            p = json.loads(r["payload"])
            if not p.get("ransomware_known") or r["last_seen"] < since:
                continue
            b.add({"type": "vulnerability", "spec_version": "2.1",
                   "id": sid("vulnerability", r["key"]),
                   "created": ts(r["first_seen"]), "modified": ts(r["last_seen"]),
                   "created_by_ref": producer, "name": r["key"],
                   "description": f"{p.get('vendor')} {p.get('product')}: {p.get('name')} "
                                  f"(CISA KEV; known ransomware campaign use)",
                   "external_references": [
                       {"source_name": "cve", "external_id": r["key"]},
                       {"source_name": "CISA KEV",
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]})

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(b.objs.values())}


def main() -> int:
    ap = argparse.ArgumentParser(description="Export the OnionClaw store as STIX 2.1")
    ap.add_argument("--version", action="version", version=f"OnionClaw stix {__version__}")
    ap.add_argument("--db", default=None)
    ap.add_argument("-o", "--output", default=None, help="write bundle to this file")
    ap.add_argument("--group", default=None, help="only this ransomware group")
    ap.add_argument("--since", default=None, help="only objects seen since YYYY-MM-DD")
    ap.add_argument("--no-kev", action="store_true", help="omit CISA KEV vulnerabilities")
    args = ap.parse_args()

    since = 0.0
    if args.since:
        since = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()

    bundle = build_bundle(Store(args.db), args.group, since, include_kev=not args.no_kev)
    out = json.dumps(bundle, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"wrote {len(bundle['objects'])} objects to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — ttp.py
MITRE ATT&CK techniques and tools per ransomware group.

Adapted from PRISM-Intel's ttp_tracker, with two changes:

  * The primary source is ransomware.live's structured ATT&CK data (tactic, technique
    ID and name, with cited details), recorded by the `groupinfra` collector as each
    group's profile. That is authoritative, so it is marked confidence "high".
  * PRISM's keyword fallback matched substrings, so "tor" fired on "sector" and
    "monitor". Keywords here match whole words only, a few unsound mappings were
    dropped (e.g. "password" is not evidence of brute force), and every keyword hit
    keeps the sentence it came from. These are confidence "low" leads.

Usage:
  python3 ttp.py                      # most-used techniques across observed groups
  python3 ttp.py --group medusa       # one group's techniques and tools
  python3 ttp.py --technique T1078    # which groups use a technique
  python3 ttp.py --json
"""
from __future__ import annotations

import sys, os, re, json, argparse
from collections import defaultdict

_skill_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _skill_dir)

from store import Store

__version__ = "2.4.0"

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TACTIC_RE = re.compile(r"^TA\d{4}$")

# Keyword → technique, matched as whole words. Only mappings where the phrase in a
# ransom note is direct evidence of the technique.
KEYWORDS = {
    "encrypted": ("T1486", "Data Encrypted for Impact"),
    "encryption": ("T1486", "Data Encrypted for Impact"),
    "exfiltrated": ("T1041", "Exfiltration Over C2 Channel"),
    "exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "data leak": ("T1657", "Financial Theft"),
    "double extortion": ("T1657", "Financial Theft"),
    "phishing": ("T1566", "Phishing"),
    "spearphishing": ("T1566.001", "Spearphishing Attachment"),
    "remote desktop": ("T1021.001", "Remote Desktop Protocol"),
    "rdp": ("T1021.001", "Remote Desktop Protocol"),
    "cobalt strike": ("T1059", "Command and Scripting Interpreter"),
    "powershell": ("T1059.001", "PowerShell"),
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "lsass": ("T1003.001", "LSASS Memory"),
    "web shell": ("T1505.003", "Web Shell"),
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "supply chain": ("T1195", "Supply Chain Compromise"),
    "shadow copies": ("T1490", "Inhibit System Recovery"),
    "vssadmin": ("T1490", "Inhibit System Recovery"),
}
_KW_RE = [(re.compile(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])"), k, v) for k, v in KEYWORDS.items()]


def attack_url(technique_id: str) -> str:
    """MITRE ATT&CK page for a technique; sub-techniques use a path segment."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def normalize_profile(group: dict) -> dict | None:
    """Turn one ransomware.live group record into a compact, stable profile.
    Returns None when the group publishes neither TTPs nor tools."""
    techniques = {}
    for tactic in group.get("ttps") or []:
        if not isinstance(tactic, dict):
            continue
        tac_id = (tactic.get("tactic_id") or "").strip()
        tac_name = (tactic.get("tactic_name") or "").strip()
        for t in tactic.get("techniques") or []:
            tid = (t.get("technique_id") or "").strip()
            if not TECHNIQUE_RE.fullmatch(tid):
                continue
            entry = techniques.setdefault(tid, {"id": tid, "name": (t.get("technique_name") or "").strip(),
                                                "tactics": [], "detail": ""})
            if tac_id and TACTIC_RE.match(tac_id) and tac_name not in [x["name"] for x in entry["tactics"]]:
                entry["tactics"].append({"id": tac_id, "name": tac_name})
            if not entry["detail"]:
                entry["detail"] = re.sub(r"\(Citation:[^)]*\)", "", t.get("technique_details") or "").strip()[:300]
    tools = {}
    for block in group.get("tools") or []:
        if isinstance(block, dict):
            for category, names in block.items():
                for n in names or []:
                    if isinstance(n, str) and n.strip():
                        tools.setdefault(category, set()).add(n.strip())
    if not techniques and not tools:
        return None
    return {
        "group": group.get("name"),
        "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
        "tools": {k: sorted(v) for k, v in sorted(tools.items())},
    }


def keyword_ttps(text: str) -> list[dict]:
    """Low-confidence techniques from free text (ransom notes). Whole-word matches only;
    each hit carries the sentence it came from."""
    if not text:
        return []
    found = {}
    sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
    for sentence in sentences:
        low = sentence.lower()
        for rx, kw, (tid, name) in _KW_RE:
            if tid not in found and rx.search(low):
                found[tid] = {"id": tid, "name": name, "keyword": kw, "evidence": sentence.strip()[:220]}
        for m in TECHNIQUE_RE.finditer(sentence):
            found.setdefault(m.group(0), {"id": m.group(0), "name": "", "keyword": "explicit id",
                                          "evidence": sentence.strip()[:220]})
    return sorted(found.values(), key=lambda t: t["id"])


def _profiles(store: Store) -> dict:
    with store._conn() as c:
        return {r["key"]: json.loads(r["payload"]) for r in
                c.execute("SELECT key, payload FROM observations WHERE kind='group_profile'")}


def _victim_text(store: Store) -> dict:
    out = defaultdict(list)
    with store._conn() as c:
        for r in c.execute("SELECT payload FROM observations WHERE kind='victim'"):
            p = json.loads(r["payload"])
            if p.get("group") and p.get("description"):
                out[p["group"].lower()].append(p["description"])
    return out


def group_ttps(store: Store, group: str) -> dict:
    """All known techniques for a group, high confidence first, with provenance."""
    g = group.lower()
    prof = next((p for k, p in _profiles(store).items() if k.lower() == g), None)
    techniques = {}
    if prof:
        for t in prof["techniques"]:
            techniques[t["id"]] = {**t, "confidence": "high", "source": "ransomware.live (MITRE ATT&CK)"}
    for text in _victim_text(store).get(g, []):
        for t in keyword_ttps(text):
            techniques.setdefault(t["id"], {**t, "confidence": "low", "source": "ransom note keyword"})
    order = {"high": 0, "low": 1}
    return {"group": prof["group"] if prof else group,
            "techniques": sorted(techniques.values(), key=lambda t: (order[t["confidence"]], t["id"])),
            "tools": prof["tools"] if prof else {}}


def technique_usage(store: Store) -> list[dict]:
    """Techniques ranked by how many observed groups use them (high-confidence data only)."""
    use = defaultdict(lambda: {"name": "", "groups": set(), "tactics": set()})
    for prof in _profiles(store).values():
        for t in prof["techniques"]:
            u = use[t["id"]]
            u["name"] = u["name"] or t["name"]
            u["groups"].add(prof["group"])
            u["tactics"].update(x["name"] for x in t["tactics"])
    rows = [{"id": k, "name": v["name"], "groups": sorted(v["groups"]), "tactics": sorted(v["tactics"])}
            for k, v in use.items()]
    return sorted(rows, key=lambda r: (-len(r["groups"]), r["id"]))


def main() -> int:
    ap = argparse.ArgumentParser(description="MITRE ATT&CK techniques and tools per ransomware group")
    ap.add_argument("--version", action="version", version=f"OnionClaw ttp {__version__}")
    ap.add_argument("--db", default=None)
    ap.add_argument("--group", help="show one group's techniques and tools")
    ap.add_argument("--technique", help="show which groups use this technique (e.g. T1078)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    store = Store(args.db)

    if args.group:
        r = group_ttps(store, args.group)
        if args.json:
            print(json.dumps(r, indent=2))
            return 0
        if not r["techniques"] and not r["tools"]:
            print(f"No ATT&CK data for {args.group!r} yet. Run swarm.py so groupinfra records group profiles.")
            return 1
        print(f"{r['group']}: {len(r['techniques'])} technique(s)\n")
        for t in r["techniques"]:
            tac = ", ".join(x["name"] for x in t.get("tactics", [])) or "—"
            print(f"  {t['id']:<10} {t['name'][:44]:<44} [{t['confidence']}] {tac}")
            if t["confidence"] == "low":
                print(f"             evidence: \"{t['evidence'][:110]}\"")
        if r["tools"]:
            print("\n  tools:")
            for cat, names in r["tools"].items():
                print(f"    {cat}: {', '.join(names)}")
        return 0

    rows = technique_usage(store)
    if args.technique:
        rows = [r for r in rows if r["id"].upper() == args.technique.upper()]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No ATT&CK data yet. Run swarm.py so groupinfra records group profiles.")
        return 0
    print(f"{'technique':<11}{'groups':>7}  name / groups")
    for r in rows[:30]:
        print(f"{r['id']:<11}{len(r['groups']):>7}  {r['name'][:46]}")
        if args.technique:
            print("             " + ", ".join(r["groups"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

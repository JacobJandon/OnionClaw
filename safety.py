# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — safety.py
Abuse-material filter shared by crawl.py and the swarm collectors.

A threat-intel tool indexes threat infrastructure, never abuse material. The
previous filter substring-matched "child" and so refused every ransomware
victim page for a children's hospital — exactly the intelligence defenders
need — while giving no signal that it had done so.

Design:
  * HARD terms  — unambiguous abuse vocabulary. Whole-word match, always block.
  * SOFT terms  — ambiguous words (child, minor, underage, ...). Block only when
                  an EXPLICIT term appears in the same text. "Children's Hospital"
                  passes; "child" next to explicit content does not.
  * Every refusal is returned with its reason so callers can log it; nothing is
    dropped silently.
"""
from __future__ import annotations

import re
from typing import NamedTuple

HARD_TERMS = (
    "csam", "pthc", "jailbait", "hurtcore", "lolicon", "kidp", "ptsc",
    "child porn", "child porno", "child pornography", "cp video", "cp videos",
    "rape video", "rape videos", "snuff film", "snuff films",
)

# "minor"/"minors" are deliberately absent: they are ordinary English ("minor injuries",
# "a minor incident") and the genuinely dangerous phrasings are already covered below.
SOFT_TERMS = (
    "child", "children", "kid", "kids", "underage",
    "preteen", "pre-teen", "teen", "loli", "lolita", "pedo", "toddler",
)

# Only terms that are strongly indicative of abuse material next to a SOFT term.
# Generic words were removed after they re-created the very false positive this module
# exists to prevent: "sex" is a routine breach-data field, so a children's hospital
# breach listing it was refused; "explicit" is ordinary English; and bare "cp" matches
# OnionClaw's own install command (`cp -r OnionClaw ...`). The specific phrases below
# cover the same abuse vocabulary without the collateral damage.
EXPLICIT_TERMS = (
    "porn", "porno", "pornography", "sexual", "sexually explicit",
    "sex video", "sex videos", "sex tape", "sex tapes",
    "nude", "nudes", "naked", "xxx", "nsfw", "erotic",
    "rape", "molest", "abuse video", "abuse videos", "hardcore",
)

# How much of the page body participates in the check.
_BODY_CHARS = 2000

# Characters allowed between a SOFT and an EXPLICIT term for them to count as one phrase.
# Roughly a clause: "underage nudes" pairs, "children's hospital ... sexual harassment
# lawsuit" two sentences apart does not.
_PAIR_WINDOW = 24


def _compile(terms):
    parts = sorted((re.escape(t) for t in terms), key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(parts) + r")(?![a-z0-9])")


_HARD_RE = _compile(HARD_TERMS)
_SOFT_RE = _compile(SOFT_TERMS)
_EXPLICIT_RE = _compile(EXPLICIT_TERMS)


class Verdict(NamedTuple):
    safe: bool
    reason: str

    def __bool__(self) -> bool:  # `if is_safe(...)` reads naturally
        return self.safe


def is_safe(url: str = "", title: str = "", text: str = "") -> Verdict:
    blob = f"{url or ''} {title or ''} {(text or '')[:_BODY_CHARS]}".lower()

    m = _HARD_RE.search(blob)
    if m:
        return Verdict(False, f"hard-term:{m.group(0)}")

    # A soft term only counts alongside an explicit one when the two are close enough to
    # plausibly describe the same thing. Scanning the whole blob meant a children's
    # hospital in the title could pair with an unrelated word 1,500 characters later.
    softs = [m for m in _SOFT_RE.finditer(blob)]
    if softs:
        for e in _EXPLICIT_RE.finditer(blob):
            for s in softs:
                gap = max(s.start(), e.start()) - min(s.end(), e.end())
                if gap <= _PAIR_WINDOW:
                    return Verdict(False, f"soft+explicit:{s.group(0)}+{e.group(0)}")

    return Verdict(True, "ok")

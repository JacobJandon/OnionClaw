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

SOFT_TERMS = (
    "child", "children", "kid", "kids", "minor", "minors", "underage",
    "preteen", "pre-teen", "teen", "loli", "lolita", "pedo", "toddler",
)

EXPLICIT_TERMS = (
    "porn", "porno", "pornography", "sex", "sexual", "nude", "nudes", "naked",
    "xxx", "nsfw", "erotic", "rape", "molest", "abuse video", "abuse videos",
    "explicit", "hardcore", "cp",
)

# How much of the page body participates in the check.
_BODY_CHARS = 2000


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

    soft = _SOFT_RE.search(blob)
    if soft:
        explicit = _EXPLICIT_RE.search(blob)
        if explicit:
            return Verdict(False, f"soft+explicit:{soft.group(0)}+{explicit.group(0)}")

    return Verdict(True, "ok")

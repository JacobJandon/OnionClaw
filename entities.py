# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
OnionClaw — entities.py
Entity extraction with validation.

Regex alone over-reports: any 26-35 char base58 string "looks like" a Bitcoin
address. Bitcoin addresses carry a checksum, so we verify it and discard the
rest. Extraction runs over the FULL text — only downstream LLM context needs
truncating, never extraction (wallets and PGP blocks usually sit below the fold).
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, Optional
from urllib.parse import urlsplit

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}

_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_IDX = {c: i for i, c in enumerate(_BECH32)}

# A "." may precede the address: www.<56>.onion is the same hidden service as <56>.onion,
# and excluding it meant subdomain onions never matched at all.
ONION_RE = re.compile(r"(?<![a-z0-9-])([a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.I)

# Fetch limits for entity extraction. sicry.fetch keeps 8,000 characters and 80 links by
# default, sized for an LLM prompt; wallets and PGP blocks often sit below that.
FULL_TEXT_CHARS = 2_000_000
FULL_TEXT_LINKS = 1000

_BTC_LEGACY_RE = re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])")
_BTC_BECH_RE = re.compile(r"(?<![A-Za-z0-9])bc1[02-9ac-hj-np-z]{11,87}(?![A-Za-z0-9])", re.I)
_ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
_XMR_RE = re.compile(r"(?<![A-Za-z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])")
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}")
_PGP_RE = re.compile(r"-----BEGIN PGP (?:PUBLIC KEY BLOCK|MESSAGE|SIGNATURE)-----")
_TOX_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{76}(?![A-Fa-f0-9])")


def _b58check_valid(addr: str) -> bool:
    n = 0
    for ch in addr:
        v = _B58_IDX.get(ch)
        if v is None:
            return False
        n = n * 58 + v
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 25:
        return False
    body, check = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == check


def _bech32_polymod(values: Iterable[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_valid(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False  # mixed case is invalid
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data_part = addr[:pos], addr[pos + 1:]
    if hrp != "bc":
        return False
    try:
        data = [_BECH32_IDX[c] for c in data_part]
    except KeyError:
        return False
    expand = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    const = _bech32_polymod(expand + data)
    witness_version = data[0]
    # v0 uses bech32 (1); v1+ (taproot etc.) use bech32m (0x2bc830a3)
    return const == (1 if witness_version == 0 else 0x2BC830A3)


def valid_btc(addr: str) -> bool:
    if addr[:3].lower() == "bc1":
        return _bech32_valid(addr)
    return _b58check_valid(addr)


def onion_host(url: str) -> str:
    """The first onion address mentioned anywhere in `url` (or any text), or ''."""
    m = ONION_RE.search(url or "")
    return (m.group(0).lower() if m else "")


IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


def site_host(value: str) -> str:
    """The host a leak-site location points to, without scheme, port or path:
    'x.onion/items' -> 'x.onion', '95.143.191.148:3000' -> '95.143.191.148'.

    ransomware.live records locations that way, and treating the raw value as a hostname
    dropped those sites from the IoC list and broke shared-host matching.
    """
    v = (value or "").strip()
    onion = service_host(v)
    if onion:
        return onion
    try:
        h = urlsplit(v if "://" in v else "//" + v).hostname
    except ValueError:
        return ""
    return (h or "").rstrip(".").lower()


def service_host(url: str) -> str:
    """The hidden service a URL actually points to: the onion in its hostname, or ''.

    onion_host() finds an onion address mentioned anywhere, which is right for
    harvesting. Deciding where a request goes needs the hostname: x.onion.ly (a Tor2web
    gateway), web.archive.org/.../x.onion, x.onion@collector.example and
    stats.example/?site=x.onion are all clearnet hosts.
    """
    try:
        h = (urlsplit(url if "://" in (url or "") else "http://" + (url or "")).hostname or "").lower()
    except ValueError:
        return ""
    if not h.endswith(".onion"):
        return ""
    m = ONION_RE.search(h)
    return m.group(0).lower() if m and h.endswith(m.group(0).lower()) else ""


def extract_entities(text: str, links: Optional[Iterable] = None,
                     base_host: str = "") -> dict:
    """Extract validated entities from page text (full text, no truncation).

    `links` may be strings or sicry-style {"text","href"} dicts.
    """
    text = text or ""

    btc = set()
    for rx in (_BTC_LEGACY_RE, _BTC_BECH_RE):
        for m in rx.finditer(text):
            a = m.group(0)
            if valid_btc(a):
                btc.add(a if a[:3].lower() != "bc1" else a.lower())

    onions = {m.group(0).lower() for m in ONION_RE.finditer(text)}
    for ln in links or []:
        href = ln.get("href", "") if isinstance(ln, dict) else str(ln)
        h = onion_host(href)
        if h:
            onions.add(h)
    onions.discard(base_host)

    return {
        "btc_wallets": sorted(btc),
        # lower-cased: the EIP-55 checksummed and lower-case spellings are one wallet
        "eth_wallets": sorted({a.lower() for a in _ETH_RE.findall(text)}),
        "xmr_wallets": sorted(set(_XMR_RE.findall(text))),
        "emails": sorted({e.lower() for e in _EMAIL_RE.findall(text)}),
        "onion_links": sorted(onions),
        "tox_ids": sorted({t.upper() for t in _TOX_RE.findall(text)}),
        "pgp": bool(_PGP_RE.search(text)),
    }

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
sync_sicry.py — update the bundled sicry.py from the upstream SICRY™ repo.

Usage:
    python3 sync_sicry.py           # fetch latest from main
    python3 sync_sicry.py --tag v1.1.1   # fetch a specific SICRY™ release tag

IMPORTANT — tag versioning:
    --tag must be a SICRY™ repository tag, NOT an OnionClaw tag.
    SICRY™ and OnionClaw have independent release cadences.

    SICRY™ available tags: v1.0.0, v1.0.1, v1.1.0, v1.1.1
    OnionClaw tags:        v1.0.0, v1.0.1, v1.1.0, v1.1.1, v1.2.0, v1.2.1

    Example: --tag v1.2.1 will 404 (no SICRY™ v1.2.1 exists).
             --tag v1.1.1 works (SICRY™ v1.1.1 exists).

Run from the OnionClaw root directory.
"""

import sys
import os
import argparse

try:
    import requests
except Exception as _e:
    print(f"Error: requests not installed — pip3 install requests ({_e})", file=sys.stderr)
    sys.exit(1)

UPSTREAM_RAW = "https://raw.githubusercontent.com/JacobJandon/Sicry/{ref}/sicry.py"
DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sicry.py")


def main():
    parser = argparse.ArgumentParser(description="Sync bundled sicry.py from upstream SICRY™")
    parser.add_argument("--version", action="version", version="OnionClaw sync_sicry 1.2.3")
    parser.add_argument("--tag",     default="main", help="git ref / tag to fetch (default: main)")
    parser.add_argument("--dry-run", action="store_true", help="print what would happen without writing")
    args = parser.parse_args()

    url = UPSTREAM_RAW.format(ref=args.tag)

    try:
        r = requests.get(url, timeout=15)
    except Exception as e:
        print(f"Error: network request failed — {e}", file=sys.stderr)
        sys.exit(1)

    if r.status_code == 404:
        print(f"Error: ref '{args.tag}' not found in the SICRY\u2122 repo (HTTP 404).",
              file=sys.stderr)
        print(f"  --tag must be a SICRY\u2122 tag, not an OnionClaw tag.",
              file=sys.stderr)
        print(f"  SICRY\u2122 available tags: v1.0.0, v1.0.1, v1.1.0, v1.1.1",
              file=sys.stderr)
        print(f"  OnionClaw tags are independent — e.g. v1.2.1 does not exist in SICRY\u2122.",
              file=sys.stderr)
        print(f"  Use --tag main to sync from the SICRY\u2122 main branch.",
              file=sys.stderr)
        sys.exit(1)
    elif not r.ok:
        print(f"Error: HTTP {r.status_code} fetching {url}", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching {url} ...")
    new_content = r.text

    # Extract upstream version
    version = "unknown"
    for line in new_content.splitlines():
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"')
            break

    print(f"Upstream version: {version}")

    if args.dry_run:
        print(f"[dry-run] Would write {len(new_content)} bytes to {DEST}")
        return

    with open(DEST, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"Updated {DEST} to SICRY™ {version}")
    print("Remember to commit: git add sicry.py && git commit -m 'chore: sync sicry.py to SICRY {}'".format(version))


if __name__ == "__main__":
    main()

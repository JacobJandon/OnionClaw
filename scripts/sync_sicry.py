#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""
sync_sicry.py — update the bundled sicry.py from the upstream SICRY™ repo.

Usage:
    python3 scripts/sync_sicry.py           # fetch latest from main
    python3 scripts/sync_sicry.py --tag v1.0.0   # fetch a specific release tag

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
DEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sicry.py")


def main():
    parser = argparse.ArgumentParser(description="Sync bundled sicry.py from upstream SICRY™")
    parser.add_argument("--tag", default="main", help="git ref / tag to fetch (default: main)")
    parser.add_argument("--dry-run", action="store_true", help="print what would happen without writing")
    args = parser.parse_args()

    url = UPSTREAM_RAW.format(ref=args.tag)
    print(f"Fetching {url} ...")

    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"Error: failed to fetch upstream — {e}", file=sys.stderr)
        sys.exit(1)

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

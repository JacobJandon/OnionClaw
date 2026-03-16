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

    The 404 error message performs a live GitHub API lookup to show the current
    SICRY™ tags at the time of the failed request.

    Example: --tag v1.2.1 will 404 if no SICRY™ v1.2.1 exists.
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

UPSTREAM_RAW  = "https://raw.githubusercontent.com/JacobJandon/Sicry/{ref}/sicry.py"
SICRY_TAGS_API = "https://api.github.com/repos/JacobJandon/Sicry/tags?per_page=50"
DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sicry.py")


def _fetch_sicry_tags() -> str:
    """Return a comma-separated list of SICRY™ tags fetched live from the GitHub API.
    Falls back to a static fallback string on any error so the 404 message is never blank."""
    try:
        resp = requests.get(SICRY_TAGS_API, timeout=10)
        if not resp.ok:
            raise ValueError(f"HTTP {resp.status_code}")
        names = [t["name"] for t in resp.json() if isinstance(t, dict) and "name" in t]
        if not names:
            raise ValueError("empty tag list")
        # Sort newest-first using semver components (ignore non-semver names)
        def _ver(n):
            stripped = n.lstrip("v")
            parts = stripped.split(".")
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return (0, 0, 0)
        names.sort(key=_ver, reverse=True)
        return ", ".join(names)
    except Exception:
        return "v1.0.0, v1.0.1, v1.1.0, v1.1.1  (could not fetch live list)"


def main():
    parser = argparse.ArgumentParser(description="Sync bundled sicry.py from upstream SICRY™")
    parser.add_argument("--version", action="version", version="OnionClaw sync_sicry 2.1.11")
    parser.add_argument("--tag",     default="main", help="git ref / tag to fetch (default: main)")
    parser.add_argument("--dry-run", action="store_true", help="print what would happen without writing")
    parser.add_argument("--check-bundled", action="store_true",
                        help="Compare bundled sicry.py version to latest upstream tag and exit")
    args = parser.parse_args()

    # BUG-5: --check-bundled warns when bundled.py is behind upstream
    if args.check_bundled:
        try:
            bundled_version = "unknown"
            if os.path.isfile(DEST):
                with open(DEST, encoding="utf-8") as _f:
                    for _l in _f:
                        if _l.startswith("__version__"):
                            bundled_version = _l.split("=")[1].strip().strip('"')
                            break
            sicry_tags = _fetch_sicry_tags()
            # pick highest from the live tag list
            def _v(n):
                try: return tuple(int(p) for p in n.lstrip("v").split("."))
                except: return (0, 0, 0)
            latest_name = max(
                (t.strip() for t in sicry_tags.split(",")),
                key=_v, default="unknown"
            )
            print(f"Bundled  : v{bundled_version}")
            print(f"Upstream : {latest_name}")
            if _v(bundled_version) < _v(latest_name):
                print("\nNOTICE: bundled sicry.py is BEHIND upstream. Run sync_sicry.py before tagging.")
                sys.exit(2)  # non-zero ⟶ CI / release scripts can catch this
            else:
                print("Bundled sicry.py is up-to-date.")
        except Exception as e:
            print(f"Error checking bundled version: {e}", file=sys.stderr)
            sys.exit(1)
        return

    url = UPSTREAM_RAW.format(ref=args.tag)

    try:
        r = requests.get(url, timeout=15)
    except Exception as e:
        print(f"Error: network request failed — {e}", file=sys.stderr)
        sys.exit(1)

    if r.status_code == 404:
        sicry_tags = _fetch_sicry_tags()
        print(f"Error: ref '{args.tag}' not found in the SICRY\u2122 repo (HTTP 404).",
              file=sys.stderr)
        print(f"  --tag must be a SICRY\u2122 tag, not an OnionClaw tag.",
              file=sys.stderr)
        print(f"  SICRY\u2122 available tags: {sicry_tags}",
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

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
import re
import hashlib
import argparse

try:
    import requests
except Exception as _e:
    print(f"Error: requests not installed — pip3 install requests ({_e})", file=sys.stderr)
    sys.exit(1)

UPSTREAM_RAW  = "https://raw.githubusercontent.com/JacobJandon/Sicry/{ref}/sicry.py"
SICRY_TAGS_API = "https://api.github.com/repos/JacobJandon/Sicry/tags?per_page=50"
DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sicry.py")


def _top_level_defs(src: str) -> set:
    """Names of top-level functions/classes — used to detect a regressive sync."""
    return set(re.findall(r"^(?:def|class) ([A-Za-z_][A-Za-z0-9_]*)", src, re.M))


def _sicry_tag_names():
    """Live SICRY™ tag names, newest first, or None when GitHub cannot be reached.

    None is distinct from an answer on purpose: offline, or past GitHub's limit of 60
    unauthenticated API requests an hour, a check must fail rather than compare against
    made-up tags.
    """
    try:
        resp = requests.get(SICRY_TAGS_API, timeout=10)
        if not resp.ok:
            return None
        names = [t["name"] for t in resp.json() if isinstance(t, dict) and "name" in t]
    except Exception:
        return None
    # Sort newest-first using semver components (ignore non-semver names)
    def _ver(n):
        try:
            return tuple(int(p) for p in n.lstrip("v").split("."))
        except ValueError:
            return (0, 0, 0)
    names.sort(key=_ver, reverse=True)
    return names or None


def _fetch_sicry_tags() -> str:
    """Comma-separated SICRY™ tags for messages; says plainly when the list is unavailable."""
    names = _sicry_tag_names()
    return ", ".join(names) if names else "unavailable (could not reach the GitHub API)"


def _content_sha(data: bytes) -> str:
    """Hash of the file content with line endings normalised to LF.

    A checkout with CRLF line endings (Git for Windows defaults to core.autocrlf=true)
    holds the same code as upstream, so it must not be reported as drift.
    """
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()[:12]


def main():
    parser = argparse.ArgumentParser(description="Sync bundled sicry.py from upstream SICRY™")
    parser.add_argument("--version", action="version", version="OnionClaw sync_sicry 2.4.0")
    parser.add_argument("--tag",     default="main", help="git ref / tag to fetch (default: main)")
    parser.add_argument("--dry-run", action="store_true", help="print what would happen without writing")
    parser.add_argument("--force", action="store_true",
                        help="overwrite even if the bundled sicry.py has functions upstream lacks")
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
            names = _sicry_tag_names()
            if not names:
                # Comparing against invented tags reported "up-to-date" (exit 0) for a
                # check that never ran.
                print("ERROR: could not fetch SICRY\u2122 tags from GitHub (offline, or the API "
                      "rate limit of 60 requests an hour was reached). Cannot check the bundled "
                      "sicry.py; try again later.", file=sys.stderr)
                sys.exit(1)
            # pick highest from the live tag list
            def _v(n):
                try: return tuple(int(p) for p in n.lstrip("v").split("."))
                except ValueError: return (0, 0, 0)
            latest_name = max(names, key=_v)
            print(f"Bundled  : v{bundled_version}")
            print(f"Upstream : {latest_name}")
            # Compare content against the SAME ref whose version we just printed. Hashing
            # main while comparing versions to the latest tag reports "drift" merely
            # because main has moved on since that tag — which is the normal state.
            try:
                ref = latest_name
                up = requests.get(UPSTREAM_RAW.format(ref=ref), timeout=15)
                if up.ok and os.path.isfile(DEST):
                    with open(DEST, "rb") as _bf:
                        local_sha = _content_sha(_bf.read())
                    up_sha = _content_sha(up.content)
                    print(f"Content  : bundled sha256 {local_sha}  upstream@{ref} {up_sha}"
                          f"  ({'identical' if local_sha == up_sha else 'DIFFERENT'})")
                    if local_sha != up_sha and _v(bundled_version) == _v(latest_name):
                        print(f"\nNOTICE: bundled version matches {ref} but the file CONTENT "
                              f"differs — the copies have drifted.")
                        sys.exit(2)
            except requests.RequestException as e:
                print(f"Content  : could not fetch upstream@{ref} ({type(e).__name__}); "
                      f"compared versions only")
            if _v(bundled_version) < _v(latest_name):
                print("\nNOTICE: bundled sicry.py is BEHIND upstream. Run sync_sicry.py before tagging.")
                sys.exit(2)  # non-zero ⟶ CI / release scripts can catch this
            elif _v(bundled_version) > _v(latest_name):
                # The content line above necessarily says DIFFERENT here; explain why.
                print(f"Bundled sicry.py (v{bundled_version}) is newer than the latest SICRY™ tag "
                      f"({latest_name}). Tag the SICRY™ release so the copies can be compared "
                      f"like for like.")
            else:
                print("Bundled sicry.py is up-to-date.")
        except Exception as e:
            print(f"Error checking bundled version: {e}", file=sys.stderr)
            sys.exit(1)
        return

    url = UPSTREAM_RAW.format(ref=args.tag)

    print(f"Fetching {url} ...")
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

    # Decode explicitly: requests falls back to ISO-8859-1 when a server omits the
    # charset, which would corrupt the non-ASCII characters in sicry.py.
    new_content = r.content.decode("utf-8")

    # Extract upstream version
    version = "unknown"
    for line in new_content.splitlines():
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"')
            break

    print(f"Upstream version: {version}")

    # Regression guard: refuse to replace a bundled file that is AHEAD of upstream.
    # (v2.3.0 shipped with its CHANGELOG but not its code upstream; a blind sync
    # would have silently deleted the only working implementation.)
    if os.path.isfile(DEST):
        with open(DEST, encoding="utf-8") as _f:
            bundled_src = _f.read()
        lost = sorted(_top_level_defs(bundled_src) - _top_level_defs(new_content))
        if lost and not args.force:
            print(f"REFUSING to sync: bundled sicry.py defines {len(lost)} top-level "
                  f"name(s) that upstream '{args.tag}' lacks:", file=sys.stderr)
            for n in lost[:15]:
                print(f"    - {n}", file=sys.stderr)
            print("  Port them upstream first, or re-run with --force to overwrite anyway.",
                  file=sys.stderr)
            sys.exit(3)

    if args.dry_run:
        print(f"[dry-run] Would write {len(r.content)} bytes to {DEST}")
        return

    with open(DEST, "wb") as f:
        f.write(r.content)

    print(f"Updated {DEST} to SICRY™ {version}")
    print("Remember to commit: git add sicry.py && git commit -m 'chore: sync sicry.py to SICRY {}'".format(version))


if __name__ == "__main__":
    main()

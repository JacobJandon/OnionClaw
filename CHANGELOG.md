# Changelog

All notable changes to OnionClaw™ are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org).

---

## [1.2.2] — 2026-03-15

### Fixed
- **BUG-1** (`pipeline.py --check-update` requires `--query`): `--query` is no
  longer `required=True` at argparse time. Standalone flags (`--check-update`,
  `--clear-cache`) exit before the manual `--query` validation, so
  `pipeline.py --check-update` works with no `--query`.
- **BUG-2** (`sync_sicry.py` tag 404 / double message): Replaced
  `raise_for_status()` with an explicit `r.status_code == 404` check that
  prints a single clear error explaining the SICRY™ vs OnionClaw tag
  versioning split. Updated docstring with full tag table.
- **BUG-3** (`check_update()` reports misleading “up to date”): Switched from
  the GitHub Releases API (only v1.0.0/v1.0.1 as formal releases) to the
  GitHub Tags API (`/tags?per_page=20`) which sees all git tags including
  v1.1.x and v1.2.x. Renamed constant `GITHUB_RELEASES_URL` →
  `GITHUB_TAGS_URL`. Passive startup notice in `pipeline.py` now fires
  correctly when behind.
- **UX-1** (`check_tor.py` / `renew.py` no `--version` or `--help`): Both
  scripts now use `argparse` with `--version` and `--json` flags. `--help`
  comes for free.
- **UX-2** (`.env.example` missing `SICRY_CACHE_TTL`): Added
  `SICRY_CACHE_TTL=600` to both `.env.example` copies.
- **UX-3** (passive update notice never fires): Fixed by BUG-3 (tags API fix)
  and by restructuring `pipeline.py` so the passive notice runs unconditionally
  in the main flow (not inside an `else` branch).

---

## [1.2.1] — 2026-03-15

### Fixed
- **ENV-1 (.env chmod on existing installs)**: `setup_env()` previously skipped
  `os.chmod(_ENV, 0o600)` when the user declined to reconfigure an existing
  `.env` (early `return` ran before the `chmod`). `chmod 600` now always runs
  first so existing installs are also protected.
- **BUG-6 (`--out` exit code)**: Both `--out` write-error handlers changed from
  `except OSError` to `except Exception` — catches `PermissionError`, FUSE
  mount errors, `UnicodeEncodeError`, etc., and guarantees `sys.exit(1)` in
  all failure paths.
- **AUTH-1 (permanent cookie-auth fix)**: `setup.py` now *applies* the fix
  instead of only documenting it:
  - New `_fix_cookie_auth()` function: adds user to `debian-tor` group via
    `sudo usermod -aG debian-tor $USER`, appends
    `CookieAuthFileGroupReadable 1` to the active torrc, and optionally
    installs a systemd drop-in
    (`/etc/systemd/system/tor.service.d/onionclaw-cookie.conf`) that
    `ExecStartPost`-`chmod g+r`s the cookie file after every Tor restart.
  - `_verify_controlport()` calls `_fix_cookie_auth()` when auth fails.
  - New constants: `TORRC_COOKIE_FIX`, `SYSTEMD_DROPIN_DIR`,
    `SYSTEMD_DROPIN_PATH`, `SYSTEMD_DROPIN_CONTENT`.

---

## [1.2.0] — 2026-03-15

### Added
- **`check_engines.py --cached N`**: reuse last engine-check result if it is
  less than `N` minutes old — skips the 15–30 s live Tor ping. Cache stored in
  `/tmp/onionclaw_engines_cache.json`.
- **`check_engines.py --json`** and **`--version`** flags
- **`pipeline.py --clear-cache`**: delete all persistent fetch results before
  the pipeline runs
- **`pipeline.py --version`**, **`fetch.py --version`**, **`search.py --version`**,
  **`sync_sicry.py --version`** flags added to every CLI script
- **`sync_sicry.py` fully documented** in `README.md` with its own `###` section
  covering `--tag`, `--dry-run`, and `--version`. Also documented in setup.py
  summary output.

### Security
- **`setup.py` sets `.env` to `chmod 600`** after writing it — prevents world-
  readable API keys on multi-user systems

### Bundled SICRY™
- Version 1.2.0 (see SICRY CHANGELOG for full details)
- SAFETY-1 token-pair matching, persistent cache, `clear_cache()`,
  redirect de-anonymization blocking

---

## [1.1.0] — 2026-03-15

### Added
- `setup.py` — first-run wizard: auto-creates `.env`, patches/creates `torrc`
  with `ControlPort 9051 + CookieAuthentication 1`, checks Python deps
- `pipeline.py --no-llm` flag — skips refine/filter/ask LLM steps; outputs raw
  scraped content without requiring an API key
- `SICRY_CACHE_TTL` env var (default 600 s) to `.env.example`

### Changed
- SKILL.md: updated engine count 18 → 12, removed dead engine names,
  added `--no-llm` to pipeline options, updated setup instructions

### Fixed
- SKILL.md setup section now references `setup.py` for first-run ease

### Bundled SICRY™
- Version 1.1.0
- Removed 6 permanently-dead engines: Torgle, Kaizer, Anima, Tornado,
  TorNet, FindTor
- `fetch()` HTTPS → HTTP automatic fallback for `.onion` addresses that
  don't serve TLS
- `fetch()` SOCKS-level retry: rebuilds session and retries once on
  SOCKS5 handshake or circuit timeout before giving up
- `fetch()` TTL result cache (`_FETCH_CACHE`, keyed by normalised URL,
  evicted after `FETCH_CACHE_TTL` seconds; avoids redundant Tor round-trips)

---

## [1.0.0] — 2026-03-14

### Added
- 7 standalone scripts: `check_tor`, `renew`, `search`, `fetch`, `ask`, `check_engines`, `pipeline`
- OpenClaw `SKILL.md` with full metadata: `requires.pip`, `version`, `author`, `license`, `repo`
- `sync_sicry.py` — pull latest `sicry.py` from upstream SICRY™ repo
- `NOTICE` file (Apache 2.0 requirement — credits Robin OSINT and SICRY™)
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`
- GitHub Actions CI (Python 3.9–3.12, syntax checks all scripts)
- `__version__ = "1.0.0"` in bundled `sicry.py`

### Fixed
- All scripts: `except ImportError` replaced with `except Exception as _e` — correct error message when `python-dotenv` missing vs `sicry.py` missing
- `check_tor.py`: removed spurious `Error: None` printed on success
- `renew.py`: `sys.exit(1)` on failure (was exiting 0)
- `pipeline.py`: hardcoded engine count replaced with `len(engine_status)`; engine name validation added
- `search.py`: engine name validation with WARN message

### Bundled SICRY™
- Version 1.0.0
- URL extraction clearnet fallback, Ahmia redirect decoder, CSS selector targeting

---

<!-- next release goes here
## [Unreleased]
### Added
### Changed
### Fixed
### Removed
-->

[1.0.0]: https://github.com/JacobJandon/OnionClaw/releases/tag/v1.0.0

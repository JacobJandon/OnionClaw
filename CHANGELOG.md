# Changelog

All notable changes to OnionClaw™ are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org).

---

## [2.1.9] — 2026-03-16

### Fixed
- **[3]** `search_and_crawl()` (bundled `sicry.py`) now returns a `job_id` and
  accepts an optional one.  All concurrent crawls share this ID in SQLite so the
  result can be passed directly to `crawl_export()`, `to_stix()`, `to_misp()`.
- **[4]** `engine_reliability()` now applies **exponential time-decay** (48 h
  half-life), widened window from 5 → 20 checks.  Recent outage is always
  visible; brand-new installs no longer look identical to healthy long-running ones.

### Improved
- **[2]** `pipeline.py --watch-check` adds a **Waiting jobs** section listing
  every active watch job not yet due, with `next=<timestamp>` per job.
- **[1]** This CHANGELOG is now up to date (all 11 previously missing v2.x entries
  retroactively filled in).

### Bundled SICRY™
- Version 2.1.9 (see SICRY CHANGELOG for full details)

---

## [2.1.8] — 2026-03-16

### Improved
- `pipeline.py`: `--daemon-poll SECONDS` flag overrides `--interval`-derived
  daemon tick rate.
- `pipeline.py`: `--watch-clear-all` bulk-disables all active watch jobs at once
  (calls `sicry.watch_clear_all()`).
- `pipeline.py`: step 4 prints mode seed onions from `mode_config(mode)["extra_seeds"]`.
- `pipeline.py` interactive REPL: `set format <fmt>` command selects output format
  (`text`/`json`/`stix`/`misp`/`csv`); drill-down fetch respects chosen format.
- `pipeline.py` interactive REPL drill-down: extracts and prints structured entities
  (e-mails, `.onion` links, BTC addresses, PGP key presence).

### Bundled SICRY™
- Version 2.1.8 (BUG-1 dispatch-time `links_found`; `watch_clear_all()`;
  `.env.example` TorPool guidance)

---

## [2.1.7] — 2026-03-16

### Fixed
- `pipeline.py`: `--no-llm` step 5 now calls `score_results(refined, raw_results)`
  instead of sorting by stale confidence — BM25 applied on the current refined query.
- `pipeline.py` interactive mode: confidence scores shown without requiring
  `--confidence` flag.

### Improved
- `pipeline.py`: `--help` epilog includes TorPool section referencing
  `SICRY_POOL_SIZE` and `.env.example`.
- `tests.py`: dedicated mock-based unit test for `--watch-check --output-dir`.

### Bundled SICRY™
- Version 2.1.7 (BUG-1 score floor 0.05, BUG-2 crawl discovery links,
  UX-2 Laplace reliability, engine_reliability window 5)

---

## [2.1.6] — 2026-03-16

### Improved
- `pipeline.py --watch-check`: inline top-5 result titles + URLs for NEW alerts.
- `pipeline.py --interactive` number-based fetch: runs `analyze_nollm()`, prints
  Entities / Keywords block without a separate analysis step.
- `pipeline.py --watch-check --output-dir DIR`: saves triggered alerts as
  `DIR/<job_id>.json` for automated downstream processing.
- Step 1 pipeline output: TorPool line when `SICRY_POOL_SIZE > 0`.

### Bundled SICRY™
- Version 2.1.6 (BUG-1 score dual-key, BUG-2 crawl all-href links_found,
  UX-4 engine_reliability returns None)

---

## [2.1.5] — 2026-03-16

### Added
- `pipeline.py`: `--watch-disable` validates job ID before disabling.
- `pipeline.py`: `--modes` flag prints all available modes.
- `pipeline.py`: `--watch-check` output includes `last=` and `next=` per job.
- `pipeline.py`: `--misp-threat-level` and `--misp-distribution` pass through to `to_misp()`.
- `pipeline.py`: interactive modes handle `help`/`?` and `history` commands.
- `pipeline.py`: `--engine-stats` shows per-engine reliability, last latency, last-seen.
- `pipeline.py`: `--watch-daemon` runs as foreground loop with configurable `--interval`.
- `pipeline.py`: MISP usage example in `--help` epilog.
- `pipeline.py`: `--check-update` also fetches latest SICRY™ upstream tag; prints
  NOTICE when bundled `sicry.py` is behind.
- `pipeline.py`: `--output-dir DIR` flag auto-names output files as
  `DIR/<job_id>.<ext>`.
- `sync_sicry.py`: `--check-bundled` flag compares bundled version to latest
  upstream SICRY™ tag; exits `2` when behind.

### Bundled SICRY™
- Version 2.1.5 (BUG-1 score list guard, BUG-2 crawl links_found all hrefs,
  BUG-3 BM25 page text, BUG-5 sync_sicry check-bundled, BUG-6 WAL cache)

---

## [2.1.4] — 2026-03-16

### Fixed
- **CRITICAL-1** `check_engines.py` syntax error: `sys.exit(1)` merged onto one
  line with `if not args.json:` — split and verified `SYNTAX OK`.
- `pipeline.py`: `new_count` → `result_count` in `--watch-check` output.
- `pipeline.py`: `--format misp` calls `sicry.to_misp()`.

### Added
- `pipeline.py`: `--watch-list` and `--watch-disable JOB_ID` sub-commands.
- `pipeline.py`: mode override NOTE when `--engines` overrides mode routing.

### Bundled SICRY™
- Version 2.1.4 (CRITICAL-2/3 CSAM blacklist, BUG-1 links_found list type,
  BUG-2 crawl_export entities+text, BUG-3 result_count key)

---

## [2.1.3] — 2026-03-16

### Fixed
- `sync_sicry.py --version` bumped to `2.1.3`.

### Bundled SICRY™
- Version 2.1.3 (engine-history KeyError, watch list j['id'], watch check
  result_count, crawl on_page 3-arg lambda, _is_content_safe rake bypass)

---

## [2.1.2] — 2026-03-16

### Fixed
- `check_engines.py`, `search.py`, `fetch.py`: Tor pre-check added so scripts
  fail fast with a clear error when Tor is not running.

### Bundled SICRY™
- Version 2.1.2 (CLI engines/engine-history KeyError, pool-start TypeError)

---

## [2.1.1] — 2026-03-16

### Bundled SICRY™
- Version 2.1.1 (`check_tor()` false-positive fix — SOCKS port probe added)

---

## [2.1.0] — 2026-03-16

### Added
- `pipeline.py`: engine retry / backoff support via bundled `sicry.py`.
- `pipeline.py`: `search_and_crawl()` available from bundled `sicry.py`.
- `pipeline.py`: MISP export via `to_misp()`.
- `pyproject.toml` added for `pip install .` support.

### Bundled SICRY™
- Version 2.1.0 (engine retry/backoff, `search_and_crawl()`, `to_misp()`)

---

## [2.0.2] — 2026-03-16

### Fixed
- `pipeline.py`: `--resume` with a nonexistent job ID exits cleanly with an
  error instead of crashing.
- `pipeline.py --no-llm`: `Refined:` header no longer omitted.
- `pipeline.py`: BM25 scores now correctly printed with `--confidence` after the
  `score → confidence` rename in `sicry.py`.

### Bundled SICRY™
- Version 2.0.2 (`score` → `confidence` rename, cached BM25 compat)

---

## [2.0.1] — 2026-03-16

### Fixed
- **BUG-1** `--resume`: now loads checkpoint and restores query without requiring
  `--query` on the command line.
- **BUG-2** BM25 scores not printed with `--confidence`: `avgdl` corrected
  (50 → 12) and snippet field used for scoring.
- **BUG-4** `--interval` warning fires even on non-watch uses — guard added.
- **UX-1** Interactive mode now prints `Goodbye!` and a help hint on exit.
- **UX-2** Empty `--query` now exits with a clear error instead of crashing.
- **UX-3** `refined_query` null no longer causes `KeyError` in JSON output.

### Bundled SICRY™
- Version 2.0.1 (BM25 avgdl fix, snippet scoring, engine error messages)

---

## [2.0.0] — 2026-03-16

### Added
- **Complete pipeline.py rewrite** — full OSINT pipeline: refine → check engines
  → search → filter → scrape → ask.
- `--resume <job_id>` checkpoint system (SQLite).
- `--watch` / `--watch-check` / `--watch-daemon` alert mode.
- `--interactive` REPL mode for exploratory sessions.
- `--format stix|csv|misp|json|md` output formats.
- `--no-llm` path with `analyze_nollm()` offline analysis.
- `--confidence` flag to print BM25 scores per result.
- Confidence scoring pipeline step.

### Bundled SICRY™
- Version 2.0.0 (TorPool, SQLite cache, crawler, watch system, STIX/MISP/CSV,
  15 MCP tools, mode routing, engine reliability, `to_stix()`, `to_misp()`)

---

## [1.2.3] — 2026-03-16

### Fixed
- **BUG-1** `renew.py --json`: guard added so `--json` flag is honoured on all
  code paths including the control-port error branch.
- **BUG-2** Missing git tags not pushed on release — release checklist updated.
- **BUG-3** `sync_sicry.py`: fetch now happens *after* tag validation, not before,
  so a 404 on a bad tag doesn't trigger a partial download.

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

## [1.1.1] — 2026-03-15

### Fixed
- Safety blacklist improvements: additional dangerous token pairs and standalone
  terms added to `_TOKEN_PAIR_BLACKLIST` and `_CONTENT_BLACKLIST` in bundled
  `sicry.py`.
- 15 further bug fixes across `pipeline.py`, `check_engines.py`, `fetch.py`,
  and `search.py` from internal testing.

### Bundled SICRY™
- Version 1.1.1 (blacklist + 15 bug fixes)

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

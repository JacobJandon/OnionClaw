# Changelog

All notable changes to OnionClaw™ are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org).

---

## [1.0.0] — 2026-03-14

### Added
- 7 standalone scripts: `check_tor`, `renew`, `search`, `fetch`, `ask`, `check_engines`, `pipeline`
- OpenClaw `SKILL.md` with full metadata: `requires.pip`, `version`, `author`, `license`, `repo`
- `scripts/sync_sicry.py` — pull latest `sicry.py` from upstream SICRY™ repo
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

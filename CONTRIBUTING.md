# Contributing to OnionClaw™

Thanks for your interest in OnionClaw™.

## Ground rules

- OnionClaw wraps SICRY™ — do not modify `sicry.py` directly here; instead submit changes upstream to [SICRY](https://github.com/JacobJandon/Sicry)
- Scripts in `scripts/` must remain standalone — no script may import another script
- Python 3.9+ compatibility required
- "OnionClaw" name and logo are not licensed for use in forks/derivatives without permission

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b fix/your-fix` or `feat/your-feature`
3. Edit scripts in `scripts/`, run syntax check: `python3 -m py_compile scripts/*.py`
4. Test locally with Tor running: `python3 scripts/check_tor.py`
5. Open a PR against `main`

## Syncing sicry.py

If SICRY™ has released a new version, use the sync script to update the bundled copy:
```bash
python3 scripts/sync_sicry.py
```

## Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

## License

By contributing you agree your contributions are licensed under Apache 2.0.
The "OnionClaw" name and logo remain the exclusive property of JacobJandon.

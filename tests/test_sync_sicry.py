# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""sync_sicry.py: the bundled-engine sync and its drift check, driven offline."""
import json
import os
import sys

import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sync_sicry

# A miniature engine file. The "™" matters: it is 3 bytes in UTF-8 but 1 character.
UP = '# SICRY™ engine\n__version__ = "2.3.1"\n\ndef search():\n    return []\n'.encode("utf-8")
TAGS = [{"name": "v2.3.1"}, {"name": "v2.3.0"}, {"name": "v1.0.0"}]


def _resp(body=b"", status=200, ctype="text/plain; charset=utf-8", url=""):
    r = requests.models.Response()
    r.status_code, r._content, r.url = status, body, url
    r.headers["Content-Type"] = ctype
    # What requests' HTTP adapter does for a real response: take the encoding from the
    # headers, which is ISO-8859-1 for text/* without a charset. Left as None, .text
    # would sniff the bytes instead and hide the decoding bug.
    r.encoding = requests.utils.get_encoding_from_headers(r.headers)
    return r


def _routes(raw=None, tags=True, raw_ctype="text/plain; charset=utf-8"):
    """Fake requests.get: the tags API and raw file URLs; anything else is 'offline'."""
    def get(url, **_):
        if url == sync_sicry.SICRY_TAGS_API and tags:
            return _resp(json.dumps(TAGS).encode(), ctype="application/json", url=url)
        if url.startswith("https://raw.githubusercontent.com/") and raw is not None:
            return _resp(raw, ctype=raw_ctype, url=url)
        raise requests.ConnectionError(f"offline: {url}")
    return get


def _run(monkeypatch, capsys, argv, get, dest):
    monkeypatch.setattr(sync_sicry, "DEST", str(dest))
    monkeypatch.setattr(sync_sicry.requests, "get", get)
    monkeypatch.setattr(sys, "argv", ["sync_sicry.py", *argv])
    code = 0
    try:
        sync_sicry.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    out = capsys.readouterr()
    return code, out.out, out.err


def test_check_fails_loudly_when_github_is_unreachable(monkeypatch, capsys, tmp_path):
    """Offline or rate-limited, it compared against made-up v1.x tags and reported
    'up-to-date' with exit 0 for a check that never ran."""
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP)
    code, out, err = _run(monkeypatch, capsys, ["--check-bundled"], _routes(tags=False), dest)
    assert code == 1
    assert "could not fetch" in err
    assert "up-to-date" not in out


def test_check_accepts_a_crlf_checkout_of_identical_code(monkeypatch, capsys, tmp_path):
    """Git for Windows checks files out with CRLF by default; same code is not drift."""
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP.replace(b"\n", b"\r\n"))
    code, out, _ = _run(monkeypatch, capsys, ["--check-bundled"], _routes(raw=UP), dest)
    assert code == 0
    assert "identical" in out and "DIFFERENT" not in out


def test_check_still_reports_real_drift(monkeypatch, capsys, tmp_path):
    """Normalising line endings must not hide a genuine content difference."""
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP + b"# a local edit upstream never got\n")
    code, out, _ = _run(monkeypatch, capsys, ["--check-bundled"], _routes(raw=UP), dest)
    assert code == 2
    assert "DIFFERENT" in out and "drifted" in out


def test_check_compares_against_the_latest_tag(monkeypatch, capsys, tmp_path):
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP)
    seen = []
    base = _routes(raw=UP)

    def get(url, **kw):
        seen.append(url)
        return base(url, **kw)

    code, out, _ = _run(monkeypatch, capsys, ["--check-bundled"], get, dest)
    assert code == 0 and "Upstream : v2.3.1" in out
    assert sync_sicry.UPSTREAM_RAW.format(ref="v2.3.1") in seen


def test_dry_run_reports_bytes_not_characters(monkeypatch, capsys, tmp_path):
    code, out, _ = _run(monkeypatch, capsys, ["--dry-run"], _routes(raw=UP), tmp_path / "sicry.py")
    assert code == 0
    assert f"Would write {len(UP)} bytes" in out
    assert not (tmp_path / "sicry.py").exists()


def test_sync_writes_upstream_bytes_exactly_even_without_a_charset(monkeypatch, capsys, tmp_path):
    """requests decodes text/plain without a charset as ISO-8859-1, which corrupted the
    non-ASCII characters; and a text-mode write rewrote line endings on Windows."""
    dest = tmp_path / "sicry.py"
    code, out, _ = _run(monkeypatch, capsys, [], _routes(raw=UP, raw_ctype="text/plain"), dest)
    assert code == 0 and "Updated" in out
    assert dest.read_bytes() == UP


def test_sync_names_the_url_even_when_the_fetch_fails(monkeypatch, capsys, tmp_path):
    code, out, err = _run(monkeypatch, capsys, [], _routes(raw=None), tmp_path / "sicry.py")
    assert code == 1
    assert "Fetching " + sync_sicry.UPSTREAM_RAW.format(ref="main") in out
    assert "network request failed" in err


def test_404_help_does_not_invent_tags_when_offline(monkeypatch, capsys, tmp_path):
    def get(url, **_):
        if url.startswith("https://raw.githubusercontent.com/"):
            return _resp(b"404: Not Found", status=404, url=url)
        raise requests.ConnectionError("offline")

    code, _, err = _run(monkeypatch, capsys, ["--tag", "v9.9.9"], get, tmp_path / "sicry.py")
    assert code == 1
    assert "unavailable" in err
    assert "v1.0.0" not in err


def test_regression_guard_still_refuses_to_drop_bundled_functions(monkeypatch, capsys, tmp_path):
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP + b"\ndef only_in_bundled():\n    pass\n")
    code, _, err = _run(monkeypatch, capsys, [], _routes(raw=UP), dest)
    assert code == 3 and "only_in_bundled" in err
    assert b"only_in_bundled" in dest.read_bytes()       # untouched


def test_check_explains_a_bundled_copy_newer_than_every_tag(monkeypatch, capsys, tmp_path):
    """Before the SICRY release is tagged, the content line says DIFFERENT; the verdict
    must explain that rather than print a bare 'up-to-date'."""
    dest = tmp_path / "sicry.py"
    dest.write_bytes(UP.replace(b'"2.3.1"', b'"2.4.0"'))
    code, out, _ = _run(monkeypatch, capsys, ["--check-bundled"], _routes(raw=UP), dest)
    assert code == 0
    assert "newer than the latest SICRY" in out and "v2.3.1" in out

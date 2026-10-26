"""What `capture --out` prints: push's Setup summary by default, the
per-item lines behind --verbose (ADR-0016's 2026-10-26 amendment).

Each test pins the sentences a user reads, so a rewording is a decision
rather than drift. The capture is the one place carryon writes a Setup
unencrypted, so the line that says so is pinned on its own.
"""

import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, cli  # noqa: E402
from tests.test_capture import build_home  # noqa: E402
from tests.timeouts import time_limit  # noqa: E402

API_KEY = "sk-ant-" + "a1B2c3D4e5" * 3
NAMES = "Claude Code, Cursor, Cross-agent skills (~/.agents)"
NOT_ENCRYPTED = "This Setup is not encrypted - keep it somewhere private."
# Root reads a mode-000 file anyway. A guard rather than a skip marker, as in
# test_destinations_hostile: run_tests.py's pytest stub has no skipif.
UNPRIVILEGED = not (hasattr(os, "geteuid") and os.geteuid() == 0)


@pytest.fixture
def home(tmp_path):
    """build_home plus one of everything the summary has a line for: a key
    in a file whose keys are stripped, a test suite in a carried skill, and a
    file this machine will not read."""
    home = build_home(tmp_path)
    (home / ".cursor" / "cli-config.json").write_text(json.dumps(
        {"authInfo": {}, "apiKey": API_KEY}))
    skill = home / ".claude" / "skills" / "mine"
    (skill / "tests").mkdir()
    (skill / "tests" / "test_mine.py").write_text("def test(): pass\n")
    locked = skill / "locked.md"
    locked.write_text("unreadable\n")
    locked.chmod(0)
    yield home
    locked.chmod(0o600)


def run(home, out, capsys, **kw):
    kw.setdefault("dry", False)
    code, _ = capture.run(out=out, home=home, **kw)
    return code, capsys.readouterr().out


def test_apply_summary(home, tmp_path, capsys):
    out_dir = tmp_path / "setup"
    code, out = run(home, out_dir, capsys)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0] == f"Capturing into {out_dir}", out
    assert lines[1] == "", out
    assert f"Setup: captured ({NAMES})" in lines, out
    assert any(line.startswith(
        "  not carried: .claude/skills/mine/locked.md - ")
        for line in lines) == UNPRIVILEGED, out
    assert "  left out: .claude/skills/mine/tests (development files)" in lines
    secrets = "  possible secrets in 1 file, not encrypted:"
    assert secrets in lines, out
    assert lines[lines.index(secrets) + 1] == (
        "    .cursor/cli-config.json (anthropic-key, openai-key, "
        "keyed-secret)"), out
    assert f"Wrote {5 if UNPRIVILEGED else 6} files to {out_dir}" in lines, out
    assert lines[-1] == NOT_ENCRYPTED, out


def test_dry_run_summary(home, tmp_path, capsys):
    out_dir = tmp_path / "setup"
    code, out = run(home, out_dir, capsys, dry=True)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0] == f"Dry run: would capture into {out_dir}", out
    assert f"Setup: to capture ({NAMES})" in lines, out
    assert "  possible secrets in 1 file, not encrypted:" in lines, out
    assert lines[-2:] == ["", "Dry run - add --apply to write it"], out
    assert "Wrote " not in out and NOT_ENCRYPTED not in out, out
    assert not out_dir.exists()


def test_the_old_report_is_gone(home, tmp_path, capsys):
    for dry in (True, False):
        _, out = run(home, tmp_path / f"setup-{dry}", capsys, dry=dry)
        for old in ("CAPTURING", "PLAN (dry run)", "categories:",
                    "SECRET SCAN", "NOT captured", "LAYOUT DRIFT",
                    "MANIFEST.json", "RESTORE.md", "in the clear",
                    "Named, not refused", "-" * 20, "ADR-"):
            assert old not in out, f"capture printed {old!r}:\n{out}"


def test_per_item_lines_are_verbose_only(home, tmp_path, capsys):
    item = "      .claude/settings.json"
    _, out = run(home, tmp_path / "a", capsys)
    assert item not in out and "  Claude Code  (claude-code)" not in out, out
    assert "OpenAI Codex CLI: not set up here" not in out, out
    _, out = run(home, tmp_path / "b", capsys, verbose=True)
    assert "  Claude Code  (claude-code)" in out, out
    assert item in out, out
    assert "  --  OpenAI Codex CLI: not set up here, skipped" in out, out


def test_layout_drift_names_the_agent(home, tmp_path, capsys):
    (home / ".claude" / "settings.json").unlink()
    _, out = run(home, tmp_path / "setup", capsys)
    assert ("  Claude Code: 1 expected path missing - run `carryon doctor`"
            in out.splitlines()), out


def test_archive_tail(home, tmp_path, capsys):
    out_dir, bundle = tmp_path / "setup", tmp_path / "setup.tar.gz"
    code, out = run(home, out_dir, capsys, archive=bundle)
    assert code == 0, out
    lines = out.splitlines()
    packed = [line for line in lines if line.startswith("Packed ")]
    assert packed and packed[0].startswith(
        f"Packed {out_dir} into {bundle} ("), out
    assert lines[-1] == NOT_ENCRYPTED, out


def test_a_file_the_archive_would_not_pack_is_named(home, tmp_path, capsys):
    out_dir, bundle = tmp_path / "setup", tmp_path / "setup.tar.gz"
    out_dir.mkdir()
    (out_dir / "stray").mkdir()
    os.mkfifo(out_dir / "stray" / "pipe")
    with time_limit(what="the archive opened a named pipe"):
        _, out = run(home, out_dir, capsys, archive=bundle)
    assert any(line.startswith("  not packed: ") and "pipe" in line
               for line in out.splitlines()), out


def test_refusal_mirrors_push(home, tmp_path, capsys):
    """The same capture set refused in the same words as push's."""
    (home / ".carryon").mkdir()
    (home / ".carryon" / "master.key").write_text("ab" * 32)
    (home / ".claude" / "skills" / "mine" / "key").symlink_to(
        home / ".carryon" / "master.key")
    out_dir = tmp_path / "setup"
    for dry, want in ((True, 1), (False, 2)):
        code, out = run(home, out_dir, capsys, dry=dry)
        assert code == want, out
        lines = out.splitlines()
        assert ("Setup: not captured - carryon won't carry these paths:"
                in lines), out
        assert any(line.startswith("  ~/.claude/skills/mine/key: ")
                   for line in lines), out
        assert "  Remove the link, or drop the path from `carry`." in lines
        assert "CAPTURE REFUSED" not in out and "ADR-" not in out, out
        assert not out_dir.exists()


def test_hostile_names_stay_escaped(home, tmp_path, capsys):
    """Run verbose as well: a name only the per-item lines print would pass
    vacuously in the summary."""
    tests = home / ".claude" / "skills" / "evil\x1b[2J\rname" / "tests"
    tests.mkdir(parents=True)
    (tests.parent / "SKILL.md").write_text("x")
    (tests / "t.py").write_text("x")
    for verbose in (False, True):
        _, out = run(home, tmp_path / f"setup-{verbose}", capsys,
                     verbose=verbose)
        assert "evil" in out, out
        assert "\x1b" not in out and "\r" not in out, repr(out)


def test_cli_passes_verbose(monkeypatch, tmp_path):
    seen = {}

    def fake_run(**kw):
        seen.update(kw)
        return 0, {}
    monkeypatch.setattr(capture, "run", fake_run)
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    cli.main(["capture", "--out", str(tmp_path / "x"), "--verbose"])
    assert seen.get("verbose") is True
    cli.main(["capture", "--out", str(tmp_path / "y")])
    assert seen.get("verbose") is False

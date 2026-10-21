"""What `push` prints: a summary by default, detail behind --verbose
(ADR-0016).

Each test pins the sentences a user reads, so a rewording is a decision
rather than drift. The one negative test is the bug this round fixed: a push
printed `capture --out`'s whole report, including a paragraph calling the
Setup in the clear, while it published a sealed one.

Homes are synthetic (tests.test_sync.build_home_a) and the keychain is forced
to the fallback file.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import keyring, rekey, sync  # noqa: E402
from tests.test_sync import (PROJ_REL, UUID_A, UUID_E, build_home_a,  # noqa: E402
                             e_line, jline, ns)

API_KEY = "sk-ant-" + "a1B2c3D4e5" * 3
ORPHAN = "-Users-someone-gone"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


@pytest.fixture
def home(tmp_path, capsys):
    """build_home_a plus one of everything the summary has a line for: a
    Setup file holding a key, a binary file and a test suite in a carried
    skill, a Transcript holding a key, and a project folder with only
    memory, which records no working directory."""
    home = build_home_a(tmp_path)
    claude = home / ".claude"
    (claude / "settings.json").write_text(
        '{"model": "opus", "env": {"ANTHROPIC_API_KEY": "%s"}}' % API_KEY)
    skill = claude / "skills" / "mine"
    (skill / "tests").mkdir(parents=True)
    (skill / "SKILL.md").write_text("A skill.\n")
    (skill / "tests" / "test_mine.py").write_text("def test(): pass\n")
    (skill / "font.woff2").write_bytes(b"wOF2\xff\xfe\x00\x01")
    project = claude / "projects" / rekey.encode_project_dir(
        str(home / PROJ_REL))
    (project / (UUID_E + ".jsonl")).write_text(
        e_line(str(home / PROJ_REL))
        + jline({"type": "user", "text": f"my key is {API_KEY}"}))
    orphan = claude / "projects" / ORPHAN / "memory"
    orphan.mkdir(parents=True)
    (orphan / "MEMORY.md").write_text("A note.\n")
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    capsys.readouterr()
    return home


def push(home, capsys, **kw):
    code = sync.push(ns(**kw), home)
    return code, capsys.readouterr().out


def test_push_prints_none_of_captures_own_report(home, capsys):
    """The bug: a push printed capture's staging lines and its warning that
    the Setup is in the clear, while publishing a sealed Setup."""
    for apply in (False, True):
        _, out = push(home, capsys, apply=apply)
        for line in ("CAPTURING", "PLAN (dry run)", "categories:", "Wrote ",
                     "MANIFEST.json", "RESTORE.md", "in the clear",
                     "SECRET SCAN", "staging", "-" * 20):
            assert line not in out, f"push printed {line!r}:\n{out}"


def test_push_cites_no_adr(home, capsys):
    for kw in ({}, {"apply": True}, {"apply": True, "verbose": True}):
        _, out = push(home, capsys, **kw)
        assert "ADR-" not in out, out


def test_apply_summary(home, capsys):
    code, out = push(home, capsys, apply=True)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0].startswith("Pushing to directory "), out
    assert "Setup: pushed, encrypted (Claude Code, OpenAI Codex CLI)" in out
    assert ("  not carried: 1 binary file (.claude/skills/mine/font.woff2) - "
            "a Setup carries text files only") in out
    assert ("  left out: .claude/skills/mine/tests (development files)"
            in out), out
    assert "  possible secrets in 1 file, carried encrypted:" in out, out
    named = lines[lines.index(
        "  possible secrets in 1 file, carried encrypted:") + 1]
    assert named == ("    .claude/settings.json "
                     "(anthropic-key, openai-key, keyed-secret)"), out
    assert ("History: 4 Sessions pushed (0 unchanged), "
            "1 project memory pushed (0 unchanged)") in out, out
    assert ("  possible secrets in 1 History file, carried encrypted "
            "(--verbose names them)") in out, out
    assert ("1 History path has no recorded working directory, so it "
            "can't be restored on another machine (--verbose lists it)"
            in out), out
    assert ORPHAN not in out, "the folder list is --verbose detail"
    assert UUID_E not in out, "the History secret list is --verbose detail"
    assert "Re-keying" not in out, "re-keying counts are --verbose detail"
    assert "Credentials" not in out and "none reported" not in out
    assert "Dry run" not in out


def test_dry_run_prints_the_same_summary_with_its_own_verbs(home, capsys):
    code, out = push(home, capsys)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0].startswith("Dry run: would push to directory "), out
    assert "Setup: to push, encrypted (Claude Code, OpenAI Codex CLI)" in out
    assert ("History: 4 Sessions to push (0 unchanged), "
            "1 project memory to push (0 unchanged)") in out, out
    assert lines[-1] == "Dry run - add --apply to push", out


def test_verbose_adds_the_detail(home, capsys):
    _, out = push(home, capsys, apply=True, verbose=True)
    assert ".claude/CLAUDE.md" in out, "capture's per-item lines"
    assert f"  ~/.claude/projects/{ORPHAN}" in out, \
        "the folders with no working directory"
    assert UUID_E in out, "the Transcript holding a possible secret"
    assert "Re-keying:" in out, "blob.bin is not UTF-8"


def test_a_skipped_session_is_named_in_the_summary(home, capsys):
    """A skip is a Session not carried, so the default output names it, once,
    with the command that sorts it out."""
    push(home, capsys, apply=True)
    cwd = str(home / PROJ_REL)
    main = (home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
            / (UUID_A + ".jsonl"))
    main.write_text(jline({"cwd": cwd, "type": "meta"}))  # now behind

    _, out = push(home, capsys, apply=True)
    assert "History: 0 Sessions pushed (3 unchanged, 1 skipped)" in out, out
    assert "Skipped 1 Session rather than overwrite the Archive's copy:" \
        in out, out
    assert (f"  {UUID_A} (claude-code): this machine's copy is behind the "
            "Archive's or has diverged - run `carryon pull` first") in out
    assert out.count(UUID_A) == 1, out


def test_a_setup_refused_says_what_to_do(home, capsys):
    """A link in the capture set to carryon's own state: the Setup is not
    pushed, the History still is, and the refusal is three lines."""
    target = home / ".claude" / "CLAUDE.md"
    target.unlink()
    target.symlink_to(home / ".carryon" / "config.json")

    code, out = push(home, capsys, apply=True)
    assert code == 2, out
    assert "Setup: not pushed - carryon won't carry these paths:" in out, out
    assert ("  ~/.claude/CLAUDE.md: it reads carryon's own state (~/.carryon)"
            in out), out
    assert "  Remove the link, or drop the path from `carry`." in out, out
    assert "History: 4 Sessions pushed" in out, out
    assert "ADR-" not in out


def test_a_stripped_json_file_is_named_by_its_home_path(home, capsys):
    """Cursor's config is captured with keys stripped, and the scan runs on
    the stripped copy; the report still names the file the user edits."""
    cursor = home / ".cursor"
    cursor.mkdir()
    (cursor / "cli-config.json").write_text(
        '{"authInfo": {}, "apiKey": "%s"}' % API_KEY)
    _, out = push(home, capsys, apply=True)
    assert "    .cursor/cli-config.json (" in out, out
    assert "after strip" not in out, out


def test_a_reason_is_escaped_like_the_path_beside_it(capsys):
    """A reason can quote a name a filesystem allowed; it may not write its
    own lines into the report."""
    class Cap:
        log, declined, findings = [], [], []
        skipped = [("skill/x.md", "read failed: x\x1b[2Jy\rforged line")]
    sync._print_setup_summary("pushed", Cap(), {"agents": {}}, [], 0, 0,
                              False)
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\r" not in out, repr(out)

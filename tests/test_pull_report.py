"""What `pull` and `sync` print: a summary by default, detail behind
--verbose (ADR-0016).

The scenario is tests.test_sync's: machine A pushes, and machine B pulls
holding a prefix copy (UUID_A), an ahead copy (UUID_E), a divergent codex
rollout (UUID_C), a Session of its own (UUID_D), and a dotfiles-owned
CLAUDE.md. UUID_F is new to B.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import keyring, rekey, sync  # noqa: E402
from tests.test_sync import (PROJ_REL, UUID_A, UUID_C, UUID_F,  # noqa: E402
                             build_home_a, build_home_b, link_home, ns)

PER_ITEM = ("  new      ", "  replace  ", "  union    ", "  keep     ",
            "  write    ", "  residue  ", "  conflict ")


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


@pytest.fixture
def home_b(tmp_path, capsys):
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = build_home_b(tmp_path, dotfiles=True)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()
    return home_b


def pull(home, capsys, **kw):
    code = sync.pull(ns(**kw), home)
    return code, capsys.readouterr().out


def test_pull_prints_a_summary_and_no_per_item_lines(home_b, capsys):
    code, out = pull(home_b, capsys, apply=True)
    assert code == 2, "the divergent rollout is a landed divergence"
    lines = out.splitlines()
    assert lines[0].startswith("Pulling from directory "), out
    assert out.index("Setup: ") < out.index("History: "), \
        "the Setup line comes first, as on push"
    assert ("History: 2 Sessions pulled (1 unchanged), "
            "1 project memory pulled (0 unchanged)") in out, out
    assert ("  diverged: 1 Session - this machine's copy is kept and the "
            "Archive's is under ~/.carryon/conflicts/:") in out, out
    assert f"    {UUID_C} (codex)" in out, out
    assert "Setup: restored from machine 'machine-a' (pushed " in out, out
    assert "): 2 files written" in out, out
    owned = [line for line in lines if line.startswith("  skipped: ")]
    assert len(owned) == 1 and owned[0].startswith(
        "  skipped: ~/.claude/CLAUDE.md - "), out
    assert owned[0].endswith(" holds it (--force writes through)"), out
    for line in PER_ITEM + ("PULLING", "PULL PLAN", "Re-keying", "ADR-",
                            "-" * 20, "?? "):
        assert line not in out, f"pull printed {line!r}:\n{out}"
    assert "Dry run" not in out


def test_dry_run_prints_the_same_summary_with_its_own_verbs(home_b, capsys):
    code, out = pull(home_b, capsys)
    assert code == 1, out
    lines = out.splitlines()
    assert lines[0].startswith("Dry run: would pull from directory "), out
    assert "History: 2 Sessions to pull (1 unchanged), " in out, out
    assert "Setup: to restore from machine 'machine-a' (pushed " in out, out
    assert "): 2 files to write" in out, out
    assert lines[-1] == "Dry run - add --apply to pull", out
    for line in PER_ITEM:
        assert line not in out, f"pull printed {line!r}:\n{out}"


def test_verbose_adds_the_per_item_lines(home_b, capsys):
    _, out = pull(home_b, capsys, apply=True, verbose=True)
    assert f"  new      {UUID_F} (claude-code)" in out, out
    assert f"  replace  {UUID_A} (claude-code)" in out, out
    assert "  write    ~/.codex/config.toml" in out, out
    assert "  residue  " in out, out
    assert "Re-keying:" in out, "blob.bin is not UTF-8"
    assert "ADR-" not in out, out


def test_sync_passes_verbose_to_both_halves(home_b, capsys):
    code = sync.sync(ns(apply=True), home_b)
    out = capsys.readouterr().out
    assert code == 2, out
    for line in PER_ITEM:
        assert line not in out, f"sync printed {line!r}:\n{out}"

    sync.sync(ns(apply=True, verbose=True), home_b)
    out = capsys.readouterr().out
    assert "  conflict " in out, "the pull half's detail"
    assert "  Claude Code  (claude-code)" not in out, \
        "sync carries only the History, so no capture lines"


def test_sync_dry_run_note_is_one_line(home_b, capsys):
    sync.sync(ns(), home_b)
    out = capsys.readouterr().out
    assert ("sync dry run: the real pull lands first, so the real push can "
            "only carry more than the plan below.") in out, out
    assert "ADR-" not in out


def test_a_session_that_only_gained_a_file_counts_as_pulled(home_b, capsys):
    """Same main Transcript, one new subagent journal from the other machine:
    the union writes it, and the summary counts that Session as pulled."""
    pull(home_b, capsys, apply=True)
    home_a = home_b.parent / "home_a"
    project_a = (home_a / ".claude" / "projects"
                 / rekey.encode_project_dir(str(home_a / PROJ_REL)))
    journal = project_a / UUID_F / "subagents" / "journal.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text('{"step": 1}\n')
    assert sync.push(ns(apply=True), home_a) == 0
    capsys.readouterr()

    _, out = pull(home_b, capsys, apply=True)
    assert "History: 1 Session pulled (2 unchanged), " in out, out

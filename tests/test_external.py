"""Externally-owned classification, exercised against a fake $HOME.

A dotfiles manager that symlinks agent config claims those paths. These tests
pin down that carryon recognises the claim in every shape it takes - a direct
link, a link on a parent directory (stow's whole-dir habit), even a link that
dangles - and that only --force writes through one.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import external  # noqa: E402
from tests.timeouts import time_limit  # noqa: E402


def build_home(tmp_path) -> pathlib.Path:
    """A fake ~ with one real file, one dotfiles-linked file, one linked dir."""
    home = tmp_path / "home"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')

    dotfiles = tmp_path / "dotfiles"
    (dotfiles / "claude").mkdir(parents=True)
    (dotfiles / "claude" / "CLAUDE.md").write_text("lives in the repo")
    (claude / "CLAUDE.md").symlink_to(dotfiles / "claude" / "CLAUDE.md")

    # the whole-directory case: ~/.codex is one link onto the repo
    (dotfiles / "codex").mkdir()
    (dotfiles / "codex" / "config.json").write_text("{}")
    (home / ".codex").symlink_to(dotfiles / "codex")
    return home


def test_plain_file_is_ours(tmp_path):
    home = build_home(tmp_path)
    status, owner = external.classify(home / ".claude" / "settings.json", home)
    assert status == "ours"
    assert owner is None


def test_missing_path_is_absent(tmp_path):
    home = build_home(tmp_path)
    status, owner = external.classify(home / ".claude" / "nothing.json", home)
    assert status == "absent"
    assert owner is None


def test_direct_symlink_is_externally_owned_with_its_resolved_target(tmp_path):
    home = build_home(tmp_path)
    status, owner = external.classify(home / ".claude" / "CLAUDE.md", home)
    assert status == "externally-owned"
    assert owner == (tmp_path / "dotfiles" / "claude" / "CLAUDE.md").resolve()


def test_symlinked_parent_directory_is_externally_owned(tmp_path):
    """The file itself is real; the claim sits on the directory above it."""
    home = build_home(tmp_path)
    status, owner = external.classify(home / ".codex" / "config.json", home)
    assert status == "externally-owned"
    assert owner == (tmp_path / "dotfiles" / "codex").resolve()


def test_missing_leaf_under_a_symlinked_parent_is_still_externally_owned(tmp_path):
    """Creating a new file inside a linked dir still creates it in the repo."""
    home = build_home(tmp_path)
    status, owner = external.classify(home / ".codex" / "brand-new.json", home)
    assert status == "externally-owned"
    assert owner == (tmp_path / "dotfiles" / "codex").resolve()


def test_broken_symlink_is_still_externally_owned(tmp_path):
    """A dangling link is still owned by whatever made it; writing a real
    file over it would shadow that claim."""
    home = build_home(tmp_path)
    gone = tmp_path / "dotfiles" / "claude" / "deleted-upstream.md"
    (home / ".claude" / "deleted-upstream.md").symlink_to(gone)

    status, owner = external.classify(
        home / ".claude" / "deleted-upstream.md", home)
    assert status == "externally-owned"
    assert owner == gone.resolve()


def test_plan_splits_do_from_skip_and_names_the_owner(tmp_path):
    home = build_home(tmp_path)
    writes = [
        (home / ".claude" / "settings.json", "setup/claude/settings.json"),
        (home / ".claude" / "fresh.json", "setup/claude/fresh.json"),
        (home / ".claude" / "CLAUDE.md", "setup/claude/CLAUDE.md"),
        (home / ".codex" / "config.json", "setup/codex/config.json"),
    ]
    do, skip = external.plan(writes, home)

    assert do == writes[:2], "ours and absent both get written, in order"
    assert [(t, s) for t, s, _ in skip] == writes[2:]
    owners = {t: o for t, _, o in skip}
    assert owners[home / ".claude" / "CLAUDE.md"] == \
        (tmp_path / "dotfiles" / "claude" / "CLAUDE.md").resolve()
    assert owners[home / ".codex" / "config.json"] == \
        (tmp_path / "dotfiles" / "codex").resolve()


def test_plan_asks_the_whole_ownership_question_not_the_symlink_half(tmp_path):
    """`plan` used to call `classify`, which answers about symlinks only, while
    the History leg beside it called `owner_of`, which answers about a second
    hard link and about something that is not an ordinary file as well. sync
    grew a private copy of this function to close that on its own leg, so the
    weaker spelling stayed exported for the next caller to find. There is one
    now, and it is this one - which is what these two shapes prove."""
    home = build_home(tmp_path)
    managed = tmp_path / "dotfiles" / "claude" / "hardlinked.md"
    managed.write_text("the repo's own copy\n")
    hard = home / ".claude" / "hardlinked.md"
    os.link(managed, hard)
    pipe = home / ".claude" / "pipe.md"
    os.mkfifo(str(pipe))

    # `plan` answers about a name and opens nothing today; the limit is here
    # because the answer this test wants is the one that must arrive at all,
    # and the write side one function over does open what it is asked about.
    with time_limit(what="plan never came back from the pipe"):
        do, skip = external.plan([(hard, "a"), (pipe, "b")], home)

    assert do == []
    owners = {t: o for t, _, o in skip}
    assert owners[hard] == external.HARD_LINK_OWNER
    assert "ordinary file" in owners[pipe]


def test_force_moves_every_skip_to_do(tmp_path):
    """--force means writing through: the repo edit becomes stated intent."""
    home = build_home(tmp_path)
    writes = [
        (home / ".claude" / "settings.json", "setup/claude/settings.json"),
        (home / ".claude" / "CLAUDE.md", "setup/claude/CLAUDE.md"),
        (home / ".codex" / "config.json", "setup/codex/config.json"),
    ]
    do, skip = external.plan(writes, home, force=True)

    assert do == writes
    assert skip == []

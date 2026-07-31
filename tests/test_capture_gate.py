"""The capture gate reached by the routes nobody checked.

The gate that keeps carryon's own state out of a Setup was closed against
symlinks and against the item's own name. Three doors were left standing, and
each of them ends in the same room - the fallback master key, bare hex that no
credential pattern matches, in the Archive's one plaintext half:

  identity    a HARD link is a second directory entry for the SAME inode.
              `is_symlink()` is False, `resolve()` answers with the member's
              own path, and every path-shaped check passes while copy2 copies
              the key's bytes verbatim. A path rule cannot see this; only
              (st_dev, st_ino) over the state directory can.
  the member  '$HOME' was asked once, about the item's root name, and never
              again about the tree that root expands into - ITEM 1's exact
              shape applied to ITEM 2's rule. `~/.mytool` is an ordinary
              directory; `~/.mytool/notes.md -> /outside/loot.txt` is a file
              from outside $HOME in the plaintext Setup.
  the caller  `carryon capture` never read ~/.carryon/config.json, so a user's
              `excludes` bound on the push leg and were ignored on this one -
              the round's own theme in a second place.

Plus the walk itself: the engine crashed rather than reported on three
ordinary, plantable conditions - a broken dotfiles link, a mode-000 file, a
FIFO - and the crash landed AFTER earlier items had been written, with no
verdict printed at all.

Every home here is synthetic and the "master key" is invented hex: what is
asserted is that those bytes are nowhere in the output, so they must be
recognisable and must not be a real key.
"""

import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, cli, config, keyring, sync  # noqa: E402
from tests.hostile_archive import (build_home_a,  # noqa: E402
                                   files_containing, ns)
from tests.timeouts import time_limit  # noqa: E402


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")

FAKE_KEY = "00112233445566778899aabbccddeeff" * 2 + "\n"
# 32 hex characters with nothing in front of them: the shape ADR-0008 names as
# the reason the ~/.carryon carve-out had to be a construction rule rather
# than something the scanner could be trusted to catch.
OPAQUE_TOKEN = "9f2c41ab77de0355c1e8b4a6902f7dd1"


def plant_state(home) -> pathlib.Path:
    key = home / ".carryon" / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(FAKE_KEY)
    return key


def key_bytes_under(out) -> list:
    return files_containing(out, FAKE_KEY.strip())


def as_home(monkeypatch, home) -> None:
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))


def write_config(home, **kw) -> None:
    cfg = config.default_config()
    cfg.update(kw)
    config.save(cfg, home)


# --- identity: a hard link is a second name for the same content -------------


def test_a_hard_link_to_the_master_key_in_a_declared_tree_is_refused(tmp_path,
                                                                     capsys):
    """`ln ~/.carryon/master.key ~/.claude/commands/notes.md`.

    Nothing about that entry is a link as far as any path check goes: it is an
    ordinary file whose resolve() is itself, comfortably under $HOME and
    nowhere near '.carryon'. The only thing it shares with the key is the
    inode, which is why the rule has to be asked about identity rather than
    about spelling.
    """
    home = build_home_a(tmp_path)
    key = plant_state(home)
    os.link(key, home / ".claude" / "commands" / "notes.md")
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert not key_bytes_under(out), \
        "a hard link published the master key in the plaintext Setup"
    assert code != 0, "capture reported success over a refused Setup"
    assert "SECRET SCAN: clean" not in report
    assert ".claude/commands/notes.md" in report, "the path is not named"


def test_a_hard_link_reached_through_a_symlink_is_refused(tmp_path):
    """The variant that keeps a symlink in the picture and still defeats a
    resolving check: ~/decoy is a hard link to the key, and the member is a
    symlink to ~/decoy. resolve() lands on ~/decoy, which is under $HOME and
    is not in ~/.carryon - so only the inode behind it answers."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    decoy = home / "decoy"
    os.link(key, decoy)
    (home / ".claude" / "commands" / "notes.md").symlink_to(decoy)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)

    assert not key_bytes_under(out)
    assert code != 0


def test_a_handpicked_hard_link_to_the_key_is_refused(tmp_path):
    """The same identity, handpicked by name rather than planted in a tree.
    `carry: ['~/decoy']` is a `file` Item, so do_file reads it with one
    read_bytes and no walk in front of it."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    os.link(key, home / "decoy")
    write_config(home, carry=["~/decoy"])
    out = tmp_path / "setup"

    cfg = config.load(home)
    with sync._swapped_registry(sync._effective_adapters(cfg, home)):
        code, _ = capture.run(out=out, dry=False, home=home)

    assert not key_bytes_under(out)
    assert code != 0


def test_the_documented_capture_command_refuses_a_hard_link(tmp_path,
                                                            monkeypatch):
    """Through cli.main, the way the README spells it. The output directory is
    documented as safe for a private git repo, so this is the door that
    matters."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    os.link(key, home / ".claude" / "commands" / "notes.md")
    as_home(monkeypatch, home)
    out = tmp_path / "setup"

    code = cli.main(["capture", "--out", str(out), "--apply"])

    assert not key_bytes_under(out)
    assert code != 0


def test_a_hard_link_never_reaches_the_archives_plaintext_half(tmp_path):
    """The push leg of the same plant. setups/<machine>/ is plaintext and
    needs no key to read, so this is the key that opens the Archive's History
    published beside the History it opens."""
    home = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="laptop"), home)
    # The real fallback key this init just wrote, not a stand-in: what makes
    # the leak invisible is that the file holds bare hex, and hard-linking the
    # genuine article is the only way to be sure nothing here is special.
    key = home / ".carryon" / "master.key"
    secret = key.read_text().strip()
    os.link(key, home / ".claude" / "commands" / "notes.md")

    code = sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home)

    assert code != 0
    assert not files_containing(dest_root, secret), \
        "the master key landed in the Archive's plaintext half"


def test_an_ordinary_multiply_linked_file_outside_state_is_still_carried(
        tmp_path):
    """The rule is identity with carryon's OWN state, not 'this file has more
    than one name'. Hard links turn up in backup schemes and in build trees,
    and refusing every one of them would be a refusal nobody could act on."""
    home = build_home_a(tmp_path)
    plant_state(home)
    twin = home / "twin.md"
    twin.write_text("ordinary content\n")
    os.link(twin, home / ".claude" / "commands" / "twin.md")
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)

    assert code == 0
    assert (out / "claude" / "commands" / "twin.md").read_text() == \
        "ordinary content\n"


# --- the member: $HOME is asked per member, not once per name ----------------


def test_a_member_link_out_of_home_in_a_handpicked_tree_is_refused(tmp_path,
                                                                   capsys):
    """`carry: ['~/.mytool']` passes every check in _relative_to_home - it is
    an ordinary real directory under $HOME. The tree is expanded AFTER that
    judgment, and the engine reads a member link through to its target
    (ADR-0007), so the boundary has to be asked again one component down."""
    home = build_home_a(tmp_path)
    plant_state(home)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("not this machine's to publish\n")
    tool = home / ".mytool"
    tool.mkdir()
    (tool / "notes.md").symlink_to(outside / "loot.txt")
    write_config(home, carry=["~/.mytool"])
    out = tmp_path / "setup"

    cfg = config.load(home)
    with sync._swapped_registry(sync._effective_adapters(cfg, home)):
        code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert not files_containing(out, "not this machine's to publish"), \
        "a file from outside $HOME landed in the plaintext Setup"
    assert code != 0
    assert ".mytool/notes.md" in report
    assert "$HOME" in report


def test_a_member_link_out_of_home_in_an_adapter_tree_is_refused(tmp_path):
    """The same member link with no handpicking involved at all. An adapter
    declares '.claude/commands' as a tree; what sits inside it is whatever the
    filesystem holds."""
    home = build_home_a(tmp_path)
    plant_state(home)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("not this machine's to publish\n")
    (home / ".claude" / "commands" / "notes.md").symlink_to(
        outside / "loot.txt")
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)

    assert not files_containing(out, "not this machine's to publish")
    assert code != 0


def test_a_member_link_out_of_home_never_reaches_the_archive(tmp_path):
    """And the push leg, since 'closed on one leg' is no evidence about the
    other - which is the whole reason this round exists."""
    home = build_home_a(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("not this machine's to publish\n")
    (home / ".claude" / "commands" / "notes.md").symlink_to(
        outside / "loot.txt")
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="laptop"), home)

    code = sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home)

    assert code != 0
    assert not files_containing(dest_root, "not this machine's to publish")


def test_an_item_whose_own_root_is_linked_out_of_home_is_still_carried(
        tmp_path):
    """The honest arrangement the rule must not break: a whole agent directory
    living on another volume or in a dotfiles checkout outside $HOME, linked
    in at its root. ADR-0007 has capture read through that happily; the
    per-member rule is about a member reaching sideways out of a tree, not
    about where the tree itself lives."""
    home = build_home_a(tmp_path)
    elsewhere = tmp_path / "elsewhere" / "commands"
    elsewhere.mkdir(parents=True)
    (elsewhere / "ship.md").write_text("ship it from elsewhere\n")
    commands = home / ".claude" / "commands"
    (commands / "ship.md").unlink()
    commands.rmdir()
    commands.symlink_to(elsewhere)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)

    assert code == 0
    assert (out / "claude" / "commands" / "ship.md").read_text() == \
        "ship it from elsewhere\n"


# --- the caller: `carryon capture` reads the config too ----------------------


def test_capture_honours_the_excludes_the_push_leg_honours(tmp_path,
                                                           monkeypatch):
    """cmd_push and cmd_pull go through the effective registry - excludes
    applied, handpicked paths added (ADR-0008) - and cmd_capture ran against
    the raw one. So the file a user excluded was pushed by neither leg and
    written in the clear by this one, under 'SECRET SCAN: clean', because an
    opaque token is exactly what the scanner cannot see."""
    home = build_home_a(tmp_path)
    (home / ".claude" / "settings.local.json").write_text(
        json.dumps({"token": OPAQUE_TOKEN}))
    write_config(home, excludes=[".claude/settings.local.json"])
    as_home(monkeypatch, home)
    out = tmp_path / "setup"

    code = cli.main(["capture", "--out", str(out), "--apply"])

    assert code == 0
    assert not files_containing(out, OPAQUE_TOKEN), \
        "`carryon capture` wrote a file the user excluded"


def test_capture_carries_the_handpicked_paths_the_push_leg_carries(
        tmp_path, monkeypatch):
    """The other half of the same registry. A user who carries a tool carryon
    has never heard of (ADR-0008) gets it in a push and used to get nothing
    from a capture, which makes the two commands describe different Setups."""
    home = build_home_a(tmp_path)
    tool = home / ".mytool"
    tool.mkdir()
    (tool / "notes.md").write_text("carried by hand\n")
    write_config(home, carry=["~/.mytool"])
    as_home(monkeypatch, home)
    out = tmp_path / "setup"

    code = cli.main(["capture", "--out", str(out), "--apply"])

    assert code == 0
    assert files_containing(out, "carried by hand"), \
        "`carryon capture` ignored the handpicked path"


# --- the walk: report, never a traceback -------------------------------------


def test_a_broken_link_in_a_captured_tree_is_reported_not_raised(tmp_path,
                                                                 capsys):
    """An everyday dotfiles link whose target moved. tree_files filtered it
    out with is_file() and copy_tree copied everything `not is_dir()`, so the
    two walks disagreed and copy2 raised FileNotFoundError out of the apply -
    after settings.json had already been written, with no verdict printed."""
    home = build_home_a(tmp_path)
    (home / ".claude" / "commands" / "gone.md").symlink_to(
        home / "nowhere" / "gone.md")
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert code == 0, "an ordinary broken link refused the whole Setup"
    assert "gone.md" in report, "the skipped member is not named"
    assert (out / "claude" / "commands" / "ship.md").is_file()


def test_an_unreadable_file_in_a_captured_tree_is_reported_not_raised(
        tmp_path, capsys):
    """pathlib's is_file() turns ENOENT, ENOTDIR, EBADF and ELOOP into False
    for you and re-raises EACCES, so a mode-000 file came out of do_tree's
    read_bytes as an uncaught PermissionError."""
    home = build_home_a(tmp_path)
    locked = home / ".claude" / "commands" / "locked.md"
    locked.write_text("secret-ish\n")
    locked.chmod(0o000)
    out = tmp_path / "setup"
    try:
        code, _ = capture.run(out=out, dry=False, home=home)
        report = capsys.readouterr().out
    finally:
        locked.chmod(0o600)

    assert code == 0
    assert "locked.md" in report
    assert (out / "claude" / "commands" / "ship.md").is_file()


def test_an_unreadable_declared_file_is_reported_not_raised(tmp_path, capsys):
    """The same one syscall over: a declared `file` Item read by do_file, with
    no walk in front of it to filter anything."""
    home = build_home_a(tmp_path)
    settings = home / ".claude" / "settings.json"
    settings.chmod(0o000)
    out = tmp_path / "setup"
    try:
        code, _ = capture.run(out=out, dry=False, home=home)
        report = capsys.readouterr().out
    finally:
        settings.chmod(0o600)

    assert code == 0
    assert "settings.json" in report
    assert (out / "claude" / "CLAUDE.md").is_file()


def test_a_fifo_in_a_captured_tree_is_skipped_by_both_walks(tmp_path, capsys):
    """The divergence itself, rather than one of its symptoms: is_file() said
    no and `not is_dir()` said yes, so a FIFO was scanned by nothing and
    handed to copy2 - which blocks on it forever. What the scanner reads and
    what the engine copies have to be one list."""
    home = build_home_a(tmp_path)
    os.mkfifo(str(home / ".claude" / "commands" / "pipe"))
    out = tmp_path / "setup"

    # The docstring's "blocks on it forever" is what this limit is for: the
    # walk and the gate both refuse a fifo today, and a regression in either
    # is a capture that never returns rather than one that answers wrong.
    with time_limit(what="the capture never came back from the pipe"):
        code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert code == 0
    assert "pipe" in report
    assert not (out / "claude" / "commands" / "pipe").exists()


def test_a_json_strip_item_that_is_not_json_is_reported_not_raised(tmp_path,
                                                                   capsys):
    """do_json_strip hands ordinary bytes to json.loads: a cli-config.json
    half-written by a crashed editor is a JSONDecodeError out of a command
    whose whole promise is to say what it found."""
    home = build_home_a(tmp_path)
    cursor = home / ".cursor"
    cursor.mkdir()
    (cursor / "cli-config.json").write_text("{not json")
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert code == 0
    assert "cli-config.json" in report
    assert (out / "claude" / "CLAUDE.md").is_file()

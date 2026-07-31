"""The capture leg reaches the same files by a second door.

`carryon push` guards what its Setup half may read before it runs the capture
engine, and test_config_security.py proves that guard closed over ~/.carryon.
`carryon capture --out DIR --apply` reaches the identical engine, over the
identical trees, and asked nothing - so the leak that was closed on the push
leg stayed wide open on this one, and the README tells the user the directory
it writes is safe to keep in a private git repo.

Three doors into the same room, each tested here on the capture leg:

  the engine   a link one component inside an adapter-declared tree
               ('.claude/commands/notes.md -> ~/.carryon/master.key') is read
               through by the engine (ADR-0007) and copied into the plaintext
               Setup, under a report that says 'SECRET SCAN: clean' because a
               master key is bare hex that matches no credential pattern.
  the boundary a handpicked `carry` entry only had to LOOK like it was under
               $HOME. The check was lexical while everything that acts on the
               answer resolves, so '~/link/loot.txt' with link -> outside was
               a file from outside $HOME in a plaintext Setup.
  the spelling a carry entry holding a NUL or a lone surrogate must be a
               refusal naming the entry, not a traceback: report-and-refuse is
               the rule everywhere else on this code.

Every home here is synthetic and the "master key" is invented hex - what is
being asserted is that those bytes are nowhere in the output, so they must be
recognisable and must not be a real key.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, cli, config  # noqa: E402
from tests.hostile_archive import build_home_a, files_containing  # noqa: E402

# Invented: stands in for the fallback key ~/.carryon/master.key holds.
FAKE_KEY = "00112233445566778899aabbccddeeff" * 2 + "\n"


def plant_state(home) -> pathlib.Path:
    """A ~/.carryon with a master.key in it, as a real machine has."""
    key = home / ".carryon" / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(FAKE_KEY)
    return key


def plain_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def key_bytes_under(out) -> list:
    return files_containing(out, FAKE_KEY.strip())


def as_home(monkeypatch, home) -> None:
    """What `carryon capture` will call this machine's home directory."""
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))


# --- the engine door ---------------------------------------------------------


def test_capture_refuses_a_link_into_state_inside_a_declared_tree(tmp_path,
                                                                  capsys):
    """The engine itself, with no caller involved. push checks this before it
    calls run(); a capture that calls run() directly got no check at all, so
    the guard belongs to the reading rather than to whoever asked for it."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    (home / ".claude" / "commands" / "notes.md").symlink_to(key)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert not key_bytes_under(out), \
        "the master key was written into the plaintext Setup"
    assert code != 0, "capture reported success over a refused Setup"
    assert ".claude/commands" in report, "the offending item is not named"
    assert ".claude/commands/notes.md" in report, \
        "the path inside it that reads state is not named"
    assert "carryon's own state" in report, "the refusal does not say why"


def test_capture_refuses_when_the_declared_item_itself_resolves_into_state(
        tmp_path, capsys):
    """Not only a member of a tree: a file Item whose own path is a link into
    ~/.carryon is read by do_file directly, one read_bytes with no walk in
    front of it."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    settings = home / ".claude" / "settings.json"
    settings.unlink()
    settings.symlink_to(key)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)

    assert not key_bytes_under(out)
    assert code != 0


def test_capture_dry_run_refuses_rather_than_promising_a_clean_setup(tmp_path,
                                                                     capsys):
    """A dry run copies nothing, so nothing leaks - but it is the report the
    user reads before typing --apply, and one that says 'clean' over a capture
    set holding the master key is the wrong sentence to print."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    (home / ".claude" / "commands" / "notes.md").symlink_to(key)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=True, home=home)
    report = capsys.readouterr().out

    assert code != 0
    assert "SECRET SCAN: clean" not in report
    assert not out.exists(), "a refused dry run created the output directory"


def test_the_documented_capture_command_refuses(tmp_path, capsys, monkeypatch):
    """The command as the README spells it, through cli.main. This is the one
    the fix is for: cmd_capture consulted nothing, so `carryon capture --out
    DIR --apply` wrote the master key into a directory documented as safe to
    put in a private git repo."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    (home / ".claude" / "commands" / "notes.md").symlink_to(key)
    as_home(monkeypatch, home)
    out = tmp_path / "setup"

    code = cli.main(["capture", "--out", str(out), "--apply"])

    assert not key_bytes_under(out), \
        "`carryon capture --apply` published the master key"
    assert code != 0


def test_the_documented_capture_command_still_captures(tmp_path, capsys,
                                                       monkeypatch):
    """The positive control, through the same door: the fix is not 'refuse
    everything'. ADR-0007 says carryon reads through an externally owned path
    happily, so an ordinary link inside a captured tree still lands in the
    Setup and the command still succeeds."""
    home = build_home_a(tmp_path)
    plant_state(home)
    (home / "notes").mkdir()
    (home / "notes" / "real.md").write_text("carried through the link\n")
    (home / ".claude" / "commands" / "linked.md").symlink_to(
        home / "notes" / "real.md")
    as_home(monkeypatch, home)
    out = tmp_path / "setup"

    code = cli.main(["capture", "--out", str(out), "--apply"])
    report = capsys.readouterr().out

    assert code == 0, report
    assert (out / "claude" / "commands" / "linked.md").read_text() == \
        "carried through the link\n"
    assert (out / "claude" / "commands" / "ship.md").exists()
    assert not key_bytes_under(out)


# --- the $HOME boundary ------------------------------------------------------


def link_out_of_home(tmp_path):
    """A home whose '~/link' leads out of it, with something worth taking on
    the other side."""
    home = plain_home(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("not under $HOME\n")
    (home / "link").symlink_to(outside)
    return home


@pytest.mark.parametrize("entry", ["~/link", "~/link/loot.txt"])
def test_carry_cannot_leave_home_through_a_symlink(tmp_path, entry):
    """'only paths under home can join a Setup' was enforced lexically - a
    relative_to and a '..' check on the unresolved string - while the engine
    that acts on the answer follows links. '~/link' spells nothing outside
    $HOME and is nowhere near it on disk, so a file from anywhere the user can
    read went into the plaintext Setup."""
    home = link_out_of_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = [entry]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "$HOME" in str(exc.value), "the refusal does not say why"


def test_carry_cannot_leave_home_through_a_doubled_slash(tmp_path):
    """'~/' comes off by string surgery, so '~//etc/passwd' arrives at the
    boundary check as an absolute path. Normalising has to happen after the
    tilde comes off, never before: normalise first and '~//etc/passwd' reads
    as '~/etc/passwd', which is a silent reinterpretation rather than a
    refusal."""
    home = plain_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = ["~//etc/passwd"]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "$HOME" in str(exc.value)


@pytest.mark.parametrize("entry", ["~/notes\x00.md", "~/notes\ud800.md",
                                   "~/.carryon\x00/master.key"])
def test_carry_a_path_no_filesystem_can_spell_is_a_sentence(tmp_path, entry):
    """resolve() answers a NUL with a ValueError and a lone surrogate with a
    UnicodeEncodeError - a ValueError subclass - and both are legal in a JSON
    config file. Report-and-refuse is the rule everywhere else on this code,
    so one bad line must name itself rather than end every command in a
    traceback.

    Already closed when this suite was written (config.spellable, and the
    ValueError arm in lands_in_state), so it is a lock rather than a
    discovery - and the sibling below is the discovery: the same class was
    still open by a spelling neither of those two characters covers.
    """
    home = plain_home(tmp_path)
    plant_state(home)
    cfg = config.default_config()
    cfg["carry"] = [entry]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    message = str(exc.value)
    assert "carry" in message
    # The refusal is itself printed, so it may not carry a character that
    # cannot be written to a terminal.
    message.encode("utf-8")


def test_carry_a_path_the_os_will_not_look_at_is_a_sentence(tmp_path):
    """The third spelling of an unlookable path, and the one still open: a
    component longer than the filesystem allows.

    It holds no NUL and no surrogate, so `spellable` passes it; resolve()
    swallows the error and answers, so the boundary checks pass it; and then
    is_dir() raises ENAMETOOLONG, which pathlib does not count among the
    errors that mean 'no'. One line in config.json ended `carryon push` and
    `carryon pull` in a traceback out of the registry, before either had said
    a word about what it was going to do.
    """
    home = plain_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = ["~/" + "a" * 6000]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "carry" in str(exc.value)


def test_carry_positive_control_a_link_that_stays_inside_home_carries(
        tmp_path):
    """Resolving the boundary must not retire ADR-0007: a dotfiles link is the
    ordinary way a Setup is laid out, and one whose target is still under
    $HOME is exactly what handpicking is for."""
    home = plain_home(tmp_path)
    (home / "dotfiles" / "mytool").mkdir(parents=True)
    (home / "dotfiles" / "mytool" / "conf.json").write_text("{}")
    (home / ".mytool").symlink_to(home / "dotfiles" / "mytool")
    cfg = config.default_config()
    cfg["carry"] = ["~/.mytool"]

    adapter = config.user_adapter(cfg, home=home)

    assert [item.src for item in adapter.items] == [".mytool"]
    assert adapter.items[0].kind == "tree", \
        "a linked directory must still be captured as a tree"


def test_carry_positive_control_an_ordinary_relative_entry_is_normalised(
        tmp_path):
    """A trailing slash, a doubled separator and a '.' component are the same
    path, and all of them still carry."""
    home = plain_home(tmp_path)
    (home / ".mytool").mkdir()
    (home / ".mytool" / "conf.json").write_text("{}")
    cfg = config.default_config()
    cfg["carry"] = ["~/.mytool//./"]

    adapter = config.user_adapter(cfg, home=home)

    assert [item.src for item in adapter.items] == [".mytool"]
    assert adapter.items[0].dst == "handpicked/.mytool"

"""carryon's own state files, read the way it reads everything else.

~/.carryon/config.json, ~/.carryon/state.json and ~/.carryon/master.key were
the three paths the chokepoint work of the last rounds never reached, and the
reason they were skipped is written into the code: they are carryon's own
files rather than a user's, so a bare `Path.read_text()` was thought good
enough. The third one outlived the fix to the other two on a narrower excuse -
it holds bare hex rather than a JSON document, so the gate's shape did not fit
it, and the read allowlist carried that as a written, reasoned entry. An
allowlist can do one thing a reviewer cannot, which is make an open defect look
approved; the gate is split into `read_state_bytes` and `read_state_json` now,
and all three files go through the first. That reasoning is
the same one the Destination layer had before ADR-0009 - carryon writes them,
but it does not control what is at that name when it next reads. A synced
folder puts a conflict copy there. A truncated write leaves a partial file. A
restored backup leaves an older one. A user, or anything running as them, can
put a directory, a device node or a named pipe at either name.

What that cost, all of it on surfaces the probes did reach through the gate
and found nothing on:

  a traceback   `_load_state`'s guard named (FileNotFoundError,
                NotADirectoryError) around the read and (ValueError,
                UnicodeDecodeError, RecursionError) around the parse, so a
                state.json that is not UTF-8 - which its own docstring calls
                ordinary, "a truncated write, a synced folder's conflict copy,
                a restored backup" - came out of BOTH push and pull as a bare
                UnicodeDecodeError. `config.load` one file over already had
                the same exception in the right block.
  a hang        a named pipe at either name blocks `open()` for ever, so
                `list`, `doctor`, `push`, `pull`, `capture` and `pair` all
                printed nothing and never returned. A hang is worse than a
                crash: there is nothing to read and nothing to report.
  a silence     a dangling symlink at either name is ENOENT to `read_text()`,
                which both readers spell "not there". config.load then runs
                the defaults - "reporting no Destination on a machine that has
                one", which is the sentence its own docstring gives for why the
                pre-read exists() had to go - and _load_state answers "nothing
                seen yet" with no line printed, silently weakening the deleted-
                Index and rollback checks the file exists for.

So the tests below drive each shape through the SUBCOMMANDS a user runs rather
than through the reader, because running the reader is not what makes any of
these a defect: `push` and `pull` are the two commands whose tracebacks were
being reported, and `list`, `doctor`, `capture` and `pair` are the four more
that hung. The fifo cases run under a wall-clock limit, since the failure they
are about is a command that never comes back - and a test that hangs is a
failure that reports nothing, which is the very thing being fixed.

The last test here is not about a state file at all but about the same
posture one leg over: a pull whose Setup was REFUSED - a forged tag, a
replayed superseded tree - printed the refusal and exited 0, so nothing a
script can read told it apart from a Setup that landed. push already answers
that question with a status; pull now answers it the same way.
"""

import json
import os
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import cli, config, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, SETUP_CATEGORIES, build_home_a, build_home_b, file_keyring,
    link_home, ns, paired, stored_setup)
from tests.timeouts import time_limit  # noqa: E402

# Nested past any interpreter's recursion limit. json.loads answers this with
# a RecursionError, which is a RuntimeError rather than a ValueError - the one
# refusal a two-name guard walks straight past.
DEEP_JSON = "[" * 200000

# Valid JSON structure, invalid UTF-8 inside it: what half a write, a latin-1
# hostname or a synced folder's byte-mangled copy leaves behind.
NOT_UTF8 = b'{"machine": "caf\xe9", "version": 1}'


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """A machine that has been through `carryon init`, with Path.home()
    pointed at it so the CLI's own entry points can be driven."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))
    return home


def run_command(name, tmp_path):
    """`carryon <name>` through the real argument parser and entry point.

    Dry runs throughout: what is under test is the read that happens before
    any of these commands has decided anything, and a dry run reaches it the
    same way an applied one does.
    """
    if name == "capture":
        return cli.main(["capture", "--out", str(tmp_path / "captured")])
    return cli.main([name])


# Every subcommand that reads carryon's own config, which is all of them
# except `init` - config.load runs before any of them has decided anything.
SUBCOMMANDS = ("list", "doctor", "push", "pull", "capture", "pair")

# The three that also read the high-water mark.
MARK_READERS = ("push", "pull", "pair")

SHAPES = ("directory", "fifo", "not-utf8", "deep-json", "dangling-link")


def plant(path, shape) -> None:
    """Put one of the shapes above at `path`, whatever is there now."""
    if path.is_symlink() or path.exists():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(str(path))
        else:
            path.unlink()
    if shape == "directory":
        path.mkdir()
    elif shape == "fifo":
        os.mkfifo(str(path))
    elif shape == "not-utf8":
        path.write_bytes(NOT_UTF8)
    elif shape == "deep-json":
        path.write_text(DEEP_JSON)
    elif shape == "dangling-link":
        path.symlink_to(path.parent / "gone.json")
    elif shape == "symlink-loop":
        path.symlink_to(path)
    elif shape == "unreadable":
        path.write_text("whatever")
        path.chmod(0o000)
    else:
        raise AssertionError(f"no such shape: {shape}")


# --- the config, which every subcommand reads before it decides anything -----


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_a_config_of_any_shape_stops_a_subcommand_with_a_sentence(
        command, shape, configured, tmp_path, capsys):
    """One question, one answer, whichever subcommand asks it and whatever is
    standing at the name.

    Six commands times five shapes, because "a traceback out of EVERY
    subcommand" and "a hang in EVERY subcommand" are both claims about the
    read that runs before any of them has decided anything - and the two that
    were closed here (a directory, a bad parse) were closed one shape at a
    time, which is what left the fifo and the dangling link open.

    A refusal rather than the defaults, for the dangling link as much as for
    the rest: a config.json that is plainly there and plainly broken must not
    read as a machine that was never set up, or a push quietly reports "no
    Destination configured" about a machine that has one.
    """
    path = config.config_path(configured)
    plant(path, shape)

    with time_limit():
        with pytest.raises(SystemExit) as exc:
            run_command(command, tmp_path)

    assert str(path) in str(exc.value), (
        f"`carryon {command}` refused a {shape} config without naming the "
        f"file: {exc.value}")


# --- the high-water mark, which is never a gate and never silent either ------


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("command", MARK_READERS)
def test_a_state_file_of_any_shape_is_a_warning_and_not_a_gate(
        command, shape, configured, tmp_path, capsys):
    """The other half, and the opposite answer for the same reason.

    _load_state's docstring says the mark is never a gate - "unreadable or
    malformed state means 'nothing seen yet', not a refused pull" - and never
    silent either, because a mark that cannot be read is the deleted-Index and
    rollback checks getting weaker and the user is the only one who can repair
    it. Both halves of that promise are asserted here for every shape: the
    command finishes, and its report names the file.

    Two of these five were already green before the fix - a directory is an
    OSError the guard named, and deep nesting is the RecursionError a previous
    round added - and they stay in the table as the controls that say the
    parametrisation is not the thing doing the work. The other three were a
    traceback, a hang and a silence respectively.
    """
    path = sync._state_path(configured)
    plant(path, shape)

    with time_limit():
        code = run_command(command, tmp_path)

    report = capsys.readouterr().out
    assert code == 0, (f"an unreadable high-water mark turned `carryon "
                       f"{command}` into a failure:\n{report}")
    assert "state.json" in report, (
        f"`carryon {command}` read a {shape} high-water mark as 'nothing seen "
        f"yet' without a word:\n{report}")


def test_a_named_pipe_at_the_state_file_does_not_block_the_gate(configured):
    """The chokepoint itself, away from any command: O_NONBLOCK on the way in
    and S_ISREG on the descriptor, which is the pair `read_carryable` already
    uses one function over. A `stat` before the open is not enough on its own -
    the pipe can arrive between the two - and O_NONBLOCK alone is not enough
    either, since a fifo opened that way reads as empty rather than as wrong.
    """
    path = config.config_path(configured)
    plant(path, "fifo")

    with time_limit():
        state = config.read_state_json(path)

    assert state.value is None
    assert not state.absent, "a pipe standing at the name read as no file"
    assert "ordinary file" in state.why


def test_the_gate_tells_a_missing_file_from_an_unreadable_one(configured):
    """"Found nothing" and "could not look" are different answers, and this
    module's whole family of defects is one being read as the other -
    the same distinction `StateIdentities` draws about the walk of the same
    directory. A dangling link is a name the user put there; the two errnos
    that mean no name is there at all are the only ones that read as absent.
    """
    path = config.config_path(configured)
    path.unlink()
    assert config.read_state_json(path).absent

    plant(path, "dangling-link")
    state = config.read_state_json(path)
    assert not state.absent, "a link pointing at nothing read as no file"
    assert state.why is not None


# --- the controls: nothing above may cost the ordinary case ------------------


def test_an_ordinary_config_and_state_file_still_load(configured, tmp_path,
                                                      capsys):
    """The positive control for the whole module. The gate reads carryon's own
    files on every command, so a gate that refused one of them would be a tool
    that does not start."""
    marks = {"destinations": {"dir:whatever": {"index_revision": 7}}}
    sync._state_path(configured).write_text(json.dumps(marks))
    capsys.readouterr()

    assert config.load(configured)["machine"] == "machine-a"
    assert sync._seen_revision(configured, "dir:whatever") == 7
    assert run_command("list", tmp_path) == 0

    report = capsys.readouterr().out
    assert "state.json" not in report, (
        "an ordinary high-water mark was reported as unreadable:\n" + report)


def test_a_missing_state_file_is_still_the_ordinary_first_run(configured,
                                                              tmp_path,
                                                              capsys):
    """A machine that has never pulled has no mark, and that is not a fault to
    report. The distinction the gate now draws is between no name at all and a
    name with nothing readable behind it - and this is the side of it that
    every freshly initialised machine is on."""
    path = sync._state_path(configured)
    if path.exists():
        path.unlink()
    capsys.readouterr()

    with time_limit():
        code = run_command("push", tmp_path)

    report = capsys.readouterr().out
    assert code == 0, report
    assert "state.json" not in report, (
        "a first run was told its high-water mark would not read:\n" + report)


def test_a_home_with_no_state_directory_at_all_still_loads_the_defaults(
        tmp_path):
    """`carryon init` runs on a machine that has neither the file nor the
    directory around it, so the effortless default has to survive the gate."""
    assert config.load(tmp_path / "never-set-up")["destination"] == ""
    assert config.read_state_json(
        config.config_path(tmp_path / "never-set-up")).absent


# --- what a pull's exit status says when its Setup was refused ---------------
#
# The rule applied, and it is push's own: the exit status answers "did all of
# what you asked for happen". A Setup is a REPLACEMENT and it lands or it does
# not, so a Setup carryon was offered and would not use is a pull that did
# less than it was asked - 2 under --apply, 1 for a dry run that would refuse,
# which is the line push already spells (`setup_code = 2 if apply else 1`).
#
# What stays 0 is everything ADR-0002 and ADR-0007 call the right answer: an
# Archive with no Setup in it (nothing was refused), a path deferred to
# whatever already owns it, and an item inside an accepted Setup refused on its
# own. Those are the pull doing its job, and a status that fired on them would
# be one users learn to ignore.


def index_object(dest_root) -> pathlib.Path:
    return pathlib.Path(dest_root) / "carryon" / "index.enc"


def test_a_pull_that_restored_its_setup_exits_zero(paired, capsys):
    """The control, and the reason the status is worth anything: it has to be
    silent on the ordinary pull before it means something on the other."""
    code = sync.pull(ns(apply=True), paired.home_b)
    report = capsys.readouterr().out

    assert code == 0, report
    assert "refuse" not in report, report
    assert (paired.home_b / ".claude" / "settings.json").exists()


def test_a_pull_whose_setup_failed_authentication_does_not_exit_zero(
        paired, capsys):
    """A forged tree: settings.json is a declared path whose hooks are shell
    commands, so editing the stored copy is the attack the tag exists for. The
    refusal was correct and printed - and the process exited 0, so a script
    that pulls and then trusts its Setup could not tell this run from one that
    restored."""
    (stored_setup(paired.dest_root, "machine-a")
     / "claude" / "settings.json").write_text(EVIL_SETTINGS)

    code = sync.pull(ns(apply=True), paired.home_b)
    report = capsys.readouterr().out

    assert "refuse" in report, report
    assert code == 2, (
        "a Setup refused on authentication reported success:\n" + report)


def test_a_dry_run_that_would_refuse_a_setup_says_so_in_its_status(paired,
                                                                   capsys):
    """The same answer one number down, because that is what push does: a plan
    that found something it would refuse is 1, an applied run that refused is
    2. A dry run is what a script runs to decide whether to run the real one.
    """
    (stored_setup(paired.dest_root, "machine-a")
     / "claude" / "settings.json").write_text(EVIL_SETTINGS)

    code = sync.pull(ns(apply=False), paired.home_b)
    report = capsys.readouterr().out

    assert "refuse" in report, report
    assert code == 1, report


def test_a_pull_that_refused_a_replayed_setup_does_not_exit_zero(tmp_path,
                                                                 capsys):
    """The other half of the same defect, and the one no tag can see: every
    superseded tree a key holder ever pushed still verifies against the Index
    that was current when they pushed it, so the only party that can refuse a
    replay is this machine's own high-water mark. It did refuse - and said so
    at exit 0."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    stale = index_object(dest_root).read_bytes()
    (home_a / ".claude" / "settings.json").write_text('{"model": "haiku"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0
    index_object(dest_root).write_bytes(stale)
    capsys.readouterr()

    code = sync.pull(ns(apply=True), home_b)
    report = capsys.readouterr().out

    assert "rolled back" in report, report
    assert code == 2, (
        "a Setup refused as a replay reported success:\n" + report)


def test_an_archive_with_no_setup_in_it_is_not_a_refusal(tmp_path, capsys):
    """The line between the two, stated as a test rather than left to the
    reader: nothing was offered, so nothing was refused. A History-only push
    is ordinary (ADR-0004 makes the Setup half optional), and a status that
    fired here would fire on every one of them."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    code = sync.pull(ns(apply=True), home_b)
    report = capsys.readouterr().out

    assert code == 0, report
    assert "none in the Archive" in report, report


# --- the third state file, which is the one holding the trust root ----------
#
# ~/.carryon/master.key was left outside the gate above because it holds bare
# hex rather than a JSON document, and the read allowlist carried that as a
# written, reasoned excuse - which is the one thing an allowlist can do that a
# reviewer cannot: make an open defect look approved. Everything the two files
# above cost, this one cost too, on the file that opens the Archive.

# The commands that ask this machine for its master key. `init` is on the list
# and the other two tables' is not: it asks BEFORE it decides anything, so
# that a machine which already holds a key is not handed a second one.
KEY_READERS = ("push", "pull", "pair")

# Every way a name can be there and not answer. 'not-utf8' and 'unreadable'
# were already refusals before this round (read_text decodes, and an EACCES
# is an OSError the guard named) and stay here as the controls that say the
# parametrisation is not what is doing the work; 'fifo' hung for ever,
# 'directory' and 'symlink-loop' raised, and 'dangling-link' was the silence -
# read_text answers ENOENT, which the reader spelled "no key stored here".
KEY_SHAPES = ("fifo", "directory", "dangling-link", "symlink-loop",
              "not-utf8", "unreadable")


@pytest.mark.parametrize("shape", KEY_SHAPES)
@pytest.mark.parametrize("command", KEY_READERS)
def test_a_master_key_of_any_shape_stops_a_subcommand_with_a_sentence(
        command, shape, configured, tmp_path, capsys):
    """A key that is there and will not read is not a key that is not there.

    The hang is the sharp end: a named pipe at ~/.carryon/master.key, or a
    symlink to /dev/zero, blocked `push`, `pull`, `pair` and `init` for ever,
    with no output at all, on both interpreters carryon must pass.

    The silence is the expensive one. A dangling link answered ENOENT, which
    `fetch_master` spells "this machine genuinely holds none yet" - so `push`
    advised running `carryon init`, which mints a fresh recovery key and
    leaves the Archive's History unopenable by the key it already had. That
    is fetch_master's own docstring describing the harm, about the one errno
    pair it still trusted.
    """
    path = configured / ".carryon" / "master.key"
    plant(path, shape)

    with time_limit():
        with pytest.raises(SystemExit) as exc:
            run_command(command, tmp_path)

    said = str(exc.value)
    assert str(path) in said, (
        f"`carryon {command}` refused a {shape} master key without naming "
        f"the file: {said}")
    assert "run `carryon init`" not in said, (
        "a key that is there and will not read must not be reported as no key "
        "at all - the advice that follows mints a new one and orphans the "
        f"Archive: {said}")


@pytest.mark.parametrize("shape", KEY_SHAPES)
def test_init_over_an_unreadable_master_key_mints_nothing(
        shape, configured, tmp_path, capsys):
    """The command that has to get this right, because it is the one that
    would replace the key.

    `init` asks whether this machine already holds one, and answers "no" by
    minting. A key it merely could not read used to read as no key at all - so
    a fifo hung it, and a dangling link had it generate a fresh recovery key,
    store it, and rewrite the config, leaving every Session already in the
    Archive sealed under the key that is still sitting in that file.
    """
    path = configured / ".carryon" / "master.key"
    plant(path, shape)
    before = path.lstat()

    with time_limit():
        with pytest.raises(SystemExit) as exc:
            cli.main(["init", "--dest", str(tmp_path / "elsewhere")])

    assert str(path) in str(exc.value)
    after = path.lstat()
    assert (after.st_mode, after.st_ino) == (before.st_mode, before.st_ino), \
        "init replaced a master key it could not read"


def test_an_honest_master_key_is_still_just_read(configured, tmp_path,
                                                 capsys):
    """The control the six shapes above are worth nothing without: the file
    carryon itself wrote, read by the same route, still opens the Archive."""
    with time_limit():
        assert cli.main(["push", "--apply"]) == 0
    assert "pushed" in capsys.readouterr().out

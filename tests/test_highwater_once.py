"""The high-water mark's warning is said once per command - and said again.

A characterization test, written before the module split that moves
`_STATE_REPORTED`, `_begin_command` and `_no_state` out of sync.py, because
nothing else in the suite counts warning lines. The de-duplication set and the
function that clears it are two halves of one promise, and a mover who leaves
the clearer behind - or lets the set be reached through a second module's
globals - breaks it with every existing test still green:

  once per command    the mark is read three or four times in one command (the
                      removal question, the rollback question, the write that
                      raises it), and four copies of one warning is how a user
                      learns to skip it.
  and again next time "once" means once per COMMAND, not once per interpreter.
                      This set outlives a command, so a second pull in the
                      same process - the suite, or any future in-process loop -
                      dropped the line entirely once, and the set grew without
                      bound besides.

Both halves are asserted over two pulls in one interpreter, which is the only
arrangement that can tell the two failures apart: counting inside one command
passes when the reset is gone, and counting across two passes when the set is.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import cli, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    build_home_a, file_keyring, ns)

# The line _no_state prints. Matched on its distinctive middle rather than the
# whole sentence, so a reworded warning stays counted and a deleted one does
# not.
WARNING = "carryon would not read"

# Valid JSON structure, invalid UTF-8 inside it: a truncated write, a synced
# folder's byte-mangled copy. Ordinary, and unreadable.
NOT_UTF8 = b'{"destinations": {"dir:caf\xe9": {}}}'


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """A machine that has been through `carryon init`, with a state.json that
    will not read standing where its high-water mark belongs."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))
    sync._state_path(home).write_bytes(NOT_UTF8)
    return home


def test_an_unreadable_mark_is_reported_once_per_command_and_once_again(
        configured, capsys):
    """Two pulls, one interpreter, one line each.

    Not "one line in total": the second pull is a second command and its user
    is owed the same sentence. And not "at least one" either - the count is
    exact on both runs, because the failure this pins is a warning printed
    once per READ of the mark rather than once per command asking about it.
    """
    capsys.readouterr()

    assert cli.main(["pull"]) == 0
    first = capsys.readouterr().out
    assert first.count(WARNING) == 1, (
        "the first pull did not say exactly once that its high-water mark "
        "would not read:\n" + first)

    assert cli.main(["pull"]) == 0
    second = capsys.readouterr().out
    assert second.count(WARNING) == 1, (
        "a second pull in the same interpreter did not say exactly once that "
        "its high-water mark would not read - the de-duplication set outlives "
        "a command and something has to clear it:\n" + second)


def test_the_set_that_de_duplicates_the_warning_is_cleared_by_its_owner(
        configured, capsys):
    """The mechanism under the test above, asserted directly.

    The two functions and the set they share are one unit: whoever holds the
    set holds the clearing of it. Reached by bare name through sync, which is
    what every other test in this suite does and what the re-export band
    exists to keep true.
    """
    capsys.readouterr()

    sync._no_state(sync._state_path(configured), "for the sake of argument")
    assert sync._STATE_REPORTED, "nothing recorded the path it just reported"
    assert capsys.readouterr().out.count(WARNING) == 1

    sync._no_state(sync._state_path(configured), "for the sake of argument")
    assert capsys.readouterr().out.count(WARNING) == 0, \
        "the same file was reported twice inside one command"

    sync._begin_command()
    assert not sync._STATE_REPORTED, \
        "_begin_command left the previous command's paths in the set"

    sync._no_state(sync._state_path(configured), "for the sake of argument")
    assert capsys.readouterr().out.count(WARNING) == 1, \
        "the warning stayed suppressed into the next command"

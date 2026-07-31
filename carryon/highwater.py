"""The High-water mark - how far into an Archive this machine has read.

An Index served from an old copy is authentic: a master key holder sealed it,
so nothing in the Archive separates a superseded catalogue from the current
one. What this machine has already seen is the one side of that comparison a
Destination cannot author, which is why the number is kept here rather than
there - and why the questions asked of it (has the Index been removed, has it
gone backwards) live beside it rather than beside the Index.

Not "revision": that names the number the Archive publishes, which is the side
the Destination CAN author. This module holds only the local half.

The one non-obvious thing: the mark is never a gate. A state.json that will
not read means "nothing seen yet" and a warning, never a refused pull - a mark
that could stop a machine working would be a worse failure than the weakened
check it is meant to raise. Never silent either, and said once per command:
the module-level set that de-duplicates that warning lives here with both the
function that writes to it and the `_begin_command` that clears it, because
"once" means once per command and the set outlives one.

A leaf over config (which owns the read and the write of carryon's own files)
and archive (which owns what an Index says about itself).
"""

from __future__ import annotations

import json
import pathlib

from . import archive, config


# --- the Archive's revision, as this machine has seen it ---------------------
#
# An Index served from an old copy is authentic - a master key holder sealed
# it - so no amount of crypto tells it from the current one. What a Destination
# cannot rewrite is what this machine already saw, so that number lives here.


def _state_path(home) -> pathlib.Path:
    return pathlib.Path(home) / ".carryon" / "state.json"


# Said once per file rather than once per read. The mark is read three or
# four times in one command - the removal question, the rollback question and
# the write that raises it - and four copies of one line is how a user learns
# to skip the line, which is the same objection _seen_revision already records
# against a rollback signal that cries wolf.
#
# Cleared as each command starts (_begin_command), because "once" means once
# per command and this set outlives one: a second pull in the same interpreter
# - the suite, or any future in-process loop - dropped the line entirely, and
# the set grew without bound besides.
_STATE_REPORTED = set()


def _begin_command() -> None:
    """Reset what is said once per command. One line today; the point is that
    module-level state used for de-duplication has an owner that clears it."""
    _STATE_REPORTED.clear()


def _no_state(path, why: str) -> dict:
    """Nothing seen yet, and one line saying why the mark could not say so."""
    if str(path) not in _STATE_REPORTED:
        _STATE_REPORTED.add(str(path))
        print(f"warning: carryon would not read {path} - {why}. carryon "
              "notices a deleted or rolled-back Index by comparing against "
              "the revision recorded there, so this machine has less to check "
              "the Destination against until the file is repaired or "
              "removed.")
    return {}


def _load_state(home) -> dict:
    """This machine's own notes about the Archive. Never a gate: unreadable
    or malformed state means 'nothing seen yet', not a refused pull.

    Never a gate, and never silent either. A mark that cannot be read is the
    same weakening _record_revision warns about when it cannot be written -
    the next pull notices one rollback less - so it says so and answers zero,
    rather than either raising or going quiet about a check that has just got
    weaker.

    Which of those two it is, this function no longer decides for itself.
    `config.read_state_json` is the one place carryon's own files turn into
    documents, and this leg had its own spelling of that read for one reason -
    the file is carryon's own rather than a user's - which is the same reason
    the Destination layer was trusted before ADR-0009 and is no better here.
    Two spellings of one question is what this cost: the decode error sat in
    the guard around the PARSE while the read was guarded for OSError only, so
    a state.json that is not UTF-8 - a truncated write, a synced folder's
    conflict copy, a restored backup, all of them ordinary and none of them an
    attacker - was a bare UnicodeDecodeError out of both `push` and `pull`,
    the two commands users actually run. A named pipe at the name blocked the
    read for ever, which is worse: nothing to read and nothing to report.

    The one thing this leg still decides is what a refusal MEANS here, and it
    is the opposite of what it means for the config: a mark that will not read
    is a warning and a zero, because the mark exists to make carryon notice
    more and must never become a way to stop a machine working.
    """
    path = _state_path(home)
    state = config.read_state_json(path)
    if state.absent:
        return {}  # nothing seen yet, and nothing wrong with that
    if state.why is not None:
        return _no_state(path, state.why)
    return state.value


def _seen_revision(home, spec: str) -> int:
    """The highest revision this machine has seen at THIS Destination.

    Per Destination, not per machine: one global number cries "rolled back"
    at a brand-new Archive the moment a home is pointed somewhere else, and a
    rollback signal users learn to skip is worse than none.
    """
    marks = _load_state(home).get("destinations")
    entry = marks.get(spec) if isinstance(marks, dict) else None
    value = entry.get("index_revision", 0) if isinstance(entry, dict) else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _record_revision(home, spec: str, revision: int) -> None:
    """Raise the high-water mark; never lower it, which is the whole point.

    The write is guarded because this mark is now load-bearing enough - it
    decides a removal, a rollback and which Setups may be restored - that a
    full or read-only $HOME turning a pull into a traceback would be the
    guard's own doing, before the report and after the History has landed. A
    mark that cannot be written is a warning: the next pull will read a lower
    number and notice one rollback less, which is a weaker check and not a
    wrong answer.
    """
    if revision <= _seen_revision(home, spec):
        return
    state = _load_state(home)
    marks = state.get("destinations")
    if not isinstance(marks, dict):
        marks = {}
    marks[spec] = {"index_revision": revision}
    state["destinations"] = marks
    path = _state_path(home)
    try:
        # The third file in ~/.carryon and the third plain write, refused
        # through a link like the two beside it (ADR-0007): a mark written
        # into somebody's dotfiles repo is a mark this machine does not have.
        config.write_state_file(
            path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    except (OSError, SystemExit) as exc:
        # SystemExit as well as OSError, and it stays a warning either way:
        # the mark is never a gate. A refusal here costs one check on the next
        # run, where a raise would cost the Snapshot this run is pushing.
        print(f"warning: could not record the Archive's revision at {path} "
              f"({getattr(exc, 'strerror', None) or exc}). carryon notices a "
              "deleted or rolled-back Index by comparing against that number, "
              "so until it can be written this machine has less to check the "
              "Destination against.")


def _rollback_note(home, spec: str, index: dict):
    """How far the Archive has gone backwards, as prose, or None."""
    seen = _seen_revision(home, spec)
    now = archive.index_revision(index)
    if not seen or now >= seen:
        return None
    return (f"the Archive's Index is at revision {now}, but this machine has "
            f"already seen revision {seen}. An Index only moves forward, so "
            "this one has been rolled back - an old copy restored, a revert, "
            "or a Destination serving what it likes. Anything pushed after "
            f"revision {now} is missing from it.")


def _index_removed_note(home, spec: str, index: dict):
    """Why the Archive's Index is gone rather than never written, or None.

    Nothing a Destination serves tells the two apart - archive.load_index
    says why, and ADR-0004's keyless Archive is the case that makes it
    genuinely undecidable there - so the evidence is local, and there is
    exactly one piece of it: this machine has read an Index at this
    Destination before. That is the number the rollback high-water mark
    already holds, put to a second question, and it is written at every
    moment this machine could have learnt the fact - a push, a pull, and the
    pairing that handed it the master key, which carries the revision inside
    the wrap so that a machine which has never pulled still holds it.

    It is the one statement about this Archive an attacker with write access
    to the Destination cannot compose: they can delete every object under
    carryon/, and none of that reaches $HOME.
    """
    if not archive.index_is_absent(index):
        return None
    seen = _seen_revision(home, spec)
    if not seen:
        return None
    return (
        f"the Archive serves no Index at {archive.INDEX_KEY}, and this "
        f"machine has already read one there at revision {seen}. Only a "
        "master key holder can write that object, so it has been deleted at "
        "the Destination - and with it the record of which machines' Setups "
        "are authenticated, which is the whole of what a stored Setup is "
        "checked against (ADR-0004). Every Setup in the Archive now reads as "
        "a keyless push nothing can verify, which is exactly what deleting "
        "it buys.")


def _refuse_on_index_removal(home, spec: str, index: dict, verb: str) -> None:
    """Stop, on either leg, when the Index has been removed since this
    machine last looked.

    Both legs and the dry run too, unlike a rollback, which pull only warns
    about: a rollback hides Sessions and carryon cannot tell a hostile replay
    from a git revert, so refusing there would strand a user whose Destination
    really did lose a write. A removal costs them nothing to refuse - the
    catalogue is the only route to a stored Session, so there is no History
    left to restore either way, and the only thing a pull could still lay
    down is a Setup that nothing vouches for. That leaves the plan a dry run
    would print as untrustworthy as the writes an --apply would make.
    """
    note = _index_removed_note(home, spec, index)
    if note is None:
        return
    raise SystemExit(
        f"refusing to {verb}: {note}\nRestore an earlier copy of the Archive "
        "(a git Destination keeps one in its history) and this machine "
        "carries on where it left off. Pushing from another machine will not "
        "rebuild it: the objects under carryon/sessions/ are named by an "
        "HMAC, and the Index was the only record of which Session each one "
        "is. So if the Archive really was emptied on purpose, accept the "
        f"loss deliberately - drop this Destination's entry from "
        f"{_state_path(home)}, and push afresh.")


def _warn_on_rollback(home, spec: str, index: dict) -> None:
    """Say so when the Archive has gone backwards - and carry on.

    A warning is the whole behaviour on the READ path. An old Index hides
    every Session pushed since it was written, but carryon cannot tell a
    hostile replay from a git revert or a synced folder restored from backup,
    and refusing would strand the user in the case where the Destination
    really did lose a write. push is the other case entirely - see
    _refuse_on_rollback.
    """
    note = _rollback_note(home, spec, index)
    if note:
        print(f"warning: {note} Anything pushed after it will look absent "
              "here.\n")


def _refuse_on_rollback(home, spec: str, index: dict) -> None:
    """Refuse to push onto an Index this machine has already seen past.

    A pull against a stale Index hides Sessions; a push against one destroys
    them. The stale catalogue is re-sealed as the current one, and every
    Session another machine pushed since is unlinked from it - along with
    that machine's entry in index['setups'], the one field _setup_catalogue
    cannot have been forged. There is nothing to merge against, because the
    Index the other machine wrote is exactly what went missing, so this fails
    closed and names the escape hatch instead of guessing.
    """
    note = _rollback_note(home, spec, index)
    if note:
        raise SystemExit(
            f"refusing to push: {note}\nPushing now would re-seal that "
            "catalogue as the current one and unlink every Session pushed "
            "since. Sort the Destination out first - restore the newer "
            f"Index, or if the rollback was deliberate, drop this "
            f"Destination's entry from {_state_path(home)} to accept it.")

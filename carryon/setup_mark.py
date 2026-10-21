"""The Setup mark: which Setup this machine last sealed or laid down, and what
it held (ADR-0015, CONTEXT.md **Setup mark**).

Kept here, beside the High-water mark and the Bases, because it records what
this machine has seen. The Archive cannot hold it: the Index's entry for a
Setup carries a random stamp rather than a digest, so nothing there says
whether a Setup changed, and a pull restores the newest Setup any vouched
machine pushed, so a Setup can be behind as well as ahead.

One record per Destination in state.json, `{"stamp", "digest"}`. A command
that moves part of a Setup clears it rather than guessing, because a digest of
the whole that describes only half of what the Archive holds is a status that
lies. Never a gate: a mark that will not read is absent, and one that will not
write is a warning, as the High-water mark is.
"""

from __future__ import annotations

import json
import pathlib

from . import capture, config
from .adapters import SETUP_CATEGORIES
from .highwater import _load_state, _state_path

KEY = "setup_marks"

# A digest no capture produces. Recorded by a pull whose Setup did not land
# whole - a write refused, one left to its external owner, or something here
# the laid-down Setup never held - so the stamp still says which Setup this
# machine has seen, and `status` still says this machine's Setup differs.
UNSETTLED = ""


def load(home, spec: str):
    """{"stamp", "digest"} for this Destination, or None when there is none
    or what is there is not one."""
    marks = _load_state(home).get(KEY)
    entry = marks.get(spec) if isinstance(marks, dict) else None
    if not isinstance(entry, dict):
        return None
    stamp, digest = entry.get("stamp"), entry.get("digest")
    if not (isinstance(stamp, str) and isinstance(digest, str)):
        return None
    return {"stamp": stamp, "digest": digest}


def whole(setup_categories, want_agents=None) -> bool:
    """Whether a command moved this machine's whole Setup, which is the only
    move a mark may describe."""
    return set(setup_categories) == set(SETUP_CATEGORIES) and not want_agents


def capture_here(home, effective) -> tuple:
    """(digest, landing paths) for this machine's whole Setup as it stands,
    or (None, ()) when a capture of it would refuse. A dry, silent
    capture: the caller is a pull that has already reported, or a `status`
    whose output is its own."""
    # Imported here, as resolve does: sync imports this module.
    from .sync import _swapped_registry
    seen = {}
    home = pathlib.Path(home)
    with _swapped_registry(effective):
        if capture.state_reads(None, set(SETUP_CATEGORIES), home):
            return None, ()
        capture.collect(home / ".carryon" / "staging" / "status", True,
                        None, None, home, digest_into=seen)
    if "digest" not in seen:
        return None, ()
    return seen["digest"], frozenset(seen["paths"])


def digest_here(home, effective):
    return capture_here(home, effective)[0]


def settle(home, spec: str, stamp, digest) -> None:
    """Record {stamp, digest}, or clear the mark when either is missing:
    the one rule every command that moves a Setup ends on."""
    if isinstance(stamp, str) and isinstance(digest, str):
        _write(home, spec, {"stamp": stamp, "digest": digest})
    else:
        _write(home, spec, None)


def _write(home, spec: str, entry) -> None:
    state = _load_state(home)
    marks = state.get(KEY)
    if not isinstance(marks, dict):
        marks = {}
    if marks.get(spec) == entry or (entry is None and spec not in marks):
        return
    if entry is None:
        marks.pop(spec, None)
    else:
        marks[spec] = entry
    state[KEY] = marks
    path = _state_path(home)
    try:
        config.write_state_file(
            path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    except (OSError, SystemExit) as exc:
        # A warning and never a raise: the mark only feeds `status`, and a
        # push that has already published its Setup must not end in a
        # traceback over a note about it.
        print(f"warning: could not record the Setup mark at {path} "
              f"({getattr(exc, 'strerror', None) or exc}). `carryon status` "
              "will say this machine's Setup is not known until a push or "
              "pull can write it.")

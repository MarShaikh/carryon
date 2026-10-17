"""The Base - the version of a per-project memory file this machine and the
Archive last agreed on (ADR-0002, amendment of 2026-10-17).

The prefix rule assumes a file only grows, and memory does not: an agent
rewrites a line of MEMORY.md in place as often as it adds one. The Base is what
tells that edit apart from a divergence. If only one side has moved off it,
that side wins, on push and on pull alike. Only when both have moved is it a
divergence, and then the prefix rule runs as it always did.

Kept in ~/.carryon/state.json under its own top-level key, beside the
High-water mark and for the same reason: it records what this machine has
seen, which no Destination can author. Not inside the mark's per-Destination
entry, because `highwater._record_revision` rewrites that entry whole.

The one non-obvious thing: a missing Base can only make carryon more cautious,
never less. So, like the mark, the store is never a gate. A state.json that will
not read means no Bases for that command, said once, and the prefix rule decides
alone. A Base that cannot be written is a warning: the next run judges that
file by the prefix rule, which is a stricter check rather than a wrong answer.

A leaf over config (which owns the read and the write of carryon's own files)
and highwater (which owns the "said once per command" set those two share).
"""

from __future__ import annotations

import hashlib
import json
import pathlib

from . import config
from .highwater import _STATE_REPORTED, _state_path

KEY = "bases"

# What the Base says about one file, when it says anything.
LOCAL = "local"        # only this machine moved off the Base: its copy wins
ARCHIVE = "archive"    # only the Archive moved off the Base: its copy wins


def digest(canonical: bytes) -> str:
    """The Base of one file: sha256 of its canonical (re-keyed) bytes, the
    same bytes push packs and pull compares, so two machines agree on it."""
    return hashlib.sha256(canonical).hexdigest()


def decide(local: bytes, incoming: bytes, base) -> str | None:
    """Which side moved off the Base, or None when the Base does not decide:
    there is none, the copies are the same, or both moved."""
    if base is None or local == incoming:
        return None
    local_moved = digest(local) != base
    archive_moved = digest(incoming) != base
    if local_moved and not archive_moved:
        return LOCAL
    if archive_moved and not local_moved:
        return ARCHIVE
    return None


def _say_once(path, sentence: str) -> None:
    key = f"bases:{path}"
    if key not in _STATE_REPORTED:
        _STATE_REPORTED.add(key)
        print(f"warning: {sentence}")


def _read(home):
    """The whole state document, or None with the reason said once."""
    path = _state_path(home)
    state = config.read_state_json(path)
    if state.absent:
        return {}
    if state.why is not None or not isinstance(state.value, dict):
        # Not "carryon would not read": the High-water mark's warning has
        # usually said that about this same file already, and a fault said
        # twice is a line users learn to skip.
        _say_once(path, f"{path} also holds the Bases that let an in-place "
                  "edit to per-project memory travel, and it is unusable ("
                  f"{state.why or 'it is not a JSON object'}). For this run "
                  "every memory file is judged by the prefix rule alone "
                  "(ADR-0002).")
        return None
    return state.value


def load(home, spec: str) -> dict:
    """{project cwd: {member: Base}} for one Destination. Read once, at the
    start of a command and before the High-water mark is written, because
    that write replaces a state.json that would not read."""
    state = _read(home)
    if not state:
        return {}
    projects = state.get(KEY, {})
    projects = projects.get(spec) if isinstance(projects, dict) else None
    if not isinstance(projects, dict):
        return {}
    out = {}
    for cwd, members in projects.items():
        if isinstance(members, dict):
            out[cwd] = {m: h for m, h in members.items()
                        if isinstance(m, str) and isinstance(h, str)}
    return out


def record(home, spec: str, cwd: str, members: dict,
           replace: bool = False) -> None:
    """Write Bases for one project. `replace` drops every member not named,
    which is what a push means: the stored tree is now exactly this one."""
    if not members and not replace:
        return
    state = _read(home)
    if state is None:
        return
    projects = state.get(KEY)
    if not isinstance(projects, dict):
        projects = {}
    per_dest = projects.get(spec)
    if not isinstance(per_dest, dict):
        per_dest = {}
    current = {} if replace else dict(per_dest.get(cwd) or {})
    current.update(members)
    if per_dest.get(cwd) == current:
        return   # every unchanged push re-states its agreement; no rewrite
    per_dest[cwd] = current
    projects[spec] = per_dest
    state[KEY] = projects
    path = _state_path(home)
    try:
        config.write_state_file(
            path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    except (OSError, SystemExit) as exc:
        _say_once(path, f"could not record Bases at {path} "
                  f"({getattr(exc, 'strerror', None) or exc}). The memory "
                  "files they were for are judged by the prefix rule alone "
                  "until one can be written.")


def project_conflict_dir(home, project_dir) -> pathlib.Path:
    """Where pull files a residue's divergent members: under ~/.carryon, by
    the name of the project directory they belong to (ADR-0002)."""
    return (pathlib.Path(home) / ".carryon" / "conflicts"
            / pathlib.PurePosixPath(project_dir).name)

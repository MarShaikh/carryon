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
FILED = "filed_bases"   # the Archive copy each filed conflict holds

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
        # Without the Bases, every memory file is judged by the prefix rule
        # alone (ADR-0002).
        _say_once(path, f"{path} is unusable ("
                  f"{state.why or 'it is not a JSON object'}), so for this "
                  "run an edited memory file only travels if it adds to the "
                  "end of the other copy.")
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


def _update(home, change) -> bool:
    """Read state.json once, let `change` edit it, write it once. True when
    what was asked for is now on disk, including when nothing needed writing.
    False, said once, when it is not, so a caller whose promise depends on
    the write can stop before making it."""
    state = _read(home)
    if state is None:
        return False
    before = json.dumps(state, sort_keys=True)
    change(state)
    if json.dumps(state, sort_keys=True) == before:
        return True   # an unchanged push re-states its agreement; no rewrite
    path = _state_path(home)
    try:
        config.write_state_file(
            path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    except (OSError, SystemExit) as exc:
        _say_once(f"{path}:write", f"could not record Bases at {path} "
                  f"({getattr(exc, 'strerror', None) or exc}). The memory "
                  "files they were for are judged by the prefix rule alone "
                  "until one can be written.")
        return False
    return True


def _projects(state, key: str, spec: str) -> dict:
    """state[key][spec], made into dicts wherever it is not one."""
    table = state.get(key)
    if not isinstance(table, dict):
        table = state[key] = {}
    per_dest = table.get(spec)
    if not isinstance(per_dest, dict):
        per_dest = table[spec] = {}
    return per_dest


def record(home, spec: str, projects: dict, replace: bool = False) -> bool:
    """Write Bases for {cwd: {member: Base}}, in one write. `replace` drops
    every member not named, which is what a push means: the stored tree is
    now exactly this one."""
    if not any(projects.values()) and not replace:
        return True

    def change(state):
        per_dest = _projects(state, KEY, spec)
        for cwd, members in projects.items():
            current = {} if replace else dict(per_dest.get(cwd) or {})
            current.update(members)
            per_dest[cwd] = current
    return _update(home, change)


def record_filed(home, spec: str, projects: dict) -> bool:
    """Remember the Base of each Archive copy a pull filed as a conflict.

    The canonical bytes pull compared are the only exact record of that
    copy. The filed file holds them expanded for this machine, possibly
    under --map, and expansion does not always run backwards. So `resolve`
    promotes this hash rather than re-deriving one from the file.
    """
    if not any(projects.values()):
        return True

    def change(state):
        per_dest = _projects(state, FILED, spec)
        for cwd, members in projects.items():
            per_dest.setdefault(cwd, {}).update(members)
    return _update(home, change)


def filed_base(home, spec: str, cwd: str, member: str):
    """The hash a pull recorded for the copy it filed, or None."""
    state = _read(home) or {}
    table = state.get(FILED)
    entry = table.get(spec) if isinstance(table, dict) else None
    entry = entry.get(cwd) if isinstance(entry, dict) else None
    value = entry.get(member) if isinstance(entry, dict) else None
    return value if isinstance(value, str) else None


def resolve_member(home, spec: str, cwd: str, member: str,
                   base: str) -> bool:
    """Make `base` the member's Base and forget the filed entry, in one
    write. False when that write did not happen."""
    def change(state):
        _projects(state, KEY, spec).setdefault(cwd, {})[member] = base
        filed = _projects(state, FILED, spec).get(cwd)
        if isinstance(filed, dict):
            filed.pop(member, None)
    return _update(home, change)


def project_conflict_dir(home, project_dir) -> pathlib.Path:
    """Where pull files a residue's divergent members: under ~/.carryon, by
    the name of the project directory they belong to (ADR-0002)."""
    return (pathlib.Path(home) / ".carryon" / "conflicts"
            / pathlib.PurePosixPath(project_dir).name)

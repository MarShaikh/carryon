"""status - what this machine and the Archive disagree about, said without
moving anything (ADR-0015, CONTEXT.md **Status**).

It reads the Index, the `setups/` listing and this machine, and nothing else:
no object is downloaded and nothing is written, here or at the Destination.
Its answers are therefore advisory, and that is safe only because it writes
nothing. The push or pull it suggests still makes every check of its own
before it writes. An Index can veto an overwrite and never authorise one, and
a status neither overwrites nor authorises.

The rules are the ones push and pull already ask, borrowed rather than
restated: the tree hash says whether a Session or a project differs at all,
`_index_veto` says when the Archive's main Transcript is longer or forked,
the Bases say which side of a project moved, and `_choose_setup_source` says
whose Setup a pull would lay down.
"""

from __future__ import annotations

import pathlib
import re

from . import archive, bases, history, resolve, setup_mark
from .destinations.base import printable
from .highwater import _begin_command, _index_removed_note, _rollback_note
from .session import (_canonical_members, _digests_hash, _index_veto,
                      _members_hash, _no_history_here)
from .setup_out import _canon_home
from .stored_setup import _choose_setup_source, _setup_catalogue
from .sync import _effective_adapters, _open_destination, _require_master

PUSH, PULL = "push", "pull"

_PUSHED_AT = re.compile(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d)")


def run(args, home) -> int:
    home = pathlib.Path(home)
    _begin_command()
    verbose = bool(getattr(args, "verbose", False))
    cfg, dest = _open_destination(home)
    master = _require_master(home)
    spec = cfg["destination"]
    effective = _effective_adapters(cfg, home)
    index = archive.load_index(dest, master)

    # The notes push and pull print, and nothing more: a status refuses
    # nothing, and the High-water mark stays where it was.
    note = (_index_removed_note(home, spec, index)
            or _rollback_note(home, spec, index))
    if note:
        print(f"warning: {note}\n")
    refused = archive.index_refusals(index)
    if refused:
        print(f"{len(refused)} entr{'y' if len(refused) == 1 else 'ies'} in "
              "the Archive's Index couldn't be read - left out below:")
        for refusal in refused:
            print(f"  {printable(str(refusal.key))}: {refusal.why}")
        print()
    # Per catalogue, as push keeps them: a cwd and a UUID are different
    # namespaces, and a refusal in one must not hide a key in the other.
    unreadable = {name: {r.key for r in refused if r.catalogue == name}
                  for name in ("sessions", "projects")}

    found = history.discover(home, list(effective.values()))
    memory, filed_sessions = _filed(index, found, home)
    filed_memory = sorted(_home_path(path, home) for _r, _m, path in memory)
    # What is filed is reported as filed and not also as something to pull:
    # the pull would only file it again, and nothing about a filed copy is
    # closed by `sync` (ADR-0015).
    items = (_sessions(index, found, effective, home, unreadable["sessions"],
                       set(filed_sessions))
             + _projects(index, found, effective, home, spec,
                         unreadable["projects"],
                         {_canon_home(r.cwd, home) for r, _m, _p in memory}))
    setup_lines = _setup(dest, index, home, effective, spec)

    if not (items or filed_memory or filed_sessions or setup_lines):
        print(f"in step with {dest.describe()}")
        return 0

    print(f"status: {dest.describe()}")
    if items:
        to_push = sum(1 for direction, _ in items if direction == PUSH)
        to_pull = len(items) - to_push
        parts = ([f"{to_push} to push"] if to_push else []) + \
                ([f"{to_pull} to pull"] if to_pull else [])
        print(f"History: {', '.join(parts)} - run `carryon sync --apply`")
        if verbose:
            for direction, label in sorted(items):
                print(f"  {direction:<8} {label}")
    if filed_memory:
        count = len(filed_memory)
        print(f"Filed: {count} memory file{'' if count == 1 else 's'} "
              f"diverged - merge {'it' if count == 1 else 'each'}, then run "
              "`carryon resolve`")
        if verbose:
            for path in filed_memory:
                print(f"  filed    {printable(path)}")
    if filed_sessions:
        count = len(filed_sessions)
        print(f"Filed: {count} Session{'' if count == 1 else 's'} diverged "
              "- the Archive's copy is under ~/.carryon/conflicts/<uuid>/ "
              "for you to merge")
        if verbose:
            for uuid in filed_sessions:
                print(f"  filed    ~/.carryon/conflicts/{printable(uuid)}/")
    for line in setup_lines:
        print(line)
    return 0


# --- the History -------------------------------------------------------------


def _pullable(meta, effective) -> bool:
    """Whether this machine carries History for the entry's agent at all:
    the cases pull itself reports as unrestorable are not something to
    pull."""
    agent = meta.get("agent", "")
    return agent in effective and not _no_history_here(agent, effective)


def _sessions(index, found, effective, home, unreadable, filed) -> list:
    entries = index.get("sessions", {})
    local = {}
    for session in found.sessions:
        local.setdefault(session.uuid, []).append(session)
    items = []
    for uuid, copies in sorted(local.items()):
        if uuid in unreadable:
            continue
        label = f"{printable(uuid)} ({printable(copies[0].agent)})"
        entry = entries.get(uuid)
        if not isinstance(entry, dict):
            items.append((PUSH, label))
            continue
        direction = _session_direction(copies, entry, home)
        if direction == PULL and uuid in filed:
            continue
        if direction is not None:
            items.append((direction, label))
    for uuid in sorted(entries):
        meta = entries[uuid]
        if uuid in local or not isinstance(meta, dict):
            continue
        if not meta.get("cwd") or not _pullable(meta, effective):
            continue
        items.append((PULL, f"{printable(uuid)} "
                            f"({printable(meta.get('agent', ''))})"))
    return items


def _session_direction(copies, entry, home):
    """PUSH, PULL, or None when this machine already holds what the Index
    describes. Only the Index and the local bytes are read: a main Transcript
    shorter than the stored one, or one whose prefix differs, is behind or
    forked, and anything else that differs is for push to compare."""
    first = None
    for session in copies:
        members = _canonical_members(session, home)
        if members is None:
            continue
        if _members_hash(members) == entry.get("tree_hash"):
            return None
        if first is None:
            first = (session, members)
    if first is None:
        return None   # nothing here would read; push and pull say why
    session, members = first
    canon = members.get(session.main_path, b"")
    return PULL if _index_veto(entry, canon) is not None else PUSH


def _projects(index, found, effective, home, spec, unreadable,
              filed) -> list:
    entries = index.get("projects", {})
    known = bases.load(home, spec)
    local = {_canon_home(r.cwd, home): r for r in found.residues if r.cwd}
    items = []
    for cwd, residue in sorted(local.items()):
        if cwd in unreadable:
            continue
        label = f"memory {printable(cwd)} ({printable(residue.agent)})"
        entry = entries.get(cwd)
        members = _canonical_members(residue, home)
        if members is None:
            continue
        if not isinstance(entry, dict):
            if members:
                items.append((PUSH, label))
            continue
        here = _members_hash(members)
        there = entry.get("tree_hash")
        if here == there:
            continue
        base = known.get(cwd)
        if not base:
            if cwd not in filed:
                items.append((PULL, label))   # pull's prefix rule decides
            continue
        agreed = _digests_hash(base)
        local_moved, archive_moved = here != agreed, there != agreed
        direction = PUSH if local_moved and not archive_moved else PULL
        if direction == PULL and cwd in filed:
            continue
        items.append((direction, label))
    for cwd in sorted(entries):
        meta = entries[cwd]
        if cwd in local or not isinstance(meta, dict):
            continue
        if not _pullable(meta, effective):
            continue
        items.append((PULL, f"memory {printable(cwd)} "
                            f"({printable(meta.get('agent', ''))})"))
    return items


def _home_path(path, home) -> str:
    try:
        return "~/" + pathlib.Path(path).relative_to(home).as_posix()
    except ValueError:
        return str(path)


def _filed(index, found, home) -> tuple:
    """(memory, sessions): the filed copies waiting on a person. Memory is
    `carryon resolve`'s own list. A Session is filed under
    ~/.carryon/conflicts/<uuid>/, and only a directory named for a Session
    this machine or the Index knows is counted as one."""
    memory = resolve.filed_memory(found, home)
    known = ({s.uuid for s in found.sessions}
             | set(index.get("sessions", {})))
    sessions = []
    root = home / ".carryon" / "conflicts"
    for uuid in sorted(known):
        directory = root / uuid
        try:
            holds = directory.is_dir() and any(p.is_file()
                                               for p in directory.rglob("*"))
        except OSError:
            holds = False
        if holds:
            sessions.append(uuid)
    return memory, sessions


# --- the Setup ---------------------------------------------------------------


def _setup(dest, index, home, effective, spec) -> list:
    here = setup_mark.digest_here(home, effective)
    mark = setup_mark.load(home, spec)
    lines = []
    if here is None:
        # A pull does not capture this machine, so a refusal here does not
        # stop one, and another machine's newer Setup is still worth saying.
        lines.append("Setup: a push would refuse it - `carryon push` shows "
                     "why")
    elif mark is None:
        return ["Setup: not known here until a full push or pull"]
    if mark is None:
        return lines
    changed_here = here is not None and here != mark["digest"]
    setups, _unusable = _setup_catalogue(dest, index)
    source, _ignored = _choose_setup_source(setups)
    if source is not None and setups[source].get("index_stamp") != mark["stamp"]:
        line = (f"Setup: {printable(source)} pushed changes "
                f"({_when(setups[source].get('pushed_at'))}) - run "
                "`carryon pull --apply` to bring them here")
        if changed_here:
            line += ("; it replaces the changes made here, after backing "
                     "them up")
        lines.append(line)
    if changed_here:
        lines.append("Setup: changed here since your last push - run "
                     "`carryon push --apply` to send it")
    return lines


def _when(pushed_at) -> str:
    match = _PUSHED_AT.match(pushed_at if isinstance(pushed_at, str) else "")
    if match is None:
        return printable(str(pushed_at))
    return f"{match.group(1)} {match.group(2)}"

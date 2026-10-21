"""`carryon resolve` - end a filed divergence in per-project memory.

ADR-0002, amendment of 2026-10-17. A pull that finds a memory file changed on
both sides keeps the local copy and files the Archive's under
~/.carryon/conflicts/<project>/. Until then nothing ever ended that state: the
next push compared against the same stored copy and skipped again. Resolving
is the user saying "my copy now includes theirs", and in three-way terms that
means "theirs is my Base". So the filed copy's canonical hash becomes that
file's Base, the filed copy goes, and the next push carries the merge.

The one non-obvious thing: it is deliberately something the user does, with
the path named. A filed copy that has merely gone missing is never taken as
resolved, because an accidental `rm -rf ~/.carryon/conflicts` would then read
as a merge of everything, and the next push would undo another machine's
edits. And if the Archive has moved again since the conflict was filed, the
Base is stale and the next run files a fresh conflict - so a wrong resolve
costs a second merge, never an overwrite.

Touches no Destination and needs no key: everything it reads is on this
machine.
"""

from __future__ import annotations

import os
import pathlib

from . import bases, config, history
from .destinations.base import printable
from .highwater import _begin_command
from .session import _rel_to_home
from .setup_out import _canon_home


def _effective(cfg, home):
    # Imported here: sync imports a great deal, and resolve needs one helper.
    from .sync import _effective_adapters
    return _effective_adapters(cfg, home)


def _filed(home, residue, rel) -> pathlib.Path:
    return bases.project_conflict_dir(home, residue.project_dir) / rel


def _identity(path):
    """(device, inode) of the file a path names, or None. Identity rather
    than spelling, because a path typed from inside a project can reach the
    same file by '..', a relative step, or a linked directory such as macOS's
    /var -> /private/var, and every one of those must name it."""
    try:
        info = os.stat(str(path))
    except (OSError, ValueError):
        return None
    return info.st_dev, info.st_ino


def _find(path, residues, sessions, home):
    """(residue, member) for the memory file at `path`, or a refusal,
    matched by file identity (see _identity)."""
    target = pathlib.Path(path).expanduser()
    wanted = _identity(target)
    for residue in residues if wanted else ():
        root = home / residue.project_dir
        for rel in residue.files:
            if _identity(root / rel) == wanted:
                return residue, rel
    for session in sessions if wanted else ():
        root = home / session.project_dir
        if any(_identity(root / rel) == wanted for rel in session.files):
            raise SystemExit(
                f"refusing to resolve {printable(str(target))}: it belongs to "
                f"Session {printable(session.uuid)}, and only per-project "
                "memory has a Base to resolve against (ADR-0002). A divergent "
                "Transcript stays filed under ~/.carryon/conflicts/<uuid>/.")
    raise SystemExit(
        f"refusing to resolve {printable(str(target))}: it is not a "
        "per-project memory file carryon carries, so nothing is filed for it")


def _plan(path, found, home, spec):
    """(local, filed, project conflicts dir, cwd, member, Base) for one
    path, or a refusal. Every path is planned before anything changes, so
    one bad path leaves all of them as they were.

    The Base is the hash pull recorded for the copy it filed: the canonical
    bytes it compared, which the expanded file cannot always reproduce (a
    `--map` pull, for one). A conflict filed before that record existed
    falls back to re-canonicalising the filed file; if that comes out
    different, the next run just files a fresh conflict.
    """
    residues = [r for r in found.residues if r.cwd]
    residue, rel = _find(path, residues, found.sessions, home)
    local = home / residue.project_dir / rel
    filed = _filed(home, residue, rel)
    state = config.read_state_bytes(filed)
    if state.absent:
        raise SystemExit(
            f"refusing to resolve ~/{printable(_rel_to_home(local, home))}: "
            "nothing is filed for it under ~/.carryon/conflicts/, so there "
            "is no Archive copy to have merged. `carryon resolve` lists what "
            "is filed.")
    if state.why is not None:
        raise SystemExit(f"refusing to resolve "
                         f"~/{printable(_rel_to_home(local, home))}: the filed "
                         f"copy at {printable(str(filed))} will not read - "
                         f"{state.why}")
    cwd = _canon_home(residue.cwd, home)
    base = bases.filed_base(home, spec, cwd, rel)
    if base is None:
        canon, _, _, _ = history.canonical_member(rel, state.value, home)
        base = bases.digest(canon)
    return (local, filed,
            bases.project_conflict_dir(home, residue.project_dir),
            cwd, rel, base)


def _prune(directory: pathlib.Path, stop: pathlib.Path) -> None:
    """Remove the directories a resolve emptied, up to and including the
    project's own conflicts directory."""
    while directory != stop.parent and directory.is_dir():
        try:
            directory.rmdir()
        except OSError:
            return
        directory = directory.parent


def filed_memory(found, home) -> list:
    """(residue, member, filed path) for every memory file a pull filed and
    nobody has resolved yet. `carryon status` counts the same list, so the
    two can never disagree about what is waiting."""
    pending = []
    for residue in (r for r in found.residues if r.cwd):
        for rel in residue.files:
            filed = _filed(home, residue, rel)
            if filed.is_file():
                pending.append((residue, rel, filed))
    return pending


def _list(found, home) -> int:
    pending = [(home / residue.project_dir / rel, filed)
               for residue, rel, filed in filed_memory(found, home)]
    if not pending:
        print("Nothing is filed: no per-project memory file is waiting to "
              "be resolved.")
        return 0
    print(f"{len(pending)} memory file(s) diverged and are filed. Merge the "
          "Archive's copy into each local copy, then run "
          "`carryon resolve <path> --apply`:")
    for local, filed in pending:
        print(f"  filed    ~/{printable(_rel_to_home(local, home))}  <- "
              f"{printable(str(filed))}")
    return 0


def run(args, home) -> int:
    home = pathlib.Path(home)
    _begin_command()
    apply = bool(getattr(args, "apply", False))
    cfg = config.load(home)
    if not cfg["destination"]:
        raise SystemExit(
            "no Destination configured - run `carryon init --dest SPEC` first")
    found = history.discover(home, list(_effective(cfg, home).values()))
    paths = getattr(args, "paths", None) or []
    if not paths:
        return _list(found, home)
    plans, seen = [], set()
    for path in paths:
        plan = _plan(path, found, home, cfg["destination"])
        if plan[1] not in seen:   # two spellings of one file resolve once
            seen.add(plan[1])
            plans.append(plan)
    for local, filed, stop, cwd, rel, base in plans:
        print(f"  resolve  ~/{printable(_rel_to_home(local, home))} - the "
              f"filed copy becomes its Base, and {printable(str(filed))} "
              "is removed")
        if not apply:
            continue
        if not bases.resolve_member(home, cfg["destination"], cwd, rel, base):
            # The Base IS the resolution. Without it the filed copy is the
            # only record of what was merged, so it stays, and the user is
            # not told the next push carries anything.
            raise SystemExit(
                f"could not record the Base for "
                f"~/{printable(_rel_to_home(local, home))} (said above), so "
                f"nothing was resolved and {printable(str(filed))} is still "
                "filed. Fix ~/.carryon/state.json and run this again.")
        filed.unlink()
        _prune(filed.parent, stop)
    if apply:
        print(f"\n{len(plans)} resolved. The next `carryon push --apply` "
              "carries the merge.")
    else:
        print("\nDry run. Re-run with --apply to resolve.")
    return 0

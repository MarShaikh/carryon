"""Detect that an agent has changed its on-disk layout.

Vendors move files without notice. When that happens a path-driven tool has two
options: fail loudly, or quietly copy less than the user thinks. Mackup chose
the second by accident and broke for years before anyone could say exactly how.

`inspect` answers three questions per installed agent:
  - is anything here that this adapter has never heard of?
  - is this platform one the adapter was actually verified on?
  - and is there anything here this machine will not answer about?

Run it before a migration, not after.

The third question is the one this walk was missing, and it is the same rule
capture.tree_files and history._listing already spell for theirs: $HOME is
input. A mode-000 agent directory needs no attacker - a backup restored with
the wrong owner, or an agent that once ran under sudo, produces one - and it
used to come out of `doctor` as a PermissionError from inside iterdir, before
a line had been printed. `doctor` is the command a user runs when something is
already wrong, so a traceback out of it is the one answer it must never give:
report it, name it, carry on with the other agents.

The non-obvious decision: the install check is `os.stat` here rather than the
`is_installed` every other caller uses. Path.exists() swallows exactly four
errnos - ENOENT, ENOTDIR, EBADF, ELOOP - and raises for every other one, so
"this machine will not answer about that path" reached this walk as an
exception rather than as an answer. The two agree wherever exists() can
answer at all; where it cannot, this one reports instead of raising, and a
root that is present but is not a directory is reported rather than counted
as an agent with nothing unrecognised in it.
"""

from __future__ import annotations

import errno
import fnmatch
import os
import pathlib
import stat
import sys

from .adapters import ADAPTERS, HOME
from .destinations.base import printable

# Every name in this report comes off the user's filesystem, and the report
# IS what doctor produces - so a filename holding a carriage return and a CSI
# erase writes its own lines into it and blanks the ones above. Same rule and
# same function as the Destination layer's, imported rather than copied: what
# a name may do to a line it appears in does not depend on which walk found
# it. (sync.py already borrows it across the same seam.)


def _is_known(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _why(exc) -> str:
    return getattr(exc, "strerror", None) or str(exc)


def _root_state(root) -> tuple:
    """('absent'|'dir'|'other', why) for one agent's directory.

    A link is followed, because an agent directory symlinked out of a
    dotfiles repo is ordinary and is still that agent's directory. A link to
    nothing is absent, which is what it means. A loop, a name this machine
    cannot spell and a path it will not traverse are none of those: they are
    the machine declining to answer, which is a finding rather than a reason
    to leave the agent out of the report.
    """
    try:
        info = os.stat(str(root))
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return "absent", ""
        return "other", f"this machine would not look at it ({_why(exc)})"
    except ValueError as exc:      # a NUL in the path: not a name at all
        return "other", f"this machine would not look at it ({exc})"
    if stat.S_ISDIR(info.st_mode):
        return "dir", ""
    return "other", "something that is not a directory stands here"


def _entries(root) -> tuple:
    """(names, why) for one agent directory - never an exception.

    The names are whatever the filesystem holds, surrogates and all: what
    cannot be spelled is escaped where it is printed, not dropped here, since
    a name doctor declines to show is a layout change doctor did not report.
    """
    try:
        return sorted(entry.name for entry in root.iterdir()), ""
    except OSError as exc:
        return [], f"this machine would not list it ({_why(exc)})"


def _declared_under(root: pathlib.Path, home: pathlib.Path) -> set:
    """Top-level names under `root` that some adapter on this machine declares.

    `known_entries` is the agent vendor's shape as an adapter records it, and a
    handpicked path (ADR-0008) is not in it by construction: the user declared
    that one, no adapter vouches for it, and the whole point is that carryon
    has never heard of the tool. doctor called it "unrecognised" and then
    printed "Nothing unrecognised is ever captured", which is false of exactly
    that path - in the one command a user runs to find out whether something
    is wrong.

    Asked of the registry the caller has in place, so `cmd_doctor` swapping in
    the effective one (excludes applied, handpicked added) is what makes the
    answer match the Setup this machine actually produces.
    """
    declared = set()
    for adapter in ADAPTERS.values():
        for item in adapter.items:
            try:
                rel = (pathlib.Path(home) / item.src).relative_to(root)
            except ValueError:
                continue
            if rel.parts:
                declared.add(rel.parts[0])
    return declared


def inspect(home: pathlib.Path = HOME, platform: str = None) -> dict:
    """Report unknown entries, platform coverage and anything unreadable."""
    home = pathlib.Path(home)
    platform = platform or sys.platform
    report = {}

    for key, adapter in ADAPTERS.items():
        # An adapter with no `detect` names no directory to walk - the
        # handpicked pseudo-adapter (ADR-0008) is one, and `home / ""` is
        # $HOME, so walking it reported every dotfile in the user's home as a
        # layout change the moment doctor started reading the effective
        # registry. What its items say still counts, one loop down.
        if not adapter.detect:
            continue
        root = home / adapter.detect
        state, why = _root_state(root)
        if state == "absent":
            continue

        unknown = []
        if state == "dir":
            names, why = _entries(root)
            declared = _declared_under(root, home)
            unknown = sorted(name for name in names
                             if not _is_known(name, adapter.known_entries)
                             and name not in declared)

        report[key] = {
            "name": adapter.name,
            "root": str(root),
            "verified_against": adapter.verified_against,
            "platforms": list(adapter.platforms),
            "platform_verified": platform in adapter.platforms,
            "unknown": unknown,
            # "" when the walk got a straight answer. Anything else is a
            # sentence about why it did not, and it is drift of its own kind.
            "unreadable": why,
            "listed": state == "dir" and not why,
        }
    return report


def format_report(report: dict, platform: str = None) -> str:
    platform = platform or sys.platform
    lines = [f"Layout check on {platform}", ""]

    if not report:
        lines.append("  No supported agents found.")
        return "\n".join(lines)

    drifting = blocked = False
    for key, info in report.items():
        lines.append(f"  {printable(info['name'])}  ({printable(key)})")
        # Which directory was walked, said rather than implied: this report
        # is about one machine's $HOME, and the reader has no other way to
        # tell a doctor that found nothing from one that looked elsewhere.
        lines.append(f"    directory        : {printable(info['root'])}")
        lines.append("    verified against : "
                     f"{printable(info['verified_against'])}")

        if info["platform_verified"]:
            lines.append(f"    platform         : {platform}, verified")
        else:
            drifting = True
            lines.append(f"    platform         : {platform} - NOT verified "
                         f"(adapter covers {', '.join(info['platforms'])})")

        if info.get("unreadable"):
            blocked = True
            lines.append("    unreadable       : "
                         f"{printable(info['unreadable'])}")
        if info.get("listed", not info.get("unreadable")):
            if info["unknown"]:
                drifting = True
                lines.append("    unrecognised     : "
                             f"{len(info['unknown'])} entries")
                for name in info["unknown"]:
                    lines.append(f"                       {printable(name)}")
            else:
                lines.append("    unrecognised     : none")
        lines.append("")

    if drifting:
        lines += [
            "Unrecognised entries are not an error. They mean this agent has",
            "something the adapter does not describe - usually a feature added",
            "since it was written. Check whether it is worth carrying, then add",
            "it to the adapter's items or exclude list so it stops being a",
            "surprise. Nothing unrecognised is ever captured.",
        ]
    elif not blocked:
        lines.append("Everything on disk is accounted for by an adapter.")
    if blocked:
        lines += [
            "",
            "An unreadable path is not a layout change and not an error here.",
            "It means this machine would not answer about somewhere an agent",
            "keeps its data, so nothing below it was checked - and a push or a",
            "pull will meet the same path. Fix the permissions, or the link,",
            "before migrating.",
        ]
    return "\n".join(lines)

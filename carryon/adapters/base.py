"""The vocabulary every adapter is written in.

An adapter says where an agent keeps its data and which of it is worth moving.
It holds no logic: the capture engine interprets these declarations, so adding
an agent never means writing a copy loop.
"""

from __future__ import annotations

from dataclasses import dataclass

CONFIG, CAPABILITY, KNOWLEDGE = "config", "capability", "knowledge"
CATEGORIES = (CONFIG, CAPABILITY, KNOWLEDGE)

# How the engine handles an item:
#   file        copy one file
#   tree        copy a directory recursively
#   json-strip  copy a JSON file with `strip` keys removed
#   skills      a skills directory where symlinks point into a shared store and
#               re-resolve from a lock file, while real directories have no
#               upstream and are the only thing a mistake destroys for good
KINDS = ("file", "tree", "json-strip", "skills")

PLATFORMS = ("darwin", "linux", "win32")


@dataclass(frozen=True)
class Item:
    """One thing worth carrying to the new machine."""

    src: str          # path relative to $HOME
    dst: str          # path relative to the bundle root
    kind: str
    category: str
    note: str
    strip: tuple = ()   # json-strip only: keys to drop
    resolvable_via: str = ""
    """skills only: the store, relative to $HOME, whose symlinks re-resolve.

    A symlink into this store is recorded in a lock file with its upstream, so
    the new machine re-installs it. A symlink anywhere else - a dotfiles repo,
    say - is managed by something this tool does not control, and is reported
    rather than assumed handled.
    """

    required: bool = False
    """True when an installed agent should essentially always have this.

    A required path going missing is reported as layout drift rather than
    silently skipped - it usually means the agent moved the file and the
    adapter needs updating. Leave False for anything a user may simply not
    have, like optional keybindings.
    """

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"{self.src}: unknown kind {self.kind!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.src}: unknown category {self.category!r}")


@dataclass(frozen=True)
class Excluded:
    """Something deliberately left behind, and why.

    Recorded in the manifest and the restore notes. An exclusion that is not
    written down reads as an oversight later, and gets 'fixed' by someone
    copying a credential onto a new machine.
    """

    path: str
    what: str
    why: str


@dataclass(frozen=True)
class Adapter:
    key: str
    name: str
    detect: str             # path under $HOME whose existence means "installed"
    verified_against: str    # the version and OS this was actually checked on
    items: tuple = ()
    exclude: tuple = ()
    platforms: tuple = ("darwin",)
    """Platforms this adapter has actually been run on.

    Not a guess. `doctor` reports when you are on a platform outside this list,
    because the paths may still be right and may equally not be.
    """

    known_entries: tuple = ()
    """Every top-level name this adapter knows about, captured or excluded.

    `doctor` reports anything in the agent's directory that is not in here.
    That is the early warning for a layout change: a new directory appearing
    is how a vendor's redesign first becomes visible. fnmatch patterns are
    allowed, so `daemon*` covers a family of files.
    """

"""Classify the paths a restore wants to write by who owns them.

A pull replaces a Setup (ADR-0002), and plenty of people symlink their agent
config out of a dotfiles repo - stow, chezmoi, yadm, a bare checkout. Copying
onto an already-symlinked path writes *through* the link and silently edits a
repository carryon does not own, surfacing only much later as an unexplained
dirty tree. So a path that is itself a symlink, or sits anywhere below one, is
externally owned (ADR-0007): skipped and named in the report, never written.
This generalises what `do_skills` already did for one directory - "must be
named rather than quietly counted as handled" was never specific to skills.

The one non-obvious decision: a broken symlink is still externally owned. The
link dangling does not change who put it there; whatever made it still claims
the path, and replacing it with a real file would silently shadow that claim.

`owner_of` is the whole question and lives here rather than in one of the
engines that asks it, which is the seventh round's correction. It began in
history.py because a Session member was the write being fixed at the time,
and then the Setup leg called across for it, and then a write into
~/.carryon needed it and config.py could not import history at all - so the
directories carryon makes under its own state got a bare mkdir instead, and
`push --apply` wrote a whole plaintext Setup through a link at
~/.carryon/staging. The question is 'who else holds this name', it has one
answer, and every leg that writes content asks it here: a $HOME restore, the
conflicts directory, the components under ~/.carryon, and the directory a
`capture --out` names. The ROOT it is asked from is the caller's, because
what each leg is entitled to make is different; the rule is not.

`write_owned` is the eighth round's correction, and it is about the gap
rather than about the rule. One function answering a question every leg asks
is not the same thing as a question every leg must ask: `owner_of` answered,
and then each leg called `Path.write_bytes` a syscall later, which follows a
symlink, rewrites a second name for the same file, blocks for ever on a named
pipe, and truncates before any of that is known. Three places in this package
already say that a check and its use must be one syscall - ADR-0009's openat
walk, `destinations/base._local_write`, `config.write_state_bytes` - and the
two legs that write into $HOME had none of it. So the question and the write
are one call now: this module answers about the ancestors, which only a path
walk can do, and then answers about the leaf on the descriptor it is about to
write to, which only an open can do. A leg that wants to put bytes somewhere
carryon does not own has no other way to do it, which is the difference
between a rule and a rule somebody remembers.

`read_carryable` is the shape being copied, one question over: the path
answer and the fstat on the open file are both kept, because each is blind to
what the other sees.
"""

from __future__ import annotations

import os
import pathlib
import stat

from .destinations.base import printable

ABSENT = "absent"
OURS = "ours"
EXTERNALLY_OWNED = "externally-owned"

HARD_LINK_OWNER = "another name for the same file (a hard link)"
# CONTEXT.md's third clause - "a path this machine will not answer about"
# counts as externally owned - applied to the one shape nobody had asked it
# about. A fifo answers open() by waiting for the other end, which is a pull
# that never returns and prints nothing; the read gate, the Destination layer
# and capture's walk each refuse one in as many words, and the restore leg's
# ownership question called it carryon's to write.
NOT_ORDINARY_OWNER = ("something that is not an ordinary file (a socket, a "
                      "device or a named pipe)")


def _owning_link(target: pathlib.Path, home: pathlib.Path):
    """The outermost symlink on the way from home down to target, if any.

    Outermost because that is the boundary the other tool actually placed;
    everything beneath it is inside that tool's repo, not a second owner.
    """
    try:
        rel = target.relative_to(home)
    except ValueError:
        # Not under home, so there is no ancestor chain between the two to
        # walk - judge the path alone.
        return target if target.is_symlink() else None
    walk = home
    for part in rel.parts:
        walk = walk / part
        if walk.is_symlink():
            return walk
    return None


def classify(target: pathlib.Path, home: pathlib.Path) -> tuple:
    """Return (status, owner): 'absent' | 'ours' | 'externally-owned'.

    `owner` is the resolved target of the claiming link, for the report;
    None unless externally owned. Ownership is judged before existence:
    a leaf that does not exist yet under a symlinked parent is still
    externally owned, because creating it creates a file in the repo.
    """
    link = _owning_link(target, home)
    if link is not None:
        return EXTERNALLY_OWNED, link.resolve()
    if not target.exists():
        return ABSENT, None
    return OURS, None


def owner_of(target: pathlib.Path, root: pathlib.Path) -> tuple:
    """(status, owner) for a path carryon is about to write. The one rule
    every leg that writes content asks, so none of them can get a weaker
    spelling of it.

    `classify` answers "is a symlink claiming this path", which is ADR-0007's
    question and only half of it. A hard link is a second directory entry for
    the same inode: `ln ~/dotfiles/journal.jsonl <member>` is not a symlink,
    resolve() answers with the member's own path, and write_bytes truncates
    and rewrites the file the dotfiles repo owns - verbatim the harm ADR-0007
    exists to prevent, by the one route it does not name. ADR-0009 already
    says as much one syscall over: "A hard link is refused for the same
    reason". st_nlink is the only tell, and this is the only place that asks
    it.

    `root` is where the ancestor walk starts, and it is the caller's own
    boundary rather than a constant: $HOME for a restore, ~/.carryon for a
    write into carryon's own state (the state directory itself may reasonably
    be a link into a synced folder - what is answered for is the chain
    carryon MAKES beneath it), and the directory the user named for a
    `capture --out`. The question is the same at all three, which is the
    point; drawing the boundary is the caller's business, and having them
    each own a copy of the question is what produced four spellings of it.

    Deference rather than a refusal, matching the symlink case: the honest
    reading is a tree somebody else manages, and a restore that writes almost
    nothing must read as deference. What it costs is a file with more than one
    name for reasons of its own - a snapshot scheme, a build tree - which is
    skipped and named rather than written.

    Everything the question needs is a syscall on a path an attacker may have
    arranged, so the whole of it is guarded. resolve() answers a symlink loop
    with a RuntimeError on Python 3.9 and with the unresolved path on 3.13, so
    an unguarded call here made the two runners carryon must pass on disagree
    about a planted loop; a name this machine cannot spell raises a
    ValueError. Either way the answer is 'something else holds this' - the
    fail-closed direction for a write.
    """
    try:
        status, owner = classify(target, root)
        if status != OURS:
            return status, owner
        st = target.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        return EXTERNALLY_OWNED, f"this machine will not look at it ({exc})"
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        return EXTERNALLY_OWNED, HARD_LINK_OWNER
    # A directory is left alone here on purpose: something a restore cannot
    # write is not the same finding as something it must not, and a directory
    # standing where a member lands already has its own report line from the
    # syscall ("something else is standing where that member lands"). What is
    # answered for is what carryon must not touch AND must not wait on.
    if not stat.S_ISREG(st.st_mode) and not stat.S_ISDIR(st.st_mode):
        return EXTERNALLY_OWNED, NOT_ORDINARY_OWNER
    return status, owner


def plan(writes, home: pathlib.Path, force: bool = False) -> tuple:
    """Split (target, source) pairs into (do, skip) by ownership.

    `do` keeps input order; `skip` entries are (target, source, owner) so the
    report can say what actually holds each path - a pull that skips a lot
    must read as deference, not failure. force=True moves everything to `do`:
    writing through the link is exactly what --force means, and the repo edit
    it causes becomes the user's stated intent instead of an accident.

    `owner_of`, not `classify`. This used to ask the symlink half alone while
    the History leg beside it asked the whole question, so a Setup item whose
    local name is a second hard link into a dotfiles repo was written through
    - and sync grew a private copy of this function to say so, which left two
    spellings of one rule with the weaker one still exported. One function,
    one answer, both legs.
    """
    do, skip = [], []
    for target, source in writes:
        status, owner = owner_of(target, home)
        if status == EXTERNALLY_OWNED and not force:
            skip.append((target, source, owner))
        else:
            do.append((target, source))
    return do, skip


def refusal(owner) -> str:
    """Why a name something else holds is not one carryon writes to.

    Public because it has a second asker now. `cli._named_path` refuses a
    path-valued ARGUMENT that is externally owned, one call before the engine
    starts, and it has to say so in the same words the writer does - two
    spellings of one rule is the shape ADR-0010 is about, and a sentence is
    even easier to copy than a check.
    """
    return (f"{printable(str(owner))} holds that name, and writing through it "
            "edits a tree carryon does not own (ADR-0007)")


def _would_not_take(exc) -> str:
    return ("this machine would not take that write "
            f"({getattr(exc, 'strerror', None) or exc})")


def _leaf_refusal(fd: int, force: bool, mode: int, set_mode):
    """Why the descriptor just opened is not one carryon may write, or None.

    Separate from `write_owned` only so the caller can close the descriptor on
    every one of these paths in one place: a leaked descriptor per refused
    member is its own denial of service on a long pull, which is the sentence
    destinations/base already writes about its own refusals.

    The ftruncate is here, after both answers and never as O_TRUNC on the
    open, which is the whole of what makes a refusal cost nothing.
    """
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return refusal(NOT_ORDINARY_OWNER)
        if info.st_nlink > 1 and not force:
            return refusal(HARD_LINK_OWNER)
        if set_mode:
            os.fchmod(fd, mode)
        os.ftruncate(fd, 0)
    except OSError as exc:
        return _would_not_take(exc)
    return None


def write_owned(target, data: bytes, root, force: bool = False,
                mode: int = 0o666, mode_from=None, set_mode: bool = False,
                exclusive: bool = False):
    """None once `data` is at `target`, or why carryon would not put it there.

    The one way in this package to write content to a path carryon does not
    own: a Session's members, the copy of a divergent one kept aside, a
    Setup's items, the files a `capture --out` lands, and - through
    `config.write_state_bytes` - carryon's own state. Every one of those used
    to be `Path.write_bytes` beside an ownership question, and a question
    beside a write is a question the next writer is written without.

    Two answers, because neither can see what the other does.

      the ancestors  `owner_of` from the caller's own root, which is the only
                     way to learn that a directory two components up is a link
                     into somebody's repository. No descriptor answers that.
      the leaf       the open itself. O_NOFOLLOW so the check and the use are
                     one syscall (ADR-0009), and an fstat on the descriptor
                     that is about to be written: st_nlink for a second name
                     for the same file, and S_ISREG because a fifo answers
                     open() by waiting for a reader that may never come. No
                     path answer survives the syscall after it.

    O_TRUNC is deliberately absent and the ftruncate happens after both
    answers - the rule `config.write_state_bytes` already spells, for the
    reason that matters more here: ADR-0002's first Consequence is that a pull
    never deletes, and a write that truncates and then refuses has shortened a
    Transcript nothing agreed to replace. What this declines to write it has
    not already destroyed.

    `force` is ADR-0007's escape hatch and keeps meaning exactly what it
    meant: the user has said to write through the link they own, so the leaf
    checks stand down with it. The ancestors and the leaf go together - half
    a --force would refuse the dotfiles-managed settings.json it exists for.

    `mode_from` carries a source file's mode over and is set on the
    descriptor, never with a chmod by name: capture used `shutil.copymode`,
    which follows the link the write had just refused to follow, in the
    function whose own docstring rules that out. `set_mode` is the state
    leg's version - there the mode is carryon's own decision (0600) rather
    than something copied, and it must apply to a file that already exists,
    which O_CREAT's mode does not.

    A sentence rather than a raise, because every caller needs a different
    thing from it: one report line beside a refused Setup item, a skip line
    in a restore, the SystemExit a command whose whole job is the write ends
    with. ADR-0009 rules out an abort partway through a pull.
    """
    target = pathlib.Path(target)
    status, owner = owner_of(target, root)
    if status == EXTERNALLY_OWNED and not force:
        return refusal(owner)

    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
    if not force:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    if exclusive:
        flags |= os.O_EXCL
    if mode_from is not None:
        try:
            mode = pathlib.Path(mode_from).stat().st_mode & 0o777
        except OSError:
            # The bytes are what matter; a mode carryon could not read is not
            # a reason to leave the file unwritten.
            mode_from = None
    try:
        # Inside the guard with the open, for the reason every stat in this
        # package is: something that is not a directory standing at a parent
        # answers mkdir with a FileExistsError that exist_ok forgives only for
        # a directory, and that was a traceback rather than a report line.
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(target), flags, mode)
    except (OSError, RuntimeError, ValueError) as exc:
        return _would_not_take(exc)

    why = _leaf_refusal(fd, force, mode, set_mode or mode_from is not None)
    if why is not None:
        try:
            os.close(fd)
        except OSError:
            # Only reachable if the descriptor is already gone, which is
            # what the refusal above would have been about anyway.
            pass
        return why
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        return _would_not_take(exc)
    return None

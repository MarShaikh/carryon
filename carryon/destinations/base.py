"""The vocabulary every Destination is written in.

A Destination is somewhere a Snapshot can be put and later fetched: a flat
store of blobs and trees under forward-slash keys ('carryon/index.enc',
'carryon/sessions/<name>.tar.enc'). The Archive that accumulates there is
already encrypted or already credential-free by the time it arrives, and
carryon holds no credentials for any Destination - it borrows whatever access
the user already has: a folder a sync client owns, a git remote their ssh key
reaches, an rclone remote they configured.

Everything that comes back from one is input (ADR-0009), so the checks that
make it safe to touch live here rather than in each type: read/write/delete/
list are concrete, and a new Destination type supplies _read_blob/_write_blob/
_delete_blob/_list_keys instead. It never gets to spell the public method, so
it cannot forget the guard - which is how the symlink hole survived a round of
fixes one layer above it, with directory and git each following links in their
own separately written rglob.

There are exactly three things carryon may do with an object a Destination
offers, and going quiet is not one of them.

*Take it.* *Refuse it by name*, which is what ADR-0009 actually promises - so
the report line IS the control, and the attacker's string never gets to author
one: an object name may hold newlines and CSI escapes, so every name printed
from here goes through `printable` first. *Or stop with a sentence*, which is
the write side only: a push that quietly did not happen is worse than one that
says why, and unlike a pull there is no attacker-chosen object to abort it.

What is ruled out is silence - a Setup that arrives short reads as a
successful pull - and raising, because one planted object that raises is a
permanent abort on every pull from every machine. So a name past NAME_MAX, an
ancestor carryon cannot traverse, a fifo, a hard link and a listing that is
not valid UTF-8 are all report lines here, never exceptions.

The one non-obvious decision: a local path is walked with openat and
O_NOFOLLOW one component at a time, and the directory descriptor is what the
read then happens inside. A walk that lstats each component and then opens the
whole path answers about the path it saw and opens the path that is there now,
and on a Destination somebody else writes to those are two different paths
often enough to matter - a thread renaming one directory to a symlink won a
read of a file outside the root about once in 150 tries against the walk this
replaces.

write_tree/read_tree have default implementations over the blob primitives, so
a new Destination type only has to supply the four - but a type where per-key
round trips are expensive (git syncs with its remote around every operation)
batches by suppressing the redundant syncs inside them, never by
re-implementing them.

Two questions hang off the verbs for the same reason the verbs are concrete:
`_confirm_write` and `_confirm_delete`. Whether a store DID the thing is a
question every type has to answer and only some types have work to do for it -
a syscall either moved the bytes or raised, while another program's exit code
is the store's word about itself. Left implicit, it was answered by accident
by the two types whose write is a syscall and invented by the one whose is
not; left off the delete entirely, it cost ADR-0005's one-time property on
every store that can report a removal it did not make.
"""

from __future__ import annotations

import errno
import os
import pathlib
import stat

# O_NOFOLLOW makes an open refuse a symlink - at the ONE component it names,
# and nothing else about the path, which is why the walk below opens every
# component rather than only the leaf. O_NONBLOCK keeps an open of a fifo from
# blocking forever on a reader that never comes.
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

# Every local write lands under this name first and is renamed into place, so
# a sync client watching the folder never uploads half a blob. list() hides
# the prefix, so an in-flight write never surfaces as a key either.
TMP_PREFIX = ".carryon-tmp-"

# "There is nothing here", which is the ordinary case - a fresh Archive has no
# Index - and the one condition that must NOT produce a report line.
ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR})

# openat and its siblings, where the platform has them. Windows has neither
# these nor O_NOFOLLOW, so it falls back to joining paths and checking each
# component with lstat: the same answers, without the guarantee that the check
# and the use are one syscall.
#
# os.rename rather than os.replace, and the two are not interchangeable in
# general: they differ on Windows, where rename will not overwrite. They are
# the same call on POSIX - and POSIX is the only place this set is ever
# non-empty - while os.replace is absent from supports_dir_fd on macOS, so
# asking for it would silently drop every mac onto the fallback walk.
HAS_OPENAT = all(fn in os.supports_dir_fd for fn in
                 (os.open, os.stat, os.mkdir, os.unlink, os.rename))


def require_key(key: str) -> str:
    """Refuse keys that could escape the Archive's root, or reach no object.

    Keys come from carryon's own layout, so a bad one is a bug - but a
    Destination's own listing is also a source of keys and is nobody's
    layout, so this is the rule everything downstream is entitled to assume.
    It therefore has to refuse what the syscalls below refuse: '..' escapes
    the Archive, a NUL comes back from os.lstat as ValueError rather than as
    an answer, and a name that will not encode as UTF-8 - what os.scandir
    hands back for an invalid filename on Linux, and what an S3 or sftp
    remote may list - cannot be passed to a subprocess or printed at all.
    """
    if not key or key.startswith("/") or "\\" in key or "\x00" in key:
        raise ValueError(f"bad Destination key: {key!r}")
    if any(part in ("..", "") for part in key.split("/")):
        raise ValueError(f"bad Destination key: {key!r}")
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"bad Destination key: {key!r}")
    return key


def join_prefix(prefix: str, rel: str) -> str:
    return f"{prefix.rstrip('/')}/{rel}" if prefix else rel


_CONTROL = {c: f"\\x{c:02x}" for c in range(0x20)}
_CONTROL[0x7f] = "\\x7f"


def printable(value) -> str:
    """A name from a Destination, safe to put in a line of a report.

    A filename may hold newlines, a carriage return, or the ESC that starts a
    CSI sequence, and the line naming a refused object is the safety property
    ADR-0009 states - so an unescaped name writes its own lines into the
    report it is meant to appear in, and can blank the ones already printed
    above it.

    Only the characters that can do that are escaped, rather than everything
    ascii() would escape: a report is read by a person, and a user whose
    paths are accented should not have to decode them. Surrogates go as well
    - os.scandir hands those back for a filename that is not valid UTF-8, and
    printing one raises UnicodeEncodeError, which is a crash with the
    attacker's timing rather than a garbled line.
    """
    text = value if isinstance(value, str) else repr(value)
    return (text.translate(_CONTROL)
            .encode("utf-8", "backslashreplace").decode("utf-8"))


def _why_failed(exc: OSError, what: str) -> str:
    """Why a syscall said no, as the tail of a report line.

    Every branch here is a condition a Destination somebody else writes to
    can create at will, so each has to end in a skip rather than an errno
    reaching the caller: pathlib swallows only ENOENT, ENOTDIR, EBADF and
    ELOOP, and every other one used to come out of a read written to treat
    filesystem trouble as absence.
    """
    if exc.errno == errno.ELOOP:
        return (f"{what} is a symlink, and a Destination does not get to "
                "point carryon at a file")
    if exc.errno == errno.ENAMETOOLONG:
        return f"{what} is a name too long for this filesystem"
    if exc.errno in (errno.EACCES, errno.EPERM):
        return f"{what} cannot be reached from here - no permission"
    return f"{what}: {exc.strerror or exc}"


def report_skipped(source: str, name: str, why: str) -> None:
    """Name an object a Destination offered and carryon would not take.

    Skipping, not raising: a Destination is untrusted input, and anyone with
    write access to one could otherwise plant a single object that aborts
    every pull. Skipping silently is the other way to get this wrong - a
    Setup that quietly arrives short reads as a successful pull - so the
    line goes to stdout, alongside the rest of the report it belongs to
    rather than on a stream the reader has to think to look at.

    The name is escaped here rather than by each caller, because a caller
    that forgets is a caller that hands the attacker a line of the report.
    """
    print(f"  !! {source}: skipping '{printable(name)}' - {why}")


def usable_keys(keys, source: str) -> list:
    """The keys of a listing that are usable at all, sorted.

    A listing is the Destination's answer, not carryon's own layout: rclone
    prints whatever object names the remote holds, and a directory or a clone
    holds whatever names anyone with write access created. Checking them here
    - at the point of listing - is what saves every caller from remembering.
    """
    good = []
    for key in keys:
        try:
            require_key(key)
        except ValueError:
            report_skipped(source, key, "not a usable Archive key")
            continue
        good.append(key)
    return sorted(good)


def is_inside(root, path) -> bool:
    """Whether path really is under root, once both are resolved.

    `target.relative_to(root)` reads like this check and is not one: it is
    lexical, so Path('/tmp/dst/../evil').relative_to('/tmp/dst') hands back
    '../evil' instead of raising, and it says nothing at all about a
    symlinked component. realpath resolves both '..' and every link, which is
    what makes the answer hold on a real filesystem rather than in string
    space. The separator on the end of root keeps '/tmp/dst-evil' from
    passing as a path under '/tmp/dst'.
    """
    root_real = os.path.realpath(str(root))
    path_real = os.path.realpath(str(path))
    return (path_real == root_real
            or path_real.startswith(root_real.rstrip(os.sep) + os.sep))


# --- one directory, addressed however this platform can address one ----------
#
# `at` is a directory descriptor where the platform has openat, and the
# directory's path where it does not. Everything below takes one and a name
# within it, so the walk is written once either way.


def _at_open(at, name: str, flags: int, mode: int = 0o666) -> int:
    if isinstance(at, int):
        return os.open(name, flags, mode, dir_fd=at)
    return os.open(os.path.join(at, name), flags, mode)


def _at_lstat(at, name: str):
    if isinstance(at, int):
        return os.stat(name, dir_fd=at, follow_symlinks=False)
    return os.lstat(os.path.join(at, name))


def _at_mkdir(at, name: str) -> None:
    if isinstance(at, int):
        os.mkdir(name, 0o755, dir_fd=at)
    else:
        os.mkdir(os.path.join(at, name), 0o755)


def _at_unlink(at, name: str) -> None:
    if isinstance(at, int):
        os.unlink(name, dir_fd=at)
    else:
        os.unlink(os.path.join(at, name))


def _at_replace(at, src: str, dst: str) -> None:
    if isinstance(at, int):
        os.rename(src, dst, src_dir_fd=at, dst_dir_fd=at)
    else:
        os.replace(os.path.join(at, src), os.path.join(at, dst))


def _at_close(at) -> None:
    if isinstance(at, int):
        os.close(at)


def _at_child(at, name: str):
    """The directory `name` inside `at`, refusing a symlink at that component.

    On a platform with openat this is one syscall that both checks and binds:
    the descriptor names the directory that was there, so swapping the name
    for a symlink afterwards changes nothing carryon then does inside it.
    Without openat the check is an lstat and the bind is a string, which is
    the race this shape exists to close - stated here rather than left for a
    reader to infer from the missing fd.

    A refused symlink always comes back as ELOOP, whichever kernel answered.
    macOS returns ENOTDIR for O_DIRECTORY|O_NOFOLLOW on a link where Linux
    returns ELOOP, and ENOTDIR is how "there is nothing here" is spelled - so
    taking the errno at face value turned a planted link into silent absence
    on exactly one platform, which is the report line going missing.
    """
    if isinstance(at, int):
        try:
            return os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
                           dir_fd=at)
        except OSError as exc:
            if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                try:
                    info = os.stat(name, dir_fd=at, follow_symlinks=False)
                except OSError:
                    raise exc
                if stat.S_ISLNK(info.st_mode):
                    raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), name)
            raise
    path = os.path.join(at, name)
    if os.path.islink(path):
        raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), path)
    if not os.path.isdir(path):
        raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), path)
    return path


class Destination:
    """Blob and tree storage under forward-slash keys."""

    # -- per-type work --------------------------------------------------------

    def _read_blob(self, key: str):
        """Bytes under an already-validated key, or None if absent."""
        raise NotImplementedError

    def _write_blob(self, key: str, data: bytes) -> None:
        raise NotImplementedError

    def _delete_blob(self, key: str) -> None:
        raise NotImplementedError

    def _list_keys(self, prefix: str) -> list:
        """Candidate keys; the prefix is a hint, not a promise this honours."""
        raise NotImplementedError

    def describe(self) -> str:
        """One line naming this Destination for reports and dry runs."""
        raise NotImplementedError

    # -- what callers use -----------------------------------------------------

    def read(self, key: str):
        """Bytes under key, or None if absent."""
        return self._read_blob(require_key(key))

    def write(self, key: str, data: bytes) -> None:
        """Store `data` under key, and answer for whether the store did it."""
        key = require_key(key)
        self._write_blob(key, data)
        self._confirm_write(key, data)

    def _confirm_write(self, key: str, data: bytes) -> None:
        """How this type knows the bytes landed. Raises if they did not.

        Concrete here for the same reason the four verbs are: a question each
        type has to REMEMBER to ask is the shape every defect in this package
        has had. It was left implicit, and the two types whose write is a
        syscall answered it by accident - the syscall either moved the bytes
        or raised - while the one whose write is another program's exit code
        had to invent an answer, invented a listing, and got a check that was
        right for creating an object and vacuous for replacing one.

        The default is that answer written down rather than an omission: a
        write that either happened or raised needs nothing further. A type
        whose store can report success and do nothing overrides this and says
        how it knows, and the posture there is the write side's everywhere in
        this layer - stop with a sentence, because a push that quietly did not
        happen is worse than one that says why.
        """
        return None

    def missing_container(self, key: str):
        """Why writing `key` here would first CREATE something that is not
        carryon's to create, or None.

        Asked before the reachability probe (ADR-0011), and it exists
        because one type's write is not only a write. On an object store the
        first component of a path is a bucket, and rclone's upload path
        makes a missing one - s3's prepareUpload and gcs's Update both reach
        makeBucket - so the probe, which is the first thing `init` writes,
        could create a billable resource in an account with nobody asked.
        That is the one promise ADR-0011 makes about what carryon does on
        your behalf, and a write is the wrong place to discover it.

        None here, because for every other type the components under the
        root are ordinary directories and making one costs nothing. The
        question is on the base class rather than asked of a type by name
        for the reason `_confirm_write` and `_confirm_delete` are: a
        question each caller has to remember to ask about one particular
        type is the shape every defect in this package has had.
        """
        return None

    def delete(self, key: str) -> bool:
        """Remove key, answering whether the store has stopped serving it.

        Deleting an absent key is not an error, and False is not one either:
        it is the fact one caller needs and the rest do not (see
        `_confirm_delete`).
        """
        key = require_key(key)
        self._delete_blob(key)
        return self._confirm_delete(key)

    def _confirm_delete(self, key: str) -> bool:
        """Whether the store has really stopped serving key.

        The sibling of `_confirm_write`, and it is here for the same reason:
        a question each type has to remember to ask is a question one type
        will not ask. It was `_confirm_write` alone, on the reasoning that a
        delete removes something carryon put there, so what a failure leaves
        behind is stale rather than wrong. That is true of every delete but
        one. ADR-0005's pairing blob is burnt on first successful read, and
        "burnt" is the whole of the one-time property - a delete that exits 0
        and removes nothing leaves the wrapped master key in the Archive while
        carryon prints "paired as ...", so a third machine joins with the same
        code and derives the same key. The joining machine has performed no
        write at that point, so `_confirm_write` never gets a chance to notice.

        The default is the same one the write side has - a delete that either
        happened or raised needs nothing further - and a type whose store can
        report success and do nothing says here how it knows otherwise.

        An answer rather than a raise, unlike the write side, because the two
        callers need opposite things from it and only one of them is about a
        promise: pruning a stale Setup member off a remote that will not
        delete leaves something stale, which is a report line and not a reason
        to abandon a push, while a pairing that could not be burnt has to say
        so where the user is reading. The refusal is named here either way -
        going quiet is what this layer rules out - and what it MEANS is the
        caller's.
        """
        return True

    def list(self, prefix: str = "") -> list:
        """Sorted keys starting with prefix, each one usable as a key.

        The prefix is re-applied to what the type returned: a listing that
        does not honour its own prefix is a Destination misbehaving, and
        read_tree slices keys on the assumption that it did.
        """
        keys = usable_keys(self._list_keys(prefix), self.describe())
        return [key for key in keys if key.startswith(prefix)]

    def write_tree(self, prefix: str, src_dir) -> None:
        """Store every file under src_dir as prefix/<relative path>.

        `is_file()` follows a symlink, so a link in the tree being published
        used to upload its target's bytes - past the home-path neutralisation
        that deliberately leaves symlinks alone (ADR-0006). A relative path
        no key can hold is reported rather than raised, for the same reason a
        listing's bad key is: it is one member, not the whole push.
        """
        src_dir = pathlib.Path(src_dir)
        for path in sorted(p for p in src_dir.rglob("*")
                           if p.is_file() and not p.is_symlink()):
            rel = path.relative_to(src_dir).as_posix()
            key = join_prefix(prefix, rel)
            try:
                require_key(key)
            except ValueError:
                report_skipped(self.describe(), rel,
                               "no Destination key can hold that name, so it "
                               "cannot be published")
                continue
            self.write(key, path.read_bytes())

    def read_tree(self, prefix: str, dst_dir) -> None:
        """Materialise every key under prefix as a file below dst_dir.

        The keys come from the Destination's own listing, which makes them
        input rather than carryon's own layout: read() would refuse an
        escaping one, but only after this method had already made a
        directory for it outside dst_dir. So each key is checked before it
        is used for anything.

        The check is on the SLICE, not on the key. require_key inspects the
        whole key while the write uses `key[len(head):]`, and a key that is
        not really under `head` slices into one that walks out of dst_dir
        while the whole key contains no '..' component at all -
        'aaaaaaaaaaaaaaaaaaa../evil' against a 19-character head. Then the
        materialised path is checked against dst_dir with both resolved,
        because every check above it is lexical and a symlinked directory
        inside dst_dir puts a perfectly well-shaped key outside it.
        """
        dst_dir = pathlib.Path(dst_dir)
        head = prefix.rstrip("/") + "/" if prefix else ""
        for key in self.list(head):
            require_key(key)
            if not key.startswith(head):
                raise ValueError(
                    f"Destination listed {key!r} under prefix {head!r}, "
                    "which it is not under")
            target = dst_dir / require_key(key[len(head):])
            if not is_inside(dst_dir, target):
                raise ValueError(
                    f"Destination key {key!r} lands outside {dst_dir} - "
                    "refusing to write through it")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = self.read(key)
            if data is not None:
                target.write_bytes(data)


class LocalTreeDestination(Destination):
    """A Destination whose objects are files under one local root.

    A directory and a git clone are both this, and both used to walk their
    root with their own `rglob` plus `is_file()` - which follows a symlink,
    so a link planted in either was enumerated as an object and read as
    though its bytes had been pushed there. The walk, the read, the write and
    the delete live here once, and neither subclass spells them.

    Subclasses set `root` and may hide names that are never Archive objects.
    """

    root = None

    def _hidden(self, name: str) -> bool:
        """Names the type keeps for itself - a tmp file, git's own .git."""
        return name.startswith(TMP_PREFIX)

    # -- the walk, in one place -----------------------------------------------

    def _descend(self, key: str, create: bool = False) -> tuple:
        """(at, leaf, why) for the directory holding root/key, or a refusal.

        `at` is None with why None for a path that simply is not there, which
        is the ordinary case and prints nothing; `at` is None with a `why`
        for anything else, which is a report line or a refusal depending on
        which side is asking. The caller closes `at` when it is done.

        Every component below the root is walked, not just the leaf: a link
        named 'skills' pointing anywhere makes 'skills/SKILL.md' a read of
        somebody else's file, and no '..' appears in the key at all. The root
        itself is exempt because the user chose it - a Destination is often
        ~/Dropbox, which is quite reasonably a link - while everything under
        it is whatever the untrusted party put there.
        """
        parts = key.split("/")
        try:
            if create:
                # The root is the user's own choice, exempt from the symlink
                # rule (a Destination is often ~/Dropbox), and a first push
                # is the ordinary reason it does not exist yet.
                os.makedirs(str(self.root), exist_ok=True)
            at = (os.open(str(self.root), os.O_RDONLY | O_DIRECTORY)
                  if HAS_OPENAT else str(self.root))
        except OSError as exc:
            if exc.errno in ABSENT and not create:
                return None, None, None
            return None, None, _why_failed(exc, "the Destination's root")
        part = ""
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        _at_mkdir(at, part)
                    except FileExistsError:
                        pass  # already there, or another writer just made it
                child = _at_child(at, part)
                _at_close(at)
                at = child
        except OSError as exc:
            _at_close(at)
            if exc.errno in ABSENT and not create:
                return None, None, None
            return None, None, _why_failed(exc, f"the component {part!r}")
        return at, parts[-1], None

    def _local_bytes(self, key: str):
        """The bytes of root/key, or None - never read through a link.

        The open is O_NOFOLLOW inside the descriptor the walk ended on, and
        what it opened is judged by fstat rather than by a stat of the name:
        a fifo would block a read, a directory is not a blob, and a hard link
        is neither a symlink nor an Archive object - link() needs no read
        permission on its target, so one planted on a shared Destination is
        the same exfiltration the symlink rule closed, one system call over.

        The fstat is on the raw descriptor, before anything wraps it, and that
        ordering is the whole of it. Wrapping first and asking afterwards
        looks equivalent and is not: os.fdopen() on a descriptor for a
        DIRECTORY raises IsADirectoryError, so the check meant to refuse one
        sat behind the call that made it unreachable. `mkdir carryon/index.enc`
        needs no key and is read on every pull and every push, which made the
        cheapest write anyone can make to a Destination a traceback out of
        both - in a layer whose posture is that a planted object is a line of
        the report.
        """
        at, leaf, why = self._descend(key)
        if at is None:
            if why is not None:
                report_skipped(self.describe(), key, why)
            return None
        try:
            try:
                if not O_NOFOLLOW:
                    # Windows has no O_NOFOLLOW, so the leaf gets the check
                    # _at_child gives every component above it. Racy, and the
                    # alternative there is following the link.
                    if stat.S_ISLNK(_at_lstat(at, leaf).st_mode):
                        raise OSError(errno.ELOOP,
                                      os.strerror(errno.ELOOP), leaf)
                handle = _at_open(at, leaf,
                                  os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
            except OSError as exc:
                if exc.errno in ABSENT:
                    return None
                report_skipped(self.describe(), key,
                               _why_failed(exc, "the object"))
                return None
        finally:
            _at_close(at)
        # Every refusal below owns `handle` and closes it by hand: a leaked
        # descriptor per planted object is its own denial of service on a
        # long-running pull, and there is no `with` yet to do it.
        try:
            info = os.fstat(handle)
        except OSError as exc:
            os.close(handle)
            report_skipped(self.describe(), key,
                           _why_failed(exc, "the object"))
            return None
        why = None
        if not stat.S_ISREG(info.st_mode):
            why = "not an ordinary file"
        elif info.st_nlink > 1:
            why = ("a hard link to a file elsewhere on this machine, and a "
                   "Destination does not get to point carryon at one")
        if why is not None:
            os.close(handle)
            report_skipped(self.describe(), key, why)
            return None
        with os.fdopen(handle, "rb") as fh:
            try:
                return fh.read()
            except OSError as exc:
                # A regular file that will not read - a failing disk, a stale
                # NFS handle, a FUSE mount the sync client just dropped. The
                # type check above cannot see any of those, and this layer
                # answers all of them the same way.
                report_skipped(self.describe(), key,
                               _why_failed(exc, "the object"))
                return None

    def _local_write(self, key: str, data: bytes) -> None:
        """Write root/key atomically, refusing rather than following a link.

        Loudly, unlike a read: a push that quietly did not happen is worse
        than one that stops and says why, and there is no attacker-chosen
        object here to abort it - only the keys carryon itself is pushing.

        The tmp file and the rename both happen inside the descriptor the
        walk ended on, so the directory a blob lands in is the one that was
        checked. Atomic because sync clients upload whatever they see the
        moment they see it: a partial file under the final key name would be
        synced half-written.
        """
        at, leaf, why = self._descend(key, create=True)
        if at is None:
            raise SystemExit(
                f"{self.describe()} will not take a write of {key}: {why}. "
                "Nothing carryon wrote put that there; remove it, or use a "
                "Destination nobody else writes to.")
        try:
            try:
                info = _at_lstat(at, leaf)
            except OSError:
                info = None
            if info is not None and stat.S_ISLNK(info.st_mode):
                raise SystemExit(
                    f"{self.describe()} holds a symlink at {key} - refusing "
                    "to write through it. Nothing carryon wrote put it "
                    "there; remove it, or use a Destination nobody else "
                    "writes to.")
            tmp = TMP_PREFIX + os.urandom(8).hex()
            try:
                handle = _at_open(
                    at, tmp,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
            except OSError as exc:
                raise SystemExit(
                    f"{self.describe()} will not take a write of {key}: "
                    + _why_failed(exc, "the in-flight file beside it"))
            try:
                with os.fdopen(handle, "wb") as fh:
                    fh.write(data)
                _at_replace(at, tmp, leaf)
            except BaseException as exc:
                # on failure, leave the sync client nothing partial to pick up
                try:
                    _at_unlink(at, tmp)
                except OSError:
                    pass
                if isinstance(exc, OSError):
                    raise SystemExit(
                        f"{self.describe()} will not take a write of {key}: "
                        + _why_failed(exc, "the object"))
                raise
        finally:
            _at_close(at)

    def _local_delete(self, key: str) -> None:
        """Remove root/key if it is an ordinary file there. Absent is fine,
        and nothing reached through a link is this key's object."""
        at, leaf, why = self._descend(key)
        if at is None:
            if why is not None:
                report_skipped(self.describe(), key, why)
            return
        try:
            info = _at_lstat(at, leaf)
            if stat.S_ISREG(info.st_mode):
                _at_unlink(at, leaf)
        except OSError:
            pass  # absent is not an error, and nothing else here is a blob
        finally:
            _at_close(at)

    def _local_keys(self, prefix: str) -> list:
        """Keys for the ordinary files under root, following no symlink.

        os.scandir with follow_symlinks=False decides what each entry is by
        lstat, so a link is never mistaken for the file or directory it
        points at, and a linked directory is never descended into. Only what
        is under the prefix being listed gets reported: a Destination is
        often a synced folder full of the user's own links, and narrating
        those on every operation would bury the one that matters.

        A listing is advisory - every key it produces is re-checked by the
        read that follows, which is the walk that holds under a race. What it
        must not do is drop a subtree without a word: a directory carryon
        cannot open takes every stored file below it out of the Archive's
        listing, and an empty report reads as an Archive that never held
        them.
        """
        root = pathlib.Path(self.root)
        if not root.is_dir():
            return []
        keys = []
        stack = [(root, "")]
        while stack:
            directory, rel = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError as exc:
                if exc.errno not in ABSENT:
                    report_skipped(self.describe(), rel or ".",
                                   _why_failed(exc, "the directory")
                                   + " - every object below it is missing "
                                     "from this listing")
                continue
            for entry in entries:
                key = f"{rel}/{entry.name}" if rel else entry.name
                if self._hidden(entry.name):
                    continue
                # an ancestor of the prefix is worth reporting too: a link
                # standing where 'carryon/' belongs hides the whole Archive
                relevant = key.startswith(prefix) or prefix.startswith(key)
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        if relevant:
                            report_skipped(self.describe(), key,
                                           "a symlink, and a Destination does "
                                           "not get to point carryon at a file")
                    elif stat.S_ISDIR(info.st_mode):
                        stack.append((pathlib.Path(entry.path), key))
                    elif not stat.S_ISREG(info.st_mode):
                        if relevant:
                            report_skipped(self.describe(), key,
                                           "not an ordinary file")
                    elif info.st_nlink > 1:
                        if relevant:
                            report_skipped(
                                self.describe(), key,
                                "a hard link to a file elsewhere on this "
                                "machine, and a Destination does not get to "
                                "point carryon at one")
                    else:
                        keys.append(key)
                except OSError as exc:
                    if relevant and exc.errno not in ABSENT:
                        report_skipped(self.describe(), key,
                                       _why_failed(exc, "the object"))
        return keys

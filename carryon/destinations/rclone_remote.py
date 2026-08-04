"""A Destination that is an rclone remote - 'remote:path'.

One module buys every backend rclone speaks (S3, B2, Drive as an API, sftp,
...) without carryon holding a credential or an SDK: the user's own rclone
config authenticates, carryon just shells out to the verbs it needs - lsf,
copyto, deletefile, cat.

The non-obvious decision: the rclone binary is resolved once at construction
and invoked by absolute path, so a missing rclone is a single clear refusal
up front rather than a per-operation surprise later.

`lsf -R` prints object names the remote chose, and this is the one type
whose listing is not constrained by a local filesystem - a remote can answer
with '../../etc/passwd' or an absolute path. It does not check them here:
the base class validates every listing at the point of listing, so no caller
of any Destination has to remember which type needed it.

Which is also why the listing is read as bytes and decoded leniently. S3, B2
and sftp all allow arbitrary bytes in a key, so a strict decode turned one
planted object name into a UnicodeDecodeError raised before any key had been
looked at - a permanent abort on every pull from every machine, for the price
of one PUT. Decoded with surrogates, the name survives as far as require_key,
which refuses it by name like any other unusable key.

That was written about the listing and true of every verb. rclone puts the
object's name in its error messages too, and the two verbs whose output is not
a listing were still asking subprocess to decode them strictly - so the same
planted name came back as a UnicodeDecodeError raised from INSIDE
subprocess.run, before carryon had seen an exit code, out of `copyto` on the
push leg and out of `deletefile` on the one that ends a pairing. Nothing here
decodes strictly now: what rclone says is the remote's string wherever it
appears, and it is read as UTF-8 with surrogateescape rather than in whatever
codec the locale happens to name.

## An exit code is the remote's word about what it did

The base class made the four verbs concrete so no type could forget the
guards on them, and left one question to each type: did the store do the
thing, or not? LocalTreeDestination answers it from an errno - ABSENT is
ENOENT and ENOTDIR, and every other errno is a report line - and
GitDestination answers a remote that will not talk with a SystemExit sync
already catches by name. This type answered every non-zero exit of every
verb the same way: absent, empty, nothing to say. So "the remote refused"
and "the Archive is fresh" were one answer, and each of the three verbs made
that mistake differently.

A listing that failed came back empty, which is what an Archive nobody has
pushed to looks like - and the guard that exists for exactly this, Session
objects standing in an Archive with no Index, is asked OF that same listing.
So a remote that would not list walked past it into `load_index`'s fresh
catalogue, and one `push --apply` sealed a brand new Index at revision one
over a populated Archive, at exit 0. The high-water mark that would have
caught it is local state ADR-0009 already names as ordinarily absent: a
machine whose $HOME came back from a backup.

So absence is confirmed rather than assumed. Exit code 3 is the one thing
rclone's own exit taxonomy is asked for - "directory not found", which is
what an Archive nobody has pushed to answers with - and anything else that
is not a clean exit sends the question to `_present`, which asks the store
whether the object is there. A read the store still lists is refused by name
and the pull carries on; a store that will not answer at all stops with a
sentence, which is what a git remote in the same state already does.

## A write is not done because rclone said so

`copyto` exiting 0 is not evidence a byte moved, and the cases where it is
not are mundane rather than hostile: rclone reads the user's own rclone.conf
and environment, so `dry_run = true` there, or a filter rule matching the
temp file carryon uploads from, makes every copyto a successful no-op. What
followed was a push that printed 'Sessions: 1 pushed' and 'Setup: pushed
(clean)', returned 0, and left an Archive holding nothing at all - and did
the same on every push thereafter, since a fresh-looking Archive is what the
next one reads too. Every other type's write is a syscall that either moved
the bytes or raised.

So a write is confirmed before it counts as done, and a write that cannot be
confirmed stops with a sentence - the write side's posture everywhere in this
layer, because a push that quietly did not happen is worse than one that says
why.

That confirmation was a listing, on the reasoning that "what a read-back would
add over it is content, which the object's seal already answers for". The
reasoning is wrong, and it is wrong in a way that made the check vacuous
everywhere except the one state it was tested in. A listing answers "is there
a key of that name", which is evidence for a CREATE and nothing at all for an
UPDATE - and every push after the first is all updates: index.enc, every
setups/<machine>/ file, and a Session tar whose key is its identity hash
rather than a hash of its bytes. With `dry_run = true` in the rclone config,
push number two exited 0, said 'Sessions: 1 pushed' and 'Setup: pushed to
setups/mac-a/ (clean)', moved nothing, and left last week's Setup in the
Archive. The seal does not catch it either: a label binds WHICH object this
is, not which version of it, so a stale object unseals perfectly. Then the
local high-water mark advanced past the Index the Archive actually holds and
every later push refused for ever as a rollback - carryon manufacturing the
rollback and then wedging itself on it.

So the question a write has to answer is "is the store serving MY bytes", and
the only thing that answers it is the bytes. Each write reads its object back
and compares. That doubles what a push moves over the network, which is a real
cost and the one this type pays for being the only type whose write is not a
syscall that either moved the bytes or raised. There is no batching left to
do: the listing that had to be amortised is gone, and a read-back cannot be
deferred without holding every pushed object in memory to compare it against.

The question itself now lives on the base class as `_confirm_write`, beside
the four verbs, because a question each type has to remember to ask is how
this one came to be answered three different ways - by an errno, by a
SystemExit, and by a listing. The default there is "the write already
answered"; this is the type that has to do the work.

## Nor is a delete, and that one is a promise

The same sentence was written about `copyto` and not about `deletefile`, on
the reasoning that a delete removes something carryon put there, so a failure
leaves something stale rather than something wrong. True of every delete but
one: ADR-0005's pairing blob is burnt on first successful read, and "burnt" IS
the one-time property. With a delete that exits 0 and removes nothing - which
is `RCLONE_DRY_RUN` in the joining machine's own environment, or a filter rule
of its own - `carryon init --join` printed "paired as ..." at exit 0 with the
wrapped master key still in the Archive, and a third machine joined with the
same code and derived the same key. The joining machine has performed no write
at that point, so `_confirm_write` never got a chance to notice.

So `_confirm_delete` sits beside it on the base class, `deletefile`'s exit
code decides nothing on its own, and what a delete that did not happen MEANS
is the caller's (sync._join says the code is still live).

## A key can be an object and a prefix at the same time

Every other type's store is a filesystem, where a name is one thing. S3, B2
and GCS all let 'carryon/index.enc' and 'carryon/index.enc/pwn' exist side by
side, and `rclone cat` on a prefix concatenates everything under it and exits
0 - so one PUT on any bucket the attacker can write to made every read of the
Index come back as the real sealed object with somebody else's bytes appended,
silently, with no report line. Silence is the one outcome this layer rules
out. It also wedged the write leg permanently, and with a misdirecting
sentence: the read-back never matched, so every push refused for ever blaming
`dry_run` in the user's own config for an object nobody had mentioned.

`_also_a_prefix` asks the listing the other half of its question -
`lsf --dirs-only` rather than `--files-only` - so both legs name what is
actually there. It costs one extra listing per read, which is what this type
pays for being the only one whose store is not a filesystem.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile

from .base import Destination, printable, report_skipped, require_key

# rclone's documented exit code for "directory not found", and the only entry
# in its taxonomy this module relies on. It is the answer an Archive nobody
# has pushed to gives, so it has to be told from a remote that is refusing -
# and reading it wrong errs towards a sentence rather than towards silence.
DIR_NOT_FOUND = 3


def _tail(stderr, lines: int = 3) -> str:
    """The last few lines rclone said, safe to put in a line of a report.

    Bytes when the call asked for them and str when it did not, so both are
    taken. Through `printable` either way: the text is whatever the remote
    told rclone, it lands in the line that reports a refusal, and a name that
    can hold a CSI escape (base.printable says why) is no different from an
    error message that can.

    Escaped per line rather than over the joined text, because carryon writes
    the line breaks and the remote writes what is inside them. Over the join,
    `printable` escapes carryon's own newlines too and a three-line rclone
    error arrives as one line of '\\x0a'.
    """
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "surrogateescape")
    return "\n".join(printable(line)
                     for line in (stderr or "").strip().splitlines()[-lines:])


class RcloneDestination(Destination):

    def __init__(self, target: str):
        self.target = target  # 'remote:path', exactly as rclone spells it
        rclone = shutil.which("rclone")
        if not rclone:
            raise SystemExit(
                "rclone not found on PATH - install it (https://rclone.org) "
                "or choose a directory or git Destination")
        self._rclone = rclone
        # What the last `deletefile` said, handed from the verb to the
        # confirmation that follows it inside one `Destination.delete` call.
        self._delete_said = ""

    def _under(self, rel: str) -> str:
        """`rel` as rclone spells it under this target. `rel` empty is the
        target itself, which is how a top-level key's directory is named."""
        if not rel:
            return self.target
        sep = "" if self.target.endswith(":") else "/"
        return f"{self.target}{sep}{rel}"

    def _remote(self, key: str) -> str:
        return self._under(require_key(key))

    def _run(self, *args, binary=False) -> subprocess.CompletedProcess:
        """rclone, with nothing it prints decoded strictly.

        `binary` says whether STDOUT is an object's bytes rather than text;
        stderr is the remote's string either way, so the text spelling names
        UTF-8 and surrogateescape rather than taking `text=True`'s defaults -
        which are the locale's codec, strict, and a UnicodeDecodeError raised
        inside subprocess.run for one byte of an object name in an error
        message.
        """
        text = ({} if binary else
                dict(text=True, encoding="utf-8", errors="surrogateescape"))
        return subprocess.run([self._rclone] + list(args),
                              capture_output=True, **text)

    # -- what the store says is there -----------------------------------------

    def _names(self, rel: str, recursive: bool, dirs: bool = False) -> tuple:
        """(names, why) for one directory of the remote.

        `names` is None with a `why` when the remote would not answer, which
        is a different thing from an empty listing and is the distinction the
        whole module turns on. Only DIR_NOT_FOUND is read as emptiness: a
        directory that is not there yet holds nothing, and every other
        non-zero exit is rclone saying it could not tell carryon.

        `dirs` asks the other half of the same listing - the prefixes rather
        than the objects - which is how `_also_a_prefix` finds a key that is
        both.
        """
        args = ["lsf", "--dirs-only" if dirs else "--files-only"]
        args += ["-R"] if recursive else []
        result = self._run(*args, self._under(rel), binary=True)
        if result.returncode == DIR_NOT_FOUND:
            return [], None
        if result.returncode != 0:
            return None, _tail(result.stderr) or f"exit {result.returncode}"
        listing = result.stdout.decode("utf-8", "surrogateescape")
        # a prefix comes back with a trailing '/', which is rclone's way of
        # saying it is one and not part of the name
        return ([line.rstrip("/") for line in listing.splitlines() if line],
                None)

    def _present(self, key: str) -> tuple:
        """(True/False/None, why) - whether the store is serving this key.

        Asked of the key's own directory rather than of the whole Archive: the
        question is about one object, and a recursive listing to settle it
        would cost one pass over every object stored, per operation.
        """
        parent, _, leaf = key.rpartition("/")
        names, why = self._names(parent, recursive=False)
        if names is None:
            return None, why
        return leaf in names, None

    def _also_a_prefix(self, key: str) -> tuple:
        """(True/False/None, why) - whether a PREFIX stands at key as well.

        The shape no local filesystem can hold and every object store can. S3,
        B2 and GCS all allow 'carryon/index.enc' and 'carryon/index.enc/pwn'
        to exist side by side, and `rclone cat` on a prefix concatenates every
        object under it and exits 0 - so a read of the Index came back as the
        real sealed object with somebody else's bytes on the end, at exit 0,
        with no report line at all. Silence is the one outcome this layer
        rules out, and the seal turns the wrong bytes into a refusal somewhere
        else entirely, where nothing connects it to the object that caused it.

        Asked of the parent's directory listing, the same call `_present`
        makes and for the same reason: the question is about one key, and a
        recursive listing to settle it would cost a pass over the whole
        Archive per read. It is one extra `lsf` on every read, which is the
        price of this being the only type whose store is not a filesystem -
        the write side already pays the same on every write (`_confirm_write`).
        """
        parent, _, leaf = key.rpartition("/")
        names, why = self._names(parent, recursive=False, dirs=True)
        if names is None:
            return None, why
        return leaf in names, None

    def missing_container(self, key: str):
        """Why writing `key` would create a bucket first, or None.

        The base class says why this is asked at all. What this type adds is
        which component the question is about: everything after the colon is
        a path, and its FIRST component is a bucket on every object store
        rclone speaks. `mine:photos/x` writes into bucket 'photos';
        `mine:` - which is exactly how `detect_candidates` spells a
        configured remote, trailing colon and all - has no path at all, so
        the first component comes from the key, and the bucket rclone would
        have made is one named after carryon's own prefix.

        Asked with `lsf`, whose exit taxonomy already tells this module the
        one thing it needs: DIR_NOT_FOUND is a container that is not there,
        a clean exit is one that is (an empty bucket lists as empty, not as
        missing), and anything else is the remote declining to say - which
        is refused too, because the alternative is guessing about somebody's
        bill.

        It cannot tell a bucket from a directory, and does not try: on sftp
        or WebDAV this refuses a path that is merely absent, which costs one
        `rclone mkdir` and is the same answer the Provider flow offers to
        make for you. Erring that way is deliberate - the other way round is
        a resource in an account, created by a tool that said it never would.
        """
        remote, _, path = self.target.partition(":")
        parts = [part for part in (path.strip("/") + "/" + key).split("/")
                 if part]
        first = parts[0]
        result = self._run("lsf", f"{remote}:{first}", binary=True)
        if result.returncode == 0:
            return None
        if result.returncode == DIR_NOT_FOUND:
            return (
                f"{printable(remote)}: has no {printable(first)!r} in it. On "
                "an object store that first component is a BUCKET, and "
                "rclone's upload would create one - so carryon stops here "
                "rather than put a billable resource in your account without "
                "asking. Make it yourself (`rclone mkdir "
                f"{printable(remote)}:{printable(first)}`), or run `carryon "
                "init` with no --dest and pick a cloud service, where "
                "carryon offers to create it after asking.")
        return (f"the remote would not say whether {printable(first)!r} is "
                "there: " + (_tail(result.stderr, 1) or "no reason given"))

    def _unreachable(self, what: str, why: str) -> SystemExit:
        return SystemExit(
            f"{self.describe()} would not {what}: {why}\n"
            "carryon cannot tell a remote that is refusing from an Archive "
            "that is empty, and reading one as the other would either restore "
            "nothing or push a fresh catalogue over everything stored. Fix "
            "the remote (`rclone lsf " + self.target + "` says what it says "
            "to rclone) and run this again.")

    # -- the four verbs -------------------------------------------------------

    def _read_blob(self, key: str):
        result = self._run("cat", self._remote(key), binary=True)
        if result.returncode == 0:
            ambiguous, why = self._also_a_prefix(key)
            if ambiguous is None:
                raise self._unreachable(f"say what it holds at {key}", why)
            if ambiguous:
                # Refused by name and the run carries on, like every other
                # planted object: one key nobody can serve unambiguously is
                # not a reason to abandon an Archive (ADR-0009).
                report_skipped(
                    self.describe(), key,
                    "the remote holds an object AND a prefix at that key, and "
                    "`rclone cat` on a prefix concatenates everything under "
                    "it - so nothing here can say which bytes are the "
                    "object's. Nothing carryon wrote put that prefix there; "
                    "remove it, or use a Destination nobody else writes to")
                return None
            return result.stdout
        there, why = self._present(key)
        if there is None:
            raise self._unreachable(f"say whether it holds {key}", why)
        if there:
            # Listed and unreadable: refused by name, and the run carries on.
            # One object nobody can serve is not a reason to abandon an
            # Archive (ADR-0009), and going quiet here is the other way to
            # get it wrong - a Setup that arrives short reads as a pull that
            # worked.
            report_skipped(self.describe(), key,
                           "the remote lists it and would not serve it: "
                           + (_tail(result.stderr, 1) or "no reason given"))
        return None

    def _write_blob(self, key: str, data: bytes) -> None:
        remote = self._remote(key)
        fd, tmp = tempfile.mkstemp(prefix="carryon-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            result = self._run("copyto", tmp, remote)
            if result.returncode != 0:
                raise SystemExit(f"rclone copyto {remote} failed:\n"
                                 + _tail(result.stderr))
        finally:
            pathlib.Path(tmp).unlink(missing_ok=True)

    def _delete_blob(self, key: str) -> None:
        """Ask the remote to remove the object. Deleting an absent key is not
        an error, matching the other types.

        Whether it actually went is `_confirm_delete`'s question, asked
        whatever this exited with - because an exit code is the remote's word
        about what it did, which is the whole of this module's posture and was
        applied to every verb but this one. What rclone said is kept for that
        answer to quote, and is the only thing this method decides.
        """
        result = self._run("deletefile", self._remote(key))
        self._delete_said = (
            "" if result.returncode == 0
            else _tail(result.stderr, 1) or f"exit {result.returncode}")

    def _confirm_delete(self, key: str) -> bool:
        """Whether the remote has really stopped serving the object.

        Reported rather than raised, matching the local type: a delete removes
        something carryon put there, so what a failure leaves behind is stale
        rather than wrong. Named, though - the stored Setup's tag covers
        exactly the files a push meant to leave, so one that outlives its
        delete is what the next pull refuses the whole Setup for, and the
        pairing blob that outlives its delete is ADR-0005's one-time property
        gone (sync._join says what it does about that).
        """
        said, self._delete_said = self._delete_said, ""
        there, why = self._present(key)
        if there is None:
            report_skipped(self.describe(), key,
                           "the remote would not say whether the delete "
                           f"landed ({why})")
            return False
        if not there:
            return True
        report_skipped(
            self.describe(), key,
            f"the remote would not delete it ({said}), so it is still in the "
            "Archive" if said else
            "the remote reported a successful delete and is still serving it "
            "- usually `dry_run` in the rclone config, or a filter rule. It "
            "is still in the Archive")
        return False

    def _list_keys(self, prefix: str) -> list:
        names, why = self._names("", recursive=True)
        if names is None:
            raise self._unreachable("list what it holds", why)
        return names

    # -- confirming a write ---------------------------------------------------

    def _confirm_write(self, key: str, data: bytes) -> None:
        """Stop unless the store is serving the bytes this call just wrote.

        The base class calls this after every write (base.write): the
        question is the layer's, and this is the one type that has to do
        real work to answer it.

        The bytes rather than the key's existence, because on every push but
        the first the key already exists: an update that never happened leaves
        a perfectly well-named object holding the previous version, which
        unseals cleanly (a label binds identity, not revision) and reads to
        every machine as the current Setup. See the module docstring for what
        that cost.

        A store that will not serve the object back is not a store that has
        confirmed anything, so the three ways this can end are the three the
        rest of the layer has: it is not there (the write did not happen), it
        is there and different (the write did not happen and the old one is
        still being served), or the store will not answer at all.
        """
        result = self._run("cat", self._remote(key), binary=True)
        if result.returncode == 0:
            if result.stdout == data:
                return
            # Ask what is actually there before blaming the user's settings.
            # A key that is also a prefix serves the object concatenated with
            # everything under it, so a write that landed perfectly well came
            # back different - and every push thereafter refused for ever with
            # a sentence pointing at an rclone.conf that had nothing to do
            # with it. A permanent denial with a misdirecting diagnosis, for
            # the price of one PUT.
            ambiguous, _why = self._also_a_prefix(key)
            if ambiguous:
                raise SystemExit(
                    f"{self.describe()} holds an object AND a prefix at "
                    f"{key}, so it cannot serve back what was just written "
                    "there: "
                    "`rclone cat` on a prefix concatenates everything under "
                    "it. Nothing carryon wrote put that prefix there - remove "
                    "the objects under that key, or use a Destination nobody "
                    "else writes to.")
            raise self._not_stored(
                key, "is serving something other than what was uploaded - the "
                     "version that was there before it, most likely")
        there, why = self._present(key)
        if there is None:
            raise self._unreachable(f"say whether the write of {key} landed",
                                    why)
        if not there:
            raise self._not_stored(key, "is not holding what was uploaded")
        raise self._unreachable(
            f"serve back the {key} it has just accepted",
            _tail(result.stderr, 1) or "no reason given")

    def _not_stored(self, key: str, what: str) -> SystemExit:
        """The sentence a user acts on, and it has to be true of the Archive.

        It used to end "Nothing was stored; the Archive is as it was", which
        is only true when the failing write is the first one. A filter that
        declined one kind of object left the whole plaintext Setup half in the
        Archive with no Index beside it - the shape ADR-0009 says a pull must
        refuse - under a line telling the user nothing had been touched.
        """
        return SystemExit(
            f"{self.describe()} reported a successful upload of {key} and "
            f"{what}.\n"
            "rclone exits 0 for a transfer it decided not to make, so this is "
            "usually `dry_run` in the rclone config, or a filter rule that "
            "matches the temp file carryon uploads from. This push stopped "
            "here: whatever it wrote before this object is in the Archive and "
            "the rest is not, so fix the remote and run it again - a push "
            "writes every object it means to, and repeating one is free.")

    def describe(self) -> str:
        return f"rclone remote {self.target}"

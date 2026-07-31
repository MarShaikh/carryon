"""A Destination that is a git repository.

carryon maintains a local clone under ~/.carryon/git/<slug> and treats the
remote as truth: every read is preceded by fetch plus hard reset to the
remote head, every write batch ends with add/commit/push. Authentication is
whatever the user's git already has - an ssh key, a credential helper -
and GIT_TERMINAL_PROMPT=0 on every call means git fails fast instead of
hanging on a password prompt inside a tool that never reads one.

The non-obvious decision: the clone is a cache, not a copy anyone edits, so
reset --hard plus clean is safe and keeps the union/conflict problem where it
belongs - in carryon's pull logic, never in git merges.

The clone is also the sharpest edge carryon has. git stores a symlink
faithfully, so a hostile remote ships one on clone, and the clone sits at a
fixed depth under $HOME - which makes a committed link of a fixed number of
parent steps a read of the same file on every machine that pulls. Nothing in
this module touches the clone's contents for that reason: walking, reading,
writing and deleting all come from LocalTreeDestination, which follows no link
it finds and refuses a hard link too. What is left here is git itself.

## git is another program, so git's output is input too

The layer's rule is that everything a Destination returns is input, and for
this type the Destination answers through git - so what git PRINTS is the
remote's string as surely as an object name is. Three things follow, and each
of them was a defect first.

A tree entry holds raw bytes, a server's rejection message is whatever the
server said, and git relays both without editing them. Decoding that strictly
- which `text=True` does, in the locale's codec rather than even in UTF-8 - is
a UnicodeDecodeError raised from INSIDE subprocess.run, before carryon has
seen an exit code: one committed name, or one byte on a pre-receive hook's
stderr, and every operation from every machine ends in a traceback. The rclone
type learned this for its listing and wrote down why; nothing carried it here,
where every call decoded the same way. So git is read as UTF-8 with
surrogateescape, and what comes back rides out through `printable` - a
server's sentence lands in a refusal carryon prints, and an unescaped CSI
there blanks the lines above it exactly as an object name would.

The remote decides what the clone holds, which makes "a fresh clone is at the
remote head" an assumption about somebody else's repository rather than a fact
about git. A remote whose HEAD names a branch that is not there - a default
branch deleted or renamed, or one line written by anyone with write access -
makes `git clone` exit 0, warn, and check nothing out. Every object then read
absent for the rest of that first operation while the second operation of the
same run, which syncs properly, answered correctly. An absent index.enc is how
a fresh Archive looks. So the clone is synced the same way whether it was just
made or not.

And the branch a commit goes to is git's choice of the LOCAL branch, while the
branch carryon reads from is `_remote_head`'s choice: two answers nothing tied
together. On that same remote the clone sits on the missing name, so one push
put the Archive's new state on a branch no reader had ever looked at - and
then, that branch now existing, every reader reset to it and saw an Archive of
one object. A write is pushed to the ref the reads come off, which also ends
the older wedge one syscall over: `git push origin HEAD` from a detached HEAD
fails permanently, and the clone is a cache carryon resets hard on every sync,
so a state it can reset out of must not be a state it stops working in.

## git's write is a cache, and three files decide what it does with it

`base._confirm_write`'s default is "the write already answered", which is true
of a syscall and false here: the syscall writes into a CACHE, and the
Archive-facing half is add/commit/push. Each step has a documented way to
succeed and move nothing, and all three are spelled in files the remote or the
user's own gitconfig gets to write.

`git add -A` is a successful no-op for anything an ignore rule matches,
`status --porcelain` does not list ignored files so the commit was skipped as
"nothing changed", and `clean -fdq` does not remove them either - so the clone
kept serving the bytes back to the machine that wrote them and even a read-back
would have passed. One committed '.gitignore' holding '*.enc', or a
`core.excludesFile` of the user's own saying the same, and a push exited 0
reporting a Setup pushed while the Archive got the plaintext Setup and no
Index: the shape ADR-0009 says a pull must refuse. Then the high-water mark
advanced past an Index that was never stored and every later push refused for
ever as a rollback, with carryon having manufactured the removal signal itself.
That is the rclone type's round-seven defect, on git, and the argument its
docstring makes about `dry_run` in the user's own rclone.conf is the same
argument about the user's own gitconfig.

So the ignore machinery is turned off rather than worked around - `add
--force`, and `clean -fdqx` so an ignored file cannot survive the reset either
- and the write is confirmed against the COMMIT, not against the working tree.
What the confirmation compares is git's own object id for the bytes, computed
here, so one `ls-tree` answers for a whole batch and no filter can sit between
the question and the answer.

A committed `.gitattributes` is the same class of thing one step further out:
it is the remote choosing what every reader's checkout lays down. With '* text
eol=crlf' committed, a write came back byte-identical on the machine that
wrote it and with every newline doubled on every other machine - so one
committed file makes the whole Archive unopenable, and the report on the
machine that holds the key says nothing. `$GIT_DIR/info/attributes` has the
highest precedence there is (gitattributes(5)), it is inside `.git` where no
checkout and no reset can reach it, and carryon writes it on every sync. What
it turns off is every attribute that can change bytes between the object
database and the working tree: `text`/`eol`/`crlf` for line endings,
`working-tree-encoding` for a charset, `filter` for a clean/smudge driver, and
`ident` for '$Id$'.

Finally the clone directory itself, which is a name like any other. It was
answered for on the run that CLONES and on no other, behind `if not
(clone_dir / '.git').is_dir()` - and `is_dir()` follows a symlink, so the
guard was unreachable exactly when the link pointed at a directory that
already held a `.git`. That is what a dotfiles repository is, and it is the
example `_clone_room`'s own docstring gives. It is asked on every sync now,
and `.git` is asked about by `lstat` rather than through.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess

from .base import LocalTreeDestination, printable, report_skipped

AUTHOR = "carryon"
AUTHOR_EMAIL = "carryon@localhost"

# Everything a `.gitattributes` can do to the bytes between the object
# database and the working tree, switched off in the one file that outranks
# it. Unknown attribute names are harmless to git, so the list can name what
# it means rather than what this git version happens to implement.
CLONE_ATTRIBUTES = ("# written by carryon on every sync: a Destination does "
                    "not get to decide\n# what a checkout of an Archive "
                    "object lays down.\n"
                    "* -text -eol -crlf -filter -ident "
                    "-working-tree-encoding\n")

# How git's own output is read. UTF-8 rather than `text=True`'s locale codec,
# because what git prints is the remote's bytes and the answer must not depend
# on LANG; surrogateescape rather than strict, because a name that is not
# UTF-8 is a name git will happily hand back and a strict decode of it raises
# from inside subprocess.run, where no exit code has been looked at yet.
# stdout round-trips - a branch name read here is passed back to git as an
# argument, and os.fsencode reverses exactly this escape.
GIT_TEXT = dict(capture_output=True, text=True,
                encoding="utf-8", errors="surrogateescape")

REMOTE_PREFIX = "refs/remotes/origin/"


def git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _object_ids(data: bytes) -> frozenset:
    """The object ids git would give these bytes, in either hash a repo uses.

    git's blob id is the digest of 'blob <len>\\0' followed by the content -
    stable, documented, and computable without asking git, so the check that
    the commit holds what carryon wrote costs no subprocess per object. Both
    hashes because a repository may be sha1 or sha256 and this is a
    comparison, not a claim about which one is in use.
    """
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return frozenset((hashlib.sha1(header + data).hexdigest(),
                      hashlib.sha256(header + data).hexdigest()))


def _tail(stderr: str, lines: int = 5) -> str:
    """The last few lines git said, safe to put in a refusal carryon prints.

    Escaped per line rather than over the joined text, because the two
    authors are different: carryon writes the line breaks and the remote
    writes what is inside them, so a real newline between lines is carryon's
    and a control character within one is not. Over the joined text
    `printable` would escape carryon's own newlines too and hand the user one
    long line of '\\x0a'; per line it keeps git's hints readable and still
    lets no CSI, no carriage return and no undecodable byte reach a terminal.
    """
    return "\n".join(printable(line)
                     for line in (stderr or "").strip().splitlines()[-lines:])


class GitDestination(LocalTreeDestination):

    def __init__(self, url: str, home=None):
        self.url = url
        self.home = pathlib.Path(home) if home else pathlib.Path.home()
        self.slug = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        self.clone_dir = self.home / ".carryon" / "git" / self.slug
        self._batching = False
        # key -> the object ids git would give the bytes just written, held
        # until there is a commit to compare them against. Ids rather than the
        # bytes, so a whole Setup tree costs one hash each rather than a copy.
        self._pending = {}

    def _clone_room(self) -> None:
        """Make the clone's own directory, having asked whose it is to make.

        The clone is the biggest thing carryon writes into its own state - a
        whole Archive, index.enc and every plaintext Setup file in it - and
        the directory it goes in was made with a bare
        `mkdir(parents=True, exist_ok=True)`. With `~/.carryon/git` a link
        into a dotfiles repo the entire clone landed in there, and unlike the
        push's staging tree nothing sweeps a clone up afterwards: it stays,
        and every later push adds to it.

        Asked of the slug as well as of `git`, because the clone does not go
        in the directory the first version answered for - it goes one
        component down, and a link at THAT name is the same whole clone in
        the same somebody else's tree. The slug is sha256 of the Destination
        URL and the URL is in ~/.carryon/config.json, so it is a name anyone
        can compute and therefore a name anyone can plant. A rule closed at a
        root and open at its members is the shape ADR-0009 keeps naming, and
        this was one.

        Asked on EVERY sync, which is the correction after that one. It used
        to run only on the branch that clones, guarded by `if not (clone_dir
        / '.git').is_dir()` - and `is_dir()` follows a symlink, so the guard
        was unreachable exactly when the link pointed at a directory that
        already held a `.git`. A dotfiles repository is that directory by
        definition and is the example the paragraph above gives, so the one
        target the check still caught was an EMPTY directory. What it cost,
        measured: a `push --apply` at exit 0 that committed and pushed the
        whole Archive to the user's dotfiles remote, with `clean` deleting an
        untracked file in that tree on the way past.

        config.state_write_path is the one function that answers this, for
        this and for the three other places carryon makes a directory under
        its own state. Imported here rather than at the top because
        config.py imports this package for `printable`, and a module-level
        import in both directions is a cycle - the same deferred import
        history.py makes of the adapter registry, and for the same reason.
        """
        from .. import config
        _room, why = config.state_write_path(self.home, "git", self.slug,
                                             directory=True)
        if why is not None:
            raise SystemExit(f"{self.describe()}: {why}")

    def _cloned(self) -> bool:
        """Whether git's own state is already in the clone directory.

        Asked of the NAME with `lstat`, never through it. A symlink at
        `<slug>/.git` is the same bypass one component further in than the one
        `_clone_room` closes: `git -C <clone>` reads `.git` as the repository
        to work in, so the reset, the commit and the push all happened in
        somebody else's repository while carryon's own Destination stayed
        empty. `.git` is a directory in every clone carryon makes; anything
        else at that name is not this clone, and a gitfile there would point
        the same way a link does.
        """
        try:
            info = os.lstat(str(self.clone_dir / ".git"))
        except OSError:
            return False
        if stat.S_ISDIR(info.st_mode):
            return True
        raise SystemExit(
            f"{self.describe()}: {self.clone_dir / '.git'} is not a "
            "directory, and carryon's clone keeps git's own state there. A "
            "symlink or a gitfile at that name points git at another "
            "repository, so the Archive would be committed and pushed to "
            "somebody else's remote. Nothing carryon wrote put it there; "
            "move it aside.")

    def _pin_attributes(self) -> None:
        """Take the checkout's byte-for-byte behaviour away from the remote.

        `$GIT_DIR/info/attributes` outranks every in-tree `.gitattributes`
        (gitattributes(5)) and lives where no checkout, reset or clean can
        reach it. Through `state_write_path` and `write_state_file` rather
        than a plain write, because every component on the way to it is under
        ~/.carryon and the rule about what carryon may write there is one
        function, not five careful call sites.
        """
        from .. import config
        path, why = config.state_write_path(
            self.home, "git", self.slug, ".git", "info", "attributes")
        if why is not None:
            raise SystemExit(f"{self.describe()}: {why}")
        config.write_state_file(path, CLONE_ATTRIBUTES)

    @property
    def root(self) -> pathlib.Path:
        """Where LocalTreeDestination walks and reads: the clone."""
        return self.clone_dir

    def _hidden(self, name: str) -> bool:
        # git's own state is not an Archive object; the base class hides the
        # in-flight tmp name, which a commit must not pick up either
        return name == ".git" or super()._hidden(name)

    # -- plumbing -------------------------------------------------------------

    def _git(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.clone_dir)] + list(args),
                              env=git_env(), **GIT_TEXT)

    def _git_or_die(self, *args) -> subprocess.CompletedProcess:
        result = self._git(*args)
        if result.returncode != 0:
            raise SystemExit(f"git {args[0]} against {self.url} failed:\n"
                             f"{_tail(result.stderr)}")
        return result

    def _sync(self) -> None:
        """Make the clone exist and match the remote head exactly.

        The fetch and reset run whether the clone was just made or not. A
        fresh clone LOOKS like it is already at the remote head, and that is
        the remote's word rather than git's guarantee: with the remote's HEAD
        naming a branch that is not there `git clone` exits 0, warns, and
        checks nothing out, so the first operation of the run read every
        object in a populated Archive as absent - which is how a fresh
        Archive looks - and the second one, syncing properly, answered
        correctly. One extra fetch on the run that clones is what a single
        answer costs.
        """
        if self._batching:
            return  # the batch synced once, before any of its keys
        self._clone_room()
        fresh = not self._cloned()
        if fresh:
            # --no-checkout, so that nothing is laid down before the
            # attributes are pinned: `git clone` applies a committed
            # .gitattributes to its own checkout, and a reset afterwards sees
            # an index that already matches the mangled working tree and
            # rewrites nothing. The reset below does the first checkout, which
            # is also what moves a refusal from `clone` to `reset` - hence the
            # sweep, which is where it always was and now covers both.
            result = subprocess.run(
                ["git", "clone", "--quiet", "--no-checkout", self.url,
                 str(self.clone_dir)],
                env=git_env(), **GIT_TEXT)
            if result.returncode != 0:
                shutil.rmtree(self.clone_dir, ignore_errors=True)
                raise SystemExit(f"git clone of {self.url} failed:\n"
                                 f"{_tail(result.stderr)}")
        try:
            self._pin_attributes()
            self._git_or_die("fetch", "--quiet", "--prune", "origin")
            head = self._remote_head()
            if head:  # an empty remote has no head to reset to
                self._git_or_die("reset", "--hard", "--quiet", head)
                # -x as well: `clean` leaves ignored files alone, so one
                # committed '.gitignore' let a local copy of an object outlive
                # the reset and keep answering reads the Archive no longer
                # served.
                self._git_or_die("clean", "-fdqx")
        except BaseException:
            # A clone this call made and could not bring to the remote head is
            # not a cache: a name the checkout refused leaves a repository
            # with git's own state and no working tree, and the next run would
            # take it for a clone that is merely stale.
            if fresh:
                shutil.rmtree(self.clone_dir, ignore_errors=True)
            raise

    def _remote_head(self):
        """The remote-tracking BRANCH ref carryon reads from, or None.

        A branch rather than origin/HEAD, because the write leg needs the
        name and origin/HEAD does not carry one: it is a symref, and
        resolving it here is what lets a push go back to the ref these reads
        came off. A dangling origin/HEAD - the remote's default branch
        deleted or renamed - fails rev-parse and falls through to the list,
        which is the case that used to leave reads and writes on different
        branches.
        """
        ref = REMOTE_PREFIX + "HEAD"
        if self._git("rev-parse", "--verify", "--quiet", ref).returncode == 0:
            resolved = self._git("symbolic-ref", "--quiet", ref)
            name = resolved.stdout.strip() if resolved.returncode == 0 else ""
            if name.startswith(REMOTE_PREFIX):
                return name
        refs = self._git_or_die(
            "for-each-ref", "--format=%(refname)",
            "refs/remotes/origin").stdout.split()
        branches = [r for r in refs if not r.endswith("/HEAD")]
        for preferred in (REMOTE_PREFIX + "main", REMOTE_PREFIX + "master"):
            if preferred in branches:
                return preferred
        return branches[0] if branches else None

    def _push_ref(self) -> str:
        """The remote branch a commit goes to: the one the reads came off.

        `git push origin HEAD` derives its destination from the LOCAL
        branch, which is git's question and not carryon's. The two answers
        came apart in both directions: on a remote whose HEAD named a
        missing branch the clone sat on that name, so a push landed where no
        reader looked and then, that branch existing, took every reader's
        view of the Archive down to the one object it held; and from a
        detached HEAD there is no local branch at all, so every push failed
        permanently against a healthy remote.

        An empty remote has no ref to name, and there the clone's own branch
        is the honest answer - it is where `git clone` decided a first commit
        goes, and the first push is the one that creates it.
        """
        head = self._remote_head()
        if head:
            return "refs/heads/" + head[len(REMOTE_PREFIX):]
        current = self._git("symbolic-ref", "--quiet", "--short", "HEAD")
        name = current.stdout.strip() if current.returncode == 0 else ""
        return "refs/heads/" + (name or "main")

    def _commit_push(self, message: str) -> None:
        if self._batching:
            return  # the batch commits once, after all of its keys
        # --force, because an ignore rule must not be able to decide what an
        # Archive holds. `add -A` alone is a successful no-op for anything a
        # committed .gitignore or the user's own core.excludesFile matches,
        # and `status --porcelain` does not list ignored files either - so
        # both halves of "did anything change" answered no about a file that
        # had plainly just been written. The clone is carryon's own cache of
        # the Archive and there is nothing in it an ignore rule is about.
        self._git_or_die("add", "-A", "--force")
        if not self._git_or_die("status", "--porcelain").stdout.strip():
            return  # nothing changed, nothing to push
        self._git_or_die("-c", f"user.name={AUTHOR}",
                         "-c", f"user.email={AUTHOR_EMAIL}",
                         "commit", "--quiet", "-m", message)
        self._git_or_die("push", "--quiet", "origin",
                         "HEAD:" + self._push_ref())

    @contextlib.contextmanager
    def _batch(self, message=None):
        """One sync before a whole tree operation, one commit after it.

        That batching is the only thing git needs to do differently from the
        base tree implementations, and doing it this way keeps it the only
        difference. read_tree used to be re-implemented here to get it, and
        the copy drifted: it lost the key validation and the containment
        check the base version does, which is a straight write-anywhere from
        a listing this class does not control.
        """
        self._sync()
        self._batching = True
        try:
            yield
        finally:
            self._batching = False
        if message is not None:
            self._commit_push(message)
        # After the commit, never before it: inside the batch there is nothing
        # to compare against yet, which is why `_confirm_write` defers here
        # rather than answering per key.
        self._confirm_pending()

    # -- what the commit actually holds ---------------------------------------

    def _committed(self) -> dict:
        """{key: object id} for everything at the local HEAD.

        One call for a whole batch. `-z` so a path is NUL-terminated rather
        than quoted - git quotes a name with a control character in it, and a
        name is the remote's bytes here as everywhere else in this module.
        A repository with no commit yet answers non-zero, which is an empty
        tree and therefore a refusal for anything that was meant to be in it.
        """
        result = self._git("ls-tree", "-r", "-z", "HEAD")
        if result.returncode != 0:
            return {}
        found = {}
        for record in result.stdout.split("\0"):
            if not record:
                continue
            meta, _, path = record.partition("\t")
            fields = meta.split()
            if len(fields) >= 3 and path:
                found[path] = fields[2]
        return found

    def _confirm_write(self, key: str, data: bytes) -> None:
        """Stop unless the COMMIT holds the bytes this call just wrote.

        The base class calls this after every write, and the default answer
        there - "the write already answered" - is the one this type cannot
        give: its write is a syscall into a cache, and three separate files
        the remote or the user's own gitconfig may hold get a say in whether
        the cache ever reaches the Archive.

        Against git's own object id rather than a read-back of the working
        tree, for two reasons. A read-back of the clone passes on the machine
        that wrote it even when nothing was committed - the ignored file is
        still sitting there. And an id can be computed from the bytes without
        a subprocess, so a whole Setup tree is confirmed by one `ls-tree`
        rather than by one `cat-file` per member.
        """
        self._pending[key] = _object_ids(data)
        if self._batching:
            return
        self._confirm_pending()

    def _confirm_delete(self, key: str) -> bool:
        """The same question in the other direction: gone from the commit.

        A delete is never inside a batch - only write_tree and read_tree
        batch, and neither deletes - so there is always a commit to ask.
        """
        if key not in self._committed():
            return True
        report_skipped(self.describe(), key,
                       "carryon removed it and the commit still holds it, so "
                       "it is still in the Archive")
        return False

    def _confirm_pending(self) -> None:
        pending, self._pending = self._pending, {}
        if not pending:
            return
        committed = self._committed()
        for key in sorted(pending):
            stored = committed.get(key)
            if stored in pending[key]:
                continue
            raise SystemExit(self._not_stored(
                key, "is not in the commit at all" if stored is None else
                     "holds something other than what was written"))

    def _not_stored(self, key: str, what: str) -> str:
        return (f"{self.describe()} took a write of {key} and the commit "
                f"{what}.\n"
                "git's write is a cache, and an ignore rule, a filter or an "
                "attribute can make add, commit or push move nothing while "
                "every one of them exits 0. carryon turns those off in the "
                "clone it owns, so something outside it is deciding here. "
                "This push stopped: whatever it wrote before this object is "
                "in the Archive and the rest is not, so fix the repository "
                "and run it again - a push writes every object it means to, "
                "and repeating one is free.")

    # -- Destination ----------------------------------------------------------

    def _read_blob(self, key: str):
        self._sync()
        return self._local_bytes(key)

    def _write_blob(self, key: str, data: bytes) -> None:
        self._sync()
        self._local_write(key, data)
        self._commit_push(f"carryon: write {key}")

    def _delete_blob(self, key: str) -> None:
        self._sync()
        self._local_delete(key)
        self._commit_push(f"carryon: delete {key}")

    def _list_keys(self, prefix: str) -> list:
        self._sync()
        return self._local_keys(prefix)

    def write_tree(self, prefix: str, src_dir) -> None:
        with self._batch(f"carryon: write tree {prefix}"):
            super().write_tree(prefix, src_dir)

    def read_tree(self, prefix: str, dst_dir) -> None:
        with self._batch():
            super().read_tree(prefix, dst_dir)

    def describe(self) -> str:
        return f"git repository {self.url}"

"""~/.carryon/config.json - what moves, by standing decision rather than flags.

Exists because of ADR-0008: the default has to be effortless, but people need
to pick exactly what moves, and carryon routinely runs over SSH, in CI, or on a
freshly imaged machine where an interactive picker is useless. So handpicking
is a file: excludes trim what the Adapters declare, and `carry` adds paths no
Adapter has heard of.

The one non-obvious decision is where a handpicked path lands. It always joins
the Setup - category config - never the History. That is the point of
ADR-0008: a Setup is fail-closed, so `user_adapter` slots the user's paths into
the existing capture engine untouched and the credential scanner protects them
for free. Handpick ~/.aws and capture refuses, naming the file; in a History
the same hit would merely be reported, which is the wrong posture for a
directory the user pointed at by hand.

The one carve-out: ~/.carryon itself is refused outright, because the
fallback master.key kept there is bare hex that no scanner pattern matches -
handpicking it would push, in the plaintext Setup, the key that decrypts the
same Archive's History. The refusal is by construction, not by spelling:
`lands_in_state` resolves the candidate and folds case, so neither a link that
resolves into ~/.carryon nor a case-variant of it (the SAME file on APFS and
NTFS) can reach the key. sync's restore leg consults the same function, so the
two legs cannot drift into disagreeing about what ~/.carryon is.

The $HOME boundary around a handpicked path is the same shape of rule and was
the same shape of mistake: "only paths under home can join a Setup", enforced
lexically over an engine that resolves. '~/link/loot.txt' spells nothing
outside home and holds no '..', and with link -> /etc it is a file from
outside home in a plaintext Setup. So `stays_under_home` asks the question
about the path that will actually be opened, links followed. It refuses on an
unresolvable path where `lands_in_state` accepts one, and that is not an
inconsistency: both fail closed, and closed points opposite ways when one rule
is a permission and the other a carve-out.

And it is asked about every path, not only about the one the user or an
Adapter named. `lands_in_state` answers about a single path while both legs
act on path TREES that are expanded after the answer: '~/.mytool' is an
innocent directory whatever is linked inside it, and the capture engine reads
a member link through to its target. `unsafe_reads` walks the expansion and
asks again per member - BOTH questions, since the $HOME boundary is a tree
rule for exactly the same reason the state carve-out is.

The last shape of the same mistake is not about paths at all. Every rule above
answers about a NAME, and a hard link is a second name for the same content:
`ln ~/.carryon/master.key ~/.claude/commands/notes.md` is not a symlink,
resolves to itself, sits under $HOME and nowhere near '.carryon', and hands
the key's bytes to copy2 with every check satisfied. What the two names share
is the inode, so `state_identities` collects (st_dev, st_ino) over the state
directory and every read compares the file it is about to open against it. A
path rule cannot see an ALIAS; only identity can, and a bind mount is another
alias landing on the same check. A COPY is a different thing and no rule here
sees one: `cp -c ~/.carryon/master.key <captured tree>` makes an APFS
clonefile, which shares the key's bytes and has an inode of its own - 22139642
and 22139643, measured - so it is captured like any other file the user put
there. That is not a hole this rule can close, since a copy of the key is
indistinguishable from any other file holding those bytes; what stands between
a user and it is that nothing carryon runs makes one.

And the last shape of all is not a rule at all but where the rules live. Each
of the paragraphs above was written after a defect, closed on the leg that was
reviewed, and found again on a leg that was not: the Setup leg asked both
questions while the History engine beside it asked only the path one, so a
hard link to the master key in a Session tree was packed and laid down at mode
0644 in every pulling machine's project directory. Patching the second leg
produces a third. So there is now ONE function - `carry_refusal` - that
answers "may this file's content leave this machine", both questions together
in every spelling that has ever mattered here, and ONE way to obtain a user
file's bytes - `read_carryable`, which asks it first and re-asks identity on
the descriptor it reads. Setup capture, handpicked trees, Session trees and
project residue all come through here.

That is the same move the Destination layer made when its four verbs became
concrete on the base class, after which the verifiers stopped finding anything
there - but it is a weaker version of it, and the difference is worth saying
plainly. A Destination subclass never gets to spell `read`, so it cannot
forget the guard; nothing in Python takes `read_bytes` away from a walk, so a
seventh caller CAN still be written. What stands in for the base class is
tests/test_state_chokepoint.py, which parses every module here and fails on
any call that turns a path into content, or writes content out, unless the
function it is in is named in an allowlist with a written reason AND makes
exactly the calls that entry argues for. Pinning the calls rather than the
function is what makes the tripwire finer than the defects: the last two
arrived INSIDE functions that were already, and rightly, allowlisted.

The write side has the same shape and one more function. `write_state_bytes`
answers for the file at the end of a path, `state_write_path` answers for the
directories carryon makes on the way there, and `external.owner_of` is the one
question underneath both - the same one the restore leg asks about $HOME and
the capture engine asks about the directory a `--out` names. Four legs had
been writing under ~/.carryon with a bare mkdir between them and somebody
else's tree.

And then the round after that found the gap rather than the rule. A question
answered in one function is not a question every leg must ask: `owner_of`
answered, and each leg called `Path.write_bytes` a syscall later, which
follows whatever is at the name by then. `write_state_bytes` was the only
write in the package that closed that gap - O_NOFOLLOW, an fstat on the
descriptor, and the truncate after both - and it closed it here because
~/.carryon was the directory being reviewed at the time. It is
`external.write_owned` now, spelled once and called from all four legs, and
this function is the state leg's framing of it.

Two things in this module were the same fault on the read side, found the same
way. `carry_refusal` returned the state carve-out from a set of inodes that a
walk of ~/.carryon collected, and that walk answered an empty set for a
directory it could not list - so mode 0300 there, which carryon never notices
because it opens its own files by name, turned the one rule a hard link cannot
defeat off for the whole run. "Found nothing" and "could not look" are
different answers; `StateIdentities` is the difference written down, and
`state_unanswered` is where both askers get it.

And the round after THAT found the surface all of the above had been kept off:
carryon's own state files. `read_carryable` gates what a user's tree may hand
over and the Destination base class gates what an Archive may, and both were
built on the rule that a path is not the content behind it - but config.json
and state.json were read with a bare `Path.read_text()`, on the reasoning that
they are carryon's own rather than a user's. That is the reasoning ADR-0009
retired one layer over. carryon writes them; it does not control what is at
that name when it next reads, and a synced folder's conflict copy, a truncated
write, a restored backup and a named pipe are each reachable without an
attacker. `read_state_json` is the gate for them - the type settled before the
open and again on the descriptor, decode and parse in one guard, a value or a
named refusal back - and it draws the distinction the rest of this module
already turns on: no name at all is a first run, and a name that will not read
is a fact worth reporting.
"""

from __future__ import annotations

import dataclasses
import errno
import fnmatch
import json
import os
import pathlib
import socket
import stat

from . import external
from .adapters import CONFIG, HOME, Adapter, Item
from .adapters.base import PLATFORMS
from .destinations.base import printable, require_key

HANDPICKED_NOTE = "handpicked - no adapter vouches for this"


def state_dir(home: pathlib.Path = HOME) -> pathlib.Path:
    """carryon's own state directory. The fallback master.key, the config
    naming the Destination, and the Archive high-water mark all live here, so
    nothing carryon carries or restores may land inside it."""
    return pathlib.Path(home) / ".carryon"


def config_path(home: pathlib.Path = HOME) -> pathlib.Path:
    return state_dir(home) / "config.json"


# What every filesystem carryon runs on will hold as one name: 255 bytes.
# Here rather than in sync.py because a machine name is checked on the way IN
# (this file) and on the way back off a Destination (sync), and the two used
# to be different functions with only the second one written down.
NAME_MAX = 255


def machine_name_refusal(name):
    """Why `name` cannot be this machine's name in the Archive, or None.

    A machine name is not a label: `archive.setup_prefix` puts it straight
    into a Destination key, so it IS one directory under carryon/setups/. The
    question was recorded as settled by `sync._machine_name_refusal`, whose
    only caller runs on the PULL leg over names that came back off a
    Destination - so nothing at all settled the argument on the way in.
    `--machine .` and `--machine /` pushed a Setup into the SHARED setups/
    root, `--machine a/b` nested it somewhere no reader looks, all at exit 0;
    and every other machine's pull then restored nothing and reported phantom
    machines named 'MANIFEST.json' and 'RESTORE.md' for ever. `--machine ..`
    was refused all along by `require_key`, which is what made the gap look
    closed.

    One plain name, then, in the words `state_write_path` already uses about a
    component under ~/.carryon - the same rule, one directory tree over. The
    two askers share this because a name refused here is one every later read
    of it is known to accept, and a rule with two spellings is what ADR-0010
    is about.
    """
    if not isinstance(name, str) or not name.strip():
        return ("a machine's name is a directory under carryon/setups/ in the "
                "Archive, and that names nothing")
    if not writable(name):
        # Neither source is exotic on Linux: argv and socket.gethostname() are
        # both decoded with surrogateescape, so bytes that are not UTF-8
        # arrive here as lone surrogates - and crypto encodes the Setup's MAC
        # label strictly, so this would otherwise be a UnicodeEncodeError in
        # the middle of a push.
        return ("it holds a character this machine cannot write out - an "
                "unpaired surrogate, most likely from a hostname or an "
                "argument that is not valid UTF-8")
    if "/" in name:
        return ("that is a path, not a name - a machine's Setup is one "
                "directory under carryon/setups/, and a '/' would nest it "
                "where no other machine looks for it")
    if name in (".", ".."):
        return "that is a directory reference, not a machine name"
    if len(name.encode("utf-8", "surrogateescape")) > NAME_MAX:
        return ("that is longer than any filesystem holds as a directory "
                "name, so no machine's Setup can be stored under it")
    try:
        require_key(name)
    except ValueError:
        return ("no Destination key can hold that name, so carryon could "
                "neither store this machine's Setup nor ask for it again")
    return None


HARD_LINK_AT_STATE = (
    "another name already points at that same file, and writing it would "
    "rewrite whatever holds the other name - a hard link needs no read "
    "permission on its target, so this is the same publication a symlink "
    "would be (ADR-0007). Remove the extra name, or move it aside.")


def write_state_bytes(path, data: bytes, mode: int = 0o600,
                      exclusive: bool = False):
    """None once `data` is at `path`, or why carryon would not write it there.

    ADR-0007 is a rule about every write carryon makes, and the writes into
    its own state directory were the ones it was not applied to - the config,
    the fallback master key, the Archive's high-water mark, and the Setup
    backup a pull takes. Each used a plain open or a plain copy2, so a link
    standing at the name sent the bytes through it into whatever tree put it
    there - and the file next to the config is the master key, which is the
    one write in the package that would publish the trust root. The capture
    leg already treats this directory as sacred in the other direction: a
    captured path that so much as lands here is refused (carry_refusal),
    because a master key is bare hex no credential pattern matches.

    The same two syscalls the Destination layer uses for the same question,
    and for the same reason a walk cannot inspect-then-open: O_NOFOLLOW so the
    check and the use are one syscall, and st_nlink because a hard link is a
    second name for the same bytes and resolves to itself. O_TRUNC is left off
    until after both, since truncating is already a write to whatever is
    there. The mode is set on the descriptor rather than the path: O_CREAT's
    mode does not apply to a file that already exists, and a chmod by name is
    the follow this function exists to avoid.

    All of which is `external.write_owned` now, and this is the state leg's
    framing of it rather than a second implementation. It was written here
    first because ~/.carryon was the write being reviewed at the time, and
    the two legs that write into $HOME were left with Path.write_bytes - one
    rule, spelled once well and twice not at all, which is the shape every
    round of this has had. The root it is answered from is the file's own
    parent: the components BETWEEN ~/.carryon and here are `state_write_path`'s
    (see below), and ~/.carryon itself is nobody's business but the user's.

    `exclusive` adds O_EXCL for the caller whose path is fresh by
    construction - a Setup backup lands under a directory name minted for that
    one pull - where anything already sitting at the name is by definition not
    carryon's own file.

    The last component is what is answered for. The directory above it is the
    user's own arrangement of their state - ~/.carryon itself may reasonably
    be a link into a synced folder - and refusing that would be a rule about
    where carryon is installed rather than about who owns the file it writes.
    A caller that needs the components BETWEEN answered for as well asks
    `state_write_path` above, which walks from the state directory down and
    makes them - which is where a backup's ~/.carryon/backups/<stamp>/ chain,
    the push's staging root and the git clone's parent are all judged.

    Returns a sentence rather than raising, because the two kinds of caller
    need opposite things from the same rule: `write_state_file` turns it into
    the SystemExit that a command whose whole job is that write must end with,
    and the pull's backup leg turns it into one report line beside the item it
    refused (ADR-0009 rules out an abort partway through a pull).
    """
    path = pathlib.Path(path)
    why = external.write_owned(path, data, path.parent, mode=mode,
                               set_mode=True, exclusive=exclusive)
    if why is None:
        return None
    if external.HARD_LINK_OWNER in why:
        return HARD_LINK_AT_STATE
    return (f"carryon would not write its own state here: {why}. A symlink "
            "at that name is the usual cause - carryon never writes through "
            "a link it does not own (ADR-0007), because that edits the tree "
            "the link points into. Remove the link, or move that tree's copy "
            "aside.")


def state_write_path(home, *parts, directory: bool = False) -> tuple:
    """(path, None) for a place under ~/.carryon carryon may write, with every
    directory it makes on the way there made - or (None, why).

    The write side's counterpart of `read_carryable`, and it exists for the
    same reason that one does. `write_state_bytes` answers for the FILE at the
    end of a path and says so in as many words: "A caller that needs the
    components BETWEEN answered for as well asks from the state directory
    down". Exactly one caller did - the Setup backup, because that was the one
    being reviewed. The push's staging root and the git clone's parent made
    their components with a bare `mkdir(parents=True, exist_ok=True)`, which
    follows a link at either of those names into whatever tree it points at.
    With `~/.carryon/staging` a link to a dotfiles repo, `push --apply` wrote a
    whole plaintext Setup in there; when the credential scan refused that Setup
    the tree was kept on purpose, so the one Setup carryon will not publish was
    the one it left behind in a repository whose job is to be committed.
    `~/.carryon/git` was the same one directory over, with a whole clone -
    index.enc included - and nothing to sweep it up afterwards.

    Seven things live under ~/.carryon now and the eighth is somebody's next
    commit, which is why this is a function rather than three more careful
    call sites. The conflicts directory is the fourth of them and does not
    call this: its components are named by a stored tar, so every member is
    asked about individually where it lands. What it did get wrong was the
    same question's OTHER half - it walked from $HOME rather than from here,
    so the same user's pull took every backup and deferred every conflict
    copy. One question, one root, whichever way a leg reaches it.

    So the components carryon makes under its own state are answered for here,
    one at a time, each asked BEFORE it is created: mkdir through a link that
    is already there creates in the other tree, so a check afterwards is a
    check after the harm. ~/.carryon itself is not answered for, which is the
    line write_state_bytes already drew - the state directory living in a
    synced folder is the user's own arrangement, and refusing it would be a
    rule about where carryon is installed.

    A component that is there and is not a directory comes back as a sentence
    too. `exist_ok` forgives an existing DIRECTORY and nothing else, so a
    plain file or a dangling link at ~/.carryon/staging was a FileExistsError
    out of push - after the recovery key had been printed and before any
    report - which is the traceback write_state_bytes' own docstring names as
    the reason its mkdir sits inside a guard.

    `directory` says whether the last component is a directory to make or a
    file about to be written there; either way it is answered for. The
    sentence is returned rather than raised because the callers need opposite
    things from it: a push turns it into a refused Setup half, a pull into one
    report line, a Destination into the SystemExit that ends the command.
    """
    state = state_dir(home)
    path = state
    for index, part in enumerate(parts):
        part = str(part)
        if part in ("", ".", "..") or "/" in part or "\x00" in part:
            # A caller composes these from a stamp, an item's relative path or
            # a catalogue key, and the last of those is a name that came back
            # from a Destination. One '..' among them walks out of the
            # directory this function exists to keep the write inside, and two
            # walk out of ~/.carryon entirely - so a component is a plain name
            # or it is nothing.
            return None, (f"carryon would not make {printable(part)!r} under "
                          "its own state directory - a component there is one "
                          "plain name, never a path")
        path = path / part
        status, owner = external.owner_of(path, state)
        if status == external.EXTERNALLY_OWNED:
            return None, (
                f"carryon would not write inside its own state directory "
                f"here: {printable(str(owner))} holds "
                f"{printable(str(path))}, and writing through it edits a tree "
                "carryon does not own (ADR-0007). Move that link aside, or "
                "point ~/.carryon itself somewhere instead: carryon answers "
                "for the directories it makes under its state directory, not "
                "for where its state directory lives")
        if index < len(parts) - 1 or directory:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return None, (
                    f"carryon would not make {printable(str(path))} "
                    f"({exc.strerror or exc}) - something that is not a "
                    "directory is standing at that name, and carryon needs a "
                    "directory there to work in")
    return path, None


def write_state_file(path, text: str, mode: int = 0o600) -> None:
    """write_state_bytes for the callers whose whole command is that write.

    The config, the fallback master key and the high-water mark each ARE the
    thing their command was asked to do, so a refusal is the command's answer
    and SystemExit is how carryon says one (house style). Encoded here rather
    than one layer down because the rule is about the file, not about the
    encoding: a Setup backup is bytes carryon never decoded.
    """
    why = write_state_bytes(path, text.encode("utf-8"), mode)
    if why is not None:
        raise SystemExit(f"{path}: {why}")


# Said the same way about a state file as about a user's file
# (read_carryable), because it is the same fact: a named pipe answers read()
# by waiting for a writer that may never come, and a device or a socket is not
# a document either.
WHY_NOT_ORDINARY = ("it is not an ordinary file - a directory, a socket, a "
                    "device or a named pipe is standing at that name")


@dataclasses.dataclass(frozen=True)
class StateFile:
    """What one of carryon's own state files held, or why nothing came back.

    Three outcomes rather than two, and the third is the whole point: "no file
    is there" and "a file is there and this machine would not read it" are
    different facts, and every defect this class was written for is one being
    taken for the other. A dangling symlink at config.json answered ENOENT,
    which `load` spelled "never configured" and ran the defaults on - the
    machine that has a Destination reporting that it has none.

    `value` is a dict from `read_state_json` and bytes from `read_state_bytes`;
    `value is None` is the one test either caller needs, since it is what both
    a refusal and an absence answer with and an empty file is b'' rather than
    None.
    """

    value: object = None
    why: str = None
    absent: bool = False


def read_state_bytes(path) -> StateFile:
    """The bytes of one of carryon's own state files, or why nothing came back.

    The gate, and the whole of it: everything below this is a question about
    what the bytes MEAN. It is split out from `read_state_json` because the
    third state file is not a JSON document - ~/.carryon/master.key holds bare
    hex - and "the parse does not fit" was taken for "the gate does not apply".
    It cost that file every defect this gate exists for, on the one file in
    carryon that opens the Archive: a named pipe there hung `init`, `push`,
    `pull` and `pair` for ever with no output at all, and a dangling link
    answered ENOENT, which `fetch_master` spells "this machine holds no key" -
    after which `init` mints a fresh recovery key and leaves the Archive's
    History unopenable by the key still sitting in that file.

    So: the type is settled BEFORE the open, and again on the descriptor the
    bytes come from, with O_NONBLOCK on the way in. A stat on its own answers
    about the name as it was a syscall ago, and a fifo arriving in between is
    an open() that never returns; O_NONBLOCK on its own is not enough either,
    since a fifo opened that way reads as an empty file rather than as a wrong
    one. It is the same pair `read_carryable` uses, for the same reason.

    A refusal is returned rather than raised, because the callers need
    opposite things from it and none of them is a traceback: `load` turns it
    into the SystemExit that ends a command whose every subcommand depends on
    the file, `fetch_master` into the one that must not read as "no key", and
    the high-water mark into a warning line, because that mark is deliberately
    never a gate.
    """
    path = pathlib.Path(path)
    try:
        os.lstat(str(path))
    except (OSError, ValueError) as exc:
        # Only these two errnos mean no name is there at all - the same pair
        # `load` already named and the same one `state_identities` uses for a
        # state directory that was never made. Everything else is a name that
        # is there and will not answer, which is a fact worth reporting rather
        # than a machine that was never set up.
        if getattr(exc, "errno", None) in (errno.ENOENT, errno.ENOTDIR):
            return StateFile(absent=True)
        return StateFile(why=f"this machine would not look at it "
                             f"({getattr(exc, 'strerror', None) or exc})")
    try:
        info = os.stat(str(path))
    except (OSError, ValueError) as exc:
        # lstat answered and stat did not: a link pointing at nothing, a loop,
        # or a target this user cannot reach. A name IS there, so this is a
        # refusal and never the first-run default.
        return StateFile(why=f"this machine would not read it "
                             f"({getattr(exc, 'strerror', None) or exc})")
    if not stat.S_ISREG(info.st_mode):
        return StateFile(why=WHY_NOT_ORDINARY)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError) as exc:
        return StateFile(why=f"this machine would not read it "
                             f"({getattr(exc, 'strerror', None) or exc})")
    try:
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return StateFile(why=WHY_NOT_ORDINARY)
            return StateFile(value=handle.read())
    except OSError as exc:
        return StateFile(why=f"this machine would not read it "
                             f"({exc.strerror or exc})")


def read_state_json(path) -> StateFile:
    """One of carryon's own JSON files, or why nothing came back.

    The read side of ~/.carryon, and it exists for the reason `read_carryable`
    exists one section down: the same question was being asked in two places
    and answered differently in each, so a shape closed at one was open at the
    other. `load` guarded UnicodeDecodeError around the parse; the high-water
    mark's reader guarded it around the read, where it cannot fire - so a
    state.json that is not UTF-8, which that function's own docstring calls
    ordinary, came out of both `push` and `pull` as a bare traceback. Neither
    refused a named pipe, so one at either name blocked every subcommand for
    ever.

    These files are carryon's own, which is why they were skipped when user
    content and Destination content were brought under gates - and it is not a
    reason. carryon writes them; it does not control what is at that name when
    it next reads. A synced folder puts a conflict copy there, a truncated
    write leaves a partial file, a restored backup leaves an older one, and
    anything running as the user can put a directory or a device node at the
    name. That is ADR-0009's rule about a Destination, and the only thing that
    made it feel inapplicable here is who owns the directory.

    Everything about the FILE is `read_state_bytes` above; what is left here
    is what the bytes mean. That split is this round's correction, and the
    reason for it is that the third state file is not JSON: ~/.carryon/
    master.key holds bare hex, so it did not fit this function's shape and was
    left reading itself with a bare `Path.read_text()` - the one state read
    still outside the gate, on the file that opens the Archive.

    Decode and parse are guarded together because they are one step - bytes to
    a document - and splitting them is exactly how the decode error ended up in
    the wrong `try`. RecursionError is named beside ValueError for the reason
    it is named wherever an Archive object is parsed: json.loads answers deep
    nesting with a RuntimeError, so a two-name guard walks past the cheapest
    input there is.

    The document has to be an object, because every file carryon keeps for
    itself is one. Both callers checked that afterwards in two spellings; a
    question with one answer belongs in one place.
    """
    state = read_state_bytes(path)
    if state.value is None:
        return state  # absent, or a refusal that has already said why
    try:
        loaded = json.loads(state.value.decode("utf-8"))
    except UnicodeDecodeError as exc:
        return StateFile(why=f"it is not valid UTF-8 text ({exc})")
    except (ValueError, RecursionError) as exc:
        return StateFile(why=f"it is not valid JSON ({exc})")
    if not isinstance(loaded, dict):
        return StateFile(why=f"it holds a {type(loaded).__name__} where "
                             "carryon writes a JSON object")
    return StateFile(value=loaded)


def spellable(text: str) -> bool:
    """Whether `text` is a path this machine's syscalls will even look at.

    Two characters no filesystem holds, neither of which fails politely. A NUL
    comes back from resolve() as a ValueError out of posixpath, and a lone
    surrogate ('\\ud800', legal in JSON and in a config file) cannot be
    encoded even with surrogateescape - UnicodeEncodeError, which is a
    ValueError subclass and so misses an `except (OSError, RuntimeError)` just
    as widely.

    Asked before either of those, because both callers exist to refuse by
    name: config.load runs on every command, so a bad `carry` line was a
    traceback out of init, push and pull alike, and sync's stored-MANIFEST
    check runs mid-pull, where a traceback strands a $HOME that already has a
    History in it (ADR-0009).
    """
    if "\x00" in text:
        return False
    try:
        text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return False
    return True


def writable(text: str) -> bool:
    """Whether `text` can be written out of this process at all.

    The strict sibling of `spellable` above, and the difference is the
    encoding's error handler rather than the characters. `spellable` asks
    whether a SYSCALL will look at a path, so it encodes with surrogateescape,
    which accepts the \\udc80-\\udcff range by design - that is what a
    filename which is not valid UTF-8 comes back from the kernel as, and
    handing it straight back is how it gets opened again. This asks whether
    the string can leave the process as bytes anyone else has to read: an
    Archive label, an object name, a JSON document that is about to be
    encoded. Those go out strictly, and a lone surrogate is a
    UnicodeEncodeError wherever they are written.

    The same question is asked of the strings that arrive from the other
    direction - archive.key_refusal of a catalogue key, history of a recorded
    cwd, sync._renderable of a stored MANIFEST - each at its own door, because
    what a caller does about the answer is what differs.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def lands_in_state(candidate: pathlib.Path, home: pathlib.Path) -> bool:
    """Whether `candidate`, every symlink on the way to it followed, lands on
    or inside carryon's own state directory (~/.carryon).

    The one rule the capture leg (user_adapter, via _relative_to_home) and the
    restore leg (sync._setup_target) both consult, so the two cannot drift into
    disagreeing about what ~/.carryon is - the drift that once let a
    case-variant through capture while restore already folded.

    Two ways a string check missed the directory, both closed here by
    construction rather than by spelling:
      symlink  '~/link/master.key' with link -> ~/.carryon is lexically
               nowhere near '.carryon', so resolve() follows the link before
               the comparison sees it. capture reads through links (ADR-0007),
               so this leg cannot defer the way restore does.
      case     on APFS and NTFS '~/.Carryon' IS '~/.carryon', one file under
               two names, so the comparison folds case. Refused on a
               case-sensitive filesystem too, where the variant is harmless:
               that costs nothing, and assuming the filesystem does not fold
               costs the master key.

    Compared per path component rather than as a string prefix, so a sibling
    like '.carryon-backup' does not trip it. A candidate that will not resolve
    at all is treated as landing here: carryon cannot prove it does not, and
    both legs fail closed on their own state. ValueError is in that arm
    alongside the two the syscall raises, because resolve() answers a NUL and
    a lone surrogate with one (see spellable) and this function's whole job is
    to give a yes or a no rather than a traceback.
    """
    state = state_dir(home)
    try:
        resolved = pathlib.Path(candidate).resolve()
        state = state.resolve()
    except (OSError, RuntimeError, ValueError):
        return True
    inner = tuple(part.casefold() for part in resolved.parts)
    outer = tuple(part.casefold() for part in state.parts)
    return inner[:len(outer)] == outer


def stays_under_home(candidate: pathlib.Path, home: pathlib.Path) -> bool:
    """Whether `candidate`, every symlink on the way to it followed, is $HOME
    or something inside it.

    The counterpart of lands_in_state, and resolved for the same reason: the
    engine that acts on the answer follows links (ADR-0007), so a check on the
    unresolved string answers about a path nobody reads. '~/link/loot.txt'
    with link -> /etc spells nothing outside $HOME, holds no '..', and is a
    file from outside $HOME in a plaintext Setup.

    Case is NOT folded here, and that is the opposite choice from
    lands_in_state on purpose. Both fail closed, and closed points in opposite
    directions: landing in ~/.carryon is a refusal, so an ambiguous spelling
    must count as landing there; staying under $HOME is a permission, so an
    ambiguous spelling must not count as staying. A path that will not resolve
    at all is not under home either - carryon cannot prove it is.
    """
    try:
        inner = pathlib.Path(candidate).resolve()
        outer = pathlib.Path(home).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return inner.parts[:len(outer.parts)] == outer.parts


def spells_state(candidate: pathlib.Path, home: pathlib.Path) -> bool:
    """Whether `candidate` NAMES carryon's own state, no link followed.

    lands_in_state's lexical half, and the two are asked about different
    parties. A path that spells '~/.carryon' was composed by whoever wrote the
    name - on the restore leg that is a master key holder, since the tar is
    sealed - and there is no honest reading of it, so it is refused whole. A
    path that only RESOLVES there got that way through a link sitting in this
    machine's own tree, which needs no key and no Destination access to plant:
    refusing on one hands anybody with write access to a project directory a
    permanent abort on every pull from every machine, which is the shape
    ADR-0009 rules out elsewhere in as many words.

    No syscall, so no ENAMETOOLONG, no EACCES and no symlink loop - which also
    means no divergence between the Python versions carryon must pass on,
    where resolve() answers a loop with a RuntimeError on one and the
    unresolved path on the other.
    """
    inner = tuple(part.casefold() for part in pathlib.Path(candidate).parts)
    outer = tuple(part.casefold() for part in state_dir(home).parts)
    return inner[:len(outer)] == outer


class StateIdentities(frozenset):
    """The state directory's inodes, and whether the walk saw all of it.

    A frozenset because that is what every caller does with it - one `in` per
    file read - and a class because "found nothing" and "could not look" are
    different answers and the plain set could only spell the first. That
    difference is the whole of the defect below.
    """

    def __new__(cls, pairs=(), unreadable=()):
        self = super().__new__(cls, pairs)
        self.unreadable = tuple(unreadable)
        return self

    @property
    def complete(self) -> bool:
        return not self.unreadable

    @property
    def why(self) -> str:
        """The sentence a refusal built on this carries, or ''."""
        if self.complete:
            return ""
        path, reason = self.unreadable[0]
        more = (f" (and {len(self.unreadable) - 1} more)"
                if len(self.unreadable) > 1 else "")
        return (f"{WHY_STATE_UNANSWERED}: {printable(str(path))} would not "
                f"list ({printable(reason)}){more}")


def state_identities(home: pathlib.Path = HOME) -> StateIdentities:
    """(st_dev, st_ino) for every ordinary file under ~/.carryon, with every
    directory the walk could not list.

    Every other rule here answers about a path, and a hard link is a second
    NAME for the same content: `ln ~/.carryon/master.key <captured tree>`
    creates a directory entry that is not a symlink, whose resolve() is
    itself, comfortably under $HOME and nowhere near '.carryon'. Every
    path-shaped check passes and copy2 copies the key verbatim. The one thing
    the two names share is the inode, which is what this collects.

    A symlink inside the state directory is skipped: what it points at is
    somebody else's file that happens to be reachable through here, and the
    identity worth protecting is the state's own content.

    What the walk could NOT see is returned rather than swallowed, and that is
    this round's correction. It used to answer an empty set for a state
    directory it could not read, `_is_state_content` read an empty set as "no",
    and the identity half of the gate - the only half a hard link cannot
    defeat - switched itself off for the whole run without a line in any
    report. Mode 0300 is the reachable spelling: a directory you may enter and
    may not list, which a botched chmod and a backup restored with the wrong
    modes both produce. carryon goes on opening its own config.json and its
    own master.key by name throughout, so nothing else notices; the push runs
    normally, and a hard link to that key in a Session tree is packed and laid
    down in every pulling machine's project directory.

    It is the shape ADR-0009's last section names: an answer inherited from a
    level that could not answer. Every other walk in this package reports a
    directory it could not list - capture.tree_files, history._listing,
    layout._entries, destinations/base._local_keys - and this was the last one
    that did not.

    scandir rather than rglob, because rglob swallows a PermissionError and
    keeps going: the errors are the point here, so the walk has to be one that
    can see them. A state directory that is simply not there is an answerable
    "none" - a machine before `init` has no key to protect - and only that one
    errno means absent.
    """
    found, unreadable = set(), []
    state = state_dir(home)
    stack = [state]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(str(directory)))
        except (OSError, ValueError) as exc:
            if (directory == state
                    and getattr(exc, "errno", None) in (errno.ENOENT,
                                                        errno.ENOTDIR)):
                continue
            unreadable.append((directory,
                               getattr(exc, "strerror", None) or str(exc)))
            continue
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                unreadable.append((entry.path, exc.strerror or str(exc)))
                continue
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(pathlib.Path(entry.path))
            elif stat.S_ISREG(info.st_mode):
                found.add((info.st_dev, info.st_ino))
    return StateIdentities(found, unreadable)


WHY_STATE = "it reads carryon's own state (~/.carryon)"
WHY_OUTSIDE_HOME = "it reads a file outside $HOME"
# Its own sentence rather than WHY_STATE, because it is a different claim: not
# "this file is carryon's own state" - which carryon has not established and
# must not assert about somebody's notes - but "carryon cannot tell, and the
# one thing it cannot tell about is the key that opens the Archive".
WHY_STATE_UNANSWERED = ("carryon cannot tell whether it reads its own state "
                        "(~/.carryon)")


def state_unanswered(identities):
    """Why the state question cannot be answered at all, or None.

    Asked wherever the identity half is - `carry_refusal` for one path,
    `unsafe_reads` for the root of a tree - so the two cannot come to differ
    about what an incomplete walk means, which is how this whole class of
    defect has arrived every time.
    """
    if identities is None or getattr(identities, "complete", True):
        return None
    return identities.why


def _is_state_content(path: pathlib.Path, identities) -> bool:
    """Whether `path` - links followed, the way the engine opens it - is one
    of the files under ~/.carryon under another name."""
    if not identities:
        return False
    try:
        st = path.stat()
    except (OSError, ValueError):
        return False
    return (st.st_dev, st.st_ino) in identities


def carry_refusal(path: pathlib.Path, home=HOME, identities=None,
                  followed=True, leaves_machine=True):
    """Why this file's CONTENT may not be read for the caller's purpose, or
    None.

    The one question, with one answer, asked wherever carryon reads a file it
    intends to carry: the Setup capture, a handpicked tree, a Session tree, a
    project's residue. Six rounds of review each found the same defect in a
    place the previous round had not looked - a rule closed where it was
    reviewed and open where it was not - and two legs asking one question in
    two spellings is what produced every one of them. There is no version of
    this that is asked in the History engine and re-derived in the capture
    engine; a leg that wants the answer calls this, and a leg that wants the
    bytes calls `read_carryable`, which calls this first.

    Both halves of the question, always, because each is blind to the other:

      identity  a hard link is a second NAME for the same content.
                `ln ~/.carryon/master.key <captured tree>` is not a symlink,
                resolves to itself, sits under $HOME and nowhere near
                '.carryon'. Every path-shaped check passes and the read hands
                the key's bytes over verbatim. Only (st_dev, st_ino) sees it,
                and a bind mount is another alias landing on the same check.
                A clonefile is NOT: it holds the same bytes under an inode of
                its own, so it is a copy rather than an alias and no identity
                rule can see one (see this module's docstring).
      path      a symlink is a name for content somewhere else, and the
                engine follows links by design (ADR-0007). `lands_in_state`
                resolves and folds case per component, so neither a link into
                ~/.carryon nor '~/.Carryon' (the SAME file on APFS and NTFS)
                gets through, and a path this machine will not resolve at all
                counts as landing there - carryon cannot prove it does not.

    Identity is asked of every path rather than only of the links, because a
    hard link is an ordinary file to every question pathlib can put. The state
    path rule is asked of every path too: a member reached through a linked
    ANCESTOR directory is not itself a link, and which walks descend into one
    is a property of pathlib's glob rather than of this rule.

    The $HOME rule is the one part that is not asked of everything, and the
    asymmetry is deliberate rather than an omission. Landing in ~/.carryon is
    a carve-out, so an ambiguous spelling must count as landing there; staying
    under $HOME is a permission a whole tree inherits from its root. An agent
    directory living on another volume or in a checkout outside $HOME, linked
    in at its root, is the arrangement ADR-0007 has capture read through
    happily - and every member under it resolves outside $HOME. So the
    boundary is asked of a link found INSIDE a tree, which is a member
    reaching sideways out of the tree its root declared.

    `followed` is False for a link the engine is known not to read through -
    the top level of a skills directory, where do_skills classifies a link as
    re-resolvable or as managed elsewhere and copies neither. The state rule
    still applies there and the $HOME rule does not: ~/.carryon is unreachable
    by construction (ADR-0008), so refusing wider than the engine reads costs
    nobody anything, while a skill symlinked to a team share is an arrangement
    the engine supports by name.

    `leaves_machine` is False for the one read whose bytes go nowhere: the
    copy a pull takes of the file it is about to replace, into
    ~/.carryon/backups. The state carve-out and the identity question hold
    there - a backup is no place to duplicate the master key either - and the
    $HOME boundary does not, because it is a rule about what may be PUBLISHED
    and those bytes are not being published. Applying it there cost `--force`
    its documented behaviour for anyone whose dotfiles checkout lives outside
    $HOME: '~/.claude/settings.json -> /opt/dotfiles/settings.json' was
    refused with a sentence about a rule that did not apply to it, and the
    flag whose whole purpose is writing through that link silently stopped
    working. One function, two questions, and which one is being asked is the
    caller's to say.

    A link that leads to neither a file nor a directory - broken, or a loop -
    is skipped: there is nothing to read through it, and refusing on one would
    fail a push over a file nobody was carrying. So is a path this machine
    will not stat at all, and that is not a hole: the walk that meets it
    cannot open it either, and `read_carryable` asks the identity question a
    second time on the descriptor it actually reads, where no answer about the
    path can go stale.

    The identity half is re-asked on that descriptor; the PATH half is not,
    and the asymmetry is worth stating rather than leaving to be noticed. A
    name that is an ordinary file when this runs and a symlink out of $HOME
    when the open happens yields the target's bytes. It needs a race in a
    directory the attacker can already write to, and the state carve-out is
    unaffected - identity covers that one whatever name it is wearing.
    """
    # Coerced, like every other rule in this module: a caller handing over a
    # string is handing over a path, and a rule whose whole job is a yes or a
    # no should not have an AttributeError as a third way out.
    path = pathlib.Path(path)
    if identities is None:
        identities = state_identities(home)
    # First, because it is the one refusal that is not about this path at all:
    # while the state walk cannot answer, no answer about any path is worth
    # more than the walk it rests on.
    unanswered = state_unanswered(identities)
    if unanswered is not None:
        return unanswered
    try:
        is_link = path.is_symlink()
        is_file = path.is_file()
        is_dir = path.is_dir()
    except (OSError, ValueError):
        return None
    if is_file and _is_state_content(path, identities):
        return WHY_STATE
    if lands_in_state(path, home):
        return WHY_STATE
    if not is_link or not (is_file or is_dir):
        return None
    if leaves_machine and followed and not stays_under_home(path, home):
        return WHY_OUTSIDE_HOME
    return None


def read_carryable(path, home=HOME, identities=None, followed=True,
                   leaves_machine=True):
    """(data, None) for a file carryon may carry, or (None, why).

    The only way in this package to turn a user's path into bytes that leave
    it, and the reason it reads rather than merely answering: a check beside a
    read is a check a walk can be written without, and that is precisely how
    the History leg came to pack a hard link to the master key while the Setup
    leg beside it refused the same file. Here the answer and the bytes come
    back from one call, so a leg that wants content has already asked.

    Both outcomes are the same shape - a sentence naming why nothing came
    back - because every caller does the same thing with them: it does not use
    the bytes, and it says so in its own report. What differs between a
    refusal and an unreadable file is the sentence, not the handling. The
    read is inside the guard for the reason every read in carryon is: a
    mode-000 file, a link whose target moved, a transcript rotated out from
    under the walk are all ordinary, and each of them used to be a traceback
    out of a command that had already written something.

    The identity question is then asked a SECOND time, on the descriptor this
    call is about to read, and that is the one thing a check beside a read can
    never do. Every answer above is about the path as it was a syscall ago,
    and a project directory is a place anybody with write access can swap a
    file for a hard link to ~/.carryon/master.key between the walk and the
    read - which is a live agent's ordinary rate of change, not an exotic
    race. fstat on the open descriptor names the inode whose bytes are coming
    back, so there is no interval left between the question and the answer.
    It is the read side of the same discipline write_state_bytes uses on the
    write side, one syscall over.

    And it is asked of a REGULAR file, with O_NONBLOCK on the way in. A named
    pipe answers read() by waiting for a writer that may never come, which is
    a `carryon push` that never returns and prints nothing - the Destination
    layer refuses one for exactly this reason (destinations/base.py). Both
    walks that reach here filter a fifo out first; that they do is a property
    of two walks rather than of this one, and being right about a fifo is not
    a thing to leave to whichever walk arrives next.

    `leaves_machine=False` drops the $HOME boundary and nothing else, for the
    one caller whose bytes stay on this machine - `carry_refusal` says which
    and why.
    """
    path = pathlib.Path(path)
    if identities is None:
        identities = state_identities(home)
    why = carry_refusal(path, home, identities, followed, leaves_machine)
    if why is not None:
        return None, why
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError) as exc:
        return None, (f"this machine would not read it "
                      f"({getattr(exc, 'strerror', None) or exc})")
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (info.st_dev, info.st_ino) in identities:
                return None, WHY_STATE
            if not stat.S_ISREG(info.st_mode):
                return None, ("it is not an ordinary file - a socket, a "
                              "device or a named pipe")
            return handle.read(), None
    except OSError as exc:
        return None, (f"this machine would not read it "
                      f"({exc.strerror or exc})")


def unsafe_reads(src: str, home: pathlib.Path = HOME, identities=None,
                 kind: str = "tree") -> list:
    """(path, why) for every path the capture engine would read for the Item
    at `src` that a Setup must not carry. '~/'-relative, sorted, empty is
    clean.

    `carry_refusal` answers about one named path, and an Item is a TREE
    expanded after that answer. '~/.mytool' is an innocent directory no rule
    refuses; put '.mytool/notes.md' inside it pointing at
    ~/.carryon/master.key and the engine copies the key into the plaintext
    Setup, and pointing it outside $HOME puts a file this machine never agreed
    to carry there instead. The same holds one component inside any
    adapter-declared tree, where no handpicking is involved at all. So the
    gate is asked again for every path the expansion produces.

    This is the ONE thing the gate cannot do for a caller, which is why it is
    a function of its own rather than a fourth argument: a Setup refuses whole
    (ADR-0001), so it has to know every offending path in the capture set
    BEFORE a byte is copied anywhere, and that is a walk with no read in it.
    Every other leg meets its files one at a time and asks through
    `read_carryable` instead.

    The item's ROOT is asked about the state and about identity, and NOT about
    $HOME. That is the one asymmetry here and it is deliberate: a whole agent
    directory living on another volume or in a checkout outside $HOME, linked
    in at its root, is the arrangement ADR-0007 has capture read through
    happily, and `_relative_to_home` already applies the boundary to the roots
    a USER names. What the member rule catches is a member reaching sideways
    out of the tree its root declared.

    `identities` is passed in by a caller asking about many Items so the state
    directory is walked once rather than once per Item; it is computed here
    when a caller asks about one. `kind` is the Item's kind, which decides
    only which of a skills directory's links the engine reads through - see
    `carry_refusal`.
    """
    home = pathlib.Path(home)
    root = home / src
    if identities is None:
        identities = state_identities(home)
    found = []
    unanswered = state_unanswered(identities)
    if unanswered is not None:
        # The whole Item, not a walk of it: while the question cannot be
        # answered it cannot be answered about any member either, and a Setup
        # refuses whole (ADR-0001). Named against the Item's own src so the
        # refusal reads like every other one this returns.
        return [(src, unanswered)]
    if lands_in_state(root, home) or _is_state_content(root, identities):
        found.append((src, WHY_STATE))
    try:
        members = sorted(root.rglob("*")) if root.is_dir() else []
    except (OSError, ValueError):
        members = []
    for path in members:
        followed = not (kind == "skills" and path.parent == root)
        why = carry_refusal(path, home, identities, followed)
        if why is None:
            continue
        try:
            rel = path.relative_to(home).as_posix()
        except ValueError:
            rel = str(path)
        found.append((rel, why))
    return found


def default_config() -> dict:
    return {
        "version": 1,
        "destination": "",
        "machine": socket.gethostname(),
        "excludes": [],
        "carry": [],
        "encrypt_all": False,
    }


def _fail(key: str, why: str):
    raise SystemExit(f"config.json: {key!r} {why}")


def validate(cfg: dict) -> dict:
    """Refuse, naming the key. A typo that validation shrugs at is a setting
    silently not applied."""
    known = default_config()
    for key in cfg:
        if key not in known:
            _fail(key, "is not a carryon setting")
    for key in known:
        if key not in cfg:
            _fail(key, "is missing")

    if cfg["version"] != 1 or isinstance(cfg["version"], bool):
        _fail("version", f"must be 1, got {cfg['version']!r}")
    if not isinstance(cfg["destination"], str):
        _fail("destination", "must be a destination spec string")
    # The third string that keys a catalogue in the Archive's Index, and the
    # only one the user chooses. It also seals the Setup's tag
    # (archive.setup_label) and names a directory on the Destination, so what
    # it may be is `machine_name_refusal` above rather than a spelling of its
    # own here: this gate sees a hand-edited config.json and `save` sees every
    # `init`, while sync settles the same question about names that came back
    # off a Destination. One question, three askers, one function.
    why = machine_name_refusal(cfg["machine"])
    if why is not None:
        _fail("machine", f"{why}. Name this machine explicitly: "
                         "`carryon init --machine NAME`")
    for key in ("excludes", "carry"):
        value = cfg[key]
        if not isinstance(value, list) or \
                not all(isinstance(v, str) and v for v in value):
            _fail(key, "must be a list of non-empty strings")
    if not isinstance(cfg["encrypt_all"], bool):
        _fail("encrypt_all", "must be true or false")
    return cfg


def load(home: pathlib.Path = HOME) -> dict:
    """The config, validated, with defaults filled for anything unset.

    A missing file is not an error - the default has to be effortless.

    Every other way of failing IS an error, and every one of them says which
    file and why. This runs before any subcommand has decided anything, so
    what escapes here escapes from init, capture, push, pull and pair alike:
    the read used to sit outside the guard, which made a config.json that is
    a directory (a synced folder, a restored backup) an IsADirectoryError and
    one this user cannot read a PermissionError, both as a bare traceback.

    Not a fallback to the defaults, which is the tempting shape: the default
    config names no Destination, so a push that quietly used it would report
    'no Destination configured' about a machine that has one, and a pull
    would look at the wrong Archive. A file that is there and unreadable is a
    different fact from a file that is not there.

    Which of those it is has been `read_state_json`'s to answer since this
    file came under a gate, and the answer got sharper in the move: an exists()
    ahead of the read swallowed ELOOP as 'missing' and a bare read swallowed a
    dangling symlink the same way, so a config.json that is plainly there and
    plainly broken silently ran the defaults. Only "no name at all" is absent
    now, and a name that will not read is a refusal naming the file.
    """
    path = config_path(home)
    state = read_state_json(path)
    if state.absent:
        return default_config()
    if state.why is not None:
        raise SystemExit(f"{path}: carryon reads its config on every command "
                         f"and {state.why}")
    return validate({**default_config(), **state.value})


def save(cfg: dict, home: pathlib.Path = HOME) -> pathlib.Path:
    """Write the config, refusing to write it through a name someone else
    owns. 0600 rather than the 0644 a plain write_text left: this file names
    the Destination, and capture refuses to carry it for that reason."""
    validate(cfg)
    path = config_path(home)
    write_state_file(path, json.dumps(cfg, indent=2) + "\n")
    return path


def apply_excludes(adapters: dict, patterns) -> tuple:
    """A filtered copy of the adapter registry, minus Items matching `patterns`.

    Returns (filtered, unmatched). A pattern that removed nothing comes back in
    `unmatched` so a typo is reported instead of silently excluding nothing.
    fnmatchcase, not fnmatch: fnmatch case-folds on darwin, and the same config
    must not exclude different things on different machines.
    """
    matched = set()
    filtered = {}
    for key, adapter in adapters.items():
        kept = []
        for item in adapter.items:
            hits = [p for p in patterns if fnmatch.fnmatchcase(item.src, p)]
            if hits:
                matched.update(hits)
            else:
                kept.append(item)
        filtered[key] = dataclasses.replace(adapter, items=tuple(kept))
    return filtered, [p for p in patterns if p not in matched]


def _relative_to_home(raw: str, home: pathlib.Path) -> str:
    path = raw.strip().rstrip("/")
    if not spellable(path):
        raise SystemExit(
            f"carry: {raw!r} holds a character no filesystem can spell (a NUL "
            "or a lone surrogate), so nothing on this machine can be read "
            "from it")
    if path.startswith("~/"):
        path = path[2:]
    elif path == "~":
        path = ""
    # Not an `elif`: '~/' is stripped by string surgery, so '~//abs/path'
    # arrives here as the absolute '/abs/path' - and a chain that had already
    # spent its branch on the tilde walked past the $HOME boundary this arm
    # exists to enforce, putting a file from outside home into the plaintext
    # Setup. One '~' followed by an absolute path IS that absolute path.
    if path.startswith("/"):
        try:
            path = str(pathlib.Path(path).relative_to(home))
        except ValueError:
            raise SystemExit(
                f"carry: {raw} is outside $HOME - only paths under home can "
                "join a Setup")
    # Normalised only now, never before the two arms above: '~//etc/passwd'
    # normalised first reads as '~/etc/passwd', which quietly carries a
    # different file instead of refusing an absolute path that left home.
    # PurePosixPath drops the empty and '.' components and nothing else - a
    # '..' is reported rather than collapsed, because collapsing one rewrites
    # the user's entry through a link they may have meant to follow.
    parts = pathlib.PurePosixPath(path).parts
    # a `..` would make `home / src` read outside $HOME after all
    if ".." in parts:
        raise SystemExit(f"carry: {raw} escapes $HOME - only paths under "
                         "home can join a Setup")
    # '~', '/', '.' and $HOME itself all normalise to no parts at all, and
    # home/'' *is* $HOME - the whole home directory as a plaintext Setup
    if not parts:
        raise SystemExit(f"carry: {raw!r} is the entire home directory - "
                         "refusing to carry it")
    path = pathlib.PurePosixPath(*parts).as_posix()
    # Everything above is spelling. This is the boundary: what the engine will
    # actually open, with the links on the way to it followed, the way the
    # engine opens it.
    if not stays_under_home(pathlib.Path(home) / path, home):
        raise SystemExit(
            f"carry: {raw} leads outside $HOME - only paths under home can "
            "join a Setup")
    # Not a string compare against '.carryon': that read only one of the
    # directory's names on a case-folding filesystem, and none of its names
    # through a link that resolves there. Resolve and fold instead, the one
    # rule the restore leg shares (sync._setup_target).
    if lands_in_state(pathlib.Path(home) / path, home):
        raise SystemExit(
            f"carry: {raw} is carryon's own state - the master key can live "
            "under ~/.carryon, and a Setup contains no credentials")
    return path


def _kind_of(path: pathlib.Path, raw: str) -> str:
    """Whether a handpicked path is a tree or a file - or a refusal, when the
    OS declines to answer.

    is_dir() looks like a question that always has an answer, and pathlib
    turns some failures into False for you: ENOENT, ENOTDIR, EBADF, ELOOP.
    ENAMETOOLONG is not on that list, so a `carry` line with a component
    longer than the filesystem allows - no NUL, no surrogate, nothing
    `spellable` can see, and a path resolve() answers about quite happily -
    came back out of the registry as an OSError. That ended `push` and `pull`
    in a traceback before either had said what it was going to do, which is
    the one thing this code never does with bad input.

    ValueError is named as well, though `spellable` refuses the two characters
    that raise it before anything reaches here: this is the syscall, and a
    function whose job is to return one of two strings should not have a third
    way out that depends on a check somewhere else still being in place.
    """
    try:
        return "tree" if path.is_dir() else "file"
    except (OSError, ValueError) as exc:
        raise SystemExit(
            f"carry: {raw!r} is a path this machine cannot look at "
            f"({exc}) - nothing can be read from it")


def user_adapter(cfg: dict, home: pathlib.Path = HOME) -> Adapter:
    """An Adapter for the paths the user handpicked in `carry`.

    Nothing vouches for these - no verified_against, no layout-drift watch -
    and the manifest says so. But because they are ordinary config Items, the
    existing engine captures them and the fail-closed scanner refuses on any
    credential inside, which is the safety property ADR-0008 buys for free.
    """
    items = []
    for raw in cfg.get("carry", []):
        src = _relative_to_home(raw, home)
        kind = _kind_of(home / src, raw)
        items.append(Item(src, f"handpicked/{src}", kind, CONFIG,
                          HANDPICKED_NOTE))
    return Adapter(
        key="handpicked",
        name="Handpicked paths",
        detect="",
        verified_against="user-supplied - unvouched",
        items=tuple(items),
        platforms=PLATFORMS,
    )

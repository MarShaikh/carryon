"""Session discovery, packing and restore - the engine behind `chats` items.

An adapter's `chats` Item only declares where an agent keeps its Sessions and
which layout they follow; this module interprets the layout. Discovery walks
the declared root and yields Session trees (a Session is a *tree*, not a file:
the main Transcript plus everything the work spawned beneath it) and the
per-project residue left beside them. Packing canonicalises every member via
rekey and tars it; unpacking expands it against the local home and lands it in
the locally re-derived project directory.

The one non-obvious decision: a Session whose Transcript records no cwd
inherits nothing - not even a sibling Session's cwd from the same project dir.
The dir name is a lossy encoding (ADR-0006) and cannot confirm a guess, so the
Session is reported and carried without a cwd rather than guessed at. All
agent specifics live in LAYOUT_STRATEGIES and the adapter declarations; the
engine itself never names an agent.

What this engine does NOT own is what a file may be read for at all. That is
config.carry_refusal, and it is the Setup engine's rule too - one function
because this module having its own spelling of it is what let a HARD link to
~/.carryon/master.key inside a Session tree be packed and laid down at mode
0644 in every pulling machine's project directory, while the capture engine
next door refused the identical file. Discovery asks it per member
(`_packable`), and every read of a member's bytes goes through
config.read_carryable (`_member_bytes`), which asks it again on the descriptor
it opens.

Nor does it own what a member may be written OVER. Who holds a landing path is
external.owner_of, and putting bytes there is external.write_owned - one
function that asks and writes, because the ask this module used to make and
the `Path.write_bytes` two lines below it were separated by a syscall, which
on a project directory anybody with an account can write to is not a small
interval. The union rule (ADR-0002) is this module's, and it is asked of a
descriptor now for the same reason: `member_verdict` opened a local Transcript
with no question at all, so a named pipe where one belongs stopped a pull for
ever.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import tarfile

from . import archive, config, external, rekey, secrets


# --- writing a member of a restored Session ----------------------------------
#
# Who owns the path is external.owner_of, which used to live here. It moved
# because the question is not the History engine's: the Setup leg asks it, the
# conflicts directory asks it, and a write into ~/.carryon needs it from
# config.py, which cannot import this module at all - so those writes grew a
# bare mkdir instead of an answer. One question, one implementation, and the
# root each leg is entitled to make things under is the caller's own.
#
# `write_member` lived here too, and was two syscalls with no question in
# them: a mkdir and a Path.write_bytes, guarded so a directory standing where
# a Transcript lands became a report line rather than a traceback. That is
# still true and it is now external.write_owned's, along with the question the
# caller used to ask a syscall earlier - the ownership answer and the write
# are one call, because the interval between them is a project directory
# anybody with an account can write to.


# --- records -----------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Session:
    """One Session tree on disk, ready to pack.

    project_dir is home-relative POSIX; files and main_path are POSIX paths
    relative to project_dir, which is also how they appear inside the tar.
    cwd is None when the main Transcript recorded none - reported, not guessed.
    """
    agent: str
    uuid: str
    project_dir: str
    cwd: str | None
    files: tuple
    main_path: str


@dataclasses.dataclass(frozen=True)
class ProjectResidue:
    """What a project dir holds outside any Session - memory files etc.

    Same path conventions as Session, so pack_session packs either record.
    """
    agent: str
    cwd: str | None
    project_dir: str
    files: tuple


@dataclasses.dataclass(frozen=True)
class Discovery:
    sessions: tuple
    residues: tuple
    missing_cwd: tuple  # home-relative paths whose cwd could not be recovered
    # home-relative paths left out because reading them would read carryon's
    # own state through a link. Reported by the caller, never silently
    # dropped: a Session quietly short a file reads as one that was carried.
    withheld: tuple = ()
    # (home-relative path, why) per directory the walk could not list and per
    # Transcript it could not open. $HOME is an input like any other: a
    # project directory left mode 000 by a backup restore, or a Transcript an
    # agent wrote under sudo, is ordinary and needs no attacker. Each one used
    # to be an OSError out of push and out of pull, thrown from inside a walk
    # with no report yet printed - which is precisely what capture.tree_files
    # and capture.do_file already refuse to do on the Setup leg.
    unreadable: tuple = ()
    # (home-relative path, why) per Session or residue whose NAME cannot be a
    # catalogue key in the Archive. Same channel shape and same reason as the
    # two above: what carryon declines to carry is said out loud, because a
    # push that quietly leaves one out reads as one that carried everything.
    unnamable: tuple = ()


@dataclasses.dataclass(frozen=True)
class PackReport:
    """What canonicalising one Session (or residue) did, plus the credential
    REPORT of ADR-0001: counts only, never a refusal, never a matched value."""
    members: int = 0
    rewritten_values: int = 0    # JSON string values changed
    text_replaced: int = 0       # occurrences rewritten in non-JSONL text
    malformed: int = 0           # JSONL lines that did not parse, passed through
    near_misses: int = 0         # case-insensitive-only matches, never rewritten
    bare_tokens: int = 0         # home became a bare '~' in text; pull reports it
    non_utf8: int = 0            # members carried unchanged
    credential_members: tuple = ()   # member relpaths where secrets.scan hit

    @property
    def has_credentials(self) -> bool:
        return bool(self.credential_members)


@dataclasses.dataclass(frozen=True)
class UnpackReport:
    """What restoring one Session did. members counts what landed, so a
    member deferred to another owner is in `deferred` and in no other count.
    `member_names` is the exception and the one field describing the incoming
    tree rather than the restore: it holds every member, landed or not."""
    members: int = 0
    rewritten_values: int = 0
    text_replaced: int = 0
    malformed: int = 0
    near_misses: int = 0
    bare_tokens: int = 0
    non_utf8: int = 0
    # (target, owner) per member some link already claims. Carried out rather
    # than printed here: this module names no caller and no agent, and the
    # pull is where deference is reported (ADR-0007).
    deferred: tuple = ()
    # (target, why) per member this machine's syscalls would not take - a
    # directory standing where a file lands, most often.
    refused: tuple = ()
    # Every file member the incoming tree held, whether it landed or not. The
    # caller needs these to answer ADR-0002's question about the LOCAL tree: a
    # local member no incoming name matches is one the Archive never held, so
    # it is kept and reported rather than deleted. Landed-or-not is the point.
    # A member deferred to another owner, or refused by a syscall, is already
    # named by its own report line and the local file it left alone is not a
    # second outcome; counting it as kept too would report one skip twice.
    member_names: tuple = ()
    # Targets whose local copy won the union rule outright: the incoming copy
    # is a byte-prefix of it, so this machine is ahead on that Transcript and
    # nothing about the main Transcript being behind changes that.
    kept: tuple = ()
    # (target, member name) per member where neither copy extends the other.
    # The local file is untouched; the incoming copy is the caller's to place
    # under ~/.carryon/conflicts/, which is a path this module does not name.
    conflicted: tuple = ()
    # Members the union rule said to write, counted whether or not this run
    # was allowed to write them. `members` answers "what landed" and is zero
    # in a dry run by construction, so a plan built from it says nothing about
    # the files it is about to lay down - which is the silence the keep and
    # conflict lines were added to end, one outcome over.
    writes: int = 0


# --- layout strategies -------------------------------------------------------


def _rel(path, root) -> str:
    return path.relative_to(root).as_posix()


def _packable(path, home, withheld, identities=None) -> bool:
    """Whether this member may be read into a Session at all.

    config.carry_refusal, which is the whole of the rule and is asked by the
    Setup leg through the same function. This leg used to ask only the PATH
    half of it - `lands_in_state` and nothing else - so a HARD link at
    '<slug>/<uuid>/notes.jsonl' to ~/.carryon/master.key went straight
    through: not a symlink, resolves to itself, under $HOME and nowhere near
    '.carryon'. It was packed, invisible to secrets.scan because a key is bare
    hex (ADR-0008 says so in as many words), and laid down at mode 0644 in a
    project directory on every machine that pulled, at exit 0 with no report
    line. No leak to the Destination - the tar is sealed under that very key -
    but the key left a 0600 file for a directory people share and screenshot,
    and was re-packed on every push thereafter.

    Two legs asking one question in two spellings is what produced that, so
    the second spelling is gone rather than corrected. `identities` is the
    state directory's inodes, collected once per discovery by the caller
    rather than once per member: this walks a whole History.

    Withheld and named rather than refusing the push, unlike the Setup leg. A
    project tree is a place users make links, the tar never reaches the
    Destination in the clear, and refusing a whole History over one link in
    one project would be a refusal the user cannot act on selectively.
    """
    if config.carry_refusal(path, home, identities) is None:
        return True
    try:
        withheld.append(path.relative_to(home).as_posix())
    except ValueError:
        withheld.append(str(path))
    return False


def _why(exc: OSError) -> str:
    return exc.strerror or str(exc)


def _listing(path, rel: str, unreadable) -> list:
    """`path`'s entries, or [] with the directory named in `unreadable`.

    Every walk on this leg reaches a directory somebody else's permissions
    decide about. capture.tree_files says the same sentence about the Setup
    leg's walk - "a directory that will not list is one skip line rather than
    a traceback out of push" - and this leg had no such line: one mode-000
    project directory, which a restored backup produces without anyone
    meaning to, ended both push and pull from inside the walk.

    Skipped rather than raised, and named rather than dropped, because the
    other projects still have to be carried: a push that stops at the first
    directory it cannot list carries nothing at all.
    """
    try:
        return sorted(path.iterdir())
    except OSError as exc:
        unreadable.append((rel, f"this machine would not list it "
                                f"({_why(exc)})"))
        return []


# What "there is nothing at that name" is spelled with. The same set
# `Path.is_dir()` swallows, minus EBADF, which no path in this walk can raise:
# ELOOP is a link pointing at itself, which is a name with nothing behind it.
_NOTHING_THERE = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP)

_DIR, _FILE, _OTHER = "dir", "file", "other"


def _kind(path, rel: str, unreadable) -> str:
    """What is at `path` - 'dir', 'file', 'other' - or None, and a line in
    `unreadable` when this machine would not say which.

    `_listing` above says this sentence about the call that LISTS a directory,
    and every call that asks what one IS was left holding `Path.is_dir()`.
    That swallows exactly four errnos and raises every other one, EACCES
    included - so one mode-000 directory anywhere on this leg was a raw
    PermissionError out of the middle of the walk, and `push` and `pull` were
    the two commands in carryon that ended in a traceback over a home that
    `list`, `doctor` and `capture` all described happily (adapters.present,
    layout._entries and capture.tree_files each answer it in their own words).
    It needs no attacker: a backup restored with the wrong owner and an agent
    that once ran under sudo are the two causes layout.py already calls
    ordinary.

    Named rather than dropped, because the alternative error is the one this
    package keeps making in the other direction: a Session silently missing
    from a push reads as a push that carried everything.
    """
    try:
        info = os.stat(str(path))
    except (OSError, ValueError) as exc:
        if getattr(exc, "errno", None) not in _NOTHING_THERE:
            unreadable.append((rel, f"this machine would not look at it "
                                    f"({_why(exc)})"))
        return None
    if stat.S_ISDIR(info.st_mode):
        return _DIR
    if stat.S_ISREG(info.st_mode):
        return _FILE
    return _OTHER


def _files_under(root, rel_base: str, home, withheld, identities,
                 unreadable) -> list:
    return sorted(
        _rel(p, root) for p in root.rglob("*")
        if _kind(p, rel_base + "/" + _rel(p, root), unreadable) == _FILE
        and _packable(p, home, withheld, identities))


def _discover_claude_projects(adapter, item, home, identities=None):
    """Project dirs under the root; in each, every top-level <uuid>.jsonl is a
    main Transcript, a dir named exactly <uuid> is that Session's subtree, and
    everything else is per-project residue."""
    root = pathlib.Path(home) / item.src
    sessions, residues, missing, withheld, unreadable = [], [], [], [], []
    if _kind(root, item.src, unreadable) != _DIR:
        return sessions, residues, missing, withheld, unreadable

    for project in _listing(root, item.src, unreadable):
        project_dir = item.src + "/" + project.name
        # Asked once per entry and remembered, for the same reason the listing
        # is: two stats of one name are two chances for the answers to
        # disagree, and each of them is a line in the report when it fails.
        kinds = {}
        if _kind(project, project_dir, unreadable) != _DIR:
            continue
        # Listed once and used twice: the mains below and the residue after
        # them are two questions about the same entries, and asking the
        # filesystem twice is two chances for the answers to disagree.
        entries = _listing(project, project_dir, unreadable)
        for entry in entries:
            kinds[entry] = _kind(entry, project_dir + "/" + entry.name,
                                 unreadable)
        mains = [p for p in entries
                 if kinds[p] == _FILE and p.suffix == ".jsonl"
                 and _packable(p, home, withheld, identities)]
        uuids = {p.stem for p in mains}

        project_cwd = None  # first recoverable cwd names the project's residue
        for main in mains:
            uuid = main.stem
            files = [main.name]
            subtree = project / uuid
            if kinds.get(subtree, _kind(subtree, project_dir + "/" + uuid,
                                        unreadable)) == _DIR:
                files += [uuid + "/" + rel
                          for rel in _files_under(subtree,
                                                  project_dir + "/" + uuid,
                                                  home, withheld, identities,
                                                  unreadable)]
            cwd = read_recorded_cwd(main, unreadable,
                                    project_dir + "/" + main.name)
            if cwd is None:
                missing.append(project_dir + "/" + main.name)
            elif project_cwd is None:
                project_cwd = cwd
            sessions.append(Session(adapter.key, uuid, project_dir, cwd,
                                    tuple(sorted(files)), main.name))

        residue_files = []
        for entry in entries:
            kind = kinds[entry]
            if kind == _FILE and entry.suffix == ".jsonl":
                continue
            if kind == _DIR and entry.name in uuids:
                continue
            if kind == _FILE:
                if _packable(entry, home, withheld, identities):
                    residue_files.append(entry.name)
            elif kind == _DIR:
                residue_files += [entry.name + "/" + rel
                                  for rel in _files_under(
                                      entry, project_dir + "/" + entry.name,
                                      home, withheld, identities, unreadable)]
        if residue_files:
            if project_cwd is None:
                missing.append(project_dir)
            residues.append(ProjectResidue(adapter.key, project_cwd,
                                           project_dir,
                                           tuple(sorted(residue_files))))
    return sessions, residues, missing, withheld, unreadable


_ROLLOUT_UUID = re.compile(
    r"rollout-.*-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$")


def _spellable(value: str) -> bool:
    """Whether this machine can encode `value` at all.

    Not config.spellable, which asks whether a syscall will look at a path and
    encodes with surrogateescape for that reason. This asks whether the string
    can be an Archive label, and crypto encodes those strictly.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def read_recorded_cwd(path, unreadable=None, rel=None):
    """cwd from a Transcript, top-level or nested in a meta line's payload.

    Verified read-only against a live ~/.codex/sessions on 2026-07-29 (keys
    only): the meta line nests cwd at payload.cwd and no line carries a
    top-level one, so a reader asking for a top-level cwd alone would come
    back empty there. A top-level cwd is honoured first, which is where the
    claude-projects layout records it.

    One reader for both layouts, and the reason is the guard rather than the
    two shapes. rekey.read_cwd catches ValueError per line, which is every way
    a line fails to parse except the cheapest to write: json.loads answers
    nesting past the interpreter's limit with RecursionError, so one 200 KB
    line of '[' at the head of one local Transcript was a traceback out of
    `carryon push` - after the Setup had been captured and reported. A line
    that will not parse is skipped, which is what this loop already did for
    every other line that will not parse; the cwd is then read from the next
    line that has one, so the Session keeps the only thing that makes it
    restorable.

    A cwd this machine cannot encode is treated as one that was never
    recorded. It reaches here as ASCII - a JSONL line spells a directory whose
    name is not valid UTF-8 with '\\udce9' escapes, and a directory named that
    way is ordinary on Linux, where os.fsdecode hands it back exactly so - and
    a cwd is not only a string carryon reports. It becomes an Archive LABEL:
    the name a project's residue object is keyed and authenticated by, which
    crypto encodes strictly. That raised a UnicodeEncodeError with Session
    objects already written and the Index never sealed, which is the state
    that makes every later push and pull from every machine refuse. Absent is
    an answer discovery already has, reports, and carries a Session without.

    So is a cwd in a Transcript this machine will not open, which is the same
    answer one syscall earlier. This open had no guard at all: a main
    Transcript at mode 000 - an agent that ran under sudo, a $HOME restored
    with the wrong owner - ended `push` and `pull` with a PermissionError
    thrown from inside discovery, before either had printed a line.
    capture.do_file names this exact errno in its own docstring for the Setup
    leg. `unreadable` is discovery's channel for saying so; without one the
    caller is asking a plain question and gets a plain None.
    """
    try:
        handle = pathlib.Path(path).open("r", encoding="utf-8",
                                         errors="replace")
    except OSError as exc:
        if unreadable is not None:
            unreadable.append((rel if rel is not None else str(path),
                               f"this machine would not read it "
                               f"({_why(exc)})"))
        return None
    # The read itself is inside the guard as well as the open: a network home
    # or a failing disk answers mid-iteration, and the two are one question.
    try:
        with handle:
            for line in handle:
                try:
                    obj = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                if not isinstance(obj, dict):
                    continue
                payload = obj.get("payload")
                for value in (obj.get("cwd"),
                              payload.get("cwd") if isinstance(payload, dict)
                              else None):
                    if isinstance(value, str) and _spellable(value):
                        return value
    except OSError as exc:
        if unreadable is not None:
            unreadable.append((rel if rel is not None else str(path),
                               f"this machine stopped being able to read it "
                               f"({_why(exc)})"))
    return None


def _discover_codex_rollouts(adapter, item, home, identities=None):
    """Each rollout-*.jsonl under the root is one flat Session; the date dirs
    above it are kept in the relpath so restore lands it where it came from."""
    root = pathlib.Path(home) / item.src
    sessions, missing, withheld, unreadable = [], [], [], []
    if _kind(root, item.src, unreadable) != _DIR:
        return sessions, [], missing, withheld, unreadable

    try:
        found = sorted(root.rglob("rollout-*.jsonl"))
    except OSError as exc:
        # rglob swallows what it meets below the root on both interpreters
        # carryon must pass, and neither promises to; the root itself is the
        # one it cannot swallow. Same sentence as the other layout's.
        unreadable.append((item.src, f"this machine would not list it "
                                     f"({_why(exc)})"))
        found = []
    for path in found:
        rel_here = item.src + "/" + _rel(path, root)
        if _kind(path, rel_here, unreadable) != _FILE or not _packable(
                path, home, withheld, identities):
            continue
        match = _ROLLOUT_UUID.search(path.name)
        uuid = match.group(1) if match else path.stem
        rel = _rel(path, root)
        cwd = read_recorded_cwd(path, unreadable, item.src + "/" + rel)
        if cwd is None:
            missing.append(item.src + "/" + rel)
        sessions.append(Session(adapter.key, uuid, item.src, cwd, (rel,), rel))
    return sessions, [], missing, withheld, unreadable


def _claude_restore_root(item, local_cwd, home):
    # The dir name is re-derived from the cwd for THIS machine, never decoded
    # from the pushing machine's name (ADR-0006).
    return pathlib.Path(home) / item.src / rekey.encode_project_dir(local_cwd)


def _codex_restore_root(item, local_cwd, home):
    return pathlib.Path(home) / item.src


@dataclasses.dataclass(frozen=True)
class LayoutStrategy:
    # (adapter, item, home, identities)
    #   -> (sessions, residues, missing, withheld, unreadable)
    # `identities` is carryon's own state inodes (config.state_identities),
    # collected once per discovery and handed down so every member is asked
    # the gate's identity question without re-walking ~/.carryon per file.
    discover: callable
    restore_root: callable  # (item, local_cwd, home) -> pathlib.Path


LAYOUT_STRATEGIES = {
    "claude-projects": LayoutStrategy(_discover_claude_projects,
                                      _claude_restore_root),
    "codex-rollouts": LayoutStrategy(_discover_codex_rollouts,
                                     _codex_restore_root),
}


def _strategy(adapter_key: str, layout: str) -> LayoutStrategy:
    strategy = LAYOUT_STRATEGIES.get(layout)
    if strategy is None:
        raise SystemExit(
            f"{adapter_key}: chats layout {layout!r} is not one this version "
            "of carryon implements - update carryon, or the adapter is ahead "
            "of the engine")
    return strategy


# --- discovery ---------------------------------------------------------------


def _named_for_the_archive(sessions, residues) -> tuple:
    """(sessions, residues, unnamable) - what may be keyed in the Index.

    A Session's UUID and a project's cwd are not only local strings: each one
    becomes the key its entry hangs from in the Archive's Index, the label its
    object is sealed under, and - for a Session - a directory this machine
    makes under ~/.carryon/conflicts. carryon mints neither. The
    claude-projects layout takes a UUID from the STEM of a file the agent
    wrote, so '...jsonl' is a Session named '..', and a cwd is whatever a
    Transcript recorded.

    The question was asked where an Index is READ and nowhere else, so a name
    like that went up at exit 0 and sealed a catalogue every machine refused
    from then on, permanently - the Archive's whole History still there and
    unreachable, from one ordinary local filename and no attacker. Asked here,
    where the name is taken off the filesystem, it is one Session left behind
    and named in the report, which is what every other push-leg skip is.

    archive.key_refusal is the one statement of what a key has to satisfy, and
    it is asked with the catalogue the name will key. A residue is checked on
    the cwd as recorded rather than in its machine-neutral form: canonicalising
    replaces the home with '~' and changes no answer this question has.
    """
    kept_sessions, kept_residues, unnamable = [], [], []
    for session in sessions:
        why = archive.key_refusal("sessions", session.uuid)
        if why is None:
            kept_sessions.append(session)
        else:
            unnamable.append((session.project_dir + "/" + session.main_path,
                              f"its name in the Archive would be "
                              f"{session.uuid!r}, and that is {why}"))
    for residue in residues:
        why = (None if residue.cwd is None
               else archive.key_refusal("projects", residue.cwd))
        if why is None:
            kept_residues.append(residue)
        else:
            unnamable.append((residue.project_dir,
                              f"the project it belongs to would be keyed by "
                              f"{residue.cwd!r}, and that is {why}"))
    return kept_sessions, kept_residues, unnamable


def discover(home, adapters) -> Discovery:
    """Every Session and every project residue the given adapters declare.

    The state directory's inodes are collected once here and handed to every
    layout, rather than re-walked per member: `config.carry_refusal` is asked
    of every file in a whole History, and the answer to its identity half is
    the same for all of them. Same reason capture.state_reads collects them
    once for the Setup leg - one gate, one collection, two legs.
    """
    identities = config.state_identities(home)
    sessions, residues, missing, withheld, unreadable = [], [], [], [], []
    for adapter in adapters:
        for item in adapter.items:
            if item.kind != "chats":
                continue
            strategy = _strategy(adapter.key, item.layout)
            (found_sessions, found_residues, found_missing, found_withheld,
             found_unreadable) = strategy.discover(adapter, item, home,
                                                   identities)
            unreadable += found_unreadable
            sessions += found_sessions
            residues += found_residues
            missing += found_missing
            withheld += found_withheld
    sessions, residues, unnamable = _named_for_the_archive(sessions, residues)
    return Discovery(tuple(sessions), tuple(residues), tuple(missing),
                     tuple(sorted(set(withheld))),
                     tuple(sorted(set(unreadable))),
                     tuple(sorted(set(unnamable))))


# --- packing -----------------------------------------------------------------


def _add_stats(total, part):
    """Two rekey stats records summed, either of which may be absent.

    Both are frozen dataclasses of counters, so this needs no per-class case
    and needs no revisiting when a counter is added to either.
    """
    if part is None:
        return total
    if total is None:
        return part
    return dataclasses.replace(total, **{
        field.name: getattr(total, field.name) + getattr(part, field.name)
        for field in dataclasses.fields(part)})


def _line_by_line(text: str, rewrite):
    """rekey's own line loop, with the guard the inner one is missing.

    _rewrite_jsonl catches ValueError per line, which covers every way a line
    can fail to parse except the cheapest one to write: json.loads answers
    nesting past the interpreter's limit with RecursionError. One 200 KB line
    of '[' in one local Transcript therefore ended a whole push. A line that
    will not parse passes through unchanged, which is what rekey already does
    for every other line that will not parse.
    """
    out, stats = [], None
    for line in text.split("\n"):
        try:
            new_line, line_stats = rewrite(line)
        except RecursionError:
            new_line, line_stats = line, None
        out.append(new_line)
        stats = _add_stats(stats, line_stats)
    return "\n".join(out), stats


def rekeyed(data: bytes, rewrite) -> tuple:
    """rekey.apply_to_bytes with the two ways an ordinary Transcript makes it
    raise turned into answers. Returns (bytes, stats, is_utf8), as it does.

    apply_to_bytes guards the DECODE - non-UTF-8 bytes come back unchanged -
    and nothing guards the rewrite or the encode after it. Two ordinary inputs
    reach both.

    A JSON string may hold a '\\ud83d' escape: six ASCII characters on disk,
    valid UTF-8, and what a tool writes when an emoji is truncated mid-pair by
    an output limit. json.loads makes it a lone surrogate, rekey re-dumps
    every CHANGED line with ensure_ascii=False, and encoding that strictly
    raises - out of a push, after Session objects are on the Destination and
    before the Index is sealed, which is the state _canonical_members' own
    docstring exists to prevent. Encoding it back as the six characters it
    arrived as is lossless here and nowhere else: inside a JSON string literal
    '\\ud83d' is the escape that parses to the same character, so the member
    round-trips. A non-JSON member cannot hold a lone surrogate at all, since
    a strict decode never produces one.

    The other is a line nested past the recursion limit, which _line_by_line
    answers.

    Every re-keying call in carryon goes through here - both directions, all
    three trees a Snapshot moves. The guard belongs one layer down in
    rekey.apply_to_bytes; rekey is standalone by design and outside this
    round's ownership, and this is the nearest boundary that catches every
    caller at once rather than one call site at a time.
    """
    try:
        return rekey.apply_to_bytes(data, rewrite)
    except (UnicodeEncodeError, RecursionError):
        pass
    # Both of those happen after apply_to_bytes' decode, so these bytes are
    # UTF-8 and the retry can take that for granted.
    text = data.decode("utf-8")
    try:
        new_text, stats = rewrite(text)
    except RecursionError:
        new_text, stats = _line_by_line(text, rewrite)
    try:
        return new_text.encode("utf-8"), stats, True
    except UnicodeEncodeError:
        return new_text.encode("utf-8", "backslashreplace"), stats, True


def canonical_member(rel: str, data: bytes, home):
    """(new_bytes, jsonl_stats, text_stats, is_utf8) for one member, in the
    machine-neutral form an Archive holds (ADR-0006).

    The one spelling of it, deliberately: the push packs with it, the push's
    change detection hashes what it returns, and pull's union rule compares a
    local file through it against the bytes the tar holds. A second spelling
    is how a comparison ends up asking a slightly different question from the
    write it decides.
    """
    if rel.endswith(".jsonl"):
        out, stats, is_utf8 = rekeyed(
            data, lambda t: rekey.canonicalise_jsonl(t, home))
        return out, stats, None, is_utf8
    out, stats, is_utf8 = rekeyed(
        data, lambda t: rekey.canonicalise_text(t, home))
    return out, None, stats, is_utf8


def expand_member(rel: str, data: bytes, home, maps=()):
    """The reverse of canonical_member: one member expanded against this home.

    Same shape, and the same reason for being one function: both legs of a
    pull - a Session tree, a project's residue - expand members, and they used
    to do it through two copies of this that had drifted in what they counted.
    """
    if rel.endswith(".jsonl"):
        out, stats, is_utf8 = rekeyed(
            data, lambda t: rekey.expand_jsonl(t, home, maps))
        return out, stats, None, is_utf8
    out, stats, is_utf8 = rekeyed(
        data, lambda t: rekey.expand_text(t, home, maps))
    return out, None, stats, is_utf8


def _tar_bytes(entries) -> bytes:
    # Normalised metadata: identical content packs to identical bytes, so
    # nothing about the pushing machine (owner, timestamps) leaks into the tar.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel, data in entries:
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class MemberUnreadable(Exception):
    """A member the walk found and the read did not get.

    A live agent rotates a transcript while a push is walking the tree, and
    that used to escape as a bare FileNotFoundError with objects already
    written and the Index never sealed - which on a first push made
    load_index refuse for every machine thereafter. A type of its own so the
    caller can report the Session and carry on with the rest.

    It also carries the gate's refusal, and the two are one exception on
    purpose. Discovery has already asked `config.carry_refusal` of every
    member, so a refusal HERE means the tree changed under the walk - a name
    that was an ordinary Transcript when it was listed and is a hard link to
    ~/.carryon/master.key by the time it is read. What the caller does about
    it is what it does about a rotated file: skip the whole Session by name,
    since the Index records a tree_hash over the declared member set and a tar
    quietly short one of them would publish a hash describing something the
    object does not hold.
    """


def _member_bytes(path, rel: str, home, identities) -> bytes:
    """One member's bytes through the gate, or MemberUnreadable naming it.

    The single read on this leg, so packing and hashing cannot come to
    disagree about which members they are willing to touch - which is the
    tree-scale version of the same defect that put a hard link to the master
    key in a tar, one function up.
    """
    data, why = config.read_carryable(path, home, identities)
    if data is None:
        raise MemberUnreadable(
            f"{rel}: {why} - it was there when the tree was walked and was "
            "something else by the time it was read")
    return data


def pack_session(session, home):
    """Canonicalise a Session (or ProjectResidue) and tar it in-memory.

    Returns (tar_bytes, PackReport). Member paths are relative to the project
    dir, in sorted order. Credentials are scanned per member and REPORTED
    (ADR-0001): a History cannot be fixed retroactively, so a hit never
    refuses and nothing is redacted.

    A member that will not read raises MemberUnreadable rather than being
    skipped: the Index records a tree_hash over the whole declared member set,
    and packing a tar that is quietly short one of them would publish a hash
    describing something the object does not hold.

    The read is `config.read_carryable` - the package's one way to turn a
    user's path into bytes that leave it - rather than a read_bytes with
    discovery's judgment remembered from a walk ago. Discovery asking the gate
    is what keeps a Session's declared member set honest; this asking it again
    is what makes the BYTES safe, and the two are not the same guarantee: the
    interval between them is a live agent's working directory.
    """
    root = pathlib.Path(home) / session.project_dir
    entries = []
    rewritten = text_replaced = malformed = near = bare = non_utf8 = 0
    credential_members = []
    identities = config.state_identities(home)

    for rel in sorted(session.files):
        data = _member_bytes(root / rel, rel, home, identities)
        out, jsonl_stats, text_stats, is_utf8 = \
            canonical_member(rel, data, home)
        if not is_utf8:
            non_utf8 += 1
        if jsonl_stats is not None:
            rewritten += jsonl_stats.rewritten_values
            malformed += jsonl_stats.malformed
            near += jsonl_stats.near_misses
        if text_stats is not None:
            text_replaced += text_stats.replaced
            near += text_stats.near_misses
            bare += text_stats.bare_tokens
        if secrets.scan(out):
            credential_members.append(rel)
        entries.append((rel, out))

    report = PackReport(len(entries), rewritten, text_replaced, malformed,
                        near, bare, non_utf8, tuple(credential_members))
    return _tar_bytes(entries), report


# --- unpack ------------------------------------------------------------------


def _expand_path(value: str, home, maps=()) -> str:
    """One canonical path -> local, matching expand_jsonl's value semantics.

    `value` is the Index's cwd on the pull leg, and that it is a string is
    archive._validated's promise, made where the Index is opened - before a
    byte of History has landed. Checking it again here would be the same rule
    in two places; what got the AttributeError out was the rule being in
    neither.

    The maps go through rekey.apply_maps rather than a loop of this module's
    own. It was a third copy of the same sequential replace, and the refusal
    that decides which map sets are usable (rekey.map_refusal) is written
    about that loop's semantics - so a copy here is a copy the refusal is only
    approximately about.
    """
    home = str(home).rstrip("/")
    if value == rekey.HOME_TOKEN:
        out = home
    else:
        out = value.replace(rekey.HOME_TOKEN + "/", home + "/")
    out, _replaced, _near = rekey.apply_maps(out, maps)
    return out


def _chats_item(agent: str, adapters=None):
    if adapters is None:
        from .adapters import ADAPTERS  # deferred: keeps this module standalone
        adapters = ADAPTERS
    adapter = adapters.get(agent)
    if adapter is None:
        raise SystemExit(f"the Index names agent {agent!r} but no adapter "
                         "for it exists on this machine's carryon")
    for item in adapter.items:
        if item.kind == "chats":
            return adapter, item
    raise SystemExit(f"adapter {agent!r} declares no chats item, so its "
                     "Sessions cannot be restored")


def unpack_session(tar_bytes: bytes, session_meta: dict, home, maps=(),
                   adapters=None, apply=True):
    """Expand a packed Session into the local encoding of its project dir.

    session_meta is the Index entry ({'agent','cwd',...}); the local project
    dir is derived from the expanded cwd by the layout's strategy. adapters
    is a key->Adapter mapping, defaulting to the registry. Returns
    (root, UnpackReport).

    The union rule (ADR-0002) runs HERE, per member, and used to be the
    caller's job - which is how it came to be asked of one file and applied to
    a whole tree. The caller decides whether a Session is replaced at all;
    what happens to each Transcript inside it is decided next to the write, by
    member_verdict, because every route into this function is a route to a
    write over somebody's local Transcript. `conflicted` names the members
    whose incoming copy the caller must set aside under ~/.carryon/conflicts/,
    since that directory is the pull's to name and not this module's.

    apply=False decides and reports and writes nothing, so a dry run can say
    which local Transcripts it would keep instead of leaving the user to infer
    it from a line about the tree.

    The tar is opened through archive.tar_members rather than here, which is
    the same rule as every other reader of a stored tree: a plaintext that is
    not a tar is one named refusal wherever it is met, and this loop used to
    answer it with a bare tarfile.ReadError - out of a pull, from inside the
    loop that writes. What the members are CALLED is settled there too, for
    the same reason and after the same defect: a name that escapes the root
    is refused before the first member is yielded, so the escape check below
    is now the backstop standing next to the join rather than the rule.

    Where it is told to write is checked three times before anything is
    written,
    because a member's landing place is decided here and the links along it
    are not.

    Against the NAME carryon's own state would have first (config.spells_state).
    A landing path that spells '~/.carryon' was composed by whoever sealed the
    tar and derived the root, which needs the master key, so there is no
    honest reading of it and it refuses whole - matching the tar-escape check
    beside it.

    Then against whoever else owns the path (ADR-0007), the rule the Setup leg
    has always followed and this one never got: write_bytes follows a link, so
    a member whose name - or whose parent DIRECTORY, the case that keeps
    recurring here - is already a symlink writes into a dotfiles repo instead,
    and one whose name is a hard link rewrites the other name for the same
    file. Authoring the Index needs a master key; neither of those does, since
    they sit in this machine's project tree, planted or left by an earlier
    pull. Deferred and reported rather than refused, because the honest case
    is a project tree somebody else manages, and ADR-0007 calls that
    deference.

    That covers the link INTO carryon's state as well, and deliberately so.
    Resolving before deferring made one dangling link - no key, no Destination
    access - a permanent abort on every pull from every machine, naming a tar
    member the user cannot find rather than the local link that caused it, and
    ADR-0009 rules out exactly that shape elsewhere. The split is by author: a
    name is a key holder's doing and refuses, a link is anybody's and defers.

    Then the syscall itself, because every check above is a check on a string.
    There is no --force on this leg - the flag means 'write through a link I
    own' about paths the local adapters declare, where a Session's member
    names come out of the tar - so the report says as much rather than leaving
    a user to hunt for it.
    """
    # Every other use of `home` here takes a str as happily as a Path;
    # external.classify walks it component by component and does not.
    home = pathlib.Path(home)
    agent = session_meta.get("agent", "")
    adapter, item = _chats_item(agent, adapters)
    strategy = _strategy(adapter.key, item.layout)

    cwd = session_meta.get("cwd")
    if not cwd:
        raise SystemExit(
            f"Session for agent {agent!r} carries no cwd, so there is no way "
            "to derive its local project dir - it was pushed from a Transcript "
            "that recorded none")
    local_cwd = _expand_path(cwd, home, maps)
    root = strategy.restore_root(item, local_cwd, home)

    members = rewritten = text_replaced = malformed = near = bare = 0
    non_utf8 = writes = 0
    deferred, refused, member_names = [], [], []
    kept, conflicted = [], []
    for member_name, data in archive.tar_members(tar_bytes,
                                                 session_meta.get("object")):
        name = pathlib.PurePosixPath(member_name)
        if name.is_absolute() or ".." in name.parts:
            raise SystemExit(f"refusing tar member {member_name!r}: "
                             "path escapes the project dir")
        # Both questions before the member is even looked at: a member
        # nothing may write is a member nothing needs to expand, and the
        # counts this returns describe what landed.
        target = root / name
        if config.spells_state(target, home):
            raise SystemExit(
                f"refusing tar member {member_name!r}: it lands in "
                "carryon's own state (~/.carryon), where the master key "
                "and the config naming the Destination live - a restored "
                "History never writes there")
        # Recorded before the write is even attempted, and above every
        # `continue` below: this is what the incoming tree HELD, which is
        # a different question from what it managed to lay down.
        member_names.append(member_name)
        status, owner = external.owner_of(target, home)
        if status == external.EXTERNALLY_OWNED:
            deferred.append((target, owner))
            continue
        # The union rule (ADR-0002), asked of the canonical bytes the tar
        # holds and before a byte of it is expanded: a member the local
        # copy wins is a member nothing needs to rewrite.
        verdict = member_verdict(target, data, home)
        if verdict == SAME:
            continue
        if verdict == KEEP:
            kept.append(target)
            continue
        if verdict == CONFLICT:
            conflicted.append((target, member_name))
            continue
        # Counted here rather than beside the write, so a dry run can say
        # how many Transcripts it would lay down instead of reporting a
        # Session as untouched and then writing four files into it.
        writes += 1
        out, jsonl_stats, text_stats, is_utf8 = \
            expand_member(member_name, data, home, maps)
        if jsonl_stats is not None:
            rewritten += jsonl_stats.rewritten_values
            malformed += jsonl_stats.malformed
            near += jsonl_stats.near_misses
        if text_stats is not None:
            text_replaced += text_stats.replaced
            near += text_stats.near_misses
            bare += text_stats.bare_tokens
        # Counted with the near-misses above rather than with the members
        # below: all three describe the re-keying pass, which happened,
        # and `members` alone describes what landed. A dry run reports
        # the pass and lands nothing.
        if not is_utf8:
            non_utf8 += 1
        if not apply:
            continue
        # The ownership answer above decided the report line; this one is
        # about the descriptor the bytes actually go to (external.py).
        why = external.write_owned(target, out, home)
        if why is not None:
            refused.append((target, why))
            continue
        members += 1

    return root, UnpackReport(members, rewritten, text_replaced, malformed,
                              near, bare, non_utf8, tuple(deferred),
                              tuple(refused), tuple(member_names),
                              tuple(kept), tuple(conflicted), writes)


# --- the union primitive (ADR-0002) ------------------------------------------


def compare_main(local_bytes: bytes, incoming_bytes: bytes) -> str:
    """How two copies of a main Transcript relate, byte-wise.

    'local-prefix' means local is a byte-prefix of incoming (incoming is
    ahead: replace the whole local Session tree); 'incoming-prefix' the
    reverse (local is ahead: skip); 'divergent' means keep local untouched
    and report. Bytes, not lines: a Transcript grows by appending.
    """
    if local_bytes == incoming_bytes:
        return "same"
    if incoming_bytes.startswith(local_bytes):
        return "local-prefix"
    if local_bytes.startswith(incoming_bytes):
        return "incoming-prefix"
    return "divergent"


# What the union rule says about one member. The relation is compare_main's;
# these are what a restore does about it, named so the loop below and the
# report read the same.
WRITE = "write"          # nothing here, or the incoming copy extends this one
SAME = "same"            # byte-identical: no write, no line, no mtime churn
KEEP = "keep"            # this machine is ahead: the local copy stays
CONFLICT = "conflict"    # neither extends the other: local stays, incoming aside

_VERDICTS = {"same": SAME, "local-prefix": WRITE,
             "incoming-prefix": KEEP, "divergent": CONFLICT}


def member_verdict(target, incoming: bytes, home) -> str:
    """ADR-0002's union rule, asked of ONE member of a Session tree.

    "The incoming file replaces the local one only when the local file is a
    byte-prefix of it - the append-only case - and otherwise both are kept."
    That is the ADR's sentence about a Transcript, and a Session holds dozens
    (CONTEXT.md): the main conversation, a subagent's, a workflow's journal.
    The replacement branch used to ask it of the main Transcript alone and
    then write every member of the tar unconditionally, so a journal the two
    machines had grown apart on was overwritten and a journal this machine was
    strictly AHEAD on was truncated - which is the harm the ADR names in as
    many words, and the one push already refuses to cause in the mirror-image
    situation.

    Asked of the PATH rather than of the member's name. A name comparison
    answers about the tar and the filesystem answers about the write, and on a
    case-insensitive filesystem - APFS by default - those differ: an incoming
    'subagents/journal.jsonl' and a local 'Subagents/journal.jsonl' are two
    names for one file, so a name-keyed rule overwrote a local Transcript and
    reported it kept in the same pull. It also means a local file no discovery
    found - a Session whose main Transcript is gone is no Session at all -
    still gets the rule, which is the whole of what the `new` branch was
    missing.

    Compared in canonical form, like the main: the local copy embeds this
    machine's home and the tar's copy embeds none, so raw bytes would call
    every shared member divergent.

    "Absent" and "there, and this machine will not read it" used to be one
    answer here, and that answer was WRITE - justified as "there is nothing
    there to lose", which is true of the first and false of the second. A
    local copy that exists and will not read answers CONFLICT instead: neither
    copy has been shown to extend the other, so the local one stays and the
    incoming one is kept aside, which is what ADR-0002 already says to do when
    nothing can be decided between two copies. No new outcome, no new report
    line, and the fail-closed direction for a pull that must never remove or
    truncate.

    Something that is there and is not a file at all stays WRITE, and the
    distinction is the report rather than the outcome: a directory standing
    where a Transcript lands is not a Transcript this machine is at risk of
    losing, and the writer refuses it by name with the sentence that says so
    ("something else is standing where that member lands"). Calling that a
    divergence would put a conflict line in front of a user who has no
    conflict.

    The open carries the same two flags every other read in this package does.
    O_NOFOLLOW because a link here is somebody else's file - the caller has
    already asked external.owner_of, and a rule closed only where somebody
    asked first is the rule this round exists to stop relying on - and
    O_NONBLOCK because a named pipe answers open() by waiting for the other
    end, which was a pull that hung for ever on a `mkfifo` anyone with write
    access to a project directory can make.

    The fstat is on the raw descriptor, before anything wraps it, which is the
    ordering destinations/base._local_bytes had to be corrected into: fdopen()
    on a descriptor for a directory raises IsADirectoryError, so a check
    written after it sits behind the call that makes it unreachable.
    """
    try:
        fd = os.open(str(target),
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return WRITE
        return CONFLICT
    except ValueError:
        return CONFLICT
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        return CONFLICT
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        return WRITE
    try:
        with os.fdopen(fd, "rb") as handle:
            local = handle.read()
    except OSError:
        return CONFLICT
    canon, _, _, _ = canonical_member(target.name, local, home)
    return _VERDICTS[compare_main(canon, incoming)]


# --- change detection --------------------------------------------------------


def tree_hash(session, home) -> str:
    """sha256 over the sorted (relpath, per-file sha256) pairs of a Session.

    Same pairs and byte encoding as archive.tree_hash, but over the Session's
    declared files only - a project dir mixes several Sessions and residue,
    so hashing the whole dir would tie them together.

    Through the gate like every other read of a member, though what leaves
    here is a digest rather than the bytes. A hash is not a publication, but
    "this read is harmless" is the reasoning that has to be re-derived at
    every new read, and re-deriving it is what this round exists to stop: a
    member the gate refuses raises, exactly as an unreadable one does.
    """
    root = pathlib.Path(home) / session.project_dir
    identities = config.state_identities(home)
    pairs = sorted(
        (rel, hashlib.sha256(_member_bytes(root / rel, rel, home,
                                           identities)).hexdigest())
        for rel in session.files)
    digest = hashlib.sha256()
    for rel, file_hash in pairs:
        digest.update(rel.encode("utf-8") + b"\0" + file_hash.encode() + b"\n")
    return digest.hexdigest()

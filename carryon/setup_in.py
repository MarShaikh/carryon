"""A Setup on the way in - which stored item this machine writes, and where.

The Setup half of an Archive is plaintext and needs no master key to write
(ADR-0004), so a stored MANIFEST is input from an untrusted Destination rather
than carryon's own output: every path in it is answered for here, one item at a
time, and a refused item is named in the report while the rest of the pull
carries on (ADR-0009). Silence is the failure mode that reads as success - an
item dropped without a word looks like a restore that is mysteriously short a
file - so nothing here returns without either a write or a refusal.

The one non-obvious thing: $HOME is not the boundary. $HOME holds ~/.zshrc and
~/.ssh/authorized_keys, so containment inside it buys nothing against an
attacker-authored MANIFEST. The boundary is what the LOCAL adapters declare
plus carryon's own state carve-out - the set of paths this machine already
decided to carry - which is why the declared check is the one rule that
survives --force and the state check is the one that precedes it. "Replace" is
a word about one item here, never about a Setup directory, and ADR-0002 permits
even that only because what was there goes to a backup first: a backup this
machine will not take is a replacement it must not make.

A leaf: archive for what a Setup carries about itself, config for the state
carve-out and the state-write gate, external for the write chokepoint, history
and rekey for expanding a machine-neutral tree against this home.
"""

from __future__ import annotations

import pathlib

from . import archive, config, external, history, rekey
from .destinations.base import printable


# --- which stored item may be written where ----------------------------------


# The three files a Setup carries about itself rather than for restoring: the
# manifest, the notes rendered from it, and the tag over the tree. No captured
# Item is ever written to one, on either leg.
SETUP_OWN_FILES = ("MANIFEST.json", "RESTORE.md", archive.SETUP_MAC_NAME)

# What every filesystem carryon runs on will hold: 255 bytes per name, and a
# path far shorter than any PATH_MAX. Shape is not the whole check - a path
# can be relative, non-empty and free of '..' and still be one the kernel
# refuses, and the refusal used to arrive as an OSError out of the syscall
# after the check rather than as a refused item.
#
# The per-name cap is config's, not a second 255: the same limit decides what
# a machine may be called, and one fact spelled in two modules is one fact
# that can come to mean two things.
NAME_MAX = config.NAME_MAX
PATH_MAX = 1024


def _relative_component_path(raw):
    """`raw` as a relative PurePosixPath with no escape in it, or None.

    The lexical half of the check both fields of a stored Setup item need: a
    string, relative, non-empty, free of '..'. Same refusal as
    config._relative_to_home and destinations.base.require_key, applied to
    the one place those paths arrive from outside carryon.

    Length is part of the shape here, because the question the callers really
    ask is "will this machine take this path", and `staging / rel` reaches
    Path.is_symlink() - whose OSError filter ignores ENOENT and re-raises
    ENAMETOOLONG - before anything else looks at it. Both spellings are
    bounded: one 5000-character component, and 600 short ones past PATH_MAX,
    so a per-component cap alone would not answer it.

    config.spellable comes first because the measurement itself is a way in:
    'surrogateescape' cannot encode a LONE surrogate, and '\\ud800' is legal
    JSON, so a stored item spelled that way raised UnicodeEncodeError out of
    the length check - a traceback out of a pull that had already written a
    History, from the one function whose answer is meant to be None."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    if raw.startswith("/") or "\\" in raw or not config.spellable(raw):
        return None
    if len(raw.encode("utf-8", "surrogateescape")) > PATH_MAX:
        return None
    path = pathlib.PurePosixPath(raw)
    # '.' and '' normalise away to no parts at all, and home / '' is $HOME
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    if any(len(part.encode("utf-8", "surrogateescape")) > NAME_MAX
           for part in path.parts):
        return None
    return path


def _within_path_limit(path) -> bool:
    """Whether the assembled path is one this machine's syscalls will take.

    Bounding the relative half of a stored item is not the same question.
    What a syscall sees is a local root joined onto it, so a `src` that is
    comfortably inside PATH_MAX on its own can still be past it once $HOME is
    in front - and external.plan walks that path with is_symlink(), which
    re-raises ENAMETOOLONG out of a pull written to treat trouble as a
    refusal. The bound is the smallest PATH_MAX carryon runs against (macOS,
    1024) rather than the local one: a Setup path near either limit is not a
    path anyone meant to carry, and one number is one behaviour to test.
    """
    return len(str(path).encode("utf-8", "surrogateescape")) <= PATH_MAX


def _declared_paths(effective: dict) -> tuple:
    """(files, trees): the src paths this machine's adapters agree to carry.

    $HOME is not a boundary worth having against an attacker-authored
    MANIFEST, because $HOME holds ~/.zshrc, ~/.ssh/authorized_keys and every
    other file some program runs on next login. What the LOCAL adapters
    declare is a boundary: it is the set of paths this machine already
    decided to carry, so a restore fills those in and invents nothing. The
    effective registry is the one push captures from, excludes applied and
    handpicked paths added (ADR-0008), so a user who carries an extra path
    keeps receiving it and one who excluded an item stops.

    A chats item is left out on purpose: it names where the History lives,
    and a Setup never carries one.
    """
    files, trees = set(), set()
    for adapter in effective.values():
        for item in adapter.items:
            if item.kind == "chats":
                continue
            rel = _relative_component_path(item.src)
            if rel is None:
                continue
            target = trees if item.kind in ("tree", "skills") else files
            target.add(rel.as_posix())
    return files, trees


def _is_declared(posix: str, declared: tuple) -> bool:
    files, trees = declared
    return posix in files or any(posix == t or posix.startswith(t + "/")
                                 for t in trees)


def _setup_target(src, home, declared) -> tuple:
    """(target, None) for where a stored Setup item may be written, or
    (None, why) refusing it.

    The Setup half of the Archive is plaintext and unauthenticated by design
    - pushing one needs no master key at all (ADR-0004) - so a stored
    MANIFEST is input from an untrusted Destination, not carryon's own
    output. `home / src` silently *becomes* an absolute src (pathlib drops
    the left operand), and a '..' walks out of $HOME the way
    config._relative_to_home warns about; either one turns a restore into a
    write anywhere on this machine.

    Three checks, narrowing. Lexical containment first, judged on the
    unresolved path because a ~/.claude/settings.json symlinked into a
    dotfiles repo outside $HOME is externally owned rather than an escape -
    ADR-0007 has external.plan decide that one, and resolving the WHOLE path
    here would quietly overrule it. Then carryon's own state. Then the only
    rule that holds under --force, which discards the ADR-0007 deference and
    would otherwise turn a lexically contained src into a write through any
    symlink the attacker can name: the path has to be one an adapter here
    declares.

    The state check resolves, where the containment check above deliberately
    does not, and the two do not conflict: config.lands_in_state refuses only
    when the resolved path lands in ~/.carryon, so a dotfiles symlink pointing
    anywhere ELSE is left for external.plan exactly as before. It is the one
    check that must win under --force - --force means 'write through a link I
    own' (ADR-0007), never 'write into carryon's own state' - so it precedes
    the declared check, which is the branch --force discards. The capture leg
    (config._relative_to_home) refuses the same paths through the same
    function, so the two cannot drift into disagreeing again.
    """
    rel = _relative_component_path(src)
    if rel is None:
        return None, ("src is not a relative path under $HOME - absolute "
                      "paths and '..' are refused")
    if config.lands_in_state(pathlib.Path(home) / rel.as_posix(), home):
        return None, "src is carryon's own state - a Setup never writes there"
    if not _is_declared(rel.as_posix(), declared):
        return None, ("src is not a path any adapter on this machine "
                      "declares - a Setup fills in the paths this machine "
                      "already carries, it does not name new ones")
    return pathlib.Path(home) / rel, None


def _setup_packed(dst, staging) -> tuple:
    """(packed, None) for which stored file an item is read from, or
    (None, why) refusing it.

    Unbounded, `staging / dst` reads any file on this machine and hands its
    bytes to whatever src names - a synced folder, or the git clone a push
    uploads wholesale. Enough '..' segments reach the root from any staging
    depth, so the lexical check is the one that matters; the resolve is for
    the case a link ever appears inside staging itself.

    The OSError arm is the answer the lexical check cannot give. Length is
    bounded above, so what is left here is everything else the kernel can
    say about a path that is shaped perfectly - and a pull that has already
    laid a History down must turn that into one refused item, not a
    traceback.

    carryon's own three files in a Setup are refused as sources outright. No
    captured Item is ever written to one, and pointing an item at MANIFEST.json
    turns the document that DESCRIBES the Setup into the content of a declared
    path: src='.claude/settings.json', dst='MANIFEST.json' writes the
    manifest's JSON - its attacker-chosen top-level keys included - over the
    settings file whose hooks are shell commands."""
    rel = _relative_component_path(dst)
    if rel is None:
        return None, ("dst is not a relative path inside the stored Setup - "
                      "absolute paths, '..' and names no filesystem can hold "
                      "are refused")
    if rel.as_posix() in SETUP_OWN_FILES:
        return None, ("dst names one of carryon's own files in the stored "
                      "Setup, which is bookkeeping about the Setup rather "
                      "than content any item carries")
    packed = pathlib.Path(staging) / rel
    try:
        if packed.is_symlink():
            return None, ("dst is a symlink in the stored Setup, not a "
                          "stored file")
        packed.resolve().relative_to(pathlib.Path(staging).resolve())
    except ValueError:
        return None, "dst resolves outside the stored Setup"
    except OSError as exc:
        return None, ("dst names a path this machine will not look at "
                      f"({exc.strerror or exc})")
    return packed, None


def _tree_members(packed, staging) -> tuple:
    """(files, refused) for one tree/skills item, re-checking every member.

    The containment check runs on the item's root; expanding that root with
    rglob and trusting the result is a sibling-path gap, because a link among
    the members is read through even though the root validated. Staging is
    written byte by byte from the Destination and holds no links today, which
    is exactly the assumption worth not making about untrusted storage.

    The symlink test comes before the directory test, and that order is the
    whole of it: `is_dir()` follows a link, so a linked DIRECTORY member was
    filtered out as "not a file" before the refusal beside it could see it -
    no write, no refusal, no report line, which is the silent drop
    _setup_writes' docstring rules out.
    """
    files, refused = [], []
    root = pathlib.Path(staging).resolve()
    for path in sorted(packed.rglob("*")):
        if path.is_symlink():
            refused.append(path)
            continue
        try:
            if path.is_dir():
                continue
            path.resolve().relative_to(root)
        except (ValueError, OSError):
            # OSError alongside ValueError because the caller names every
            # member of this list in the report, and "this machine would not
            # look at it" is a refusal like any other rather than a crash.
            refused.append(path)
            continue
        files.append(path)
    return files, refused


def _setup_writes(manifest: dict, staging, home, declared,
                  categories=None) -> tuple:
    """(writes, refused): (target, source) pairs mapping the stored Setup
    back onto $HOME, driven by the MANIFEST the capture engine wrote, plus
    the items refused before a byte moved in either direction.

    Both fields are validated up front because both are attacker-reachable
    (see _setup_target). A refused item comes back named rather than dropped:
    silently skipping one reads as a successful restore that is quietly
    missing a file.

    `categories` is `pull --category`'s slice of the Setup leg (ADR-0012 /
    R6): every MANIFEST item carries the category it was captured under, and
    an item whose category was not chosen is not part of this pull at all -
    not validated, not refused, not written - the same silence push's capture
    engine answers an unchosen category with. None means no flag was given
    and is the pre-flag behaviour exactly, malformed category fields
    included."""
    writes, refused = [], []
    agents = manifest.get("agents")
    if not isinstance(agents, dict):
        return writes, [("MANIFEST.json", "names no 'agents' object")]
    for key, agent in sorted(agents.items()):
        items = agent.get("items") if isinstance(agent, dict) else None
        if not isinstance(items, list):
            refused.append((printable(key), "declares no 'items' list"))
            continue
        for item in items:
            if not isinstance(item, dict):
                refused.append((printable(key),
                                f"declares a malformed item: "
                                f"{printable(repr(item))}"))
                continue
            if categories is not None \
                    and item.get("category") not in categories:
                continue
            src, dst = item.get("src"), item.get("dst")
            # Both fields in the label, whichever one was refused: the pair is
            # the attempt, and half of it reads as an ordinary item.
            label = (f"{printable(key)} src={printable(repr(src))} "
                     f"dst={printable(repr(dst))}")
            target, why = _setup_target(src, home, declared)
            if target is None:
                refused.append((label, why))
                continue
            packed, why = _setup_packed(dst, staging)
            if packed is None:
                refused.append((label, why))
                continue
            if not _within_path_limit(target):
                refused.append(
                    (label, "src assembles into a path longer than this "
                            "machine's syscalls take"))
                continue
            if item.get("kind") in ("file", "json-strip"):
                if packed.is_file():
                    writes.append((target, packed))
                else:
                    # A Destination with write access can delete individual
                    # stored files; dropping them here reads as a clean
                    # restore that is quietly short a file.
                    refused.append(
                        (label, "the stored Setup holds no such file - it was "
                                "removed from the Destination, or the "
                                "MANIFEST names one that never existed"))
            elif packed.is_dir():
                members, bad = _tree_members(packed, staging)
                if not members and not bad:
                    # The same reasoning as the missing file above, one level
                    # up: an item that produces no write and no refusal is an
                    # item nothing in the report accounts for.
                    refused.append(
                        (label, "the stored tree holds no files - it was "
                                "emptied on the Destination, or the MANIFEST "
                                "names a tree that never had any"))
                for f in members:
                    # Re-checked per member, not once for the item's root: a
                    # member's name comes from the stored tree rather than
                    # from the MANIFEST, so bounding the root's `src` says
                    # nothing about where a member lands.
                    landing = target / f.relative_to(packed)
                    if not _within_path_limit(landing):
                        refused.append(
                            (f"{label} member='{printable(f.name)}'",
                             "the member assembles into a path longer than "
                             "this machine's syscalls take"))
                        continue
                    # Both questions, not just length. _setup_target answered
                    # the state question for the item's ROOT, and a member
                    # lands one or more components further down, where a link
                    # in this home - '.claude/commands/sub -> ~/.carryon', or
                    # the leaf itself - puts the write inside carryon's own
                    # state. Under --force there is nothing after this to stop
                    # it: force discards ADR-0007's deference and hands every
                    # landing straight to the write, so a stored member named
                    # 'sub/master.key' replaced the key that opens the same
                    # Archive.
                    if config.lands_in_state(landing, home):
                        refused.append(
                            (f"{label} member='{printable(f.name)}'",
                             "the member lands in carryon's own state - a "
                             "Setup never writes there, --force included"))
                        continue
                    writes.append((landing, f))
                for f in bad:
                    refused.append(
                        (f"{label} member='{printable(f.name)}'",
                         "a member of the stored tree is a link out of it, "
                         "not a stored file"))
            else:
                refused.append(
                    (label, "the stored Setup holds no such directory"))
    return writes, refused


# --- the one item-at-a-time write, and the copy that permits it --------------


def _backed_up(target, backup_path, home, identities=None):
    """None once `target`'s current bytes are saved at `backup_path`, or why
    this machine would not save them there.

    A Setup backup is a write of the user's content into carryon's own state,
    and it was the one restore-leg write that asked neither of the questions
    its two neighbours ask. `external.plan` beside it asks external.owner_of
    about the target; config.write_state_file beside it opens with O_NOFOLLOW
    and refuses a second hard link. This asked nothing, so a link at
    ~/.carryon/backups sent a user's Setup into whatever tree it pointed at,
    and a link standing where the copy lands was followed and truncated -
    which is ADR-0007's harm, by both of the routes ADR-0007 names, in the one
    write nobody had reviewed.

    Both questions, then, and each from the boundary it belongs to.
    `config.state_write_path` answers the first: the directories under
    ~/.carryon that this pull is about to make - 'backups', the stamped
    directory, and the item's own path within it - are asked about one at a
    time and made as it goes. ~/.carryon itself is not, which is the line
    config.write_state_file already draws for the same reason: the state
    directory living in a synced folder is the user's own arrangement.
    A backup_path that is not under ~/.carryon at all is refused rather than
    made, because the only place a pull is entitled to make room is carryon's
    own state.

    Then the write goes through config.write_state_bytes, exclusively,
    because every component of that chain was minted by this pull and
    anything already sitting at the name is by definition not carryon's file.

    The read asks the gate with `leaves_machine=False`, which is the second
    question minus its $HOME half. These bytes go to ~/.carryon and off no
    machine at all, so the boundary about what may be PUBLISHED does not
    apply to them - and applying it cost `--force` its documented behaviour
    for a dotfiles checkout outside $HOME, which is an ordinary arrangement
    and not an exotic one. What stays is the state carve-out and the identity
    question: a backup is no place to duplicate the master key either.

    A sentence rather than a raise: a pull that has already laid a History
    down does not abort (ADR-0009), and the caller turns this into one report
    line beside the item it is refusing to replace.
    """
    try:
        parts = pathlib.Path(backup_path).relative_to(
            config.state_dir(home)).parts
    except ValueError:
        return ("the backup would land outside ~/.carryon, and carryon's own "
                "state directory is the one place a pull makes room in")
    _room, why = config.state_write_path(home, *parts)
    if why is not None:
        return why
    data, why = config.read_carryable(target, home, identities,
                                      leaves_machine=False)
    if data is None:
        return f"the file that is there now will not read ({why})"
    return config.write_state_bytes(backup_path, data, exclusive=True)


def _restore_setup_item(target, source_path, backup_path, home, maps,
                        identities, force: bool = False):
    """(rekey stats, is_utf8, None) once one Setup item is on disk here, or
    (None, True, why) for an item this machine would not take.

    A function of its own, and that is this round's structural point rather
    than tidiness. `sync.pull` is seven hundred lines and has to be in both
    enforcement allowlists - it legitimately reads a staged Setup and
    legitimately writes into $HOME - so every read and every write anywhere
    inside it was pre-excused, and the defect the write allowlist was written
    for was a copy2 sitting in the middle of this very loop. A tripwire whose
    unit is larger than the unit defects arrive in says nothing. Lifted out,
    the exemption is thirty lines wide and says exactly which calls it covers.

    Every check above this is a check on a STRING and every way this can still
    fail is in the SYSCALL after one: `src` may be a declared path whose
    parent is an ordinary file here (mkdir raises FileExistsError, which
    exist_ok forgives only for a directory), or a declared tree root that is a
    directory here while the item calls itself a file (write_bytes raises
    IsADirectoryError). Both used to land mid-loop, after earlier items were
    written and their backups taken, with the report never printed.

    The write is external.write_owned, which is the same sentence one level
    up: external.plan answered about these names before the loop began, and
    what is at a name is not a thing an answer keeps being right about. It
    carries `force` for the same reason the plan does - ADR-0007's escape
    hatch is one decision, and a plan that lets an item through to a writer
    that refuses it would be half of it.
    """
    try:
        if target.is_file():
            # The backup is not a courtesy: ADR-0002 permits replacing a
            # Setup item BECAUSE what was there is recoverable. So a backup
            # this machine will not take is a replacement it must not make -
            # the item is refused by name and the local file left exactly as
            # it is, which is the same posture every other refusal on this
            # leg has.
            reason = _backed_up(target, backup_path, home, identities)
            if reason is not None:
                return None, True, (
                    f"{reason}. Nothing was replaced - ADR-0002 replaces a "
                    "Setup item only where the copy it makes first is "
                    "recoverable")
            # ADR-0002's "recoverably from the backup" is only a promise the
            # user can act on if the report says where the backup went.
            print(f"           backed up to {backup_path.parent}")
        # The stored Setup is machine-neutral (ADR-0006), so it is expanded
        # against this home the same way a History is - a hook command
        # written as '~/bin/notify' only runs here once it names this
        # machine's home.
        # read_bytes rather than the content gate: this reads the staging
        # tree carryon just materialised from the Destination, which is an
        # Archive's bytes on their way IN, not a user's file on its way out.
        data, stats, is_utf8 = history.rekeyed(
            source_path.read_bytes(),
            lambda t: rekey.expand_text(t, home, maps))
    except OSError as exc:
        return None, True, (f"this machine would not take that write "
                            f"({exc.strerror or exc}) - the stored Setup "
                            "names a path that is something else here")
    why = external.write_owned(target, data, home, force=force)
    if why is not None:
        return None, True, (f"{why} - the stored Setup names a path that is "
                            "something else here")
    return stats, is_utf8, None

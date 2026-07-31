"""The Session - the smallest thing carryon moves as a unit.

A Session travels as one sealed tree and is settled member by member, and this
module holds both halves of that sentence. The tree question is which whole
object may replace which - push's skip reasons, and where pull's incoming tree
lands. The member question is what happens to each Transcript inside it once
the tree is here.

The one non-obvious thing: push and pull are ONE rule here, not two. ADR-0002's
union rule is a single comparison asked on both legs - a stored tree is
replaced only when what it holds is contained in what this machine holds, and
an incoming member replaces a local one only when it extends it - so this leg
must not be split by direction the way the Setup legs are. Splitting it is
exactly how the two came to disagree: push compared one Transcript and replaced
thirty files, and pull's fast path then declined to fetch the tree that would
have shown it.

The skip, keep, conflict and deference lines live here for the same reason.
They are the outcomes of that one comparison rather than a printing concern,
and `_rel_to_home` - how every one of them names a path - is also how pull and
`_kept_local_members` name theirs, so a module named for printing could not
hold it.

A leaf over archive (what a stored object is), config (the read gate),
external (who owns a path) and history (the expansion, and the union rule
itself).
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import NamedTuple

from . import archive, config, external, history
from .destinations.base import printable


# --- naming a path, and what a Session's members come to ---------------------


def _rel_to_home(path, home) -> str:
    try:
        return pathlib.Path(path).relative_to(home).as_posix()
    except ValueError:
        return str(path)


def _canonical_members(session, home):
    """{relpath: canonical bytes} for a Session's declared files, or None when
    one of them will not read.

    Canonical, because raw local bytes embed this machine's home: two machines
    holding the same Session would never agree on anything derived from them,
    and every push would re-upload the whole History - the exact cost ADR-0003
    exists to avoid. Re-keying makes the homes cancel out, the same way
    main_sha256 already does for the union rule (ADR-0002).

    None rather than an exception, because the ordinary cause is a live agent
    rotating a transcript between the walk and the read. That used to escape
    as a bare FileNotFoundError with Session objects already written and the
    Index never sealed - and on a FIRST push, that state makes load_index
    refuse for every machine thereafter, with 'delete the Archive and push
    afresh' as the named cure.

    The read is config.read_carryable, which is the whole package's one way to
    turn a user's path into bytes that leave it. This is the THIRD walk over a
    Session's members - discovery, this, and the pack - and a third read
    written to its own rule is exactly how the first two came to disagree
    about a hard link to the master key. It is the same skip either way, since
    a member the gate refuses is one this push must not hash, upload or
    compare against the Archive.
    """
    root = pathlib.Path(home) / session.project_dir
    identities = config.state_identities(home)
    members = {}
    for rel in session.files:
        data, _why = config.read_carryable(root / rel, home, identities)
        if data is None:
            return None
        members[rel], _, _, _ = history.canonical_member(rel, data, home)
    return members


def _members_hash(members: dict) -> str:
    """history.tree_hash's encoding, over canonical member bytes."""
    digest = hashlib.sha256()
    for rel in sorted(members):
        file_hash = hashlib.sha256(members[rel]).hexdigest()
        digest.update(rel.encode("utf-8") + b"\0" + file_hash.encode() + b"\n")
    return digest.hexdigest()


def _no_history_here(agent: str, effective: dict) -> bool:
    """True when the effective adapter declares no chats item - typically
    because the user excluded it in config (ADR-0008)."""
    return not any(item.kind == "chats" for item in effective[agent].items)


# --- the union rule on the way out -------------------------------------------
#
# Which stored tree push may replace, and why it may not.


_DIVERGED_SKIP = ("this machine's copy and the Archive's have diverged - "
                  "neither main Transcript is a byte-prefix of the other, so "
                  "neither may overwrite the other. Pull first: the "
                  "Archive's copy lands under ~/.carryon/conflicts/ and this "
                  "one stays put (ADR-0002)")


def _index_veto(entry, canon: bytes):
    """Why the Index alone already proves this push must not overwrite, or
    None. Never the reverse.

    An Index entry can VETO an overwrite without a download and can never
    AUTHORISE one, and that asymmetry is the whole of this function. An Index
    cannot be forged, but it can disagree with the object it describes by two
    routes that need no forgery: replaying an authentic Index at exactly the
    revision this machine last recorded, which slips under _rollback_note's
    'now >= seen' test, and push's own write order, which puts objects on the
    Destination before the Index that describes them and leaves them there if
    the push is interrupted. Acting on that disagreement is only harmful in
    one direction - a veto that is wrong costs a skip and a 'pull first', an
    authorisation that is wrong destroys a Transcript in the only copy that is
    not on this machine.

    A local main SHORTER than the stored one is behind or divergent; either
    way it is a skip, and the bytes are only needed to say which.
    """
    size = entry.get("main_size")
    sha = entry.get("main_sha256")
    usable = (isinstance(size, int) and not isinstance(size, bool)
              and size >= 0 and isinstance(sha, str))
    if not usable:
        return None
    if len(canon) < size:
        return ("this machine's copy is behind the Archive's, or has diverged "
                "from it - its main Transcript is shorter than the one the "
                "Index records, so replacing could overwrite a longer "
                "Transcript with a shorter one; pull first (ADR-0002)")
    if hashlib.sha256(canon[:size]).hexdigest() != sha:
        return _DIVERGED_SKIP
    return None


def _tree_behind_reason(stored: dict, local: dict):
    """Why the local tree is not ahead of the stored one, or None.

    ADR-0002's union rule, raised from the main Transcript to the tree, which
    is the unit push actually REPLACES. Comparing one file and replacing
    thirty is how a Session whose subtree diverged while its main stood still
    read as 'ahead': the stored main was a byte-prefix of the local one, so
    push replaced the whole object and the subagent journals only the Archive
    held were deleted, reported as a successful push with no skip line - and
    the cure every skip message names could not help, because pull's fast path
    declined to fetch a tree whose main matched.

    Ahead means ahead everywhere: every member the Archive holds is present
    here, and this machine's copy of it starts with the stored bytes. Anything
    else is a skip with the same cure as any other behind-or-divergent case.
    """
    missing = sorted(rel for rel in stored if rel not in local)
    if missing:
        return ("the Archive holds files this machine does not - "
                + ", ".join(printable(rel) for rel in missing[:3])
                + (f" and {len(missing) - 3} more" if len(missing) > 3 else "")
                + ". Replacing the stored Session would delete them, and a "
                "Session is replaced whole; pull first (ADR-0002)")
    for rel in sorted(stored):
        if local[rel] == stored[rel]:
            continue
        if local[rel].startswith(stored[rel]):
            continue
        return (f"this machine's {printable(rel)} is not an extension of the "
                "Archive's - behind, or diverged; pull first (ADR-0002)")
    return None


def _push_skip_reason(dest, master, session, entry, members: dict):
    """Why push must leave this Session's Archive object alone, or None.

    ADR-0002's union rule, mirrored onto push: an Archive object is replaced
    only when what it holds is contained in what this machine holds - the
    append-only case, the same comparison history.compare_main runs for pull,
    raised to the tree because the tree is what gets replaced. A machine that
    pulled an older state, or never pulled, is BEHIND, and replacing would
    overwrite a longer Transcript with a shorter one in the only copy that is
    not on the other machine; DIVERGENT is the same skip with the same cure.
    Both are reported by name, never raised, and never overwrite.

    The stored object is fetched before any overwrite. That is a download the
    Index used to avoid, and the Index is exactly the thing that cannot be
    trusted to authorise one: see _index_veto. The veto still runs first, so a
    push that is obviously behind costs nothing, and a Session with no entry
    at all - the whole of a first push - is never fetched because this
    function is not called for one.
    """
    canon = members.get(session.main_path, b"")
    veto = _index_veto(entry, canon)
    if veto is not None:
        return veto
    try:
        stored = _stored_members(
            archive.get_session(dest, master, session.uuid,
                                entry.get("object")), entry.get("object"))
    except archive.ObjectRefused as exc:
        return (f"could not fetch the Archive's copy to compare against "
                f"({exc}) - nothing was overwritten; sort the Destination "
                "out and push again")
    why = _main_mismatch(stored, entry)
    if why is not None:
        return (f"{why} - nothing was overwritten; investigate the "
                "Destination")
    if (entry.get("main_path") or session.main_path) not in stored:
        return ("the Archive's stored tree holds no main Transcript to "
                "compare against - nothing was overwritten; pull first")
    return _tree_behind_reason(stored, members)


def _residue_skip_reason(dest, master, cwd, entry, members: dict):
    """Why push must leave this project's stored residue alone, or None.

    The Session rule with the main Transcript taken out of it: a residue has
    no main, so there is nothing to veto on and the stored object is always
    fetched before it is replaced. Residues are memory files - small, and one
    per project - so the download is not the cost it would be for a Session
    tree.
    """
    try:
        stored = _stored_members(
            archive.get_project(dest, master, cwd, entry.get("object")),
            entry.get("object"))
    except archive.ObjectRefused as exc:
        return (f"could not fetch the Archive's copy to compare against "
                f"({exc}) - nothing was overwritten; sort the Destination "
                "out and push again")
    return _tree_behind_reason(stored, members)


def _stored_members(tar_bytes, what=None) -> dict:
    """{member name: bytes} of a stored tree. The tar holds canonical bytes
    (pack_session re-keys before it packs), so these compare directly against
    _canonical_members.

    ObjectRefused when the plaintext is not a tar, like every other reader of
    one: archive.tar_members carries the whole of that rule, and this spells
    no open of its own.

    Called at every fetch site on both legs, which makes it the moment an
    object stops being bytes and starts being a tree - and therefore the one
    place a Destination-sourced tar can be refused with nothing yet written.
    Every leg already wraps its fetch in `except ObjectRefused`, so putting
    this inside that same try is what turns 'not a tar' into the skip line
    beside every other reason an object cannot be used. Left to the readers
    that WRITE, the same refusal arrives mid-walk, with part of a Session
    already laid down in $HOME.
    """
    return dict(archive.tar_members(tar_bytes, what))


def _main_mismatch(stored: dict, meta):
    """Why this tree is not the version of the Session the Index names, or
    None.

    A label binds WHICH object a blob is, not which VERSION of it: an earlier
    authentic tar for the same Session was sealed by a key holder under the
    same label, so it unseals cleanly and a Destination that keeps old copies
    can roll one transcript back with nothing downstream noticing. The Index
    already records the main Transcript's canonical hash for the union rule
    (ADR-0002) - checking the fetched tree against it costs one hash.

    A Session pushed before the Index recorded main_path is not checked; the
    alternative is refusing to restore everything an older carryon wrote.

    Takes the members rather than the tar, so the tree is extracted once per
    fetch and every reader after this one is looking at the same extraction.
    It used to take the bytes and open them for the one member it wanted,
    which is how a second bare tarfile.open came to sit on both legs.

    `main_path` is the Index's, on both legs, and that it is a string is
    archive._validated's promise - made once where the Index is opened rather
    than at each of the places that index it out.
    """
    main_path = meta.get("main_path")
    expected = meta.get("main_sha256")
    if not main_path or not expected:
        return None
    data = stored.get(main_path)
    if data is None:
        return (f"the stored tree holds no {main_path!r}, which the Index "
                "names as its main Transcript - the Destination served some "
                "other tree for this Session")
    if hashlib.sha256(data).hexdigest() != expected:
        return ("the stored tree's main Transcript is not the one the Index "
                "records - an older copy of this Session, served back in "
                "place of the current one")
    return None


# --- the union rule on the way in --------------------------------------------
#
# Where an incoming tree lands, member by member, and what it did to the copy
# this machine already held.


def _safe_member(member_name: str) -> pathlib.PurePosixPath:
    """The member's relative path, having refused one that escapes its root.

    A backstop rather than the rule. archive.member_refusal answers this for
    every stored member before the first one is handed out, because a raise
    from HERE lands inside the loop that writes, with the tree's earlier
    members already in $HOME - which is what it used to do. What is left is
    the check standing next to the join it protects, for a name that reached
    this loop by some route the reader does not cover.
    """
    name = pathlib.PurePosixPath(member_name)
    if name.is_absolute() or ".." in name.parts:
        raise SystemExit(f"refusing tar member {member_name!r}: "
                         "path escapes its root")
    return name


def _expand_member(name: str, data: bytes, home, maps) -> tuple:
    """(expanded_bytes, near_misses, bare_tokens, non_utf8) for one member.

    history.expand_member is the expansion itself, shared with the Session
    leg; what this adds is the shape this leg's counters want.
    """
    out, jsonl_stats, text_stats, is_utf8 = history.expand_member(
        name, data, home, maps)
    stats = jsonl_stats if jsonl_stats is not None else text_stats
    near = stats.near_misses if stats else 0
    bare = text_stats.bare_tokens if text_stats else 0
    return out, near, bare, (0 if is_utf8 else 1)


def _extract_tree(tar_bytes, root, home, maps,
                  into_state=False, deferred=None, refused=None,
                  only=None, conflicted=None, what=None):
    """Expand a packed tree under `root` by ADR-0002's rule, per member.
    Returns (written, kept, near_misses, bare_tokens, non_utf8).

    An existing local file is replaced only by a copy that extends it, kept
    when it is already ahead or identical, and named in `conflicted` when
    neither copy extends the other so the caller can set the incoming one
    aside. That is the ADR's sentence, and it is the whole rule this function
    applies now.

    It used to offer a second posture, `skip_existing` - "an existing local
    file always wins" - which is what the ADR rejects rather than what it
    says, and both legs that took it were wrong in the same two ways. A file
    this machine was BEHIND on was never caught up, so the 'pull first' its
    push had just been told to run left it exactly where it was and the next
    push was refused again. And a DIVERGENT incoming copy was dropped on the
    floor rather than kept: ADR-0002 keeps both copies, and one of them went
    without a line in the report.

    `only` restricts the walk to the named members, for the caller that has
    already decided about the rest of the tar - the divergent MEMBERS of a
    Session whose other members landed normally. Restricting the tar rather
    than building a second one keeps one extraction path with one set of
    guards on it.

    into_state names the one caller whose root is carryon's own state on
    purpose - the conflicts directory, kept there precisely so a divergent
    Transcript is not discovered as a phantom Session (ADR-0002) - and turns
    off the name check every other write here makes. A residue root is derived
    from a cwd the Archive recorded, so a root that SPELLS ~/.carryon puts the
    write beside the master key, and only a master key holder could have
    composed it; that refuses, per member, since the root is not where the
    expansion stops. A link that RESOLVES there is anybody's to plant and is
    deferred like any other link - see unpack_session, which carries the whole
    reasoning.

    The ownership rule (ADR-0007) runs on every member of every caller, this
    one included: the conflicts directory is carryon's own only as far as
    carryon made it, and a link a previous pull left one component inside it
    is written through exactly like a link in an agent's project tree. It is
    asked before the union rule, and has to be: `member_verdict` reads the
    path, and a broken link reads as 'nothing here yet' while the write that
    followed would CREATE the file at the other end, in the repo the link
    belongs to.

    Where that walk STARTS is `into_state`'s second job, and the two answers
    used to be one directory apart and different. A member landing under
    ~/.carryon is judged from ~/.carryon down, the way the Setup backup is
    and for the reason config.write_state_bytes gives: the state directory
    itself may be a link into a synced folder, and refusing that would be a
    rule about where carryon is installed rather than about who owns the file
    being written. This leg walked from $HOME instead, so the same user's
    pull took every backup and deferred every conflict copy - one question,
    two spellings, which is the drift this round exists to end.

    `deferred`, `refused` and `conflicted` are lists the caller passes to be
    told which members skipped and why - a link already holding the path, a
    syscall this machine would not take, or two copies neither of which
    extends the other - since a skip nobody reports reads as a restore quietly
    short a file. Out-parameters rather than more return values: what this
    returns is unpacked positionally everywhere it is called, and three
    optional arguments cost less than three more positions.

    `what` names the object these bytes came out of, for the refusal
    archive.tar_members raises when they are not a tree at all. Optional
    because a caller that packed the tar itself has no Destination key to
    give, and the refusal then says so rather than inventing one.
    """
    written = kept = near = bare = non_utf8 = 0
    root = pathlib.Path(root)
    # As in unpack_session: external.classify walks the home component by
    # component, where everything else here takes a str just as happily.
    home = pathlib.Path(home)
    # The boundary the ownership walk starts from, which is the caller's
    # rather than a constant (external.owner_of): ~/.carryon for the copy
    # kept aside, $HOME for everything laid down in an agent's own tree.
    owned_from = config.state_dir(home) if into_state else home
    for member_name, data in archive.tar_members(tar_bytes, what):
        if only is not None and member_name not in only:
            continue
        name = _safe_member(member_name)
        target = root / name
        if not into_state and config.spells_state(target, home):
            raise SystemExit(
                f"refusing tar member {member_name!r}: it lands in "
                "carryon's own state (~/.carryon), where the master key "
                "and the config naming the Destination live - a restored "
                "History never writes there")
        # Before the union rule, not after: a link that already claims the
        # path is deference by name (ADR-0007), where 'kept' is the union
        # rule's own word and says nothing about who owns the file.
        status, owner = external.owner_of(target, owned_from)
        if status == external.EXTERNALLY_OWNED:
            if deferred is not None:
                deferred.append((target, owner))
            continue
        verdict = history.member_verdict(target, data, home)
        if verdict != history.WRITE:
            if verdict == history.CONFLICT and conflicted is not None:
                # Set aside and named by the caller, which is the only one
                # that can say which directory it goes in.
                conflicted.append((target, member_name))
            else:
                # A caller that passes no list has nowhere further to put
                # a second copy, because it IS the somewhere else: the
                # conflicts directory holds what an earlier pull set aside
                # and a later one may only extend it.
                kept += 1
            continue
        out, m_near, m_bare, m_non = _expand_member(member_name, data,
                                                    home, maps)
        # Asked again where the bytes go, on the descriptor rather than on the
        # name (external.write_owned): the answer above is a syscall old.
        why = external.write_owned(target, out, owned_from)
        if why is not None:
            if refused is not None:
                refused.append((target, why))
            continue
        near += m_near
        bare += m_bare
        non_utf8 += m_non
        written += 1
    return written, kept, near, bare, non_utf8


def _report_deferred(deferred, home) -> int:
    """Name every restored path a link already claims, and count them.

    The Setup leg's skip line in the History leg's words, and for the same
    reason: a pull that writes almost nothing must read as deference rather
    than as a failure (ADR-0007), which it only does if the report says what
    holds each path. --force is named because it does NOT apply here - a user
    who has just watched it write through an owned link on the Setup leg
    would otherwise reach for it and find nothing.
    """
    for target, owner in deferred:
        print(f"  skip     ~/{printable(_rel_to_home(target, home))} - "
              f"externally owned; {printable(str(owner))} holds it (a "
              "restored History is never written through a link, --force "
              "included)")
    return len(deferred)


def _report_refused(refused, home) -> int:
    """Name every restored path this machine's syscalls would not take.

    A directory standing where a member lands, most often - one `mkdir` in a
    project tree, needing no key at all. It used to end the pull mid-loop with
    an IsADirectoryError and no report; a report line is the whole difference,
    and it has to name the path so the user can remove what is in the way.
    """
    for target, why in refused:
        print(f"  refuse   ~/{printable(_rel_to_home(target, home))} - this "
              f"machine would not take that write ({printable(str(why))}); "
              "something else is standing where that member lands")
    return len(refused)


def _identity(path):
    """(device, inode) for a path, or None when this machine will not say.

    Which file a name refers to is the filesystem's question and not the
    string's. Two names differing only in case are one file on APFS and two on
    ext4, and a report that answers from the names states the opposite of what
    happened on one of them.
    """
    try:
        st = path.stat()
    except (OSError, ValueError):
        return None
    return (st.st_dev, st.st_ino)


def _identities(paths) -> set:
    return {ident for ident in (_identity(p) for p in paths)
            if ident is not None}


def _kept_local_members(local_session, root, unrep, agent, home) -> int:
    """Report the local members the incoming tree did not hold, and count them.

    This is where a replacement stops being a replacement of the DIRECTORY.
    ADR-0002 opens its Consequences with "Pull never deletes", and this branch
    used to: it unlinked every local member whose name the incoming tar did
    not carry, including members the Archive never held. No attacker is needed
    to reach it. push skips a Session it is behind on and tells the user to
    pull first; they pull, their main Transcript is a byte-prefix of the
    incoming one, and the subagent journal or workflow journal that existed
    only on that machine was gone.

    A main Transcript being behind says nothing about whether the subtree is a
    subset. Resume the same Session on two machines and each grows Transcripts
    the other never saw while the mains stay in a clean prefix relation - that
    is the ordinary shape, not the corner. So the trees are unioned: the
    incoming member wins every name it holds (unpack_session has already
    overwritten those), and a local-only member stays. A member the Archive
    holds under a NEW name after a rename is the one case where something
    stale genuinely ought to go, and that is `--mirror`, which ADR-0002 defers
    on purpose.

    Kept is measured against what the tar HELD rather than what landed, so a
    member deferred to another owner (ADR-0007) or refused by a syscall is
    counted once, on its own line, and not again here.

    Which local files the tar held is asked of the filesystem rather than of
    the names. `rel not in incoming` compares strings while the write compares
    paths, and on a case-insensitive filesystem - APFS by default - those give
    opposite answers: a local 'Subagents/journal.jsonl' and an incoming
    'subagents/journal.jsonl' are one file, so the name comparison counted it
    as one the Archive never held and printed a keep line about a Transcript
    that had just been written over. Inodes are what "the same file" means,
    and a member the tar decided about is named by its own line either way.

    The count is returned to be added up rather than discarded: the deletion
    it replaces was silent, and a pull that says nothing about the tree it
    just decided about is the same failure with a kinder outcome.
    """
    local_root = pathlib.Path(home) / local_session.project_dir
    if root != local_root:
        # `--map` sends the restore to a directory the local Session is not
        # in, so nothing of the local tree was superseded and all of it is
        # kept. Named by directory rather than by member, because what the
        # user needs here is where the two copies now sit.
        print(f"  keep     ~/{printable(_rel_to_home(local_root, home))} - "
              "the incoming tree was restored to another directory, so this "
              f"machine's copy of {printable(local_session.uuid)} is left "
              "where it is, "
              "whole")
        return len(local_session.files)
    decided = _identities(root / name for name in unrep.member_names)
    incoming = set(unrep.member_names)
    kept = [rel for rel in local_session.files
            if rel not in incoming
            and _identity(local_root / rel) not in decided]
    if kept:
        # The mirror image of the union line, and deliberately its shape: that
        # one says what the Archive held and this machine did not, this one
        # says what this machine holds and the Archive did not.
        print(f"  keep     {printable(local_session.uuid)} ({agent}) - "
              f"{len(kept)} "
              "file(s) this machine holds and the Archive did not; left in "
              "place, since a pull never deletes")
    return len(kept)


def _restore_root(agent: str, cwd: str, effective: dict, home, maps):
    """Where an incoming Session or residue lands on THIS machine.

    Derived from the recorded cwd by the layout's own strategy and never
    decoded from the stored directory name (ADR-0006). unpack_session derives
    the same root from the same three things; pull needs it one step earlier,
    to ask which of this machine's copies of a Session the incoming tree is
    about to land on top of. The engine keeps these helpers module-private on
    purpose, and growing its public surface for one caller would be worse than
    reaching in.
    """
    adapter, item = history._chats_item(agent, effective)
    strategy = history._strategy(adapter.key, item.layout)
    return strategy.restore_root(item, history._expand_path(cwd, home, maps),
                                 home)


def _choose_local_copy(copies, landing, home) -> tuple:
    """(the local copy the incoming tree lands on, the other copies of it).

    A machine can hold the same Session in two project dirs - a copied project
    tree, a cwd that moved - and discovery finds both. The dict that used to
    hold one Session per UUID was last-wins, so the union comparison and the
    keep accounting could be done against a directory the incoming tree never
    touched: the report then blamed a `--map` nobody passed, counted that
    copy's files as kept, and said nothing at all about the directory being
    written into.

    The copy standing in the landing directory is the one the union rule is
    about. The others are untouched by definition, and get a line saying so
    rather than being silently spoken for.
    """
    if not copies:
        return None, ()
    ordered = sorted(copies, key=lambda s: s.project_dir)
    chosen = ordered[0]
    for session in ordered:
        if landing is not None and \
                pathlib.Path(home) / session.project_dir == landing:
            chosen = session
            break
    return chosen, tuple(s for s in ordered if s is not chosen)


def _report_other_copies(others, uuid: str, home) -> int:
    for session in others:
        root = pathlib.Path(home) / session.project_dir
        print(f"  keep     ~/{printable(_rel_to_home(root, home))} - this "
              f"machine holds another copy of {printable(uuid)} there and the "
              "incoming "
              "tree landed elsewhere, so it is left where it is, whole")
    return sum(len(session.files) for session in others)


class _Landed(NamedTuple):
    """What laying one incoming Session tree down did, for pull's summary."""
    kept: int = 0          # members whose local copy won the union rule
    conflicted: int = 0    # members where neither copy extends the other
    deferred: int = 0
    refused: int = 0
    near: int = 0
    bare: int = 0
    non_utf8: int = 0


def _land_session(tar_bytes, meta, uuid, home, maps, effective,
                  apply) -> tuple:
    """Restore one incoming Session tree and report what it did to the local
    one. Returns (root, UnpackReport, _Landed).

    Both branches that write a Session tree come through here - the one where
    this machine has never seen the UUID and the one where it is behind on it -
    because both write over the same kind of file. A Session is discovered only
    through its top-level `<uuid>.jsonl`, so a subtree whose main Transcript is
    gone is no Session at all to discovery: it took the `new` branch, which
    wrote over every same-named local member with no comparison and no
    accounting, under a summary reading `1 new, 0 replaced`. The union rule
    lives in unpack_session for that reason; this is where its outcomes are
    reported and where a divergent incoming copy is placed.

    ~/.carryon/conflicts/<uuid>/ is the same directory a wholly divergent
    Session goes to, and for the same reason (ADR-0002): a stray Transcript
    written into a project dir would be discovered as a phantom Session on the
    next push.
    """
    root, unrep = history.unpack_session(tar_bytes, meta, home, maps,
                                         adapters=effective, apply=apply)
    deferred = _report_deferred(unrep.deferred, home)
    refused = _report_refused(unrep.refused, home)
    for target in unrep.kept:
        print(f"  keep     ~/{printable(_rel_to_home(target, home))} - this "
              "machine's copy is ahead of the Archive's (the incoming one is "
              "a byte-prefix of it); left in place (ADR-0002)")
    conflict_dir = home / ".carryon" / "conflicts" / uuid
    for target, _name in unrep.conflicted:
        print(f"  conflict ~/{printable(_rel_to_home(target, home))} - "
              "divergent; local kept, incoming under "
              f"{printable(str(conflict_dir))}")
    near = bare = non_utf8 = 0
    if apply and unrep.conflicted:
        c_deferred, c_refused = [], []
        _, _, near, bare, non_utf8 = _extract_tree(
            tar_bytes, conflict_dir, home, maps, into_state=True,
            only=frozenset(name for _t, name in unrep.conflicted),
            deferred=c_deferred, refused=c_refused)
        deferred += _report_deferred(c_deferred, home)
        refused += _report_refused(c_refused, home)
    return root, unrep, _Landed(len(unrep.kept), len(unrep.conflicted),
                                deferred, refused,
                                unrep.near_misses + near,
                                unrep.bare_tokens + bare,
                                unrep.non_utf8 + non_utf8)

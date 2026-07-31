"""Authenticated - what a machine's Setup is once a master key holder pushed it.

A tag over the whole plaintext tree, with the Index recording that the tag
exists and which tree is current. The record lives in the Index because the tag
itself sits where an attacker can strip it, so this module never reads "no tag
here" as an answer: the Index's flag decides the posture and the tag is then
either produced or refused by name.

The one non-obvious thing: verifying is not the check. A tag says a key holder
wrote these bytes at some time, and every tree a Destination has ever held goes
on verifying for ever, so versioned storage holds an unlimited supply of tags
that pass. `_stale_stamp` is what says WHICH tree is meant, by comparing the
stamp inside the tag against the sealed Index's copy - and its docstring calls
itself "the one freshness rule, asked at both doors". That is what the two
Setup legs share, and it is why they can split into a way out and a way in
without either importing the other. It was asked on the pull leg only once,
and one ordinary `push --category config` laundered a replayed tree.

A leaf over archive (what a tag is and how it opens) and nothing else in this
package.
"""

from __future__ import annotations

import hashlib
import pathlib

from . import archive
from .destinations.base import printable


# --- the Index's record, and the freshness rule both doors ask ---------------


def _index_setup_entry(index, machine: str) -> dict:
    """The encrypted Index's own record of this machine's Setup, or {}.

    The Index is sealed, so what is in here was written by a master key
    holder; the shape is still checked, because a carryon that wrote a shape
    this one does not know is not a reason to raise.
    """
    if index is None:
        return {}
    entries = index.get("setups")
    entry = entries.get(machine) if isinstance(entries, dict) else None
    return entry if isinstance(entry, dict) else {}


def _stale_stamp(vouched, entry) -> bool:
    """Whether a verified tag vouches for a tree the Index does not call
    current. The one freshness rule, asked at both doors into
    open_setup_manifest.

    A tag says 'a key holder wrote these bytes at some time', which is not
    'this is the Setup a key holder means you to have now'. Every tree a
    Destination has ever held keeps verifying, so versioned storage holds an
    unlimited supply of tags that pass; the stamp inside the tag, compared
    against the sealed Index's copy, is what says which one is current.

    It was asked on the pull leg only, and the push leg is a door into the
    same room: a partial push carried a replayed tree's hashes forward into a
    NEW tag under a NEW stamp and the Index recorded that stamp as current, so
    one ordinary `push --category config` laundered a tree the pull leg had
    been refusing correctly right up to that moment.
    """
    return vouched["stamp"] != entry.get("index_stamp", entry.get("stamp"))


def _vouch_for_stored_manifest(raw, carried: dict, prefix: str) -> None:
    """SystemExit unless the stored MANIFEST is the one the previous tag
    vouches for. Silent when it is.

    The partial push's overlay is a signing oracle without this. The stored
    MANIFEST is read back off the Destination, merged into the document this
    push writes, and then MACed with the user's own master key - so an
    attacker who edits that one file, and leaves every other stored file at
    the hash the honest tag already covers, gets their JSON signed and served
    to every pulling machine as authenticated. The sibling read three lines
    below this one was guarded against exactly that and this one was not.

    Only reachable with a key in hand, which is also why it can be checked:
    _carried_setup_files has just proved a tag over the stored tree, and the
    manifest inside that tag names MANIFEST.json's hash like any other file's.
    A keyless partial push has nothing to check against and does not come
    here - it also signs nothing, so there is no oracle to close.

    A stop rather than a skip, matching its neighbour: a push that ignored the
    stored MANIFEST would drop every item this push did not select, and one
    full push replaces the tree with content read from this machine.
    """
    want = carried.get("MANIFEST.json")
    if raw is None:
        if want is None:
            return
        wrong = "the Archive serves none"
    elif want is None:
        wrong = "the tag vouches for no MANIFEST.json at all"
    elif hashlib.sha256(raw).hexdigest() == want:
        return
    else:
        wrong = "the stored one is not the bytes it vouches for"
    raise SystemExit(
        f"refusing a partial Setup push: {prefix}/MANIFEST.json does not "
        f"match this machine's last authenticated Setup - {wrong}. A partial "
        "push merges that document into the one it signs, so carrying on "
        "would put the user's own master key behind content the Destination "
        "wrote. Push the whole Setup (`carryon push --apply` with no "
        "--category or --agent) to replace and re-authenticate it.")


def _carried_setup_files(dest, master, machine, prefix, index_entry) -> dict:
    """The stored tree's vouched {path: sha256} entries, for a keyed partial
    push to carry forward - or SystemExit when nothing vouches for them.

    A partial push overlays onto the stored tree, so its new SETUP.mac has to
    cover files this push did not write. Hashing them as served would sign
    whatever the Destination is holding with the user's own key (ADR-0009);
    carrying entries out of the PREVIOUS verified manifest signs only what a
    key holder already vouched for. Stored content with no valid manifest is
    therefore a stop, not a shrug: the fix is one full push, which replaces
    the tree with content read from this machine.

    What this does NOT do is re-read the stored tree to check it still
    matches, and that is a size decision rather than an oversight: a partial
    push consumes the CONTENT of exactly one stored file, the MANIFEST, and
    _vouch_for_stored_manifest checks that one. For the rest it carries
    forward hashes, so a file the Destination has edited keeps the honest
    hash in the new tag and the next pull refuses the whole Setup by name
    (setup_tree_mismatches). Downloading a whole skills tree on every
    `push --category` to turn that refusal from the pull's into this push's
    would cost every honest partial push a full read of the Archive.

    What it DOES check, beyond that the tag verifies, is that the tag vouches
    for the tree the Index calls current. A tag alone authenticates every
    superseded tree just as well as the latest one, and this is the second
    door into open_setup_manifest - the pull leg's check was no evidence about
    this one. Without it, replaying an old tree here got its hashes carried
    into a fresh tag under a fresh stamp, and the Index recorded that stamp as
    current: one ordinary `push --category config` laundering a tree the pull
    leg had been refusing correctly right up to that moment."""
    mac_key = prefix + "/" + archive.SETUP_MAC_NAME
    if not any(key != mac_key for key in dest.list(prefix + "/")):
        return {}  # nothing stored: this push authors the whole tree
    raw = dest.read(mac_key)
    vouched = (archive.open_setup_manifest(raw, master, machine)
               if raw is not None else None)
    if vouched is not None and not _stale_stamp(vouched, index_entry):
        return vouched["files"]
    if vouched is not None:
        raise SystemExit(
            f"refusing a partial Setup push: the Archive's Setup for machine "
            f"'{machine}' carries a valid authentication tag for a tree "
            f"pushed at {printable(vouched['pushed_at'] or 'no time')}, while "
            "the encrypted Index records a different tree as the current one "
            f"({printable(index_entry.get('pushed_at') or 'no time')}) - an "
            "earlier tree, tag and all, served back in place of it. A partial "
            "push would carry that tree's file hashes into the tag it writes "
            "and the Index would then record the new stamp as current, which "
            "is how a superseded Setup becomes the live one. Push the whole "
            "Setup (`carryon push --apply` with no --category or --agent) to "
            "replace and re-authenticate it.")
    cause = ("the encrypted Index records this machine's Setup as "
             "authenticated, so the tag was stripped or broken at the "
             "Destination"
             if index_entry.get("authenticated") is True else
             "it was pushed without a master key, or before Setups were "
             "authenticated")
    raise SystemExit(
        f"refusing a partial Setup push: the Archive already holds a Setup "
        f"for machine '{machine}' with no valid authentication tag - "
        f"{cause}. A partial push overlays onto that tree and cannot vouch "
        "for content it did not write; push the whole Setup (`carryon push "
        "--apply` with no --category or --agent) to replace and "
        "authenticate it.")


# --- the tag a stored tree carries, on the way in ----------------------------


def _stored_setup_tag(staging, master, machine) -> tuple:
    """(present, vouched) for the SETUP.mac inside a materialised Setup tree.

    Two answers rather than one, because the caller says a different sentence
    about a tag that was never served, one that will not verify and one that
    does - and because on the unauthenticated path the mere PRESENCE of a tag
    is evidence in itself rather than the absence of a problem.

    A read that will not happen counts as no tag. The file came off the
    Destination like the rest of the tree, and every branch that consumes this
    answer fails closed.
    """
    path = pathlib.Path(staging) / archive.SETUP_MAC_NAME
    try:
        if not path.is_file():
            return False, None
        raw = path.read_bytes()
    except OSError:
        return False, None
    return True, archive.open_setup_manifest(raw, master, machine)


def _detached_tag_refusal(source: str, verifies: bool) -> str:
    """Why a Setup the Index does not vouch for may not carry a tag at all.

    A SETUP.mac is written only by a push that holds the master key, and that
    same push records the tree in the encrypted Index and seals it - the two
    are written by one branch and cannot come apart at the source. So a stored
    tree that carries a tag while the Index does not record it as
    authenticated is the Index being served not being the one that push wrote:
    deleted, or rolled back, at the Destination.

    That is the tell archive.load_index says is unavailable, and it is
    unavailable THERE: load_index reasons from the Session objects, and
    _index_removed_note from this machine's high-water mark. This is the same
    question asked of the Setup half, where the answer is a statement only a
    master key holder could have written and needs no local mark to read - the
    case that matters, because a machine paired by a carryon that predates the
    revision in the pairing payload, or one whose $HOME was restored from a
    backup, holds no mark at all and used to restore the tree unverified with
    two notes and exit 0.

    ADR-0004's keyless push leaves no tag whatsoever, so the honest
    unverifiable Archive never reaches here and keeps restoring with its
    warning. That is exactly what makes the two distinguishable.

    A tag that does NOT verify takes the same refusal, and deliberately so.
    The difference between the two is a directory renamed at the Destination -
    the label binds the machine name, so 'setups/mac-a' served as
    'setups/mac-A' verifies under neither - a forged tag, or a tree lifted
    from another Archive. None of those is a Setup to lay down over this
    machine's own, and treating 'it does not verify' as a reason to carry on
    would hand the whole check back to whoever can rename a directory.
    """
    head = (f"the stored Setup for machine '{printable(source)}' is refused "
            "whole: it carries an authentication tag that ")
    if verifies:
        return head + (
            "verifies under this machine's master key, while the encrypted "
            "Index does not record that Setup as authenticated. Only a master "
            "key holder can write that tag, and the push that writes one "
            "records the tree in the Index in the same breath - so the Index "
            "being served is not the one that push wrote: it has been deleted "
            "or rolled back at the Destination, which is what makes every "
            "Setup here read as a keyless push nothing can verify. Nothing "
            "from it was restored; restore an earlier copy of the Archive (a "
            "git Destination keeps one in its history), or push the Setup "
            "again from a machine that holds the master key.")
    return head + (
        "does not verify under this machine's master key, while the encrypted "
        "Index does not record that Setup as authenticated. A keyless push "
        "(ADR-0004) writes no tag at all, so this is not one: it is a forged "
        "tag, a Setup directory renamed at the Destination, or a tree from "
        "another Archive. Nothing from it was restored; push the Setup again "
        "from a machine that holds the master key, or investigate the "
        "Destination.")


def _setup_authentication(staging, master, source, entry) -> tuple:
    """(refusal, note) for the materialised Setup, before anything is written.

    refusal is a list of report lines refusing the Setup WHOLE - a partial
    Setup is worse than none, so verification never salvages the files that
    still match. note is a warning to print and then restore anyway.

    Which posture applies is decided by the encrypted Index's 'authenticated'
    flag, never by a MISSING SETUP.mac: the MAC file sits in the plaintext
    half, so 'no tag here' is the attacker's cheapest sentence to write, and
    honouring it would let stripping the tag downgrade the pull to the keyless
    path (ADR-0009). Index says authenticated and the tag is missing, forged,
    or vouches for a different tree: refusal. Index says unauthenticated - a
    keyless push (ADR-0004) or an Archive from before Setups were
    authenticated: restore, with the warning said plainly rather than
    implying safety.

    A tag that IS there is the other half of that rule, and it was the half
    missing here. The flag decides the posture; it never decided whether the
    file was worth opening, so this function used to return on the
    unauthenticated branch before it looked. A present tag under an
    unauthenticated flag is a contradiction between two statements, one of
    which only a master key holder can write and the other of which the
    Destination merely serves - see _detached_tag_refusal.

    The MAC label uses the Index's spelling of the machine, not the stored
    directory's: on a case-folding Destination a rename leaves one directory
    under another name, and the honest tree must keep verifying. With no Index
    entry there is no such spelling and the directory's own name is all there
    is, which is the right name anyway - an honest push stores a tree under
    the machine it bound into the label.
    """
    present, vouched = _stored_setup_tag(staging, master,
                                         entry.get("index_name") or source)
    if not entry.get("authenticated"):
        if present:
            return [_detached_tag_refusal(source, vouched is not None)], None
        if entry.get("vouched"):
            return None, (
                "the encrypted Index records this Setup, but from before "
                "Setups were authenticated - its content cannot be verified; "
                "push it again from a machine that holds the master key")
        # unvouched: the 'nothing in the encrypted Index vouches for it'
        # note already printed is the warning for this case.
        return None, None
    head = (f"the stored Setup for machine '{printable(source)}' is refused "
            "whole: the encrypted Index records it as authenticated, ")
    tail = (" Nothing from it was restored; push the Setup again from a "
            "machine that holds the master key, or investigate the "
            "Destination.")
    if not present:
        return [head + "but the Archive serves no authentication tag with it "
                "- stripped at the Destination, or overwritten by a keyless "
                "push." + tail], None
    if vouched is None:
        return [head + "and its authentication tag does not verify - the tag "
                "was forged or damaged at the Destination." + tail], None
    # The tag proves a key holder wrote this tree; the stamp inside it is what
    # says WHICH tree they meant. Both come from the same MACed payload, and
    # the Index's copy of the stamp is sealed, so a Destination serving back a
    # superseded tree tag-and-all - the copy any versioned storage keeps - is
    # an authentication failure rather than a quiet rollback of whatever the
    # last push tightened. Checked against the Index's own fields, never
    # against the catalogue's reported time, which for an unauthenticated
    # Setup can come from the plaintext MANIFEST an attacker authors.
    if _stale_stamp(vouched, entry):
        return [head + "and its authentication tag vouches for a Setup "
                f"pushed at {printable(vouched['pushed_at'] or 'no time')} "
                "rather than for the one the Index records as current "
                f"({printable(entry.get('index_pushed_at') or 'no time')}) - "
                "an earlier tree, tag and all, served back in place of it."
                + tail], None
    problems = archive.setup_tree_mismatches(staging, vouched["files"])
    if problems:
        return ([head + "and the stored tree is not the one its tag vouches "
                 "for." + tail] + problems), None
    return None, None

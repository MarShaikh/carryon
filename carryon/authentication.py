"""Which stored Setup a key holder means you to have NOW.

This module used to answer two questions, and ADR-0014 took the first one away.
It was "did a master key holder write these bytes", asked of a plaintext tree
by way of a MAC file sitting beside it, plus "and is this the tree they meant
last". A sealed Setup answers the first by opening at all - the seal is an HMAC
over the object's label and then its ciphertext, so a Setup that unseals under
this machine's key, bound to this machine's name, was written by a key holder
and there is nothing left to check.

The second question survives sealing completely intact, and that is the whole
reason this file still exists. A seal says a key holder wrote these bytes AT
SOME TIME. Every sealed Setup a Destination has ever held goes on opening for
ever, so a versioned bucket, a git history or a synced folder's trash holds an
unlimited supply of objects that pass, and serving an old one back silently
undoes whatever the last push tightened. The push therefore stamps the sealed
tree and the encrypted Index with one fresh value, and the pull requires them
to agree.

The temptation ADR-0014 creates is to read "it unsealed" as "it is current".
Those are different sentences, and only the Index says the second - which is
why `_stale_stamp` is asked at BOTH doors into a Setup, in and out. It was
asked on the pull leg only, once, and one ordinary `push --category config`
laundered a replayed tree.

A leaf over archive and nothing else in this package.
"""

from __future__ import annotations

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


def _stale_stamp(stamped, entry) -> bool:
    """Whether a Setup that opened is one the Index does not call current.

    The one freshness rule, asked at both doors. A sealed object says 'a key
    holder wrote these bytes at some time', which is not 'this is the Setup a
    key holder means you to have now'; the stamp sealed inside the tree,
    compared against the sealed Index's copy, is what says which one is
    current.

    It was asked on the pull leg only, and the push leg is a door into the
    same room: a partial push read the stored tree, carried it forward into a
    new object under a NEW stamp, and the Index recorded that stamp as
    current - so one ordinary `push --category config` laundered a tree the
    pull leg had been refusing correctly right up to that moment.
    """
    return stamped["stamp"] != entry.get("index_stamp", entry.get("stamp"))


def stamped_or_none(staging):
    """The stamp sealed inside a materialised Setup, or None.

    None for every way there is not one this carryon can read - absent,
    malformed, the wrong shape. The caller's question is only ever 'can this
    tree's freshness be checked', and a stamp that cannot answer it takes the
    same fail-closed branch as a missing one.

    No MAC to check first, which is the whole of what sealing bought: these
    bytes came out of an object that opened under the master key, so they were
    a key holder's before they reached this function.
    """
    path = pathlib.Path(staging) / archive.SETUP_STAMP_NAME
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return archive.read_stamp(raw)


def setup_freshness(staging, source, entry) -> tuple:
    """(refusal, note) for a Setup that has already unsealed.

    refusal is a list of report lines refusing the Setup WHOLE - a partial
    Setup is worse than none, so this never salvages the files that still
    match. note is a warning to print and then restore anyway.

    What it no longer does is decide whether a key holder wrote the tree.
    `archive.get_setup` settled that by unsealing it under a label bound to
    the machine; nothing that reaches here is the Destination's authorship.
    So there is no 'authenticated' flag to consult and no detached-tag
    contradiction to resolve - both were shapes of the plaintext era, and a
    keyless push that could produce an unauthenticated Setup no longer exists.

    One question is left, and it is the one sealing cannot answer.
    """
    stamped = stamped_or_none(staging)
    head = (f"the stored Setup for machine '{printable(source)}' is refused "
            "whole: ")
    tail = (" Nothing from it was restored; push the Setup again from a "
            "machine that holds the master key, or investigate the "
            "Destination.")
    if stamped is None:
        if not entry:
            # No Index record and no stamp: an Archive written before ADR-0014,
            # or by a carryon this one does not know. It opened under the
            # master key, so it is a key holder's - but nothing says it is the
            # current one, and saying so is better than implying safety.
            return None, (
                "this Setup opened under the master key, so a key holder "
                "wrote it, but it carries no freshness stamp - nothing here "
                "can tell it from an earlier one served back in its place. "
                "Push it again from a machine that holds the master key")
        return [head + "the encrypted Index records a current Setup for it, "
                "and the tree the Archive served carries no freshness stamp "
                "at all - an Archive from before stamps existed, or a tree "
                "assembled at the Destination." + tail], None
    if not entry:
        return None, (
            "nothing in the encrypted Index records this Setup, so its stamp "
            "has nothing to be checked against - it opened under the master "
            "key, which proves who wrote it and not when")
    if _stale_stamp(stamped, entry):
        return [head + "it opened under the master key, but it is the Setup "
                f"pushed at {printable(stamped['pushed_at'] or 'no time')} "
                "rather than the one the Index records as current "
                f"({printable(entry.get('index_pushed_at') or 'no time')}) - "
                "an earlier tree served back in place of it." + tail], None
    return None, None

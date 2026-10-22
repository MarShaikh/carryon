"""Which stored Setup a key holder means you to have NOW.

"Did a master key holder write these bytes" is answered by the seal (ADR-0014):
a Setup that unseals under this machine's key, bound to this machine's name,
was written by a key holder.

"Is this the Setup they meant last" is not, and it is this module's whole
job. A seal says a key holder wrote these bytes AT
SOME TIME. Every sealed Setup a Destination has ever held goes on opening for
ever, so a versioned bucket, a git history or a synced folder's trash holds an
unlimited supply of objects that pass, and serving an old one back silently
undoes whatever the last push tightened. The push therefore stamps the sealed
tree and the encrypted Index with one fresh value, and the pull requires them
to agree.

The temptation ADR-0014 creates is to read "it unsealed" as "it is current".
Those are different sentences, and only the Index says the second - which is
why `_stale_stamp` is asked at BOTH doors into a Setup, in and out: asked on
the pull leg only, one ordinary `push --category config` launders a replayed
tree.

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


def setup_freshness(staging, source, entry):
    """Report lines refusing a Setup that has already unsealed, or None.

    The refusal is WHOLE - a partial Setup is worse than none, so this never
    salvages the files that still match.

    Whether a key holder wrote the tree is already settled:
    `archive.get_setup` unsealed it under a label bound to the machine.

    What is left is the question sealing cannot answer: a sealed object says
    'a key holder wrote these bytes at some time', and a versioned
    Destination keeps every one they ever pushed. Which is CURRENT is the
    Index's stamp to answer, and a Setup nothing calls current is refused.

    The one caller is the pull, with a `_setup_catalogue` entry for a Setup
    the Index vouches for, so `entry` is always populated here. The push door
    calls `_stale_stamp` directly from setup_out, and may pass `{}`.
    """
    stamped = stamped_or_none(staging)
    head = f"the stored Setup for machine '{printable(source)}' "
    tail = " Push the Setup again from a machine with the master key."
    if stamped is None:
        # An Archive from before stamps existed, or a tree assembled at the
        # Destination.
        return [head + "has no freshness stamp, so nothing says it is the "
                "current one." + tail]
    if _stale_stamp(stamped, entry):
        # An earlier tree served back in place of the current one.
        return [head + "is an older one (pushed "
                f"{printable(stamped['pushed_at'] or 'at no recorded time')}) "
                "than the Index records as current ("
                f"{printable(entry.get('index_pushed_at') or 'no time')})."
                + tail]
    return None

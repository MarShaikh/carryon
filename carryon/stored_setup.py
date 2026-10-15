"""What a Destination serves as a Setup, turned into something either leg can
act on.

A `setups/<machine>.tar.enc` key is a claim, not a fact, and ADR-0014 moved
which part of it is the claim. The BYTES are now a fact: a Setup opens under
the master key or it does not, so nobody without the key can author one and
there is no plaintext tree left to edit a file inside. What stays a claim is
everything that is not inside the seal - the NAME, which an attacker chooses
freely because a key is where it is read from and a listing is how the user
learns a machine exists at all, and the fact of being CURRENT, which no seal
can carry: a versioned Destination keeps every sealed Setup ever pushed and
all of them open. So a name is still input, refused one thing at a time
(ADR-0009) while the run carries on, and what answers the second question is
the Index's stamp rather than any timestamp a Destination serves.

The one field an attacker cannot forge is still whether the encrypted Index
vouches for a name, which is what _choose_setup_source requires before it
weighs the timestamp.

The one non-obvious thing: the two readers of a stored MANIFEST are twins that
refuse at different sizes, which is why they sit side by side here rather than
one calling the other. A pull can skip one Setup and finish, so
_stored_manifest hands back a report line; a push that ignored one would
merge onto nothing and silently drop from the Archive every item it did not
select, so _stored_setup_manifest stops the command and names the file. Same
bytes, same refusals - _JSON_REFUSALS lives here because all three of its users
do - and the unit refused is the whole difference.

A leaf: archive for where a Setup sits, config for what a machine may be
called, and the Destination base for printing an untrusted name.
"""

from __future__ import annotations

import json
import pathlib

from . import archive, config
from .destinations.base import printable

# What a sealed Setup's key ends with, so a listing can be split back into a
# machine name. Spelled once here rather than re-derived beside each use: it is
# the same string `archive.setup_key` builds, and two spellings of one suffix
# is how a machine called 'x.tar' would come back as 'x'.
SEALED_SUFFIX = ".tar.enc"


# --- the twin readers of a stored MANIFEST -----------------------------------


# Every way json.loads says no to attacker-authored bytes. RecursionError is
# the one a two-exception guard misses, and it is the cheapest to trigger:
# 400 KB of '[' is a pull that dies before it reports anything. It is a
# RuntimeError rather than a ValueError, so it has to be named.
_JSON_REFUSALS = (ValueError, UnicodeDecodeError, AttributeError,
                  RecursionError)


def _stored_manifest(staging) -> tuple:
    """(manifest, None) for the stored Setup's MANIFEST, or (None, why).

    It comes out of a sealed object an untrusted Archive served, so a key
    holder wrote it - but a key holder's older or newer carryon, or one with a
    bug, which is enough: missing, unparseable and not-an-object are report
    lines, not a traceback out of a pull that has already laid a History
    down."""
    path = pathlib.Path(staging) / "MANIFEST.json"
    if not path.is_file():
        return None, ("stored Setup has no MANIFEST.json - cannot map it "
                      "back onto $HOME; skipped")
    try:
        manifest = json.loads(path.read_text())
    except _JSON_REFUSALS as exc:
        return None, (f"stored Setup's MANIFEST.json will not parse ({exc}); "
                      "skipped")
    except OSError as exc:
        return None, (f"stored Setup's MANIFEST.json will not read ({exc}); "
                      "skipped")
    if not isinstance(manifest, dict):
        return None, ("stored Setup's MANIFEST.json is not a JSON object; "
                      "skipped")
    return manifest, None


def _stored_setup_manifest(raw, prefix):
    """The Archive's stored MANIFEST for this machine, or None if it holds
    none. SystemExit if it holds one that is not a MANIFEST.

    This is the sibling read path to pull's, and it had no guard of any kind:
    a partial push has to read the stored MANIFEST before it can overlay onto
    it, and handed the bytes straight to json.loads. ADR-0009's rule does not
    stop at the pull - a stored MANIFEST is input on the way out too.

    A sentence rather than a report line, because the two sides differ in
    what they can do next. A pull can skip one Setup and finish; a push that
    ignored an unreadable MANIFEST would write a merged one built from
    nothing, which silently drops from the Archive every item this push did
    not select - so it stops and names the file instead.
    """
    if raw is None:
        return None
    unusable = SystemExit(
        f"the MANIFEST.json inside the Archive's stored Setup "
        f"({prefix}.tar.enc) will not parse, and a partial push has to merge "
        "onto it - carrying on would drop every item this push did not "
        "select from the stored Setup. Push the whole Setup (`carryon push "
        "--apply` with no --category or --agent) to replace it.")
    try:
        stored = json.loads(raw.decode("utf-8"))
    except _JSON_REFUSALS:
        raise unusable
    if not isinstance(stored, dict):
        raise unusable
    return stored


# --- the catalogue: which names are machines, and who vouches ----------------


def _machine_name_refusal(machine: str):
    """Why this stored Setup cannot name a machine, or None.

    Every name here comes out of the Destination's own listing, which makes it
    input: it is only a machine as far as this machine can act on it. A name
    carryon cannot put back into a key - a backslash, a '..', a NUL, all of
    them legal on some filesystem - is one require_key refuses, and left to
    the next read it would surface as a ValueError aborting a pull that had
    already written a History to $HOME.

    A directory under setups/ is a pre-ADR-0014 Setup, and the caller
    answers that case, not this function.

    The shape half is `config.machine_name_refusal` rather than a second
    spelling here, and the round that discovered why is the reason it moved:
    the CLI enumeration recorded THIS function as the door `--machine` goes
    through, and this function has one caller, on the pull leg, over names
    that never came from an argument. So the same rule now answers on the way
    in and on the way back, and what stays here is the half that is only true
    of a listing - a name with nothing stored under it.
    """
    if not machine:
        return "the Archive holds a Setup key with no machine name in it"
    return config.machine_name_refusal(machine)


def _vouched_machines(index, machines) -> dict:
    """{listed machine name: the Index entry that vouches for it}.

    The Index is encrypted, so a name recorded there was put there by a master
    key holder - the one thing about a listed Setup an attacker cannot forge,
    since the key it sits at is theirs to choose.

    Exact names first, and a name listed exactly always answers for itself.
    Then the case-folded fallback, which exists because a Destination can
    rename and on a case-insensitive one (APFS, NTFS) 'setups/MACHINE-A.tar.enc'
    IS 'setups/machine-a.tar.enc' - the same object holding the same honest
    bytes, while index['setups'] is keyed by whatever spelling the pushing
    machine used. Comparing exactly there let a rename take the vouching off an
    honest Setup: add one invented name beside it and the pull restored nothing
    at all, at exit 0, with no key involved.

    Since ADR-0014 the fallback is WORDING rather than a guard, and it is kept
    deliberately rather than by oversight. The seal's label binds the machine
    name, so a renamed object does not open under the Index's spelling whatever
    this function says: with the fold the renamed name is chosen and the seal
    refuses it, without the fold nothing is vouched and the pull says so
    instead. Both exit non-zero, both restore nothing, and a planted Setup
    claiming the year 9999 loses either way - so what the fold still changes is
    only which sentence the user reads, and the one it produces names the
    machine they were expecting. Removing it should be a decision, not a
    side effect, which is why it is pinned by a test.
    """
    entries = index.get("setups", {})
    if not isinstance(entries, dict):
        return {}
    vouched = {m: m for m in machines if m in entries}
    for name in entries:
        if name in machines:
            continue
        fold = name.casefold()
        renamed = [m for m in machines
                   if m.casefold() == fold and m not in vouched]
        if len(renamed) == 1:
            vouched[renamed[0]] = name
    return vouched


def _setup_catalogue(dest, index) -> tuple:
    """(setups, refused) for every Setup the Archive holds.

    setups is machine -> {'pushed_at', 'vouched', ...}; refused is (name, why)
    for every key under setups/ that cannot be treated as a machine's Setup at
    all.

    A Setup's timestamp comes from the sealed Index (ADR-0014), never from
    anything the Destination serves in the clear.

    The listing is used only as DISCOVERY. Which machines an
    Archive holds is still read off the Destination, because a name nobody can
    read is a name nobody can offer the user - so the names here are still
    input, still go through `_machine_name_refusal`, and still prove nothing on
    their own. What makes one trustworthy is that `archive.get_setup` unseals
    it later; what makes it CURRENT is the Index's stamp.
    """
    machines, sealed = set(), set()
    for key in dest.list(archive.SETUPS_PREFIX):
        rest = key[len(archive.SETUPS_PREFIX):]
        if rest.endswith(SEALED_SUFFIX):
            machine = rest[:-len(SEALED_SUFFIX)]
            machines.add(machine)
            sealed.add(machine)
            continue
        # A key under setups/ that is not a sealed object is an Archive from
        # before ADR-0014 - a directory per machine. Its name is still listed
        # so the user is told it is there and why nothing can be done with it,
        # rather than the Archive appearing to hold no Setups at all.
        machines.add(rest.partition("/")[0])
    entries = index.get("setups", {})
    if not isinstance(entries, dict):
        entries = {}
    vouched = _vouched_machines(index, machines)
    setups, refused = {}, []
    for machine in sorted(machines):
        why = _machine_name_refusal(machine)
        if why is not None:
            # Before the read, not after: asking the Destination for this
            # name at all is what would end the pull.
            refused.append((machine, why))
            continue
        if machine not in sealed:
            refused.append((machine, "the Archive holds it as a plaintext "
                                     "tree, which is how Setups were stored "
                                     "before they were sealed (ADR-0014) - "
                                     "push again from a machine that holds "
                                     "the master key to replace it"))
            continue
        entry = entries.get(vouched.get(machine), {})
        known = entry.get("pushed_at", "") if isinstance(entry, dict) else ""
        # A str, or nothing: the value reaches a report line and a
        # comparison, and a TypeError there would escape the one
        # `except SystemExit` around this call after the pull had already
        # written to $HOME.
        if not isinstance(known, str):
            known = ""
        # index_name is the Index's own spelling of the machine - the one the
        # pushing side bound into the seal's label - which a case-folding
        # Destination rename must not detach from the object it vouches for.
        setups[machine] = {"pushed_at": known,
                           "vouched": machine in vouched,
                           "index_name": vouched.get(machine),
                           "index_pushed_at": known,
                           "index_stamp": (entry.get("stamp")
                                           if isinstance(entry, dict)
                                           else None)}
    return setups, refused


# --- whose Setup this pull restores ------------------------------------------


def _index_setup_names(index) -> list:
    """Every machine the encrypted Index records a Setup push for, sorted.

    Non-empty means a master key holder has pushed a Setup to this Archive at
    some point - the fact _no_setup_source_note uses to tell a deletion from
    an Archive that never held one."""
    entries = index.get("setups") if isinstance(index, dict) else None
    if not isinstance(entries, dict):
        return []
    return sorted(name for name in entries if isinstance(name, str))


def _choose_setup_source(setups: dict) -> tuple:
    """(source, ignored): whose Setup this pull restores, or None.

    A listed name is a claim and the Index is the only answer to it, so among
    machines the Index vouches for the stamp breaks the tie, and a machine it
    does not vouch for cannot win however new it says it is. The timestamp
    being weighed is the Index's own, not one a Destination serves: ADR-0014
    put the Setup inside a seal, so there is no captured_at in the clear left
    to raise.

    This machine's own name buys nothing here. A machine name is
    socket.gethostname(), a guessable string rather than a secret, and a
    machine that holds the master key and pushed a Setup is already in
    index['setups'].

    No Index vouches for nothing, so it chooses nothing (ADR-0014's
    amendment), and _no_setup_source_note says why."""
    candidates = {m: e for m, e in setups.items() if e["vouched"]}
    if candidates:
        # The Index's timestamp alone: every candidate is vouched, and the
        # time comes from the sealed Index rather than from anything the
        # Destination serves in the clear.
        source = max(candidates, key=lambda m: candidates[m]["pushed_at"])
        return source, sorted(set(setups) - set(candidates))
    return None, sorted(setups)


def _no_setup_source_note(setups: dict, index_names, index_absent=True) -> str:
    """Why this pull restores no Setup, for the report.

    Three different situations reach it and they call for different sentences:
    an Index that exists and records no Setup push, which is a key holder
    saying nothing here is vouched for; one where the Index names Setups the
    Archive holds no object for, which is what a deletion looks like from
    here; and no Index at all, where nothing says whether any Setup is
    current.

    A name under setups/ costs an attacker nothing, but the bytes at it will
    not open unless a key holder wrote them, so each sentence says where the
    verdict comes from: the Index, or its absence."""
    held = ", ".join(printable(m) for m in sorted(setups))
    if not index_names and not index_absent:
        return (
            f"\nSetup: none restored - the Archive holds Setups for {held}, "
            "and the encrypted Index records no Setup push at all. The Index "
            "is sealed, so that is a master key holder saying nothing here is "
            "vouched for; since ADR-0014 a push cannot write a Setup without "
            "the master key and a keyed push records itself, so a name under "
            "setups/ that no push accounts for is one someone put there. Push "
            "a Setup from a machine that holds the master key, then pull "
            "again.")
    if index_names:
        missing = ", ".join(printable(m) for m in index_names)
        return (
            "\nSetup: none restored - the encrypted Index records Setup "
            f"pushes for {missing}, and the Archive holds an object for none "
            f"of them. What it holds is {held}, which no master key holder "
            "ever pushed. The Index is the record of what was pushed here, so "
            "this is what those objects being deleted - and a name nobody "
            "vouches for being left in their place - looks like from this "
            "machine. Push a Setup from a machine that holds the master key, "
            "then pull again.")
    # Only a machine with no record of an Index here gets this far:
    # _refuse_on_index_removal stops the pull before the Setup leg on any
    # machine that has read one. So saying so is a fact, not a guess, and it
    # is the fact that would otherwise have settled the case.
    some, which = (("a Setup", "whether it is current") if len(setups) == 1
                   else ("Setups", "which of them is current"))
    return (
        f"\nSetup: none restored - the Archive holds {some} for {held}, and "
        "this Archive serves no Index at all, so there is no master key "
        f"holder's record here to say {which}. This machine has never read "
        "one at this Destination either, which would have settled it. A Setup "
        "opens under the master key or not at all, but the seal says who "
        "wrote it and never when. Since ADR-0014 a keyed push always writes "
        "the Index, so an Archive with a Setup and no Index is most likely "
        "one the Index was removed from. Push a Setup from a machine that "
        "holds the master key, then pull again.")

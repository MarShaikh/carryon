"""What a Destination serves as a Setup, turned into something either leg can
act on.

A `setups/<machine>/` directory is a claim, not a fact: the tree is plaintext
and needs no master key to write (ADR-0004), so every name and every document
here is input, refused one thing at a time (ADR-0009) - this directory, this
catalogue entry, this stored MANIFEST - while the run carries on. The one field
an attacker cannot forge is whether the encrypted Index vouches for a name, and
that is what _choose_setup_source ranks on before any timestamp.

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


# --- the twin readers of a stored MANIFEST -----------------------------------


# Every way json.loads says no to attacker-authored bytes. RecursionError is
# the one a two-exception guard misses, and it is the cheapest to trigger:
# 400 KB of '[' is a pull that dies before it reports anything. It is a
# RuntimeError rather than a ValueError, so it has to be named.
_JSON_REFUSALS = (ValueError, UnicodeDecodeError, AttributeError,
                  RecursionError)


def _stored_manifest(staging) -> tuple:
    """(manifest, None) for the stored Setup's MANIFEST, or (None, why).

    It comes from the plaintext half of an untrusted Archive, so missing,
    unparseable and not-an-object are report lines - not a traceback out of a
    pull that has already laid a History down."""
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
        f"the Archive's stored {prefix}/MANIFEST.json will not parse, and a "
        "partial push has to merge onto it - carrying on would drop every "
        "item this push did not select from the stored Setup. Push the whole "
        "Setup (`carryon push --apply` with no --category or --agent) to "
        "replace it, or repair the file at the Destination.")
    try:
        stored = json.loads(raw.decode("utf-8"))
    except _JSON_REFUSALS:
        raise unusable
    if not isinstance(stored, dict):
        raise unusable
    return stored


# --- the catalogue: which names are machines, and who vouches ----------------


def _machine_name_refusal(machine: str, has_tree: bool):
    """Why this Setup directory cannot name a machine, or None.

    Every name here is a directory name the Destination chose, which makes it
    input: it is only a machine as far as this machine can act on it. Two
    ways it is not. A key with no '/' after the name is a bare file where a
    tree belongs, so there is nothing to restore. And a name carryon cannot
    put back into a key - a backslash, a '..', a NUL, all of them legal in a
    directory name on some filesystem - is one require_key refuses, which
    used to surface as a ValueError out of the very next read.

    Both used to be admitted and both aborted a pull that had already written
    a History to $HOME.

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
    if not has_tree:
        return ("a Setup is a tree of files, and this names a single stored "
                "file with nothing under it")
    return config.machine_name_refusal(machine)


def _vouched_machines(index, machines) -> dict:
    """{stored directory name: the Index entry that vouches for it}.

    The Index is encrypted, so a name recorded there was put there by a
    master key holder - the one field in the Setup half an attacker cannot
    forge, and the one _choose_setup_source ranks on before it looks at any
    timestamp.

    Exact names first, and a name listed exactly always answers for itself.
    Then the case-folded fallback, which exists because a Destination can
    rename a directory and on a case-insensitive one (APFS, NTFS)
    'setups/MACHINE-A' IS 'setups/machine-a' - the same directory holding the
    same honest content, while index['setups'] is keyed by whatever spelling
    the pushing machine used. Comparing exactly there let a rename take the
    vouching off an honest Setup: add one invented directory beside it and
    the pull restored nothing at all, at exit 0, with no key involved.

    The fallback claims a vouched name only when exactly one listed directory
    folds to it and nothing claimed it exactly. It grants an attacker nothing
    they did not already have - anyone who can create 'setups/MACHINE-A' can
    write into 'setups/machine-a' instead, since the tree is plaintext and
    needs no master key (ADR-0004) - while on a case-SENSITIVE Destination,
    where the two really are two directories, the exact branch keeps winning.
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
    """(setups, refused) for every Setup directory the Archive holds.

    setups is machine -> {'pushed_at', 'vouched'}; refused is (name, why) for
    every directory that cannot be treated as a machine's Setup at all.

    The encrypted Index alone is not authoritative on timing: a Setup-only
    push needs no master key (ADR-0004) and so cannot record itself there.
    The plaintext tree's own MANIFEST carries captured_at, which fills the
    gap - and wins when newer, since a keyless push after a keyed one would
    otherwise pin the stale Index timestamp.

    But that timestamp, and the machine list itself, come out of the
    plaintext tree, which anyone with write access to the Destination can
    author. So each entry also records whether the Index vouches for the
    machine: the Index is encrypted, so a name recorded there was put there
    by a master key holder. That is the one field here an attacker cannot
    forge, and _choose_setup_source ranks on it before it looks at any
    timestamp. Machines the Index knows but the Archive no longer holds a
    tree for are left out - there is nothing to restore from."""
    machines, trees = set(), set()
    for key in dest.list(archive.SETUPS_PREFIX):
        rest = key[len(archive.SETUPS_PREFIX):]
        machine, sep, _ = rest.partition("/")
        machines.add(machine)
        if sep:
            trees.add(machine)
    entries = index.get("setups", {})
    if not isinstance(entries, dict):
        entries = {}
    vouched = _vouched_machines(index, machines)
    setups, refused = {}, []
    for machine in sorted(machines):
        why = _machine_name_refusal(machine, machine in trees)
        if why is not None:
            # Before the read, not after: the point of the check is that
            # asking for this name at all is what used to end the pull.
            refused.append((machine, why))
            continue
        raw = dest.read(archive.SETUPS_PREFIX + machine + "/MANIFEST.json")
        captured = ""
        if raw is not None:
            try:
                captured = json.loads(raw.decode("utf-8")).get("captured_at")
            except _JSON_REFUSALS:
                captured = ""
        if not isinstance(captured, str):
            captured = ""
        entry = entries.get(vouched.get(machine), {})
        known = entry.get("pushed_at", "") if isinstance(entry, dict) else ""
        # A str, or nothing. _validated proves the entry is an object and
        # stops one level above where this indexes; max() over a str and an
        # int is a TypeError, and it escapes the one `except SystemExit`
        # wrapped around this whole call - a traceback out of a pull that has
        # already written to $HOME, from the very case _validated exists for.
        if not isinstance(known, str):
            known = ""
        authenticated = (isinstance(entry, dict)
                         and entry.get("authenticated") is True)
        # index_name is the Index's own spelling of the machine - the one the
        # pushing side bound into the Setup MAC's label - which a case-folding
        # Destination rename must not detach from the directory it vouches
        # for. authenticated and index_pushed_at ride along for the same
        # reason vouched does: they are the Index's answers, and only the
        # Index's.
        #
        # Once a Setup is authenticated the Index is the whole authority on
        # when it was pushed, so max() stops applying: the plaintext
        # captured_at beside it is the attacker's to set, and letting it win
        # printed the NEWEST time in the one line the user reads while the
        # pull was restoring an older tree. max() survives for the
        # unauthenticated case, where a keyless push (ADR-0004) genuinely
        # cannot record itself in the Index and the plaintext field is the
        # only timestamp there is.
        setups[machine] = {"pushed_at": known if authenticated
                           else max(captured, known),
                           "vouched": machine in vouched,
                           "index_name": vouched.get(machine),
                           "index_pushed_at": known,
                           "index_stamp": (entry.get("stamp")
                                           if isinstance(entry, dict)
                                           else None),
                           "authenticated": authenticated}
    return setups, refused


# --- whose Setup this pull restores ------------------------------------------


def _index_setup_names(index) -> list:
    """Every machine the encrypted Index records a Setup push for, sorted.

    Non-empty means a master key holder has pushed a Setup to this Archive at
    some point - the fact _choose_setup_source weighs an unvouched directory
    against."""
    entries = index.get("setups") if isinstance(index, dict) else None
    if not isinstance(entries, dict):
        return []
    return sorted(name for name in entries if isinstance(name, str))


def _choose_setup_source(setups: dict, index_names, index_absent: bool
                         ) -> tuple:
    """(source, unvouched, ignored): whose Setup this pull restores.

    A setups/<machine>/ directory is a claim, not a fact - the tree is
    plaintext and needs no key to write (ADR-0004) - and the captured_at that
    used to decide the winner sits inside it. So a timestamp only ever breaks
    a tie between machines the encrypted Index vouches for.

    This machine's own name buys nothing here. A machine name is
    socket.gethostname(), a guessable string rather than a secret, and a
    machine that holds the master key and pushed a Setup is already in
    index['setups']; a keyless push (ADR-0004) is genuinely unvouched however
    the directory is labelled, so it takes the flagged path like any other.

    Nothing vouched for at all is a legitimate state, because ADR-0004's
    keyless push cannot record itself: one unvouched Setup is still restored,
    flagged as unvouched, since there is nothing to choose between. Two or
    more, with nothing to separate them but an attacker-writable timestamp,
    and carryon restores none - the user can push a Setup from a machine that
    holds the key and pull again.

    But 'nothing vouched for' has to mean there is no key holder's statement
    here AT ALL, not that the statement happens to name no Setup. Two ways it
    was read too narrowly, and both end in the same downgrade.

    Deleting the vouched directory and authoring one under a name the Index
    has never heard of costs an attacker nothing - the tree is plaintext and
    needs no key (ADR-0004) - and it used to land on this branch, which
    restored their settings.json behind one note and skipped Setup
    authentication entirely, because the flag that would have refused it hangs
    off the Index entry they had just detached themselves from. index_names
    closes that: a Setup with no tree behind it is a tree that went missing,
    not a machine that never pushed.

    And index_names is empty for every Index written before the first keyed
    Setup push - a History-only push, a push whose Setup half was refused, and
    the empty catalogue `pair` seals so a joining machine has an anchor at all.
    Those are authentic objects at revision 1 or more, which a versioned
    Destination keeps forever (ADR-0009), and replaying one put a fully paired
    machine on this branch with no rollback signal to notice by: seen and
    served were the same number. So the question is whether an Index EXISTS.
    A key holder's empty catalogue is a key holder saying "nothing here is
    vouched for", which is an answer; no Index at all is nobody saying
    anything, which is ADR-0004's keyless Archive and the only case this
    branch was ever for."""
    candidates = {m: e for m, e in setups.items() if e["vouched"]}
    if candidates:
        # Authentication outranks any timestamp, and the timestamp only
        # separates machines of the same standing. An unauthenticated vouched
        # entry - an Archive from before Setups were authenticated, or a
        # machine that has only pushed keylessly - reports the time its own
        # plaintext MANIFEST claims, which anyone with write access can set to
        # the year 9999; ranking on that alone let a freely editable tree beat
        # one whose content a key holder had vouched for.
        source = max(candidates,
                     key=lambda m: (bool(candidates[m].get("authenticated")),
                                    candidates[m]["pushed_at"]))
        # About the source chosen, not about whether any candidate existed:
        # the flag is the one warning a user can act on, and reporting the
        # wrong thing suppresses it exactly when it matters.
        return (source, not candidates[source]["vouched"],
                sorted(set(setups) - set(candidates)))
    if len(setups) == 1 and not index_names and index_absent:
        return next(iter(setups)), True, []
    return None, True, sorted(setups)


def _no_setup_source_note(setups: dict, index_names, index_absent=True) -> str:
    """Why this pull restores no Setup, for the report.

    Three different situations reach it and they call for different sentences:
    an Archive nobody has ever pushed a keyed Setup to, where the Setups are
    simply indistinguishable; one where the Index names Setups the Archive no
    longer holds - which is what deleting a vouched tree and re-authoring it
    under another name looks like from here; and one where the Index exists
    and vouches for nothing, which is a key holder saying so."""
    held = ", ".join(printable(m) for m in sorted(setups))
    if not index_names and not index_absent:
        return (
            f"\nSetup: none restored - the Archive holds Setups for {held}, "
            "and the encrypted Index records no Setup push at all. The Index "
            "is sealed, so that is a master key holder saying nothing here is "
            "vouched for, while a directory under setups/ needs no key to "
            "write (ADR-0004). Push a Setup from a machine that holds the "
            "master key, then pull again.")
    if index_names:
        missing = ", ".join(printable(m) for m in index_names)
        return (
            "\nSetup: none restored - the encrypted Index records Setup "
            f"pushes for {missing}, and the Archive holds a tree for none of "
            f"them. What it holds is {held}, which no master key holder ever "
            "pushed: a directory under setups/ needs no key to write "
            "(ADR-0004), so this is what a vouched Setup being deleted and "
            "re-authored under another name looks like. Push a Setup from a "
            "machine that holds the master key, then pull again.")
    return (
        f"\nSetup: none restored - the Archive holds Setups for {held}, the "
        "encrypted Index vouches for none of them, and the only thing "
        "separating them is a timestamp anyone who can write to the "
        "Destination could have authored. Push a Setup from a machine that "
        "holds the master key, then pull again.")

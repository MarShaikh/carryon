"""The Archive's layout on a Destination, and the encrypted Index at its head.

This module is the one place that knows where things live under 'carryon/' and
how objects are named (ADR-0003), so the engine and CLI never spell a key. A
Session or a project's residue is an encrypted tar whose name is an HMAC under
the master key - the Destination learns object counts and sizes, never a
Session UUID or a project path - and the Index is an encrypted blob read first
on every pull.

The one non-obvious decision: Setups are stored as plaintext trees while
everything else is encrypted. A Setup is clean by construction - ADR-0001 has
carryon refuse to produce one containing a credential - and plaintext is what
makes a git Destination worth having: each push diffs as readable changes to
settings and skills instead of an opaque blob churning. A History has neither
property, so it takes the encrypted path without exception. Plaintext is not
the same as unauthenticated, though: a Setup's content is executable (hooks,
skills), so a keyed push MACs a manifest of the tree into SETUP.mac and the
encrypted Index records that it did - see the Setup-authentication section.

Every encrypted object is sealed under a *label* - its logical identity, the
same string its name is HMACed from - so a Destination cannot serve one
object's ciphertext under another object's key and have it decrypt. Which
object a blob is has to be part of what the blob says, because the key it
happens to sit at is the untrusted party's choice.
"""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import secrets as stdlib_secrets  # carryon.secrets is the scanner, not this
import string
import tarfile
from typing import NamedTuple

from . import crypto
from .destinations.base import printable, require_key

PREFIX = "carryon"
INDEX_KEY = PREFIX + "/index.enc"
SESSIONS_PREFIX = PREFIX + "/sessions/"
PROJECTS_PREFIX = PREFIX + "/projects/"
SETUPS_PREFIX = PREFIX + "/setups/"
PAIR_PREFIX = PREFIX + "/pair/"
# Directly under the Archive's own prefix rather than in a probe/ directory:
# on a Destination whose store is a filesystem, deleting the probe cannot
# take its directories with it (a pull never deletes, and the removal
# scanner holds that line for carryon's own writes too), so the residue of
# one probe must be a directory the first push creates anyway.
PROBE_PREFIX = PREFIX + "/probe-"

INDEX_VERSION = 1
INDEX_LABEL = "index"

PROBE_BYTES = 32

_LOCATOR_CHARS = set(string.ascii_uppercase + string.digits)


class ObjectRefused(SystemExit):
    """One object this machine will not use, named instead of opened.

    A SystemExit subclass, so an uncaught one still reaches the user as a
    sentence rather than a traceback; a type of its own, so a caller that can
    carry on without this particular object - a pull, which has usually
    written several already - can catch exactly that and go on with the rest.
    Everything a Destination serves is input, so the failure mode is
    report-and-skip: a hostile Destination gets to make carryon decline to
    restore something, with a reason, and never to abort partway through.

    The Index is the one object with no such option, and load_index raises a
    plain SystemExit for it: there is nothing to skip on to.
    """


# --- what `init` asks a Destination before it finishes (ADR-0011) ------------
#
# Two questions, and they are here rather than on the Destination base class
# because both are asked about an ARCHIVE at a Destination: one reads a key
# this module names, the other writes one, and a key nothing else in the
# package spells is how a second spelling of 'carryon/' gets written.


def occupied(dest) -> bool:
    """Whether an Archive is already at this Destination.

    Reads and lists, writes nothing, which is what makes it safe to ask
    before anything has been decided. It is the check that catches the
    mistake costing most: `init` without `--join` against an Archive that
    already exists mints a SECOND recovery key, prints it as though it were
    the one that mattered, and fails only at the first push - by which point
    the user holds two keys, cannot tell them apart, and `init` refuses to run
    again because this machine already holds a master key.

    The Index first, because it is the one object that is there if and only
    if a push (or a `pair`, which seals a fresh Index before minting a code)
    has completed. But the Index is also ONE object, and anyone with write
    access to the Destination can make one object unservable - delete it,
    or on an object store shadow it with a prefix - and an Archive read as
    fresh because its catalogue is missing is an Archive about to be
    re-founded under a second key. So the listing `_join` already trusts is
    asked as well: objects under carryon/ with no readable Index is
    somebody's Archive in a state worth investigating, never a place to
    start a new one. The cost of reading a stray probe or a half-finished
    push as occupancy is a refusal that names `--join` - the fail-safe
    direction, since the cure for a false yes is reading the sentence, and
    the cure for a false no is a recovery key that opens nothing.
    """
    if dest.read(INDEX_KEY) is not None:
        return True
    return bool(dest.list(PREFIX + "/"))


def probe_key() -> str:
    """A name for one reachability probe, belonging to no machine.

    Random, and that is the whole specification: the probe lands in the
    plaintext half of untrusted storage before any master key exists, so it
    must carry no machine name, no home path and no timestamp. A random name
    also keeps two machines probing the same Archive at the same moment from
    taking each other's object for their own.
    """
    return PROBE_PREFIX + stdlib_secrets.token_hex(16)


def reachable(dest):
    """None if write, read and delete all work here, else the sentence why.

    The other half of what `init` asks, and the half that needs a write. A
    Destination that authenticates is not a Destination that works: rclone
    exits 0 for a transfer it decided not to make, a git remote can accept a
    connection and refuse a push, and a synced folder can be read-only. Each
    of those is a first `push` that fails after the user has been told this
    machine is set up.

    The three verbs in order, because a later one proves nothing without the
    earlier: bytes are written, read back and compared - a store serving the
    version that was there before is the rclone type's whole subject and is
    not a working Destination - and then deleted, which is the one this
    function must answer for even when it has nothing to do with the user's
    credentials. An object carryon put in somebody's storage and cannot take
    back is a line they are entitled to.

    A sentence rather than an exception, because the caller is `init` and what
    it does with a no is refuse before it has minted anything. SystemExit is
    caught for the same reason: it is how every type in the Destination layer
    says a write did not land, and here it is an answer rather than the end of
    the command.
    """
    key = probe_key()
    # Before the write, because for one type the write is not only a write:
    # on an object store rclone's upload creates a missing bucket, so the
    # probe could have put a billable resource in somebody's account while
    # checking whether it could write to it. Every other type answers None.
    absent = dest.missing_container(key)
    if absent is not None:
        return absent

    payload = stdlib_secrets.token_bytes(PROBE_BYTES)
    try:
        dest.write(key, payload)
    except (OSError, SystemExit) as exc:
        # Nothing to clean up that this call knows of: a write that raised
        # is a write the layer says did not land.
        return f"the probe's write did not land - {exc}"

    try:
        served = dest.read(key)
    except (OSError, SystemExit) as exc:
        return _stranded(dest, key,
                         f"the probe was written and the read back failed "
                         f"- {exc}")
    if served != payload:
        return _stranded(dest, key,
                         "the probe was written and the read back served "
                         + ("nothing at all" if served is None
                            else "something other than what went up"))

    if not _try_delete(dest, key):
        return _left_behind(key, "the probe was written and read back")
    return None


def _stranded(dest, key: str, why: str) -> str:
    """`why`, plus what became of the probe.

    Every way out after a successful write comes through here, because the
    object is carryon's and it is in somebody else's storage: the two paths
    that returned without trying the delete left it there for good, and on
    a git Destination that is a commit, on an object store a line of the
    bill. A stray probe is also read as an Archive by the one listing that
    asks whether a Destination holds anything at all, so it turns `init
    --join` against an empty Destination into "no pairing blob for that
    code" - a user sent to burn a fresh code over carryon's own litter.
    """
    return why if _try_delete(dest, key) else _left_behind(key, why)


def _left_behind(key: str, why: str) -> str:
    return (f"{why}, and the delete of {printable(key)} did not go through "
            "- that object is still in the Archive and carryon cannot "
            "remove it")


def _try_delete(dest, key: str) -> bool:
    """Whether the store has stopped serving the probe. Never raises: the
    write and the read have already answered, and a delete that fails is a
    fact this function reports rather than a second way to crash."""
    try:
        return bool(dest.delete(key))
    except (OSError, SystemExit):
        return False


# --- the Index ---------------------------------------------------------------


class IndexRefusal(NamedTuple):
    """One catalogue entry this machine will not use, and why.

    Carries the entry itself as well as its name, because a refusal here is
    not the end of that record: save_index puts it back exactly as it came so
    a push does not delete what it could not read.
    """

    catalogue: str
    key: str
    entry: object
    why: str


class Index(dict):
    """The Archive's catalogue as this machine may use it.

    A dict, so every loop over `index['sessions']` reads as it always did -
    and reads only the entries that passed the door, which is the point: a
    rule spelled once where the Index is opened does not depend on each room
    remembering it (ADR-0009). What did not pass is on `refused`, for the leg
    to report and for save_index to put back.

    A class attribute rather than an __init__, so an Index built from a plain
    dict - by a test, or by a caller that never went through load_index -
    answers `.refused` with nothing rather than an AttributeError.
    """

    refused = ()


def fresh_index() -> Index:
    return Index({"version": INDEX_VERSION, "sessions": {}, "projects": {},
                  "setups": {}})


def index_refusals(index) -> tuple:
    """Every entry load_index set aside, whatever the caller is holding.

    A plain dict answers 'nothing', and so does the None a keyless
    Setup-only push carries where an Index would be (ADR-0004). Spelled once
    here rather than as a getattr at each of the three places that ask,
    because the alternative is a leg that has to remember which of the three
    it was handed - and the whole point of setting these aside at the door is
    that no room downstream has to remember anything.
    """
    return getattr(index, "refused", ())


def index_revision(index: dict) -> int:
    """How many times this Index has been written, or 0.

    An Index comes out of an untrusted Destination, so a revision that is not
    a whole number reads as 'no revision' rather than raising: this counter
    exists to notice a rollback, and refusing to pull over a malformed one
    would hand the Destination a denial of service.
    """
    value = index.get("revision", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def index_is_absent(index: dict) -> bool:
    """True when this catalogue came from nowhere - the Destination served no
    Index and load_index answered with a fresh one.

    save_index bumps the revision before every write, so every Index an
    Archive has ever held stands at 1 or more and 0 is a number no stored
    Index can carry. That makes the revision the one field that answers 'did
    these entries come off the Destination at all', which callers need
    because an Index that is merely empty and an Index that is missing mean
    opposite things about a stored Setup: the first is a key holder saying
    'nothing is vouched for here', the second is nobody saying anything.
    """
    return index_revision(index) == 0


# The three catalogues, and the shape every reader and writer here assumes of
# them: an object keyed by Session UUID, project cwd or machine name, whose
# values are objects. Checked once, where the Index is opened, because the
# alternative is every loop over it re-asking - and the ones that did not ask
# reached `for uuid in index['sessions']` with a list and raised a bare
# AttributeError out of a pull that had already written to $HOME.
_CATALOGUES = ("sessions", "projects", "setups")

# Per catalogue, the fields a caller then indexes OUT of an entry and hands to
# something that only takes a string. Checked here for the same reason the
# entry itself is: a guard that stops one level above where the code actually
# indexes is a guard with a hole in it, and this is the hole it left twice.
# `cwd` reached str.replace inside history._expand_path and `main_path`
# reached tarfile.getmember on both the pull leg and the push leg, each a bare
# AttributeError; `agent` is the same shape one field over, since `agent not
# in adapters` is a dict lookup and an unhashable value raises there.
#
# Only the fields with no check of their own are listed, and the boundary is
# where the question can be ANSWERED rather than how much it costs to answer
# it wrong (ADR-0009). main_size, main_sha256, object and pushed_at are each
# isinstance-checked at the point of use, because each is asked there against
# something only that reader holds - is this a usable Destination key, does
# this match the bytes that came back - and a door that cannot ask the
# question cannot settle it.
_ENTRY_STRINGS = {
    "sessions": ("agent", "cwd", "main_path"),
    "projects": ("agent",),
    "setups": (),
}

# Per catalogue, whether the key an entry hangs from is also a component of a
# path this machine has to compose. A Session's UUID is: divergent incoming
# Transcripts are set aside under ~/.carryon/conflicts/<uuid>/ (ADR-0002), and
# the uuid goes into that path verbatim. A project's cwd is an absolute path
# by nature and names nothing local - the project directory is re-derived from
# it rather than decoded (ADR-0006) - and a machine name reaches a Destination
# key through the Destination's own listing, which require_key has already
# answered about, so neither takes the component check.
#
# The rest of the check is every catalogue's, because all three keys become an
# Archive LABEL - session_label, project_label, setup_label - and crypto
# encodes a label strictly. The setups one gets there indirectly: the pull leg
# checks a stored tag under the INDEX's spelling of the machine rather than
# the directory's, so that a case-folding rename does not break an honest
# tree. Nothing but require_key, one module over, currently keeps a key that
# will not encode out of that path - which is the whole shape of this class,
# so it is answered here rather than left to hold by coincidence.
_KEY_IS_PATH_COMPONENT = {"sessions": True, "projects": False,
                          "setups": False}


def key_refusal(catalogue: str, key):
    """Why this catalogue key is not one carryon can use, or None.

    The key was the one string in the Index nothing had ever asked about. The
    round that moved validation from the container down to the fields kept its
    subject at the entry: `sessions` is an object, and each value in it is an
    object, and each named field of that value is a string. What every entry
    hangs FROM stayed out of scope, and it is not a lesser string than the
    fields beside it - it seals the object, it names it, and a Session's is a
    directory. A lone surrogate there is legal JSON, six ASCII characters on
    the Destination, and a UnicodeEncodeError out of crypto's label encode,
    raised mid-pull with Sessions already written into $HOME.

    Public, and asked on both sides, which is the half the first fix left out.
    A rule spelled only where an Index is READ makes a key carryon should
    never have minted permanent: the writer seals it at exit 0 and every
    machine that pulls afterwards declines the Session it names, for ever,
    while the machine that still holds it goes on believing it is pushed. So
    history.discover asks this where a Session's name is taken off the
    filesystem, save_index asks it again where an Index becomes bytes, and
    load_index asks it of what comes back.

    A JSON object's keys are strings by construction, so the isinstance is
    about a catalogue this process built rather than read; it is spelled out
    because the two questions after it are only meaningful of a string.

    No shape is asked of a UUID beyond what a path component needs. carryon
    does not mint these names: the claude-projects layout takes the stem of a
    file the agent wrote, and the codex-rollouts layout falls back to a whole
    rollout filename when its regex does not match one. Refusing a key for not
    looking like a UUID would refuse an honest Archive, which is the same
    fault as letting a bad one through, pointing the other way. Length is left
    out for the mirror reason: a name too long for the filesystem is an OSError
    the write already answers with a report line, while a separator or a '..'
    is an escape that nothing answers at all.

    A backslash is not asked about either, and used to be. The clause was
    borrowed from require_key one module over, where it is right because a
    Destination KEY must not hold one; here the question is whether a
    DIRECTORY on this machine can be called this, and on macOS and Linux
    'a\\b' plainly can. A rule that refuses an ordinary local filename is the
    same defect as one that lets a bad name through: the file was there, the
    Session was the user's, and the answer was an Archive nobody could open.
    """
    if not isinstance(key, str):
        return f"a {type(key).__name__} where JSON can only hold a string"
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        return ("a string this machine cannot encode - it holds an unpaired "
                "surrogate, which is legal JSON and legal in a Python str and "
                "is neither a name nor a label carryon can write")
    if not _KEY_IS_PATH_COMPONENT[catalogue]:
        return None
    if not key or key in (".", "..") or "/" in key:
        return "not a name one directory can be called"
    if "\x00" in key:
        return ("a name holding a NUL, which the syscall answers with a "
                "ValueError rather than the OSError a restore is written to "
                "take as a refusal")
    return None


def load_index(dest, master_key: bytes) -> dict:
    """The Archive's catalogue, or a fresh one if nothing was ever pushed.

    The parse is guarded even though the seal proves a master key holder
    wrote these bytes: json.loads has more ways to fail than a caller
    remembers - RecursionError on deep nesting is neither a ValueError nor a
    UnicodeDecodeError - and there is nothing to skip on to here, so the
    difference the guard makes is a sentence instead of a traceback.

    A missing Index is only 'nothing was ever pushed' when nothing else was
    either. Session objects with no Index are the tell that the Index was
    deleted at the Destination (every push that writes a Session writes it),
    and answering fresh there turns a pull into a silent no-op reported as
    success and a push into a re-seal of an empty catalogue - on a machine
    that has never pulled, with no high-water mark to notice by (ADR-0009).

    A stored Setup with no Index is not that tell, and this is where the
    question stops being answerable from here at all: ADR-0004's keyless
    push writes a plaintext tree and no Index, which is what an Archive whose
    Index has been deleted also looks like. Both are the absence of one
    object from a namespace the attacker writes to, and no rule over what the
    Destination serves separates them - so this answers fresh for both, and
    the caller decides. What can separate them is not on the Destination: it
    is whether the machine asking has ever seen an Index here, which is the
    high-water mark sync keeps under $HOME and hands to a joining machine
    inside the pairing wrap. index_is_absent is how a caller with that
    knowledge tells this answer from a real empty catalogue.
    """
    blob = dest.read(INDEX_KEY)
    if blob is None:
        if dest.list(SESSIONS_PREFIX) or dest.list(PROJECTS_PREFIX):
            raise SystemExit(
                f"the Archive holds encrypted Session objects but no Index "
                f"at {INDEX_KEY}. Every push that writes a Session writes "
                "the Index too, so it has been deleted at the Destination; "
                "treating this as a fresh Archive would make a pull "
                "restore nothing while reporting success, and a push "
                "re-seal an empty catalogue over every stored Session. "
                "Restore an earlier copy of the Archive (a git Destination "
                "keeps one in its history); if the loss was deliberate, "
                "delete the Archive's carryon/ objects as well and push "
                "afresh.")
        return fresh_index()
    try:
        raw = crypto.unseal(blob, master_key, INDEX_LABEL)
    except crypto.CryptoError:
        raise SystemExit(
            f"could not open the Archive's Index at {INDEX_KEY}: this is the "
            "wrong recovery key, the Archive was not written by carryon, or "
            "what the Destination served is not the Index it was given")
    try:
        index = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise SystemExit(
            f"the Archive's Index at {INDEX_KEY} opened but will not parse "
            f"({exc}). It was sealed under this recovery key, so it was "
            "written by a machine that holds it - restore an earlier copy of "
            "the Archive, or push from a machine whose Index is intact.")
    if not isinstance(index, dict):
        raise SystemExit(
            f"the Archive's Index at {INDEX_KEY} is not a JSON object - "
            "restore an earlier copy of the Archive")
    return _validated(index)


def entry_refusal(catalogue: str, key, entry):
    """Why no leg may act on this catalogue entry, or None.

    Three levels in one answer - the key the entry hangs from, the entry
    itself, and the fields a leg indexes out of it - because the hole has
    three times been exactly one level wide: the catalogue was guarded and the
    entry was not, then the entry was guarded and its fields were not, then
    the fields were guarded and the key they hang from was not.

    A field that is absent, or null, is not refused. Absent is an older or
    newer carryon leaving it out, and every reader here already treats
    missing as 'not recorded' - but null is stronger than that: carryon
    WRITES one. A Transcript recording no cwd is reported and carried rather
    than guessed at (history.discover), so its Index entry holds "cwd": null
    and the pull leg has a report line waiting for it. A check reading
    'present and not a string' would refuse that honest Archive.

    What is refused is a field holding some other type, because that is the
    shape the readers cannot answer about - and refusing it here rather than
    at each use is the point. The two that got out were both guarded one
    level up, at the entry, and neither was guarded where the string was
    actually used; a rule spelled once at the door does not depend on every
    room remembering it.
    """
    why = key_refusal(catalogue, key)
    if why is not None:
        return (f"its key in the '{catalogue}' catalogue is {why}. A "
                "catalogue key is not only a label in a report: it is what "
                "the object it stands for is sealed and named under, and a "
                "Session's is a directory this machine has to be able to "
                "make")
    if not isinstance(entry, dict):
        return (f"the '{catalogue}' catalogue holds a "
                f"{type(entry).__name__} under that name where carryon "
                "writes an object")
    for field in _ENTRY_STRINGS[catalogue]:
        value = entry.get(field)
        if value is not None and not isinstance(value, str):
            return (f"it records '{field}' as a {type(value).__name__} where "
                    "carryon writes a string, and both a pull and a push hand "
                    "that field straight to something that only takes one")
    return None


def _validated(index: dict) -> Index:
    """The Index with every entry no leg may act on set aside and named.

    The remedy is the size of the damage, and that is this round's whole
    correction. Every check above descended a level - catalogue, entry,
    field, key - and the refusal stayed where the first one was written: one
    unusable record refused the Index whole, which is every Session, every
    residue and every Setup, on both legs, on every machine, permanently.
    ADR-0009 had already ruled that shape out for the objects an Archive
    holds ("one planted object that raises is a permanent abort on every pull
    from every machine") and the Index's own entries are reached by the same
    reading of the same untrusted bytes. So an entry that will not do is
    dropped from the catalogue the legs read, kept verbatim on `refused` for
    save_index to put back, and named in the report - the same answer every
    unusable object gets.

    A catalogue that is absent is filled in rather than refused - an Index
    written before that catalogue existed is still an Index, and every writer
    here indexes into all three. One that is present and is not an object is
    where the granularity argument stops and the whole Index is refused: a
    list cannot be read entry by entry, so there is nothing to set aside and
    nothing to carry forward, and using the catalogue at all would mean
    writing a replacement over whatever a key holder put there.
    """
    index = Index(index)
    refused = []
    for name in _CATALOGUES:
        entries = index.get(name)
        if entries is None:
            index[name] = {}
            continue
        if not isinstance(entries, dict):
            raise SystemExit(
                f"the Archive's Index at {INDEX_KEY} opened, but its "
                f"'{name}' catalogue is a {type(entries).__name__} where "
                "carryon writes an object keyed by name. It was sealed under "
                "this recovery key, so it was written by a machine that "
                "holds it - restore an earlier copy of the Archive, or push "
                "from a machine whose Index is intact.")
        usable = {}
        for key, entry in entries.items():
            why = entry_refusal(name, key, entry)
            if why is None:
                usable[key] = entry
                continue
            refused.append(IndexRefusal(name, key, entry, (
                f"{why}. It was sealed under this recovery key, so a machine "
                "that holds it wrote this - nothing was restored or replaced "
                "for it, and carryon will not delete a record it could not "
                "read. Push again from a machine that still holds what it "
                "names to write a fresh entry, or restore an earlier copy of "
                "the Archive.")))
        index[name] = usable
    index.refused = tuple(refused)
    return index


def save_index(dest, master_key: bytes, index: dict) -> None:
    """Write the Index, one revision further on.

    The counter is bumped here rather than by the caller so it cannot be
    forgotten on a code path that writes the Index: a revision that stands
    still is a rollback nobody notices. It is bumped in place because the
    caller's dict is the same object a later save would write again.

    Every LIVE catalogue key is put through the reader's own question first,
    and that is the invariant rather than a second opinion: carryon must not
    mint a name no machine will restore the Session under. The upstream
    refusal - a Session whose name this machine cannot use is dropped at
    discovery and named in the report - is what makes the ordinary case one
    skipped Session instead of a failed push, and this is what makes the bad
    case reachable only by a bug in carryon rather than by a filename. Refused
    before the revision is bumped and before a byte is written, so the Index
    already on the Destination is exactly as it was.

    Then what load_index set aside goes back in, which is the other half of
    that invariant and reaches further than it. A push seals the whole
    catalogue, so an entry this machine declined to READ is one it is about to
    decide the fate of, and dropping it would be a repair carryon is not
    entitled to make: the entry is the only record of which object holds that
    Session and its key is the only name the object was sealed under, and
    this machine could read neither. Carried through untouched, the damage
    stays visible and reported on every run until a machine that still holds
    the Session pushes a fresh entry; dropped, it is a Session nobody can
    reach again and no report to say so.

    setdefault, not assignment, because a live entry always wins: an entry
    refused for its KEY can never collide (a key that fails key_refusal is
    exactly the one no live entry can carry), but one refused for its shape
    hangs from a perfectly good name, and this push may have just written a
    correct entry under it. That is the repair the report asks for, and the
    carry-forward must not undo it.

    Sealed from a copy so the caller's catalogues keep holding only what it
    may act on. The revision alone is bumped in place, since that counter is
    the caller's to carry into a later save.
    """
    for name in _CATALOGUES:
        for key in index.get(name, {}):
            why = key_refusal(name, key)
            if why is not None:
                raise SystemExit(
                    f"carryon will not seal an Index it could not open again: "
                    f"its '{name}' catalogue is keyed by {printable(str(key))}"
                    f", and that is {why}. Nothing was written, so the "
                    "Archive's Index is untouched - but this is a bug in "
                    "carryon rather than anything you can repair from here; "
                    "please report the name above.")
    index["revision"] = index_revision(index) + 1
    payload = dict(index)
    for refusal in index_refusals(index):
        catalogue = dict(payload.get(refusal.catalogue) or {})
        catalogue.setdefault(refusal.key, refusal.entry)
        payload[refusal.catalogue] = catalogue
    raw = json.dumps(payload, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    dest.write(INDEX_KEY, crypto.seal(raw, master_key, INDEX_LABEL))


# --- Session and project objects ---------------------------------------------
#
# Labels carry a domain prefix so a Session UUID and a project path that
# happened to be equal as strings could never share an object name - or,
# since the same label seals the blob, be substituted for one another.


def session_label(uuid: str) -> str:
    return "session:" + uuid


def project_label(cwd: str) -> str:
    return "project:" + cwd


def session_key(master_key: bytes, uuid: str) -> str:
    return (SESSIONS_PREFIX
            + crypto.hmac_name(master_key, session_label(uuid)) + ".tar.enc")


def project_key(master_key: bytes, cwd: str) -> str:
    return (PROJECTS_PREFIX
            + crypto.hmac_name(master_key, project_label(cwd)) + ".tar.enc")


def _put_object(dest, master_key: bytes, key: str, label: str,
                tar_bytes: bytes, meta: dict) -> str:
    dest.write(key, crypto.seal(tar_bytes, master_key, label))
    # Complete the caller's metadata so it drops straight into the Index.
    meta["object"] = key
    return key


def _get_object(dest, master_key: bytes, object_key: str,
                label: str) -> bytes:
    """The object's bytes, having proved it is the object that was asked for.

    The Index says which key holds a Session, but the Destination decides
    what comes back from that key. The label is carryon's own answer to
    'which object is this', so it is the one the seal is checked against.

    The key is validated before it is used, for the reason load_index guards
    its own JSON parse: the seal proves a master key holder wrote this Index,
    and that is still not the same as the field being a usable key. read()
    validates it too and says so with a ValueError, which is a traceback out
    of a caller that has usually written a History already - while every
    other way this object can be unusable is an ObjectRefused the pull reports
    and skips on from. One answer for one question.

    The read itself is guarded for the same reason. A transport syncs on the
    READ path - GitDestination fetches before serving, and _git_or_die
    answers a dead or hostile remote with SystemExit - and that lands
    mid-pull, after Sessions have already been written to $HOME. A failure
    the Destination manufactures takes the report-and-skip path like
    everything else it sends (ADR-0009), never an abort.
    """
    try:
        object_key = require_key(object_key)
    except (ValueError, AttributeError, TypeError):
        # AttributeError and TypeError as well as ValueError: require_key asks
        # a string's questions, and a stored field that is a number or null
        # answers none of them.
        raise ObjectRefused(
            f"the Index names {object_key!r} as the object holding {label!r}, "
            "and that is not a key any Archive can hold. Nothing was read for "
            "it; push again from a machine that holds the master key to write "
            "a fresh Index.")
    try:
        blob = dest.read(object_key)
    except SystemExit as exc:
        raise ObjectRefused(
            f"the Destination failed while serving {object_key}: {exc} "
            "Nothing was read for it; try again once the Destination is "
            "reachable.")
    if blob is None:
        raise ObjectRefused(
            f"the Index refers to {object_key} but the Archive does not hold "
            "it - if the Destination is a synced folder it may still be "
            "syncing; try again once it settles")
    try:
        return crypto.unseal(blob, master_key, label)
    except crypto.CryptoError as exc:
        # Named as tampering rather than as a key problem, because by the
        # time anything gets here the key is known good: load_index opened
        # the Index with it, under a label of its own (ADR-0009). A user told
        # "wrong key" would go looking for the wrong thing entirely.
        raise ObjectRefused(
            f"{object_key} failed its integrity check: {exc} The recovery key "
            "in use already opened this Archive's Index, so this is tampering "
            "or corruption at the Destination rather than a wrong key; "
            "nothing was restored from it.")


def member_refusal(name: str):
    """Why no restore may lay this stored member down, or None.

    A member name is a path a caller joins onto a root it derived, and both
    ways it can escape that root end the same way: '..' climbs out and an
    absolute name replaces the root entirely, because `root / '/etc/x'` IS
    '/etc/x'. A NUL is the third, and answers differently from the other two -
    the syscall raises ValueError, which every write on the restore leg is
    written to take as an OSError and does not catch.

    Composing one needs the master key, since the tar is sealed - so the
    honest reading is a key holder's Archive with something wrong in it, and
    the answer is the answer every other unusable object gets: this object is
    refused, the rest of the Archive is not.
    """
    if "\x00" in name:
        return ("a name holding a NUL, which the syscall answers with a "
                "ValueError rather than the OSError a restore takes as a "
                "refusal")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return "a path that escapes the root it would be restored under"
    return None


def _tar_files(tar_bytes: bytes, label: str):
    """Every file member of a stored tar: first the name list, then the pairs.

    Split off from tar_members so that nothing but tarfile's own code runs
    inside the broad `except` - the property tar_members' docstring argues
    from, and the one that decides whether a future defect in carryon reads
    to the user as 'this Archive object is damaged'. The caller's checks run
    in the caller's frame while this generator is suspended at a yield.

    Every exception the guarded region can raise is caught, rather than the
    ones tarfile documents, because the two interpreters carryon must pass do
    not agree on what it raises: 3.9 lets a zlib.error straight out of its own
    transparent-mode detection loop where 3.13 wraps the same failure in a
    ReadError. A guard naming types is green on one runner and a traceback on
    the other.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            yield [m.name for m in members]
            for member in members:
                yield member.name, tar.extractfile(member).read()
    except Exception as exc:
        # printable over the cause as well as the name: 3.13's ReadError
        # reports one line per compression method it tried, and this sentence
        # is one line of a report where the next line names the next object.
        why = printable(f"{type(exc).__name__}: {exc}")
        raise ObjectRefused(
            f"{label} opened under this Archive's key, and what came out is "
            f"not a tar carryon can read ({why}). The seal proves a master "
            "key holder wrote those bytes, so this is damage at the "
            "Destination rather than tampering - nothing was read from it. "
            "Push the Session again from a machine that still holds it, or "
            "restore an earlier copy of the Archive.")


def tar_members(tar_bytes: bytes, what=None):
    """(member name, bytes) for every file in a stored tree - or ObjectRefused.

    The one place carryon opens a tar that came off a Destination. There were
    four, in two modules and on both legs, and each was reached by a different
    branch: the version check, the push leg's union comparison, a Session
    restore and a residue restore. Guarding them one at a time is how a
    tarfile.ReadError survived a round of fixes with three of the four still
    bare - so a call site does not get to spell the open, only to ask for the
    members.

    The seal has already proved a master key holder wrote these bytes, which
    is exactly why this is a refusal rather than an alarm: a key holder's
    Archive whose object came back damaged - a lost block, a truncated write,
    a synced folder's conflict copy - is the ordinary reading, and it takes
    the same named refusal every other Destination-sourced failure produces.

    What the members are CALLED is settled here too, and that is the same
    rule one level further out. 'Not a tar' was refused at the open while a
    tar that opens perfectly and holds a member named '../../../escape.txt'
    was still answered from inside the loop that writes - by two callers, each
    next to its own write, each raising there with the tree's earlier members
    already in $HOME and the rest of the pull abandoned. A name is a property
    of the object, not of the caller, so the object is refused whole and
    before the first member is handed out.

    Lazy, but the ordering means a caller that writes as it goes writes
    nothing from a tar this function will not finish: tarfile walks the whole
    header chain in getmembers() before anything is yielded, which is where a
    truncated archive answers, and every member name is checked in this frame
    before the first pair goes out.
    """
    label = (printable(str(what)) if what is not None
             else "a stored Archive object")
    walk = _tar_files(tar_bytes, label)
    for name in next(walk):
        why = member_refusal(name)
        if why is not None:
            raise ObjectRefused(
                f"{label} holds a member named {printable(name)}, and that is "
                f"{why}. The seal proves a master key holder wrote those "
                "bytes, so this is an Archive with something wrong in it "
                "rather than an attack - nothing was read from it, and "
                "nothing it holds was written. Push the Session again from a "
                "machine that still holds it, or restore an earlier copy of "
                "the Archive.")
    yield from walk


def put_session(dest, master_key: bytes, uuid: str, tar_bytes: bytes,
                meta: dict) -> str:
    """Store one Session tree as an encrypted tar; returns the object key.
    meta gains an 'object' field, making it the Index entry for this uuid."""
    return _put_object(dest, master_key, session_key(master_key, uuid),
                       session_label(uuid), tar_bytes, meta)


def get_session(dest, master_key: bytes, uuid: str, object_key: str) -> bytes:
    return _get_object(dest, master_key, object_key, session_label(uuid))


def put_project(dest, master_key: bytes, cwd: str, tar_bytes: bytes,
                meta: dict) -> str:
    """Same as put_session, for a project's residue (memory files etc.)."""
    return _put_object(dest, master_key, project_key(master_key, cwd),
                       project_label(cwd), tar_bytes, meta)


def get_project(dest, master_key: bytes, cwd: str, object_key: str) -> bytes:
    return _get_object(dest, master_key, object_key, project_label(cwd))


# --- Setups: plaintext trees, one per machine --------------------------------


def setup_prefix(machine: str) -> str:
    return SETUPS_PREFIX + machine


def put_setup(dest, machine: str, local_dir) -> None:
    """Make the Archive's Setup for this machine match local_dir exactly.

    Stale keys are deleted after the new tree is written: the Archive keeps
    the *most recent* Setup per machine, so a skill deleted locally must not
    resurrect on the next pull.

    The wanted set is built the way write_tree builds its writes, symlink
    exclusion included. Two walks with different ideas of what a file is put
    a staged link's published target into `wanted` and kept the sweep from
    ever removing it.
    """
    prefix = setup_prefix(machine)
    dest.write_tree(prefix, local_dir)

    local_dir = pathlib.Path(local_dir)
    wanted = {prefix + "/" + p.relative_to(local_dir).as_posix()
              for p in local_dir.rglob("*")
              if p.is_file() and not p.is_symlink()}
    for key in dest.list(prefix + "/"):
        if key not in wanted:
            dest.delete(key)


def get_setup(dest, machine: str, local_dir) -> None:
    """Materialise a stored Setup under local_dir, or refuse it by name.

    read_tree treats the Destination's own listing as input and refuses a key
    that escapes its root, and the local filesystem refuses names it cannot
    hold; both arrive here as exceptions with no bearing on the rest of a
    pull. They are turned into one refusal so the caller can report this
    Setup as unreadable and still finish - the Setup half runs last, so an
    abort here strands a $HOME that already has a History in it.

    The listing sits inside the guard with the read. A listing is the
    Destination's answer too, so whatever a transport can raise while
    producing one belongs to this Setup rather than to the whole pull.
    SystemExit is in the guard for the same reason: a transport that syncs
    on the READ path answers a dead remote with one (GitDestination's
    _git_or_die), and that too is the Destination's answer about this Setup.
    ObjectRefused passes through first - it IS a SystemExit, and rewrapping
    our own refusal would bury the sentence that names the cause.
    """
    prefix = setup_prefix(machine)
    try:
        if not dest.list(prefix + "/"):
            raise ObjectRefused(
                f"the Archive holds no Setup for machine '{machine}'")
        dest.read_tree(prefix, local_dir)
    except ObjectRefused:
        raise
    except (ValueError, OSError, SystemExit) as exc:
        raise ObjectRefused(
            f"the stored Setup for machine '{machine}' could not be laid out "
            f"for reading: {exc}")


# --- the Setup's authentication tag ------------------------------------------
#
# The Setup is plaintext by design, and its content is executable - a hook in
# settings.json, a skill - so a Destination that can rewrite one holds code
# execution on every pulling machine. It cannot be sealed without giving up
# what ADR-0004 buys, so it is authenticated instead: a manifest of (relative
# path, sha256) pairs over the whole tree, MACed under a key derived from the
# master key with its own domain separator (crypto.SETUP_INFO), stored inside
# the tree as SETUP.mac. The file is the attacker's to delete or replace - the
# encrypted Index's 'authenticated' flag, which they cannot write, is what
# makes either of those a refusal instead of a downgrade. The Index says WHEN
# too, and the tag repeats it, because a tag that says only 'a key holder
# wrote this' authenticates every superseded tree just as well as the current
# one.

SETUP_MAC_NAME = "SETUP.mac"
SETUP_MANIFEST_VERSION = 1


def setup_label(machine: str) -> str:
    # Bound to the machine as the Index spells it, so one machine's
    # authenticated tree cannot be served whole under another's name.
    return "setup:" + machine


def setup_tree_manifest(root) -> dict:
    """{relative path: sha256} over a Setup tree's ordinary files.

    The MAC file itself is excluded - it cannot vouch for its own bytes - and
    symlinks are excluded the way every writer of this tree excludes them
    (put_setup, write_tree), so pushing and verifying agree on what the tree
    contains."""
    root = pathlib.Path(root)
    return {p.relative_to(root).as_posix():
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*")
            if p.is_file() and not p.is_symlink()
            and p.relative_to(root).as_posix() != SETUP_MAC_NAME}


def seal_setup_manifest(master_key: bytes, machine: str, files: dict,
                        pushed_at: str, stamp: str) -> bytes:
    """The bytes of a SETUP.mac: hex tag, newline, canonical JSON manifest.

    stamp and pushed_at are what the push that wrote this tree recorded for
    itself in the encrypted Index, and they are bound in for one reason: a MAC
    over the machine and the file hashes alone proves 'a key holder wrote
    these bytes at some time', which is not 'this is the Setup a key holder
    means you to have now'. Every tree a Destination has ever held keeps
    verifying, so a Destination that keeps versions - a git history, a
    versioned bucket, a synced folder's trash - holds an unlimited supply of
    tags that pass, and replaying one silently undoes whatever the last push
    tightened. Binding both lets the pull check the tag against the Index,
    which is sealed and so is the one side of the comparison an attacker
    cannot author.

    The stamp is what the check turns on (crypto.new_stamp says why a
    timestamp cannot be); pushed_at rides along so a refusal can say WHEN the
    tree it was served claims to be from, which is the part a user can act on.
    """
    payload = json.dumps({"version": SETUP_MANIFEST_VERSION, "files": files,
                          "pushed_at": pushed_at, "stamp": stamp},
                         sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    tag = crypto.setup_tag(master_key, setup_label(machine), payload)
    return tag.hex().encode("ascii") + b"\n" + payload


def open_setup_manifest(raw: bytes, master_key: bytes, machine: str):
    """The vouched manifest - {'files': {path: sha256}, 'pushed_at': str,
    'stamp': str} - or None.

    None for every way the bytes are not a manifest a key holder wrote -
    truncated, forged, re-labelled, malformed - because the caller's question
    is only ever 'does anything vouch for this tree', and the answer to a
    broken tag and a missing one is the same. The tag is checked before the
    JSON is parsed: everything after the first newline is untrusted input
    until the MAC says a key holder wrote it.

    A payload with no stamp or no pushed_at in it is not a manifest this
    carryon wrote, and it cannot be checked for freshness, so it is None like
    any other shape it does not recognise: the caller's fail-closed branch is
    the right one for a tag that cannot answer the question the caller asks.
    """
    head, _, payload = raw.partition(b"\n")
    try:
        tag = bytes.fromhex(head.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None
    if len(tag) != crypto.MAC_BYTES:
        return None
    if not crypto.setup_tag_ok(master_key, setup_label(machine), payload,
                               tag):
        return None
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    files, pushed_at, stamp = (doc.get("files"), doc.get("pushed_at"),
                               doc.get("stamp"))
    if not isinstance(files, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in files.items()):
        return None
    if not isinstance(pushed_at, str) or not isinstance(stamp, str):
        return None
    return {"files": files, "pushed_at": pushed_at, "stamp": stamp}


def setup_tree_mismatches(root, files: dict) -> list:
    """Every way the materialised tree differs from the vouched manifest.

    Exact both ways: a file the manifest names and the tree lacks was deleted
    at the Destination, a file the tree holds and the manifest does not was
    planted there, and a hash mismatch is an edit. Names go through printable
    because the planted ones are the attacker's strings and these lines land
    in the pull report."""
    actual = setup_tree_manifest(root)
    problems = []
    for rel in sorted(set(files) | set(actual)):
        if rel not in actual:
            problems.append(f"{printable(rel)}: named by the pushed manifest, "
                            "missing from the stored tree")
        elif rel not in files:
            problems.append(f"{printable(rel)}: present in the stored tree, "
                            "never pushed by a key holder")
        elif files[rel] != actual[rel]:
            problems.append(f"{printable(rel)}: content differs from what "
                            "the key holder pushed")
    return problems


# --- pairing: one-time blobs (ADR-0005) --------------------------------------


def pairing_key(locator: str) -> str:
    """Where a pairing blob sits: the code's locator half, used verbatim.

    The locator is the half of the pairing code that is not a secret, drawn
    independently of the half that wraps the master key, so publishing it as
    a filename on untrusted storage guards nothing and gives nothing away.
    This used to be sha256(whole code)[:16] - an unsalted, single-iteration
    digest of the very secret the 600,000-iteration wrap exists to protect,
    published where anyone can read it. Truncation was no help: 64 bits still
    pin a unique preimage.

    Normalised, not hashed, because the locator arrives from a hand-typed
    code and both machines must name the same object; the charset check keeps
    a mistyped one from becoming a path.
    """
    canon = "".join(locator.split()).replace("-", "").upper()
    if not canon or not set(canon) <= _LOCATOR_CHARS:
        raise ValueError(f"bad pairing locator: {locator!r}")
    return PAIR_PREFIX + canon + ".enc"


def put_pairing(dest, locator: str, wrapped_blob: bytes) -> None:
    dest.write(pairing_key(locator), wrapped_blob)


# There is deliberately no read-and-delete helper here. The blob is
# unauthenticated (ADR-0005: the joining machine has no key to check a tag
# with), so a caller has to unwrap it AND read a well-formed payload out of
# it before the one-time delete is earned - see sync._join. A helper that
# deleted on read would burn a live pairing code on a tampered or truncated
# blob, and it was there for long enough to be worth naming.


# --- change detection --------------------------------------------------------


def tree_hash(root) -> str:
    """sha256 over the sorted (relpath, per-file sha256) pairs of a tree.

    Location-independent on purpose: two machines holding byte-identical
    Session trees at different homes agree on the hash, which is what lets
    needs_push skip an upload.

    Symlinks are excluded, the way put_setup and setup_tree_manifest exclude
    them, because is_file() follows one: a link in the tree put its TARGET's
    bytes into the hash, and read_bytes() on a target this process may stat
    and may not read is a PermissionError out of a hash. Nothing calls this
    today, which is why the rule matters rather than why it does not - a
    link-following walk in the module whose whole rule is that nothing found
    on a Destination is followed (ADR-0009) gets adopted eventually, and the
    two walks it would be adopted alongside already say `not p.is_symlink()`.
    """
    root = pathlib.Path(root)
    pairs = sorted(
        (p.relative_to(root).as_posix(),
         hashlib.sha256(p.read_bytes()).hexdigest())
        for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    digest = hashlib.sha256()
    for rel, file_hash in pairs:
        # NUL cannot occur in a path, so the encoding is unambiguous.
        digest.update(rel.encode("utf-8") + b"\0" + file_hash.encode() + b"\n")
    return digest.hexdigest()


def needs_push(index: dict, uuid: str, tree_hash: str) -> bool:
    """True unless the Archive already holds this Session at this tree_hash."""
    entry = index.get("sessions", {}).get(uuid)
    return entry is None or entry.get("tree_hash") != tree_hash

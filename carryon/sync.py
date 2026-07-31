"""init, push, pull, pair - the orchestration that moves a Snapshot.

This module exists so the two halves of a Snapshot stay distinct all the way
to the Destination: a Setup goes through the existing fail-closed capture
engine and lands as a plaintext tree, a History goes through
discover/pack/encrypt and lands as one object per Session (ADR-0003), and
only this file sequences the two. The one non-obvious decision: the capture
engine reads the shared adapter registry as a module global, so push swaps
the registry's *contents* in place - excludes applied, handpicked paths added
(ADR-0008) - for the duration of the capture. `capture` and `is_installed`
alias the same dict, so mutating it is the one change both see, and the
engine keeps its promise of never learning about any particular caller.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import pathlib
import re
import secrets as stdlib_secrets  # carryon.secrets is the scanner, not this
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import NamedTuple

from . import (archive, capture, config, crypto, destinations, external,
               history, keyring, rekey, restore)
from .adapters import ADAPTERS, CATEGORIES, HISTORY, SETUP_CATEGORIES
from .destinations.base import join_prefix, printable, require_key

PAIRING_TTL_SECONDS = 24 * 3600


# --- shared helpers ----------------------------------------------------------


def _utc_now() -> str:
    return (datetime.now(timezone.utc).isoformat(timespec="seconds")
            .replace("+00:00", "Z"))


def _subset(value, known, label):
    """A comma-separated flag value as a validated set, or None for 'all'."""
    if not value:
        return None
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    unknown = chosen - set(known)
    if unknown:
        raise SystemExit(
            f"unknown {label}: {', '.join(sorted(unknown))}\n"
            f"known {label}s: {', '.join(known)}")
    return chosen


# A pairing code has two halves that never mix. Six characters name the
# object in the Archive and are not a secret; ten characters wrap the master
# key and are never written down anywhere. 32 unambiguous characters, 5 bits
# each: 30 bits of public locator, 50 bits behind PBKDF2 at 600,000
# iterations - roughly 1.3e21 SHA-256 compressions to search, about 2000
# GPU-years. The whole code used to be 40 bits AND its sha256 was the object
# name, which put the guard at 55 GPU-seconds.
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"  # no I, L, O or U
LOCATOR_CHARS = 6
SECRET_CHARS = 10
CODE_CHARS = LOCATOR_CHARS + SECRET_CHARS
CODE_DISPLAY = "-".join(["XXXX"] * (CODE_CHARS // 4))

# What a hurried reader turns into what: the alphabet omits these, so a code
# containing one was mistyped in a direction we can undo.
_AMBIGUOUS = {"I": "1", "L": "1", "O": "0"}


class PairingCode(NamedTuple):
    """The two halves, kept apart by type so neither can be used as the other.

    locator names the object on the Destination and is published there;
    secret is the only thing ever handed to the key-wrapping KDF.
    """
    locator: str
    secret: str


def _canon_code(code: str) -> str:
    stripped = "".join(code.split()).replace("-", "").upper()
    return "".join(_AMBIGUOUS.get(c, c) for c in stripped)


def parse_pairing_code(code: str) -> PairingCode:
    """A typed pairing code split into its locator and secret halves.

    Tolerant of case, hyphens, spacing and the characters people substitute
    for the ones the alphabet leaves out; strict about everything else, so a
    mangled code fails here with an explanation instead of reaching the
    Destination and failing as 'no pairing blob'."""
    canon = _canon_code(code)
    if len(canon) != CODE_CHARS or not set(canon) <= set(PAIR_ALPHABET):
        raise SystemExit(
            f"{code!r} is not a pairing code: {CODE_CHARS} characters shown "
            f"as {CODE_DISPLAY}, letters and digits only (I, L, O and U never "
            "appear - a typed I or L reads as 1, a typed O as 0)")
    return PairingCode(canon[:LOCATOR_CHARS], canon[LOCATOR_CHARS:])


def new_pairing_code() -> str:
    """A fresh code for display, in groups of four.

    Every character is drawn on its own, so the locator half carries no
    information about the secret half: an attacker reading the object's name
    off the Destination learns the six characters that name it and nothing
    that shortens the search for the other ten."""
    raw = "".join(stdlib_secrets.choice(PAIR_ALPHABET)
                  for _ in range(CODE_CHARS))
    return "-".join(raw[i:i + 4] for i in range(0, CODE_CHARS, 4))


def _home_forms(home) -> list:
    """Every spelling of this machine's home a captured value may carry.

    rekey owns the rule; this is here so the Setup half spells it the same
    way. The two did drift - the History half knew one spelling and turned a
    Transcript's '/private/var/.../home' into '/private~/...' - which is why
    the definition lives in one place now rather than two that agree by
    review.
    """
    return rekey.home_forms(home)


def _canon_home(value, home):
    """A single value in the Archive's machine-neutral form (ADR-0006).

    Every occurrence, not just a leading one: rekey.canonicalise_text rewrites
    the home wherever it sits in a value, because paths turn up in running
    prose as often as in fields. Two rewriters promising different things is
    how a leak survives the fix for it.
    """
    if value is None:
        return None
    for form in _home_forms(home):
        if value == form:
            return rekey.HOME_TOKEN
        value = value.replace(form, rekey.HOME_TOKEN)
    return value


def _home_near_misses(text: str, home) -> int:
    """Hits that match the home case-insensitively only.

    ADR-0006 never folds case when rewriting - on a case-sensitive filesystem
    two spellings are two directories - so these are counted and reported
    rather than rewritten. rekey owns the counting rule; a second copy of it
    here would drift from the one the History half reports.
    """
    return sum(rekey._near_misses(text, form) for form in _home_forms(home))


@contextlib.contextmanager
def _swapped_registry(effective: dict):
    saved = dict(ADAPTERS)
    ADAPTERS.clear()
    ADAPTERS.update(effective)
    try:
        yield
    finally:
        ADAPTERS.clear()
        ADAPTERS.update(saved)


def _effective_adapters(cfg: dict, home) -> dict:
    filtered, unmatched = config.apply_excludes(ADAPTERS, cfg["excludes"])
    for pattern in unmatched:
        print(f"note: exclude pattern {pattern!r} matched nothing")
    user = config.user_adapter(cfg, home)
    if user.items:
        filtered[user.key] = user
    return filtered


def _open_destination(home):
    cfg = config.load(home)
    if not cfg["destination"]:
        raise SystemExit(
            "no Destination configured - run `carryon init --dest SPEC` first")
    return cfg, destinations.from_spec(cfg["destination"], home)


def _require_master(home) -> bytes:
    master = keyring.fetch_master(home=home)
    if master is None:
        raise SystemExit(
            "this machine holds no master key - run `carryon init`, or "
            "`carryon init --join CODE --dest SPEC` with a code from "
            "`carryon pair` on an already-paired machine")
    return master


def _rel_to_home(path, home) -> str:
    try:
        return pathlib.Path(path).relative_to(home).as_posix()
    except ValueError:
        return str(path)


# --- the Archive's revision, as this machine has seen it ---------------------
#
# An Index served from an old copy is authentic - a master key holder sealed
# it - so no amount of crypto tells it from the current one. What a Destination
# cannot rewrite is what this machine already saw, so that number lives here.


def _state_path(home) -> pathlib.Path:
    return pathlib.Path(home) / ".carryon" / "state.json"


# Said once per file rather than once per read. The mark is read three or
# four times in one command - the removal question, the rollback question and
# the write that raises it - and four copies of one line is how a user learns
# to skip the line, which is the same objection _seen_revision already records
# against a rollback signal that cries wolf.
#
# Cleared as each command starts (_begin_command), because "once" means once
# per command and this set outlives one: a second pull in the same interpreter
# - the suite, or any future in-process loop - dropped the line entirely, and
# the set grew without bound besides.
_STATE_REPORTED = set()


def _begin_command() -> None:
    """Reset what is said once per command. One line today; the point is that
    module-level state used for de-duplication has an owner that clears it."""
    _STATE_REPORTED.clear()


def _no_state(path, why: str) -> dict:
    """Nothing seen yet, and one line saying why the mark could not say so."""
    if str(path) not in _STATE_REPORTED:
        _STATE_REPORTED.add(str(path))
        print(f"warning: carryon would not read {path} - {why}. carryon "
              "notices a deleted or rolled-back Index by comparing against "
              "the revision recorded there, so this machine has less to check "
              "the Destination against until the file is repaired or "
              "removed.")
    return {}


def _load_state(home) -> dict:
    """This machine's own notes about the Archive. Never a gate: unreadable
    or malformed state means 'nothing seen yet', not a refused pull.

    Never a gate, and never silent either. A mark that cannot be read is the
    same weakening _record_revision warns about when it cannot be written -
    the next pull notices one rollback less - so it says so and answers zero,
    rather than either raising or going quiet about a check that has just got
    weaker.

    Which of those two it is, this function no longer decides for itself.
    `config.read_state_json` is the one place carryon's own files turn into
    documents, and this leg had its own spelling of that read for one reason -
    the file is carryon's own rather than a user's - which is the same reason
    the Destination layer was trusted before ADR-0009 and is no better here.
    Two spellings of one question is what this cost: the decode error sat in
    the guard around the PARSE while the read was guarded for OSError only, so
    a state.json that is not UTF-8 - a truncated write, a synced folder's
    conflict copy, a restored backup, all of them ordinary and none of them an
    attacker - was a bare UnicodeDecodeError out of both `push` and `pull`,
    the two commands users actually run. A named pipe at the name blocked the
    read for ever, which is worse: nothing to read and nothing to report.

    The one thing this leg still decides is what a refusal MEANS here, and it
    is the opposite of what it means for the config: a mark that will not read
    is a warning and a zero, because the mark exists to make carryon notice
    more and must never become a way to stop a machine working.
    """
    path = _state_path(home)
    state = config.read_state_json(path)
    if state.absent:
        return {}  # nothing seen yet, and nothing wrong with that
    if state.why is not None:
        return _no_state(path, state.why)
    return state.value


def _seen_revision(home, spec: str) -> int:
    """The highest revision this machine has seen at THIS Destination.

    Per Destination, not per machine: one global number cries "rolled back"
    at a brand-new Archive the moment a home is pointed somewhere else, and a
    rollback signal users learn to skip is worse than none.
    """
    marks = _load_state(home).get("destinations")
    entry = marks.get(spec) if isinstance(marks, dict) else None
    value = entry.get("index_revision", 0) if isinstance(entry, dict) else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _record_revision(home, spec: str, revision: int) -> None:
    """Raise the high-water mark; never lower it, which is the whole point.

    The write is guarded because this mark is now load-bearing enough - it
    decides a removal, a rollback and which Setups may be restored - that a
    full or read-only $HOME turning a pull into a traceback would be the
    guard's own doing, before the report and after the History has landed. A
    mark that cannot be written is a warning: the next pull will read a lower
    number and notice one rollback less, which is a weaker check and not a
    wrong answer.
    """
    if revision <= _seen_revision(home, spec):
        return
    state = _load_state(home)
    marks = state.get("destinations")
    if not isinstance(marks, dict):
        marks = {}
    marks[spec] = {"index_revision": revision}
    state["destinations"] = marks
    path = _state_path(home)
    try:
        # The third file in ~/.carryon and the third plain write, refused
        # through a link like the two beside it (ADR-0007): a mark written
        # into somebody's dotfiles repo is a mark this machine does not have.
        config.write_state_file(
            path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    except (OSError, SystemExit) as exc:
        # SystemExit as well as OSError, and it stays a warning either way:
        # the mark is never a gate. A refusal here costs one check on the next
        # run, where a raise would cost the Snapshot this run is pushing.
        print(f"warning: could not record the Archive's revision at {path} "
              f"({getattr(exc, 'strerror', None) or exc}). carryon notices a "
              "deleted or rolled-back Index by comparing against that number, "
              "so until it can be written this machine has less to check the "
              "Destination against.")


def _rollback_note(home, spec: str, index: dict):
    """How far the Archive has gone backwards, as prose, or None."""
    seen = _seen_revision(home, spec)
    now = archive.index_revision(index)
    if not seen or now >= seen:
        return None
    return (f"the Archive's Index is at revision {now}, but this machine has "
            f"already seen revision {seen}. An Index only moves forward, so "
            "this one has been rolled back - an old copy restored, a revert, "
            "or a Destination serving what it likes. Anything pushed after "
            f"revision {now} is missing from it.")


def _index_removed_note(home, spec: str, index: dict):
    """Why the Archive's Index is gone rather than never written, or None.

    Nothing a Destination serves tells the two apart - archive.load_index
    says why, and ADR-0004's keyless Archive is the case that makes it
    genuinely undecidable there - so the evidence is local, and there is
    exactly one piece of it: this machine has read an Index at this
    Destination before. That is the number the rollback high-water mark
    already holds, put to a second question, and it is written at every
    moment this machine could have learnt the fact - a push, a pull, and the
    pairing that handed it the master key, which carries the revision inside
    the wrap so that a machine which has never pulled still holds it.

    It is the one statement about this Archive an attacker with write access
    to the Destination cannot compose: they can delete every object under
    carryon/, and none of that reaches $HOME.
    """
    if not archive.index_is_absent(index):
        return None
    seen = _seen_revision(home, spec)
    if not seen:
        return None
    return (
        f"the Archive serves no Index at {archive.INDEX_KEY}, and this "
        f"machine has already read one there at revision {seen}. Only a "
        "master key holder can write that object, so it has been deleted at "
        "the Destination - and with it the record of which machines' Setups "
        "are authenticated, which is the whole of what a stored Setup is "
        "checked against (ADR-0004). Every Setup in the Archive now reads as "
        "a keyless push nothing can verify, which is exactly what deleting "
        "it buys.")


def _refuse_on_index_removal(home, spec: str, index: dict, verb: str) -> None:
    """Stop, on either leg, when the Index has been removed since this
    machine last looked.

    Both legs and the dry run too, unlike a rollback, which pull only warns
    about: a rollback hides Sessions and carryon cannot tell a hostile replay
    from a git revert, so refusing there would strand a user whose Destination
    really did lose a write. A removal costs them nothing to refuse - the
    catalogue is the only route to a stored Session, so there is no History
    left to restore either way, and the only thing a pull could still lay
    down is a Setup that nothing vouches for. That leaves the plan a dry run
    would print as untrustworthy as the writes an --apply would make.
    """
    note = _index_removed_note(home, spec, index)
    if note is None:
        return
    raise SystemExit(
        f"refusing to {verb}: {note}\nRestore an earlier copy of the Archive "
        "(a git Destination keeps one in its history) and this machine "
        "carries on where it left off. Pushing from another machine will not "
        "rebuild it: the objects under carryon/sessions/ are named by an "
        "HMAC, and the Index was the only record of which Session each one "
        "is. So if the Archive really was emptied on purpose, accept the "
        f"loss deliberately - drop this Destination's entry from "
        f"{_state_path(home)}, and push afresh.")


def _warn_on_rollback(home, spec: str, index: dict) -> None:
    """Say so when the Archive has gone backwards - and carry on.

    A warning is the whole behaviour on the READ path. An old Index hides
    every Session pushed since it was written, but carryon cannot tell a
    hostile replay from a git revert or a synced folder restored from backup,
    and refusing would strand the user in the case where the Destination
    really did lose a write. push is the other case entirely - see
    _refuse_on_rollback.
    """
    note = _rollback_note(home, spec, index)
    if note:
        print(f"warning: {note} Anything pushed after it will look absent "
              "here.\n")


def _refuse_on_rollback(home, spec: str, index: dict) -> None:
    """Refuse to push onto an Index this machine has already seen past.

    A pull against a stale Index hides Sessions; a push against one destroys
    them. The stale catalogue is re-sealed as the current one, and every
    Session another machine pushed since is unlinked from it - along with
    that machine's entry in index['setups'], the one field _setup_catalogue
    cannot have been forged. There is nothing to merge against, because the
    Index the other machine wrote is exactly what went missing, so this fails
    closed and names the escape hatch instead of guessing.
    """
    note = _rollback_note(home, spec, index)
    if note:
        raise SystemExit(
            f"refusing to push: {note}\nPushing now would re-seal that "
            "catalogue as the current one and unlink every Session pushed "
            "since. Sort the Destination out first - restore the newer "
            f"Index, or if the rollback was deliberate, drop this "
            f"Destination's entry from {_state_path(home)} to accept it.")


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



def _print_rekey_notes(near: int, bare: int, non_utf8: int) -> None:
    """The Re-keying counts the design says are reported, never acted on."""
    if near:
        print(f"Re-keying: {near} near-miss(es) - a path matched the home "
              "case-insensitively only; left alone, never rewritten (ADR-0006)")
    if non_utf8:
        print(f"Re-keying: {non_utf8} member(s) not UTF-8 - carried "
              "unchanged, paths inside them untouched")
    if bare:
        print(f"Re-keying: {bare} bare '~' token(s) - a home occurrence with "
              "nothing after it; expansion leaves these standing")


# --- init --------------------------------------------------------------------


def init(args, home) -> int:
    home = pathlib.Path(home)
    if keyring.fetch_master(home=home) is not None:
        raise SystemExit(
            "this machine already holds a master key - it already opens an "
            "Archive. Remove it deliberately (keychain service 'carryon') "
            "before running init again.")

    machine = args.machine or config.default_config()["machine"]
    why = config.machine_name_refusal(machine)
    if why is not None:
        # Here rather than at `config.save`, which is where `validate` would
        # have caught it: by then this leg has minted and stored a master key
        # (so a second `init` refuses, saying this machine already holds one)
        # and the join leg has already DELETED the pairing blob, which is
        # one-time by design (ADR-0005). A refused name must cost neither.
        raise SystemExit(
            f"machine name {printable(machine)!r}: {why}."
            + ("" if args.machine else
               " That is this machine's hostname; name it explicitly with "
               "`carryon init --machine NAME`."))

    if args.join:
        return _join(args, home, machine)

    spec = args.dest
    if not spec:
        candidates = destinations.detect_candidates(home)
        usable = [c for c in candidates if "<" not in c[0]]
        if len(usable) == 1:
            spec, label = usable[0]
            print(f"one Destination found: {label} ({spec}) - using it; "
                  "pass --dest to choose differently")
        else:
            lines = [f"  {s:<44} {label}" for s, label in candidates]
            listing = "\n".join(lines) if lines else "  (none found)"
            raise SystemExit(
                "pick a Destination with --dest SPEC. Candidates on this "
                "machine:\n" + listing
                + f"\nA spec is {destinations.SPEC_FORMS}.")
    dest = destinations.from_spec(spec, home)  # validates the spec early

    display, master = crypto.new_recovery_key()
    keyring.store_master(master, home=home)
    cfg = config.default_config()
    cfg["destination"] = spec
    cfg["machine"] = machine
    path = config.save(cfg, home)

    print(f"initialised: machine {machine!r}, Destination {dest.describe()}")
    print(f"config written to {path}")
    print()
    print("Your recovery key - shown once, never stored by carryon:")
    print()
    print(f"    {display}")
    print()
    print("Put it in your password manager now. It is the only way back into")
    print("the Archive if this machine's keychain is lost; there is no reset.")
    return 0


def _pairing_payload(raw: bytes) -> dict:
    """A pairing payload, having proved it is one. SystemExit if it is not.

    The pairing blob is the one Archive object with no MAC - the machine
    reading it holds no master key yet - and AES-CBC is malleable, so a byte
    flipped anywhere but the last block leaves the PKCS#7 padding intact and
    openssl exits 0 over garbage. An exit code is therefore not proof the
    code opened the blob; a payload that parses and carries a 32-byte key is
    the strongest proof available, and it has to be had BEFORE the one-time
    delete, or tampering burns the code that would have worked.

    The message names a wrong code first because that is what usually lands
    here. Padding validates by luck for about one wrong code in 256, so this
    is the ordinary mistyped-code path often enough to matter, and the two
    causes are genuinely indistinguishable from inside: nothing carryon can
    check tells a wrong key from an edited blob when neither is authenticated.
    Reporting only the rarer one sent a user hunting for tampering that had
    not happened.

    Everything the caller will act on is proved here, before the one-time
    delete, and the creation time is part of that. It used to be read one
    line AFTER the delete with a bare float(), so a payload carrying no
    created_at, or one that is not a number, burnt the object and then raised
    ValueError or TypeError out of `carryon init --join` - the precise
    outcome the read/delete split exists to prevent, arrived at by the field
    the split does not cover. NaN is asked about too, and is the reason the
    test is 'finite' rather than 'a number': json.loads parses NaN happily, it
    survives float(), and it loses every comparison it takes part in, so
    `now - created_at > TTL` is False forever and a pairing code's 24-hour
    life quietly becomes unlimited.

    RecursionError joins the parse guard for the reason it joins every other
    one in carryon: json.loads answers nesting past the interpreter's limit
    with a RuntimeError, which a guard naming ValueError and UnicodeDecodeError
    walks straight past. Reaching it needs the pairing secret, so this is the
    same corruption-or-skew class as a damaged Archive object rather than an
    attack - and it takes the same named refusal.
    """
    tampered = SystemExit(
        "that pairing blob did not open into a pairing payload. Most likely "
        "it is a wrong or expired code that openssl happened not to reject: "
        "a pairing blob carries no authentication tag (the joining machine "
        "has no key to check one with), so roughly one wrong code in 256 "
        "gets this far. Failing that, the blob was tampered with or written "
        "by something other than carryon. It was left in place either way; "
        "mint a fresh code with `carryon pair`, and delete the old object if "
        "it stays broken.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise tampered
    if not isinstance(payload, dict):
        raise tampered
    try:
        master = bytes.fromhex(payload["master"])
    except (KeyError, TypeError, ValueError):
        raise tampered
    if len(master) != crypto.MASTER_BYTES:
        raise tampered
    payload["master_key"] = master
    created = payload.get("created_at")
    if (isinstance(created, bool) or not isinstance(created, (int, float))
            or not math.isfinite(created)):
        raise tampered
    payload["created_at"] = float(created)
    # The revision the pairing machine read, if this payload carries one.
    # Absent or nonsensical reads as 'nothing known about this Archive'
    # rather than a refusal: a pairing's job is to hand over the key, and a
    # payload written by a carryon that predates the field is not a reason to
    # leave a machine unable to join. What it costs is the freshness the
    # joining machine would otherwise start with - see pair().
    revision = payload.get("index_revision", 0)
    if (isinstance(revision, bool) or not isinstance(revision, int)
            or revision < 0):
        revision = 0
    payload["index_revision"] = revision
    return payload


def _join(args, home, machine) -> int:
    if not args.dest:
        raise SystemExit(
            "--join needs --dest: a pairing code travels through the "
            "Destination (ADR-0005), so name the same one the paired "
            "machine uses")
    code = parse_pairing_code(args.join)
    dest = destinations.from_spec(args.dest, home)

    # Read and delete are two steps, deliberately: the blob must survive a
    # failed unwrap AND a tampered payload, so the one-time delete happens
    # below, only once _pairing_payload has proved the code opened it.
    key = archive.pairing_key(code.locator)
    blob = dest.read(key)
    if blob is None:
        if not dest.list(archive.PREFIX + "/"):
            raise SystemExit(
                f"no Archive at {args.dest!r} - carryon found nothing "
                "there at all. Check the spec against the one `carryon "
                "pair` printed on the paired machine; a synced folder may "
                "also still be syncing.")
        raise SystemExit(
            "no pairing blob for that code - mistyped, already used, or "
            "never minted. Run `carryon pair` on a paired machine for a "
            "fresh one.")
    try:
        raw = crypto.unwrap_key(blob, code.secret)
    except crypto.CryptoError:
        # Deliberately not deleted, and this is now the ordinary case for a
        # typo: the locator half still names the real blob, so burning it on
        # a failed unwrap would cost the user the code that works.
        raise SystemExit(
            "wrong or expired code - the pairing blob would not unwrap "
            "under it. The blob was left in place, so the right code still "
            "works; mint a fresh one with `carryon pair` if in doubt.")
    payload = _pairing_payload(raw)
    # One-time (ADR-0005): burnt on first successful read. `delete` answers
    # whether the store really stopped serving it, because on a Destination
    # whose verbs are another program's exit code it can report a delete it
    # did not make - and "burnt" is the whole of the one-time property. This
    # machine has performed no write at this point, so nothing upstream could
    # have noticed. Said here rather than left to the report line the layer
    # already prints, because what it MEANS is this leg's: the code the user
    # is holding still opens the Archive.
    burnt = dest.delete(key)
    # created_at is a finite float by now, checked above the delete: an
    # expired code is a real code and is burnt, a payload carryon did not
    # write is refused and left in place.
    if time.time() - payload["created_at"] > PAIRING_TTL_SECONDS:
        raise SystemExit(
            "that pairing code expired (codes live 24 hours) and has now "
            "been deleted - mint a fresh one with `carryon pair`")

    keyring.store_master(payload["master_key"], home=home)
    cfg = config.default_config()
    cfg["destination"] = args.dest
    cfg["machine"] = machine
    config.save(cfg, home)
    # What this machine knows about the Archive before it has ever read it:
    # the revision the pairing machine saw. It arrived inside the wrap, so
    # the Destination could not have written it, and from here on an Archive
    # serving no Index is a removal rather than a fresh one (ADR-0009).
    _record_revision(home, args.dest, payload["index_revision"])
    print(f"paired as {machine!r}: this machine now opens the Archive at "
          f"{dest.describe()}")
    if not burnt:
        print(f"warning: the pairing blob at {printable(key)} is still in the "
              "Archive, so that code is STILL LIVE until it expires (24 "
              "hours) and anyone who has seen it can join with it. Remove "
              "that object by hand, or treat the code as known.")
    return 0


# --- push --------------------------------------------------------------------


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


# What a MANIFEST holds at the top level. A stored one can hold anything -
# the file is plaintext on untrusted storage - and a partial push writes its
# merge back into the Archive, so a key the capture engine never produces is
# dropped here rather than accumulated, signed and served on.
_MANIFEST_FIELDS = ("tool", "version", "captured_at", "source_home",
                    "categories", "scope", "agents")


def _renderable(value) -> bool:
    """Whether every string anywhere inside `value` can be written to a file.

    A partial push re-renders RESTORE.md out of the merged MANIFEST, and
    write_text encodes strictly - so a lone surrogate, which is legal in JSON
    and legal in a Python str, is a UnicodeEncodeError at the write. It
    reaches here as pure ASCII on the Destination ('\\ud800' is six ordinary
    characters in a JSON file) and every guard between there and the write
    asks isinstance(x, str), which it answers yes to.

    NOT config.spellable, which is the same question about a different
    destination: that one encodes with surrogateescape because it is asking
    whether a syscall will look at a path, and surrogateescape accepts the
    \\udc80-\\udcff range by design. This asks whether the string can be
    written into a document, and the answer there is strict UTF-8 or nothing.

    Iterative rather than recursive because the document is untrusted and
    arbitrarily deep: json.loads has already refused anything past the
    recursion limit (_JSON_REFUSALS), and a checker that added its own frames
    on top of a document that only just parsed would be a second limit, hit
    later and reported worse.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return True


def _carryable_item(raw):
    """One stored item, or None when it is not one this carryon would have
    written. Fields it does not know ride along untouched - so the whole item
    is asked the renderability question, not just the three named fields."""
    if not isinstance(raw, dict):
        return None
    if not all(isinstance(raw.get(field), str)
               for field in ("src", "dst", "kind")):
        return None
    if not isinstance(raw.get("carried", []), list):
        return None
    if not isinstance(raw.get("external", {}), dict):
        return None
    if not _renderable(raw):
        return None
    return raw


def _carryable_agent(raw):
    """A stored agent entry with the fields a MANIFEST is rendered from made
    recognisable, or None when it is not an entry at all.

    A partial push carries forward agents it did not capture, and the keyless
    path (ADR-0004) has no tag to check them against, so their shape is
    checked rather than assumed. restore.build_restore subscripts
    agent['excluded'], agent['items'] and each item's 'kind', 'dst' and 'src'
    with no guard at all, so one key left out of a planted entry was a
    KeyError straight out of `carryon push --category` - a traceback where
    ADR-0009 asks for a sentence, from a document the Destination authored.

    "Recognisable" now includes writable-back-out. Every check here was an
    isinstance against str, and a string is not the same thing as a string
    this machine can put in a file: the same push that could not subscript a
    missing key could not encode a lone surrogate either, and the second one
    survived the fix for the first. The whole entry is asked, once, after the
    per-field repairs - fields this carryon does not know ride along into the
    document, so they have to be able to ride along out of it.
    """
    if not isinstance(raw, dict):
        return None
    agent = dict(raw)
    if not isinstance(agent.get("name"), str):
        agent["name"] = "(a stored entry naming no agent)"
    items = agent.get("items")
    agent["items"] = ([i for i in items if _carryable_item(i) is not None]
                      if isinstance(items, list) else [])
    excluded = agent.get("excluded")
    agent["excluded"] = ([e for e in excluded
                          if isinstance(e, dict)
                          and all(isinstance(e.get(f), str)
                                  for f in ("path", "what", "why"))]
                         if isinstance(excluded, list) else [])
    if not _renderable(agent):
        return None
    return agent


def _merge_setup_manifest(stored: dict, fresh: dict, pushed_categories,
                          dropped=None) -> dict:
    """The stored MANIFEST with a freshly captured slice layered in.

    Per agent, fresh items replace stored items in the pushed categories only;
    agents not captured this time (absent here, or filtered by --agent) carry
    over. This matters because pull restores a Setup solely from what the
    MANIFEST names: overlaying the files while writing the partial capture's
    manifest as-is would silently drop every unselected item from all
    subsequent pulls until the next full push.

    Nothing is taken from `stored` unchecked, because `stored` came back from
    the Destination and is the attacker's to author (ADR-0009). It used to
    start from dict(stored), which carried every top-level key and every
    uncaptured agent whole into a document the key holder then signed. What
    survives now is a field this carryon writes, holding a shape this carryon
    produces: a set union over the integer 7 raised TypeError, sorting
    categories mixed with non-strings raised another, and an agent missing a
    key was a KeyError out of the renderer - none of them a shape to repair,
    all of them a shape to ignore.

    `dropped` collects a sentence per stored entry ignored, because ignoring
    one is not nothing: pull restores a Setup solely from what the MANIFEST
    names, so an agent dropped here is an agent no later pull lays down. It
    was a silent decision and the report the caller prints is the whole of
    the difference between a partial push that declined something and one
    that is mysteriously short an agent."""
    if dropped is None:
        dropped = []
    merged = {key: value for key, value in stored.items()
              if key in _MANIFEST_FIELDS and _renderable(value)}
    for key in ("tool", "version", "captured_at", "source_home", "scope"):
        if key in fresh:
            merged[key] = fresh[key]
    known = stored.get("categories")
    merged["categories"] = sorted(
        {c for c in (known if isinstance(known, list) else [])
         if isinstance(c, str) and _renderable(c)}
        | {c for c in fresh.get("categories", []) if isinstance(c, str)})
    stored_agents = stored.get("agents")
    agents = {}
    if isinstance(stored_agents, dict):
        for key, stored_agent in stored_agents.items():
            name = printable(str(key))
            if not isinstance(key, str) or not _renderable(key):
                dropped.append(
                    f"the stored agent keyed {name} is not named by anything "
                    "this machine can write back out")
                continue
            agent = _carryable_agent(stored_agent)
            if agent is None:
                dropped.append(
                    f"stored agent {name} is not an entry this carryon could "
                    "write back out, so it is not carried into the merged "
                    "MANIFEST and no later pull will restore it")
                continue
            was = stored_agent.get("items")
            lost = (len(was) - len(agent["items"])
                    if isinstance(was, list) else 0)
            if lost:
                dropped.append(
                    f"stored agent {name} carried {lost} item(s) this "
                    "carryon could not write back out; the rest of the entry "
                    "is merged as usual")
            agents[key] = agent
    for key, fresh_agent in fresh.get("agents", {}).items():
        stored_agent = agents.get(key)
        if stored_agent is None:
            agents[key] = fresh_agent
            continue
        kept = [item for item in stored_agent["items"]
                if item.get("category") not in pushed_categories]
        replacement = dict(fresh_agent)
        replacement["items"] = kept + list(fresh_agent.get("items", []))
        agents[key] = replacement
    merged["agents"] = agents
    return merged


# Anything still shaped like a filesystem root after the home has been
# rewritten names some directory on this machine - a team share, a volume, a
# case-variant home resolve() would not normalise. An Archive names no
# machine, so those are withheld rather than published.
_ABSOLUTE = re.compile(r"^(?:/|\\\\|[A-Za-z]:[\\/])")
WITHHELD = "(withheld: a path on the machine this Setup came from)"


def _neutralise_manifest(manifest: dict, home) -> tuple:
    """(manifest, withheld): a MANIFEST with no local path left in it.

    The guarantee is per string value, not per field: the capture engine
    records the home it read from *and* the resolved target of every
    externally owned skill symlink - a dotfiles repo, typically - and an
    adapter or item kind added later can record another without anyone
    revisiting this function. That is right for a local `carryon capture`
    directory and wrong for the Archive, which is machine-neutral by ADR-0006
    and whose setups/ tree is its one plaintext half.

    Two steps, because rewriting alone cannot cover the second: a value under
    the home becomes '~', and a value that is still absolute afterwards is
    withheld. That closes the cases a rewrite has to leave alone - a target
    outside $HOME entirely, and a spelling of the home that differs only by
    case, which ADR-0006 forbids folding.
    """
    # rekey._walk is the recursion canonicalise_jsonl already runs over a
    # parsed Transcript line: string values only, keys untouched (ADR-0006).
    # Reaching for a private helper beats a third path-rewriter that would
    # then have to be kept in step with the other two.
    withheld = []

    def canon(value: str) -> tuple:
        new = _canon_home(value, home)
        if _ABSOLUTE.match(new):
            withheld.append(new)
            new = WITHHELD
        return new, new != value, 0

    neutral, _, _ = rekey._walk(manifest, canon)
    return neutral, len(withheld)


def _neutralise_staged_setup(staging, manifest: dict, home) -> tuple:
    """The whole staged Setup made machine-neutral.
    (manifest, withheld, near, undecodable).

    Not just the two files carryon generates: a Setup carries the CONTENT of
    settings.json, CLAUDE.md and every skill, and a hook command or an
    instruction line spells the home out as readily as a manifest field does.
    CONTEXT.md's promise - what sits in the Archive does not mention your
    laptop's home at all - is a whole-tree promise, and re-keying the Setup
    the way ADR-0006 already re-keys a History is also what makes a restored
    hook path work on a machine whose home is somewhere else.

    RESTORE.md is re-rendered from the neutralised MANIFEST rather than
    scrubbed on its own. It is a rendering of that MANIFEST, and the two being
    written from different sources is exactly how resolved symlink targets
    reached a Destination while this was reported closed.

    A file that does not decode as UTF-8 is withheld and named, not carried.
    This used to be a skip, justified in a comment by images in a skill - but
    it was decided by the decoder rather than by intent, so it also covered
    every latin-1 note, every truncated log and every file with one stray
    byte in it, any of which can spell the home out and did travel verbatim
    into the one plaintext half of the Archive. Nothing here can tell a PNG
    from a note, and a Setup that names this machine is what ADR-0006 rules
    out, so the file stays here and the push report names it. Deleting it
    from the staging tree is what withholds it: a full push mirrors that tree
    onto the Archive, so one also clears a file an earlier version published.
    """
    staging = pathlib.Path(staging)
    generated = {staging / "MANIFEST.json", staging / "RESTORE.md"}
    near = 0
    undecodable = []
    for path in sorted(p for p in staging.rglob("*")
                       if p.is_file() and not p.is_symlink()):
        if path in generated:
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            undecodable.append(path.relative_to(staging).as_posix())
            path.unlink()
            continue
        near += _home_near_misses(text, home)
        neutral_text = _canon_home(text, home)
        if neutral_text != text:
            path.write_bytes(neutral_text.encode("utf-8"))

    neutral, withheld = _neutralise_manifest(manifest, home)
    path = staging / "MANIFEST.json"
    if path.is_file():
        path.write_text(json.dumps(neutral, indent=2))
        (staging / "RESTORE.md").write_text(restore.build_restore(neutral))
    return neutral, withheld, near, undecodable


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


def _push_partial_setup(dest, master, machine, staging, manifest,
                        pushed_categories, withheld=(),
                        index_entry=None, pushed_at="",
                        stamp="") -> None:
    """Overlay a partial capture onto the Archive's Setup, MANIFEST included.

    Files not selected this time survive because an overlay never deletes;
    the MANIFEST and RESTORE.md are regenerated from the merged view so they
    keep describing the whole stored tree, not just this push's slice.

    Withheld files are the one thing an overlay does delete, and that is the
    point: withholding is done by removing the file from the staging tree,
    which only a FULL push turns into a deletion in the Archive (put_setup
    sweeps stale keys). On a partial push the file an earlier version
    published stayed there, with the source machine's home inside it, while
    the report said it had not gone - so the deletion is spelled out here
    rather than left to the mirror that does not run.

    With a master key the overlay is authenticated: the new SETUP.mac joins
    fresh hashes for this push's slice onto the entries the previous verified
    manifest vouched for, minus the withheld. The carry-forward is resolved -
    and the stored MANIFEST proved to be the one it vouches for - BEFORE a
    byte is written, so either refusal leaves the Archive untouched.

    What the merge could not carry is printed rather than raised. The keyless
    path (ADR-0004) is the one that meets an attacker-authored MANIFEST with
    nothing to check it against, and stopping there would hand anyone with
    write access to the Destination a permanent `push --category config` on
    every keyless machine - so the entry is dropped, named, and the rest of
    the push carries on. A stored document that will not PARSE is still a
    stop one function up, because there is no rest of the push to carry on
    with: the merge would be built from nothing.
    """
    prefix = archive.setup_prefix(machine)
    raw = dest.read(prefix + "/MANIFEST.json")
    carried = {}
    if master is not None:
        carried = _carried_setup_files(dest, master, machine, prefix,
                                       index_entry or {})
        _vouch_for_stored_manifest(raw, carried, prefix)
    stored = _stored_setup_manifest(raw, prefix)
    staging = pathlib.Path(staging)
    if stored is not None:
        dropped = []
        merged = _merge_setup_manifest(stored, manifest, pushed_categories,
                                       dropped)
        for why in dropped:
            print(f"  drop     {printable(prefix)}/MANIFEST.json - {why}")
        (staging / "MANIFEST.json").write_text(json.dumps(merged, indent=2))
        (staging / "RESTORE.md").write_text(restore.build_restore(merged))
    if master is not None:
        files = dict(carried)
        files.update(archive.setup_tree_manifest(staging))
        for rel in withheld:
            files.pop(rel, None)
        (staging / archive.SETUP_MAC_NAME).write_bytes(
            archive.seal_setup_manifest(master, machine, files, pushed_at,
                                        stamp))
    dest.write_tree(prefix, staging)
    for rel in withheld:
        dest.delete(join_prefix(prefix, rel))


def _captured_state_reads(effective: dict, want_agents, categories,
                          home) -> list:
    """(item src, path it reads, why) for every path this push's Setup half
    would read that a Setup must not carry. Empty is clean.

    Run BEFORE the capture engine rather than over the manifest it produces,
    so that on a hit the key is never copied anywhere at all - not into the
    staging tree a refusal leaves behind for inspection, and certainly not
    into the Archive.

    The engine's own function, asked over the registry this push captures
    from, rather than a second walk written to the same rule. Two spellings of
    one rule is how the capture leg and the push leg came to disagree about
    what ~/.carryon is in the first place, and a rule with one implementation
    cannot drift however many legs consult it.
    """
    with _swapped_registry(effective):
        return capture.state_reads(want_agents, categories, home)


def push(args, home) -> int:
    home = pathlib.Path(home)
    _begin_command()
    apply = bool(getattr(args, "apply", False))
    cfg, dest = _open_destination(home)
    machine = cfg["machine"]
    now = _utc_now()

    effective = _effective_adapters(cfg, home)
    want_agents = _subset(getattr(args, "agent", None), effective, "agent")
    want_categories = _subset(getattr(args, "category", None), CATEGORIES,
                              "category")
    setup_categories = (set(SETUP_CATEGORIES) if want_categories is None
                        else want_categories & set(SETUP_CATEGORIES))
    do_history = want_categories is None or HISTORY in want_categories

    # Only a History is encrypted (ADR-0004), so a Setup-only push must work
    # with no master key at all - locked keychain, machine never paired.
    # Without a key the encrypted Index cannot be read or written, so such a
    # push records nothing there; pull learns of the Setup from the plaintext
    # tree's own MANIFEST instead.
    master = (_require_master(home) if do_history
              else keyring.fetch_master(home=home))

    print(f"{'PUSH PLAN (dry run)' if not apply else 'PUSHING'} -> "
          f"{dest.describe()}\n")

    # Before a byte is written anywhere, Setup half included: a push onto an
    # Index this machine has already seen past destroys catalogue entries
    # rather than merely hiding them. A keyless Setup-only push has no Index
    # to check, which is ADR-0004's cost and is reported at the end.
    index = archive.load_index(dest, master) if master is not None else None
    index_refused = archive.index_refusals(index)
    # A record load_index set aside is still a record: the Archive holds a
    # Session, and the entry describing it is the thing this machine could not
    # read. Taking that for 'no entry' would put the Session down the branch
    # that writes without comparing - ADR-0002's rule is asked only where an
    # entry exists - so a machine one turn behind would overwrite the Archive's
    # longer copy with its own, which is the exact loss _push_skip_reason
    # exists to prevent. Named per catalogue rather than as one set, because a
    # cwd and a UUID are different namespaces.
    unreadable_records = {
        name: {refusal.key for refusal in index_refused
               if refusal.catalogue == name}
        for name in ("sessions", "projects")}
    if index is not None and apply:
        # Removal first: it is the more specific reading of the same missing
        # number, and it names what actually happened.
        _refuse_on_index_removal(home, cfg["destination"], index, "push")
        _refuse_on_rollback(home, cfg["destination"], index)
        # Recorded here rather than only beside save_index below, because
        # what the mark answers is 'has this machine ever read an Index at
        # this Destination' and it has, whether or not this push turns out
        # to change anything worth sealing.
        _record_revision(home, cfg["destination"],
                         archive.index_revision(index))
    elif index is not None:
        note = (_index_removed_note(home, cfg["destination"], index)
                or _rollback_note(home, cfg["destination"], index))
        if note:
            print(f"warning: {note}\nA push would seal a catalogue over that "
                  "as the current one, so --apply will refuse until it is "
                  "sorted out.\n")

    # Setup half: the fail-closed capture engine, verbatim (ADR-0001), behind
    # one gate the engine cannot apply for itself - what it may read at all.
    # Staged under ~/.carryon rather than a TemporaryDirectory so a refusal
    # can honour capture's promise that the written files are left in place
    # for inspection.
    setup_code = 0
    setup_pushed = False
    setup_withheld = setup_near = 0
    setup_undecodable = []
    # One value this push writes into the Setup's tag and into the encrypted
    # Index entry beside it, so a pull can tell the tree this push meant from
    # every earlier tree whose tag also verifies (crypto.new_stamp).
    setup_stamp = crypto.new_stamp()
    state_reads = (_captured_state_reads(effective, want_agents,
                                         setup_categories, home)
                   if setup_categories else [])
    if state_reads:
        # Before the capture engine runs, so nothing is copied even locally.
        setup_code = 2 if apply else 1
        print("SETUP REFUSED: a path in the capture set reads what a Setup "
              "may not carry\n")
        for src, rel, why in state_reads:
            print(f"  !! ~/{printable(src)}")
            print(f"     ~/{printable(rel)} - {why}")
        print("\nThe fallback master key under ~/.carryon is bare hex that no")
        print("credential pattern matches, and the config beside it names the")
        print("Destination - so a Setup carrying either would publish them in")
        print("the Archive's one plaintext half; a file from outside $HOME is")
        print("one this machine never agreed to publish. Remove the link, or")
        print("drop the path from `carry` (ADR-0008). Nothing was captured.\n")
    staging_root = why_staging = None
    if setup_categories and not state_reads:
        # The one place a Setup is materialised in the clear, and the
        # directory it goes in is one carryon makes under its own state -
        # so it is answered for the way every other component under there
        # now is (config.state_write_path). A link at that name published
        # the whole Setup into the tree it pointed at, and a plain file at
        # it was a FileExistsError out of push with no report at all.
        staging_root, why_staging = config.state_write_path(
            home, "staging", directory=True)
    if why_staging is not None:
        setup_code = 2 if apply else 1
        print("SETUP REFUSED: carryon will not stage a Setup here\n")
        print(f"  !! {printable(why_staging)}\n")
        print("A Setup is captured in the clear before it is published, so")
        print("the directory it is staged in has to be carryon's own. The")
        print("History half below is unaffected - it is encrypted and never")
        print("staged on disk.\n")
    elif staging_root is not None:
        staging = pathlib.Path(tempfile.mkdtemp(prefix="setup-",
                                                dir=str(staging_root)))
        keep_staging = False
        try:
            with _swapped_registry(effective):
                setup_code, manifest = capture.run(
                    out=staging, dry=not apply, want_agents=want_agents,
                    want_categories=setup_categories, home=home)
            if setup_code == 0 and apply:
                manifest, setup_withheld, setup_near, setup_undecodable = \
                    _neutralise_staged_setup(staging, manifest, home)
                if (setup_categories == set(SETUP_CATEGORIES)
                        and want_agents is None):
                    # The MAC goes INTO staging before the mirror, so the
                    # tree and its tag land in one put_setup and the stale-key
                    # sweep keeps rather than deletes it. A keyless push
                    # writes no tag - there is no key to derive one from -
                    # which is ADR-0004's cost, reported below.
                    if master is not None:
                        (staging / archive.SETUP_MAC_NAME).write_bytes(
                            archive.seal_setup_manifest(
                                master, machine,
                                archive.setup_tree_manifest(staging), now,
                                setup_stamp))
                    archive.put_setup(dest, machine, staging)
                else:
                    # A partial Setup overlays rather than mirrors, so the
                    # items not selected this time survive in the Archive -
                    # and a withheld file has to be deleted by name, since
                    # the mirror that would have swept it does not run.
                    _push_partial_setup(
                        dest, master, machine, staging, manifest,
                        setup_categories, setup_undecodable,
                        _index_setup_entry(index, machine), now,
                        setup_stamp)
                setup_pushed = True
            elif setup_code != 0 and apply:
                keep_staging = True
                print(f"\nRefused Setup staging kept at {staging}")
        finally:
            if not keep_staging:
                shutil.rmtree(staging, ignore_errors=True)

    # History half: incremental per Session against the Index (ADR-0003).
    sessions_pushed = sessions_unchanged = sessions_skipped = 0
    residues_pushed = residues_unchanged = residues_skipped = 0
    credential_files = []
    missing_cwd = ()
    withheld_history = ()
    unreadable_history = ()
    unnamable_history = ()
    rk_near = rk_bare = rk_non_utf8 = 0
    index_changed = False

    if do_history:
        adapters_list = [a for key, a in effective.items()
                         if not want_agents or key in want_agents]
        found = history.discover(home, adapters_list)
        missing_cwd = found.missing_cwd
        withheld_history = found.withheld
        unreadable_history = found.unreadable
        unnamable_history = found.unnamable

        for session in found.sessions:
            members = _canonical_members(session, home)
            if members is None:
                sessions_skipped += 1
                print(f"  skip     {session.uuid} ({session.agent}) - a file "
                      "in it was there when the tree was walked and gone by "
                      "the time it was read; nothing was pushed for it")
                continue
            th = _members_hash(members)
            if not archive.needs_push(index, session.uuid, th):
                sessions_unchanged += 1
                continue
            if session.uuid in unreadable_records["sessions"]:
                sessions_skipped += 1
                print(f"  skip     {session.uuid} ({session.agent}) - the "
                      "Archive's Index holds a record for this Session that "
                      "this machine could not read (named below), so there "
                      "is nothing to compare its stored copy against; "
                      "nothing was overwritten")
                continue
            main_bytes = members.get(session.main_path, b"")
            entry = index.get("sessions", {}).get(session.uuid)
            if isinstance(entry, dict):
                # The Archive already holds a different version of this
                # Session, so ADR-0002's rule decides who wins - in the dry
                # run too, so the plan shows the same skips the apply would.
                why = _push_skip_reason(dest, master, session, entry, members)
                if why is not None:
                    sessions_skipped += 1
                    print(f"  skip     {session.uuid} ({session.agent}) - "
                          f"{why}")
                    continue
            try:
                tar_bytes, report = history.pack_session(session, home)
            except history.MemberUnreadable as exc:
                sessions_skipped += 1
                print(f"  skip     {session.uuid} ({session.agent}) - {exc}")
                continue
            credential_files += [f"{session.uuid}: {rel}"
                                 for rel in report.credential_members]
            rk_near += report.near_misses
            rk_bare += report.bare_tokens
            rk_non_utf8 += report.non_utf8
            sessions_pushed += 1
            if not apply:
                continue
            meta = {
                "agent": session.agent,
                "cwd": _canon_home(session.cwd, home),
                "machine": machine,
                "tree_hash": th,
                "main_path": session.main_path,
                "main_size": len(main_bytes),
                "main_sha256": hashlib.sha256(main_bytes).hexdigest(),
                "pushed_at": now,
            }
            archive.put_session(dest, master, session.uuid, tar_bytes, meta)
            index["sessions"][session.uuid] = meta
            index_changed = True

        for residue in found.residues:
            if residue.cwd is None:
                continue  # already in missing_cwd via discovery
            cwd = _canon_home(residue.cwd, home)
            members = _canonical_members(residue, home)
            if members is None:
                residues_skipped += 1
                print(f"  skip     {printable(cwd)} - a memory file in it "
                      "was there when the tree was walked and gone by "
                      "the time it was read")
                continue
            th = _members_hash(members)
            if cwd in unreadable_records["projects"]:
                # Same rule as the Session loop above, and a residue needs it
                # at least as much: memory files accumulate, so the copy this
                # push would write over is the only one that holds what the
                # other machines wrote.
                residues_skipped += 1
                print(f"  skip     {printable(cwd)} - the Archive's Index "
                      "holds a record for this project that this machine "
                      "could not read (named below), so there is nothing to "
                      "compare its stored copy against; nothing was "
                      "overwritten")
                continue
            entry = index["projects"].get(cwd)
            if entry is not None and entry.get("tree_hash") == th:
                residues_unchanged += 1
                continue
            if isinstance(entry, dict):
                # Residue was exempt from the union rule entirely: put_project
                # replaced the whole stored tar on any tree_hash difference,
                # with no comparison and no skip line, while pull's residue leg
                # unions per file and never deletes. So a machine holding a
                # byte-prefix of the Archive's memory file - the textbook
                # BEHIND case, the one the Session beside it was protected
                # from - truncated it in the Archive and deleted files it never
                # had. ADR-0002 calls a History an accumulation; a residue is
                # part of one.
                why = _residue_skip_reason(dest, master, cwd, entry, members)
                if why is not None:
                    residues_skipped += 1
                    print(f"  skip     {printable(cwd)} - {why}")
                    continue
            try:
                tar_bytes, report = history.pack_session(residue, home)
            except history.MemberUnreadable as exc:
                residues_skipped += 1
                print(f"  skip     {printable(cwd)} - {exc}")
                continue
            credential_files += [f"{printable(cwd)}: {rel}"
                                 for rel in report.credential_members]
            rk_near += report.near_misses
            rk_bare += report.bare_tokens
            rk_non_utf8 += report.non_utf8
            residues_pushed += 1
            if not apply:
                continue
            meta = {"agent": residue.agent, "machine": machine,
                    "tree_hash": th, "pushed_at": now}
            archive.put_project(dest, master, cwd, tar_bytes, meta)
            index["projects"][cwd] = meta
            index_changed = True

    if apply and setup_pushed and index is not None:
        # authenticated is unconditionally True on this path: index is only
        # non-None when a master key is held, and every keyed Setup push -
        # full or partial - wrote a SETUP.mac above (or refused). This flag
        # is what a pull checks the MAC's presence against, and it lives in
        # the encrypted Index precisely because the MAC file itself sits in
        # the plaintext half an attacker can strip (ADR-0009). The stamp is
        # here for the same reason and answers the next question after
        # 'authenticated': which of the trees that verify is the current one.
        index["setups"][machine] = {"pushed_at": now, "authenticated": True,
                                    "stamp": setup_stamp}
        index_changed = True
    if apply and index_changed:
        archive.save_index(dest, master, index)
        _record_revision(home, cfg["destination"],
                         archive.index_revision(index))

    # The report, in one place, so the two halves' different promises stay
    # side by side: a Setup is clean or refused, a History is encrypted.
    print()
    print("-" * 74)
    verb = "pushed" if apply else "to push"
    if index_refused:
        # Said on this leg too, and not only on the pull's. A push seals the
        # catalogue again, so these are the entries it carried through
        # untouched rather than deleted (archive.save_index) - and the machine
        # reading this line is often the one that still holds the Session and
        # can write a fresh entry for it, which is the whole cure.
        count = len(index_refused)
        print(f"{count} entr{'y' if count == 1 else 'ies'} in the Archive's "
              "Index this machine could not read - carried through exactly as "
              "they came, since carryon does not delete a record it cannot "
              "read. Nothing was pushed or replaced for them:")
        for refusal in index_refused:
            print(f"  ?? {printable(str(refusal.key))} - {refusal.why}")
    if do_history:
        session_line = (f"Sessions: {sessions_pushed} {verb}, "
                        f"{sessions_unchanged} unchanged")
        if sessions_skipped:
            session_line += (f", {sessions_skipped} skipped rather than "
                             "overwrite the Archive's copy (named above)")
        print(session_line)
        residue_line = (f"Project residue: {residues_pushed} {verb}, "
                        f"{residues_unchanged} unchanged")
        if residues_skipped:
            residue_line += (f", {residues_skipped} skipped rather than "
                             "overwrite the Archive's copy (named above)")
        print(residue_line)
        if withheld_history:
            print(f"{len(withheld_history)} History path(s) WITHHELD - they "
                  "read carryon's own state through a link, and the master "
                  "key is bare hex no credential pattern matches (ADR-0008). "
                  "They were not packed and will not be laid down anywhere:")
            for rel in withheld_history:
                print(f"  -- ~/{printable(rel)}")
        if unreadable_history:
            # Named for the same reason the withheld paths above are: this
            # push covers less than the adapters declare, and a user who is
            # not told reads it as covering more.
            print(f"{len(unreadable_history)} History path(s) this machine "
                  "would not read - nothing under them was carried, and "
                  "nothing here was overwritten:")
            for rel, why in unreadable_history:
                print(f"  !! ~/{printable(rel)} - {printable(why)}")
        if unnamable_history:
            # The Archive is what cannot hold these, not this machine: the
            # files are here and stay here, readable and untouched. Said in
            # the same shape as the two above because it is the same fact -
            # this push covers less than the adapters declare - and said at
            # all because the alternative was sealing a catalogue keyed by a
            # name no machine could open the Index past.
            print(f"{len(unnamable_history)} History path(s) carryon cannot "
                  "name in an Archive - they stay on this machine, and "
                  "nothing else was affected:")
            for rel, why in unnamable_history:
                print(f"  -- ~/{printable(rel)} - {printable(why)}")
        if missing_cwd:
            print(f"{len(missing_cwd)} path(s) recorded no cwd - carried "
                  "without one; they cannot be laid down elsewhere until a "
                  "cwd is known:")
            for rel in missing_cwd:
                print(f"  ?? {rel}")
        if credential_files:
            print(f"Credentials REPORTED in {len(credential_files)} "
                  "transcript file(s) - carried and encrypted, never "
                  "redacted (ADR-0001):")
            for label in credential_files:
                print(f"  !! {label}")
        else:
            print("Credentials: none reported in the History")
        _print_rekey_notes(rk_near, rk_bare, rk_non_utf8)
    if setup_categories:
        if state_reads:
            print("Setup: REFUSED - a captured path reads carryon's own "
                  "state or a file outside $HOME (named above); nothing was "
                  "captured and nothing was written to the Archive's Setup")
        elif setup_code != 0:
            print("Setup: REFUSED - a credential is in the capture set (see "
                  "above); nothing was written to the Archive's Setup")
        else:
            print(f"Setup: {verb} to setups/{machine}/ (clean)")
            if setup_withheld:
                print(f"  {setup_withheld} path(s) withheld from the MANIFEST "
                      "- they name a directory on this machine and an Archive "
                      "names none (ADR-0006); RESTORE.md says so where they "
                      "were")
            if setup_near:
                print(f"  {setup_near} near-miss(es) - a captured file names a "
                      "path matching this home case-insensitively only; "
                      "carried as written, never rewritten (ADR-0006)")
            if setup_undecodable:
                print(f"  {len(setup_undecodable)} file(s) WITHHELD - not "
                      "UTF-8, so carryon cannot read one to tell whether it "
                      "spells this machine's home out, and the Archive's one "
                      "plaintext half names no machine (ADR-0006). They "
                      "stayed here and a pull elsewhere will be without them; "
                      "the rest of the Setup went:")
                for rel in setup_undecodable:
                    print(f"  -- {rel}")
            if apply and setup_pushed and master is None:
                print("  warning: pushed without a master key, so this Setup "
                      "carries no authentication tag and cannot be verified "
                      "by the machines that pull it (ADR-0004; the encrypted "
                      "Index was not touched)")
    if not apply:
        print("\nDry run. Re-run with --apply to push.")
    return setup_code


# --- pull --------------------------------------------------------------------
#
# Everything below this line reads from the Destination, so everything below
# this line is handling input: a machine name, a stored MANIFEST, a member of
# a stored tree, the ciphertext behind an Index entry. The failure mode is the
# same for all of them and it is neither of the two that come naturally.
# Never crash: an abort partway through a pull leaves a $HOME with someone
# else's History in it and no report saying what landed, and a hostile
# Destination can trigger one at will. Never go quiet either: an item dropped
# without a word reads as a restore that succeeded and is mysteriously short a
# file. Report and skip - name the thing, say why, carry on with the rest.


def _parse_maps(pairs) -> list:
    """The (OLD, NEW) pairs a pull will apply, having refused an unusable set.

    The door, and there used to be two. `rekey.map_refusal` states what a
    usable set is and cli.cmd_pull asked it - which left every other caller of
    `sync.pull` walking straight past: this project's own suites, and any
    future command that pulls. The rule is the same rule; where it is asked
    decides whether it is asked at all, so it is asked here, at the one
    function every pull takes its maps from, before the Destination is opened
    and before a byte is read.
    """
    maps = []
    for raw in pairs or []:
        if "=" not in raw:
            raise SystemExit(f"--map {raw!r}: expected OLD=NEW")
        old, new = raw.split("=", 1)
        if not old or not new:
            raise SystemExit(f"--map {raw!r}: OLD and NEW must be non-empty")
        maps.append((old, new))
    why = rekey.map_refusal(pairs)
    if why is not None:
        raise SystemExit(why)
    return maps


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


def _setup_writes(manifest: dict, staging, home, declared) -> tuple:
    """(writes, refused): (target, source) pairs mapping the stored Setup
    back onto $HOME, driven by the MANIFEST the capture engine wrote, plus
    the items refused before a byte moved in either direction.

    Both fields are validated up front because both are attacker-reachable
    (see _setup_target). A refused item comes back named rather than dropped:
    silently skipping one reads as a successful restore that is quietly
    missing a file."""
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


def _no_history_here(agent: str, effective: dict) -> bool:
    """True when the effective adapter declares no chats item - typically
    because the user excluded it in config (ADR-0008)."""
    return not any(item.kind == "chats" for item in effective[agent].items)


def _backup_root(home) -> pathlib.Path:
    """Where this pull's copies of the Setup files it replaces go.

    ADR-0002 permits a Setup to be replaced item by item because what was
    there goes to a timestamped backup first - "recoverably from the backup"
    is the sentence, and the backup is the whole of what makes the replacement
    acceptable. The stamp was `_utc_now()`, which is second granularity, so
    two pulls inside one second wrote into the same directory and copy2
    overwrote the first pull's copy with the second's. The file the user
    actually wanted back is the one the FIRST pull saved.

    crypto.new_stamp already argues this exact case one object over - "a
    timestamp is only as fine as the clock it is read from - two pushes in one
    second stamp the same string, and the second-granularity one carryon
    records is exactly that case" - so the same 128 bits from the OS go on the
    end of the timestamp. The timestamp stays in front because a user looking
    for last Tuesday's settings.json sorts this directory by name.

    Unguessable is a second thing it buys, and a welcome one rather than the
    point: a name an attacker can predict is a name they can plant a link at
    before the pull runs. Neither property is left to carry the rule on its
    own, because a name nobody can guess is luck rather than a guard: every
    file under this directory is created exclusively (O_EXCL, see `_backed_up`),
    so even a name that did somehow recur cannot cost anybody a saved copy -
    the second write is refused and reported instead of overwriting the first.
    """
    return (pathlib.Path(home) / ".carryon" / "backups"
            / f"{_utc_now()}-{crypto.new_stamp()}")


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


def pull(args, home) -> int:
    home = pathlib.Path(home)
    _begin_command()
    apply = bool(getattr(args, "apply", False))
    force = bool(getattr(args, "force", False))
    maps = _parse_maps(getattr(args, "map", []))
    cfg, dest = _open_destination(home)
    master = _require_master(home)
    index = archive.load_index(dest, master)
    # Before the banner, because nothing has been read or written yet and the
    # refusal is the whole of what this pull has to say.
    _refuse_on_index_removal(home, cfg["destination"], index, "pull")

    print(f"{'PULL PLAN (dry run)' if not apply else 'PULLING'} <- "
          f"{dest.describe()}\n")
    _warn_on_rollback(home, cfg["destination"], index)
    # Read before the mark is raised, since recording this pull's revision
    # would make the rollback invisible to the Setup half below.
    rolled_back = _rollback_note(home, cfg["destination"], index)
    if apply:
        # A dry run is a plan and writes nothing under $HOME, high-water
        # mark included; it still reads the mark to warn.
        _record_revision(home, cfg["destination"],
                         archive.index_revision(index))

    effective = _effective_adapters(cfg, home)
    local = history.discover(home, list(effective.values()))
    # Every copy per UUID, not one: a machine can hold the same Session in two
    # project dirs, and which of them the incoming tree lands on is a question
    # about the recorded cwd rather than about discovery order.
    local_by_uuid = {}
    for session in local.sessions:
        local_by_uuid.setdefault(session.uuid, []).append(session)

    restored = replaced = ahead = unchanged = conflicts = 0
    # Members of a Session where neither copy of a Transcript extends the
    # other. The local one stays and the Archive's goes under
    # ~/.carryon/conflicts/<uuid>/ - the same answer ADR-0002 gives for a
    # wholly divergent Session, one file down.
    member_conflicts = 0
    # Files added to a Session this machine already had. ADR-0002 unions a
    # History, and a Session is a tree: the Archive holding members this
    # machine does not is the ordinary case after another machine wrote a
    # subagent journal, and it is not a replacement of anything.
    session_union = 0
    # The same case seen from the other side: local members of a Session the
    # incoming tree replaced that the incoming tree does not hold. They are
    # kept - a pull never deletes - and counted here so that the keeping is
    # something the report states rather than something the user has to infer
    # from the absence of a line.
    session_kept = 0
    rk_near = rk_bare = rk_non_utf8 = 0
    # Restored files some other tool already owns: skipped, named as they are
    # met, and counted here for the summary (ADR-0007).
    history_deferred = 0
    # Restored files this machine's syscalls would not take - something else
    # standing where the member lands. A different sentence from deference and
    # counted separately, because the cure is different too.
    history_refused = 0
    unrestorable = []
    # Sealed objects the Archive holds and this machine could not open. They
    # are reported like any other skip and then decide the exit status at the
    # very end - see the SystemExit that closes this function.
    unopenable = []
    # Index entries archive.load_index set aside, on the same terms: this
    # pull restored nothing for them, which is the same shortfall an
    # unopenable object is, so they are named in the report and counted
    # towards the exit status rather than left for the user to notice by a
    # Session that never arrived.
    unreadable_entries = [(refusal.key, refusal.why)
                          for refusal in archive.index_refusals(index)]
    unrestorable += unreadable_entries

    def account(landed) -> None:
        """Add one landed Session tree to the run's totals. A closure rather
        than seven more lines at each of the two places that lay a tree
        down - and the two of them differing in what they counted is how a
        branch came to report `0 replaced` about a tree it had written."""
        nonlocal session_kept, member_conflicts, history_deferred, \
            history_refused, rk_near, rk_bare, rk_non_utf8
        session_kept += landed.kept
        member_conflicts += landed.conflicted
        history_deferred += landed.deferred
        history_refused += landed.refused
        rk_near += landed.near
        rk_bare += landed.bare
        rk_non_utf8 += landed.non_utf8

    for uuid in sorted(index.get("sessions", {})):
        meta = index["sessions"][uuid]
        agent = meta.get("agent", "")
        if agent not in effective:
            unrestorable.append((uuid, f"no adapter for agent {agent!r}"))
            continue
        if _no_history_here(agent, effective):
            unrestorable.append(
                (uuid, f"agent {agent!r} carries no History on this machine "
                       "(excluded in config?) - the Session stays in the "
                       "Archive"))
            continue
        landing = (_restore_root(agent, meta["cwd"], effective, home, maps)
                   if meta.get("cwd") else None)
        local_session, other_copies = _choose_local_copy(
            local_by_uuid.get(uuid, ()), landing, home)
        if local_session is None:
            if not meta.get("cwd"):
                unrestorable.append(
                    (uuid, "pushed without a cwd - no local project dir "
                           "can be derived"))
                continue
            tar_bytes = None
            if apply:
                try:
                    # .get, not a subscript: the Index is sealed, so a key
                    # holder wrote it - and a carryon that wrote a shape this
                    # one does not know is exactly the case archive._validated
                    # is written for. _get_object refuses a field that is not
                    # a key by name; a KeyError here was a traceback out of a
                    # pull that had already written to $HOME.
                    #
                    # Read into members here rather than inside
                    # _land_session, which is the loop that writes: the
                    # fetch's own `except` is where a Session the Archive
                    # cannot serve becomes a skip line rather than a
                    # tarfile.ReadError over a half-restored tree.
                    tar_bytes = archive.get_session(dest, master, uuid,
                                                    meta.get("object"))
                    stored = _stored_members(tar_bytes, meta.get("object"))
                except archive.ObjectRefused as exc:
                    unrestorable.append((uuid, str(exc)))
                    unopenable.append((uuid, str(exc)))
                    continue
                why = _main_mismatch(stored, meta)
                if why is not None:
                    unrestorable.append((uuid, why))
                    continue
            print(f"  new      {printable(uuid)} ({agent})")
            restored += 1
            if apply:
                # New to the Index, which is not the same as new to this
                # machine: the local tree still gets the union rule, member by
                # member, inside _land_session.
                _root, _unrep, landed = _land_session(
                    tar_bytes, meta, uuid, home, maps, effective, apply)
                account(landed)
            continue

        # Known on both sides. The union rule keys on main Transcript bytes
        # (ADR-0002), compared in canonical form so the homes cancel out - but
        # the thing being decided about is the TREE, so the tree hash decides
        # whether there is anything to do at all. Deciding 'unchanged' from
        # the main alone is how a Session whose subtree the Archive held and
        # this machine did not was never fetched, which left the cure every
        # push skip names ('pull first') unable to help.
        local_members = _canonical_members(local_session, home)
        if local_members is None:
            unrestorable.append(
                (uuid, "a local file in it was there when the tree was walked "
                       "and gone by the time it was read"))
            continue
        canon = local_members.get(local_session.main_path, b"")
        if meta.get("tree_hash") == _members_hash(local_members):
            unchanged += 1
            continue

        try:
            tar_bytes = archive.get_session(dest, master, uuid,
                                            meta.get("object"))
            stored = _stored_members(tar_bytes, meta.get("object"))
        except archive.ObjectRefused as exc:
            unrestorable.append((uuid, str(exc)))
            unopenable.append((uuid, str(exc)))
            continue
        why = _main_mismatch(stored, meta)
        if why is not None:
            unrestorable.append((uuid, why))
            continue
        incoming_main = stored.get(local_session.main_path)
        relation = ("divergent" if incoming_main is None
                    else history.compare_main(canon, incoming_main))
        if relation in ("same", "incoming-prefix"):
            # The main says there is nothing to REPLACE, and the tree beneath
            # it is exactly where two machines diverge while their mains stand
            # still. So every member gets ADR-0002's rule, through the same
            # function the replacement below goes through.
            #
            # This branch used to union with "existing local files always
            # win", which is the posture ADR-0002 rejects rather than the rule
            # it states, and it broke the ADR both ways round. A member this
            # machine was BEHIND on was never caught up, so push went on
            # refusing the Session and 'pull first' - the cure every skip line
            # names, and the one the ADR promises works - cured nothing. And a
            # member that had DIVERGED was dropped on the floor instead of
            # being kept under ~/.carryon/conflicts/: carryon promises both
            # copies survive, kept one, and said nothing about the other. Pull
            # onto the new machine and wipe the old one, which is what this
            # tool is for, and that copy is gone.
            if not meta.get("cwd"):
                unrestorable.append(
                    (uuid, "its tree differs from this machine's but it was "
                           "pushed without a cwd, so no local project dir can "
                           "be derived"))
                continue
            if relation == "same":
                unchanged += 1
            else:
                ahead += 1
            root, unrep, landed = _land_session(tar_bytes, meta, uuid, home,
                                                maps, effective, apply)
            account(landed)
            # `members` is what landed and is zero by construction in a dry
            # run; `writes` is what the rule decided, which is what a plan has
            # to say out loud.
            wrote = unrep.members if apply else unrep.writes
            if wrote:
                session_union += wrote
                print(f"  union    {printable(uuid)} ({agent}) - {wrote} "
                      f"file(s) {'written' if apply else 'to write'}: the "
                      "Archive holds members this machine does not, or a "
                      "copy that extends one it has (ADR-0002)")
            session_kept += _kept_local_members(local_session, root, unrep,
                                                agent, home)
            session_kept += _report_other_copies(other_copies, uuid, home)
        elif relation == "local-prefix":
            if not meta.get("cwd"):
                unrestorable.append(
                    (uuid, "incoming is ahead but was pushed without a cwd"))
                continue
            # "every member it EXTENDS" rather than "the tree": the main
            # Transcript being a byte-prefix authorises the replacement and
            # decides nothing below it (ADR-0002 unions a History, and a
            # Session holds dozens of Transcripts). This line described a
            # branch that took the whole directory with it, then one that
            # overwrote every name the tar held.
            print(f"  replace  {printable(uuid)} ({agent}) - local is a "
                  "byte-prefix, so the incoming tree wins every member "
                  "it extends")
            replaced += 1
            # Run in a dry run too, and reporting is the whole reason: what
            # the user is deciding about is which of their Transcripts
            # survive, so the plan has to name them. unpack_session writes
            # nothing when apply is False.
            root, unrep, landed = _land_session(tar_bytes, meta, uuid, home,
                                                maps, effective, apply)
            account(landed)
            session_kept += _kept_local_members(local_session, root, unrep,
                                                agent, home)
            session_kept += _report_other_copies(other_copies, uuid, home)
        else:
            # Conflicts land under ~/.carryon, deliberately OUTSIDE the
            # agent's own tree: a stray <uuid>.jsonl written into a project
            # dir would be discovered as a phantom Session on the next push
            # or pull (the claude-projects layout treats every top-level
            # *.jsonl there as a main Transcript).
            conflict_dir = home / ".carryon" / "conflicts" / uuid
            print(f"  conflict {printable(uuid)} ({agent}) - divergent; local "
                  f"kept, incoming under {printable(str(conflict_dir))}")
            conflicts += 1
            if apply:
                # into_state waives the ~/.carryon rule for this root and
                # nothing else: a link one component inside the conflicts
                # tree - a previous pull's, or planted - is still somebody
                # else's path, and the copy kept aside is not worth writing
                # into their repo to keep.
                #
                # union, because this directory holds the only copy of a
                # divergent incoming Transcript on the machine: a later pull
                # replaces one of them only with a copy that extends it.
                c_deferred, c_refused = [], []
                c_written, c_kept, c_near, c_bare, c_non = _extract_tree(
                    tar_bytes, conflict_dir, home, maps, into_state=True,
                    deferred=c_deferred, refused=c_refused)
                rk_near += c_near
                rk_bare += c_bare
                rk_non_utf8 += c_non
                history_deferred += _report_deferred(c_deferred, home)
                history_refused += _report_refused(c_refused, home)
                # The line above promises a copy; this says what the copy
                # actually holds, since a member may have been deferred to a
                # link, refused by a syscall, or already sitting there from
                # an earlier pull.
                print(f"           {c_written} file(s) written there, "
                      f"{c_kept} already there and left alone")

    # Project residue: ADR-0002's rule per file, the same rule the Session
    # loop above applies and the same one push already refuses a residue over.
    # A residue is memory - the notes that accrete beside a project's
    # Transcripts - so it is part of a History and accumulates like one.
    residue_written = residue_kept = residue_conflicts = 0
    local_residues = {_canon_home(r.cwd, home): r
                      for r in local.residues if r.cwd}
    for cwd in sorted(index.get("projects", {})):
        meta = index["projects"][cwd]
        agent = meta.get("agent", "")
        if agent not in effective:
            unrestorable.append((cwd, f"no adapter for agent {agent!r}"))
            continue
        if _no_history_here(agent, effective):
            unrestorable.append(
                (cwd, f"agent {agent!r} carries no History on this machine "
                      "(excluded in config?) - the residue stays in the "
                      "Archive"))
            continue
        local_residue = local_residues.get(cwd)
        if local_residue is not None:
            # _canonical_members rather than _canonical_tree_hash: the hash
            # helper turns an unreadable member into a MemberUnreadable, which
            # nothing on this leg catches, thrown after the Session half has
            # already written into $HOME. push answers the same file with a
            # skip line one function over; the two legs read the same tree and
            # must answer the same way.
            local_members = _canonical_members(local_residue, home)
            if local_members is None:
                unrestorable.append(
                    (cwd, "a memory file in this machine's copy could not be "
                          "read, so there is nothing here to compare the "
                          "Archive's copy against; nothing was written"))
                continue
            if _members_hash(local_members) == meta.get("tree_hash"):
                continue
        root = _restore_root(agent, cwd, effective, home, maps)
        # printable, because `cwd` is a key out of the Index's projects
        # catalogue: archive._validated proves it is a string this machine can
        # spell and asks no more than that, since a cwd is an absolute path
        # and not a name a report can take verbatim.
        print(f"  residue  {printable(cwd)} -> {root} (union per file, "
              "ADR-0002)")
        if apply:
            try:
                # Read into members before _extract_tree starts writing them
                # out. This leg has no version check to open the tar first, so
                # a residue object that is not a tree would otherwise be found
                # out mid-walk, with part of the memory already laid down.
                tar_bytes = archive.get_project(dest, master, cwd,
                                                meta.get("object"))
                _stored_members(tar_bytes, meta.get("object"))
            except archive.ObjectRefused as exc:
                unrestorable.append((cwd, str(exc)))
                unopenable.append((cwd, str(exc)))
                continue
            r_deferred, r_refused, r_conflicted = [], [], []
            written, kept, r_near, r_bare, r_non = _extract_tree(
                tar_bytes, root, home, maps, deferred=r_deferred,
                refused=r_refused, conflicted=r_conflicted)
            residue_written += written
            residue_kept += kept
            rk_near += r_near
            rk_bare += r_bare
            rk_non_utf8 += r_non
            history_deferred += _report_deferred(r_deferred, home)
            history_refused += _report_refused(r_refused, home)
            if r_conflicted:
                # A residue has no Session UUID to file its conflicts under,
                # so it goes under the name of the directory the files belong
                # to. Nothing there can collide with a Session's: a project
                # directory is derived from an absolute cwd (ADR-0006), so it
                # begins with the separator's '-', and a UUID never does.
                conflict_dir = home / ".carryon" / "conflicts" / root.name
                residue_conflicts += len(r_conflicted)
                for target, _name in r_conflicted:
                    rel = _rel_to_home(target, home)
                    print(f"  conflict ~/{printable(rel)} - divergent; local "
                          "kept, incoming under "
                          f"{printable(str(conflict_dir))}")
                c_deferred, c_refused = [], []
                _extract_tree(
                    tar_bytes, conflict_dir, home, maps, into_state=True,
                    only=frozenset(name for _t, name in r_conflicted),
                    deferred=c_deferred, refused=c_refused)
                history_deferred += _report_deferred(c_deferred, home)
                history_refused += _report_refused(c_refused, home)

    # Setup half: replace wholesale after a backup (ADR-0002), deferring to
    # whatever already owns a path (ADR-0007).
    setup_written = setup_skipped = setup_refused = 0
    # Whether the Setup half was refused AS A WHOLE - carryon was offered a
    # stored Setup and would not use the one it chose. It is what this pull's
    # exit status is built from, and it is deliberately narrower than
    # setup_refused above: that counter also rises for a path deferred to
    # whatever owns it and for one item inside a Setup that was accepted,
    # which ADR-0002 and ADR-0007 both call the right answer rather than a
    # failure. A status that fired on those is one a script learns to ignore.
    setup_denied = False
    setups, unusable, setups_unreachable = {}, [], None
    try:
        setups, unusable = _setup_catalogue(dest, index)
    except SystemExit as exc:
        # The catalogue is read from the Destination, and a transport that
        # syncs on the READ path answers a dead or hostile remote with
        # SystemExit (GitDestination's _git_or_die) - here, AFTER the
        # Session loop has written to $HOME. Same rule as everything else on
        # this layer (ADR-0009): a Destination failure once work has landed
        # is reported and skipped, never a raise that eats the report.
        setups_unreachable = str(exc)
    index_names = _index_setup_names(index)
    index_absent = archive.index_is_absent(index)
    source, unvouched, ignored = _choose_setup_source(setups, index_names,
                                                      index_absent)
    if setups_unreachable is not None:
        source = None
        setup_refused += 1
        setup_denied = True
        print("\nSetup: none restored - the Destination failed while the "
              f"stored Setups were being read: {setups_unreachable}\n"
              "  The History above landed; pull again once the Destination "
              "is reachable.")
    elif rolled_back is not None:
        # A rollback only WARNED, and the Setup half of a pull is executable
        # content. Replay a superseded Index, its tree and its SETUP.mac
        # together and every check downstream agrees - the tag verifies, the
        # stamp matches the Index, the tree matches the manifest - so a hook
        # the user removed between two pushes comes back at exit 0. Nothing in
        # the Archive can tell that from the current state; the one party that
        # can is this machine's own high-water mark, and a printed line is not
        # an answer to code.
        #
        # The History half above is deliberately not refused with it. A
        # History is an accumulation (ADR-0002): a stale catalogue hides
        # Sessions and lays down no wrong answer, and refusing there would
        # strand a user whose Destination really did lose a write. A Setup is
        # a replacement, and a replacement out of a catalogue this machine has
        # already seen past is a rollback of whatever the last push tightened.
        source = None
        setup_refused += 1
        # Only if there was one to refuse. A rollback is a fact about the
        # Index, and an Archive whose Setup half is empty had nothing for this
        # branch to withhold - saying otherwise would fail a pull over a
        # Setup that does not exist, which is the "cries wolf" objection
        # _seen_revision already records against the rollback signal itself.
        setup_denied = bool(setups)
        print("\nSetup: none restored - the Archive's Index has been rolled "
              "back (see the warning above), and a Setup is replaced whole "
              "rather than unioned. Every superseded tree a key holder ever "
              "pushed still verifies against the Index that was current when "
              "they pushed it, so restoring from a rolled-back one would undo "
              "whatever the last push tightened - a removed hook, a revoked "
              "skill - with nothing downstream able to notice.\n"
              "  The History above landed. Sort the Destination out (restore "
              f"the newer Index), or if the rollback was deliberate, drop "
              f"this Destination's entry from {_state_path(home)} to accept "
              "it.")
    elif not setups:
        print("\nSetup: none in the Archive" if not unusable
              else "\nSetup: nothing under setups/ that carryon can use")
    elif source is None:
        # The Archive holds Setups and carryon will use none of them - a
        # vouched tree deleted and an unvouched one left under another name is
        # the shape that gets here. Nothing was restored and something was
        # offered, which is the same fact as a refusal further down.
        setup_denied = True
        print(_no_setup_source_note(setups, index_names, index_absent))
    else:
        print(f"\nSetup: from machine '{printable(source)}' "
              f"(pushed {printable(setups[source]['pushed_at'])})")
    # Printed whichever branch ran, and before the restore: a directory under
    # setups/ that carryon cannot treat as a machine at all is the user's to
    # sort out at the Destination, and dropping it silently hides the fact
    # that the Archive holds something carryon would not touch.
    for name, why in unusable:
        setup_refused += 1
        # repr, because the names that get here are the ones with something
        # unprintable or unexpected in them.
        print(f"  refuse   a stored Setup named '{printable(name)}': {why}")
    if source is not None:
        if unvouched:
            print(f"  note     nothing in the encrypted Index vouches for "
                  f"'{printable(source)}' - a keyless Setup push (ADR-0004) "
                  "looks like "
                  "this, and so does a planted one")
            if archive.index_is_absent(index):
                # The residue nothing can decide, said out loud rather than
                # left implicit in the line above. This machine has never
                # read an Index here - or _refuse_on_index_removal would
                # have stopped the pull - so a deleted Index and an Archive
                # that never had one are the same two objects on the same
                # Destination, and the user is the only party who knows
                # which of the two they are looking at.
                #
                # 'Nothing left to check against' is the accurate reading only
                # once the stored Setup's own tag has been asked, which
                # happens below: a tag is a key holder's statement and a
                # keyless Archive carries none, so the two ARE separable when
                # one is there. This line prints before that read, so it says
                # what is left rather than claiming nothing is.
                print("  note     and the Archive serves no Index at all, so "
                      "there is no master key holder's record here to check "
                      "any of it against. This machine has never read one at "
                      "this Destination either, which would have settled it; "
                      "what is left is whatever authentication tag the stored "
                      "Setup carries, and a keyless Archive (ADR-0004) "
                      "carries none")
        for other in ignored:
            print(f"  ignored  a stored Setup named '{printable(other)}' - "
                  "no master key holder ever pushed a Setup under that name, "
                  "so its timestamp cannot win")
        with tempfile.TemporaryDirectory(prefix="carryon-setup-") as staging_s:
            staging = pathlib.Path(staging_s)
            manifest = why = refusal = None
            try:
                archive.get_setup(dest, source, staging)
            except archive.ObjectRefused as exc:
                why = str(exc)
            else:
                # Authentication runs on the materialised tree, before a byte
                # moves towards $HOME - the staging dir is carryon's own and
                # is discarded with the refusal.
                refusal, note = _setup_authentication(staging, master,
                                                      source, setups[source])
                if note:
                    print(f"  note     {note}")
                if refusal is None:
                    manifest, why = _stored_manifest(staging)
            if refusal is not None:
                # One refused Setup, however many lines explain it: the
                # counter feeds the summary's 'refused and not written'.
                setup_refused += 1
                setup_denied = True
                print(f"  refuse   {refusal[0]}")
                for line in refusal[1:]:
                    print(f"           {line}")
            elif why is not None:
                # An object the Archive would not serve, or a stored MANIFEST
                # that will not parse: the Setup carryon chose did not land,
                # which is the same answer to the same question as the
                # authentication refusal above.
                setup_denied = True
                print(f"  {why}")
            else:
                writes, refused = _setup_writes(manifest, staging, home,
                                                _declared_paths(effective))
                for label, reason in refused:
                    setup_refused += 1
                    print(f"  refuse   {label}: {reason}")
                do, skip = external.plan(writes, home, force=force)
                # One directory per pull, minted here rather than per item so
                # every file this run replaces is recoverable from one place
                # (ADR-0002), and named through a helper so the same run never
                # writes into a directory an earlier run made.
                backup_root = _backup_root(home)
                state_ids = config.state_identities(home)
                prefix = archive.setup_prefix(source)
                for target, source_path in do:
                    rel = _rel_to_home(target, home)
                    packed_rel = source_path.relative_to(staging).as_posix()
                    # Both sides, always: a write reading from somewhere other
                    # than this machine's stored Setup is only visible in the
                    # dry run if the dry run says where it reads from.
                    print(f"  write    ~/{printable(rel)}  <- "
                          f"{printable(prefix)}/{printable(packed_rel)}")
                    if not apply:
                        continue
                    stats, is_utf8, reason = _restore_setup_item(
                        target, source_path, backup_root / rel, home, maps,
                        state_ids, force=force)
                    if reason is not None:
                        setup_refused += 1
                        print(f"  refuse   ~/{printable(rel)}: {reason}")
                        continue
                    rk_near += stats.near_misses if stats else 0
                    rk_bare += stats.bare_tokens if stats else 0
                    rk_non_utf8 += 0 if is_utf8 else 1
                    setup_written += 1
                for target, source_path, owner in skip:
                    setup_skipped += 1
                    packed_rel = source_path.relative_to(staging).as_posix()
                    print(f"  skip     ~/"
                          f"{printable(_rel_to_home(target, home))}  <- "
                          f"{printable(prefix)}/{printable(packed_rel)} - "
                          f"externally owned; {printable(str(owner))} holds "
                          "it (--force writes through)")

    print()
    print("-" * 74)
    print(f"Sessions: {restored} new, {replaced} replaced, "
          f"{unchanged} unchanged, {ahead} ahead locally, "
          f"{conflicts} divergent (kept aside)")
    if conflicts:
        print("Divergent incoming copies land under "
              "~/.carryon/conflicts/<uuid>/ - a local Session is never "
              "deleted")
    if member_conflicts:
        # Counted apart from the Sessions above because the Session itself was
        # not divergent: these are Transcripts INSIDE it that neither copy
        # extends, and a user reading '1 replaced' or '1 unchanged' has no
        # other way to learn that one of their files did not go with it.
        print(f"Sessions: {member_conflicts} file(s) inside a restored "
              "Session were divergent - the local copy is kept and the "
              "Archive's is under ~/.carryon/conflicts/<uuid>/ (ADR-0002); "
              "neither copy overwrote the other")
    if session_union:
        # Not "no local file was replaced", which was the old line and was
        # only true because this branch never applied the rule: a member the
        # Archive's copy EXTENDS is replaced, which is the append-only case
        # ADR-0002 names, and is what makes 'pull first' work.
        print(f"Sessions: {session_union} file(s) written into Sessions this "
              "machine already had - the Archive held members it did not, or "
              "a copy extending one it had (ADR-0002); nothing this machine "
              "was ahead on was touched")
    if session_kept:
        # Deliberately not "the Archive did not hold them": that is true of
        # the ordinary case and not of the --map one, where the Archive's copy
        # landed in another directory. What both have in common is that the
        # incoming tree did not supersede them, and the lines above say which.
        print(f"Sessions: {session_kept} local file(s) kept in Sessions the "
              "incoming tree landed on (named above) - nothing superseded "
              "them and a pull never deletes (ADR-0002). A stale member goes "
              "only under --mirror, which is deliberately not built")
    print(f"Project residue: {residue_written} file(s) written, "
          f"{residue_kept} kept (this machine's copy is ahead)")
    if residue_conflicts:
        print(f"Project residue: {residue_conflicts} memory file(s) were "
              "divergent - the local copy is kept and the Archive's is under "
              "~/.carryon/conflicts/<project>/ (ADR-0002); neither copy "
              "overwrote the other")
    if history_refused:
        print(f"History: {history_refused} file(s) NOT written - this machine "
              "would not take the write (named above); something else is "
              "standing where those members land")
    if history_deferred:
        # Its own line rather than a number folded into the two above: those
        # count Sessions and files carryon decided about, and this counts the
        # ones it declined to decide about because something else owns them.
        print(f"History: {history_deferred} file(s) externally owned and "
              "skipped (named above) - a link already holds each of those "
              "paths, and writing through one edits a tree carryon does not "
              "own (ADR-0007)")
    if local.unreadable:
        # The walk that answers "what does this machine already have" is the
        # one the union rule is decided against, so a directory it could not
        # list is a Session pull may take for new. Said out loud for that
        # reason rather than for the walk's own sake.
        print(f"History: {len(local.unreadable)} local path(s) this machine "
              "would not read while looking for what it already has - "
              "anything the Archive holds under one of them was compared "
              "against nothing:")
        for rel, why in local.unreadable:
            print(f"  !! ~/{printable(rel)} - {printable(why)}")
    _print_rekey_notes(rk_near, rk_bare, rk_non_utf8)
    setup_line = (f"Setup: {setup_written} file(s) written, "
                  f"{setup_skipped} externally owned and skipped")
    if setup_refused:
        # One counter for two kinds of refusal - an item a stored MANIFEST
        # should not have named, and a stored Setup this machine cannot use -
        # because the user's question is the same either way: what did the
        # Archive hold that did not land here, and why.
        setup_line += (f", {setup_refused} refused and not written (named "
                       "above)")
    print(setup_line)
    if setup_denied:
        # Said out loud beside the number, because the exit status below is
        # the thing that changed and a status nobody can see explained is one
        # somebody suppresses. The History is named because it is the half
        # that DID land: a Setup is a replacement and refusing one lays
        # nothing wrong down, while a History is an accumulation (ADR-0002)
        # and refusing it would strand a user whose Destination really did
        # lose a write.
        print("Setup: none of it landed - carryon was offered a stored Setup "
              "and would not use it (named above). `carryon pull` reports "
              "that in its exit status, the way `carryon push` reports a "
              "Setup it refused; the History above is unaffected.")
    for label, why in unrestorable:
        # The label is a catalogue key out of the Index and the why often
        # quotes one: both are strings this machine did not choose.
        print(f"  ?? {printable(label)}: {why}")
    if not apply:
        print("\nDry run. Re-run with --apply to lay this down.")
    if unopenable or unreadable_entries:
        # Last, and only after everything else has landed and been reported.
        # An encrypted object this machine cannot open, or an Index entry it
        # could not read, is not the ordinary refusal ADR-0009 made a report
        # line: the recovery key already opened the Index, so the Archive
        # holds something a key holder did not write, or wrote wrong. That is
        # worth an exit status - but not worth losing the rest of a pull
        # over, which is why it fires here and not where it was found.
        #
        # Both counted in one sentence, and separately, because the cures
        # differ: an object is re-pushed from a machine that still holds the
        # Session, while an entry is re-written by any push that names it.
        # The reasons are repeated here rather than left to the report above:
        # this is the message a script or a scrollback sees.
        count = len(unreadable_entries)
        parts = ([f"{len(unopenable)} object(s) the Archive would not open"]
                 if unopenable else [])
        if count:
            parts.append(f"{count} entr{'y' if count == 1 else 'ies'} in its "
                         "Index this machine could not read")
        raise SystemExit(
            f"pull finished with {' and '.join(parts)}. Everything else "
            "above landed; these were skipped, not written:\n"
            + "\n".join(f"  {printable(label)}: {why}"
                        for label, why in unopenable + unreadable_entries))
    # The same two numbers push uses for a Setup it refused, and for the same
    # reason: an exit status answers "did all of what you asked for happen".
    # A Setup is a replacement - it lands or it does not - so a stored Setup
    # carryon would not use is a pull that did less than it was asked, and
    # every check that catches one (a forged tag, a replayed tree, a Setup
    # nothing vouches for) used to print its refusal and report success. What
    # stays 0 is what ADR-0002 and ADR-0007 call the right answer: an Archive
    # with no Setup in it refused nothing, and a path deferred to whatever
    # already owns it is carryon working as documented.
    return (2 if apply else 1) if setup_denied else 0


# --- pair --------------------------------------------------------------------


def pair(args, home) -> int:
    home = pathlib.Path(home)
    cfg, dest = _open_destination(home)
    master = _require_master(home)
    spec = cfg["destination"]

    # A pairing hands over more than the key. The joining machine has no way
    # of its own to learn that this Archive has an Index, and that fact is
    # the only thing that stops a deleted one reading to it as ADR-0004's
    # keyless Archive - so the revision travels in the payload, which is
    # wrapped under the pairing secret and therefore not the Destination's to
    # read or edit.
    #
    # An Archive with no Index at all gets one here rather than handing the
    # new machine a permanent 'nothing to check against'. Sealing an empty
    # catalogue over a real one would be the harm _refuse_on_rollback exists
    # to prevent, which is why the removal check runs first: past it, either
    # this machine has never seen an Index here, or there is one to read.
    index = archive.load_index(dest, master)
    _refuse_on_index_removal(home, spec, index, "pair")
    if archive.index_is_absent(index):
        archive.save_index(dest, master, index)
    revision = archive.index_revision(index)
    _record_revision(home, spec, revision)

    code = new_pairing_code()
    parts = parse_pairing_code(code)  # the same split the joining machine does
    payload = json.dumps({"master": master.hex(),
                          "created_at": time.time(),
                          "index_revision": revision}).encode("utf-8")
    archive.put_pairing(dest, parts.locator,
                        crypto.wrap_key(payload, parts.secret))

    print("Pairing code - on the new machine, run:")
    print()
    print(f"    carryon init --join {code} --dest {cfg['destination']}")
    print()
    print("Use it once, within 24 hours: joining deletes the blob it names,")
    print("and after that carryon says so. The master key travels through the")
    print("Destination wrapped under the code (ADR-0005), so nothing passes")
    print("between the machines directly.")
    if isinstance(dest, destinations.GitDestination):
        # "It works once" was printed for every Destination and is false of
        # this one: a delete is a commit, and the blob stays in the
        # repository's history for anyone who can clone it. The one-time
        # property is about what the Archive SERVES, and git serves its past
        # as well.
        print()
        print("This Destination is a git repository, which keeps its history:")
        print("the deleted blob stays recoverable by anyone who can clone it,")
        print("so the code is single-use rather than single-read. Rotate the")
        print("recovery key if a code leaks.")
    return 0

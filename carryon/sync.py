"""init, push, pull, pair - the orchestration that moves a Snapshot.

This module exists so the two halves of a Snapshot stay distinct all the way
to the Destination: a Setup goes through the existing fail-closed capture
engine and lands as one sealed object per machine (ADR-0014), a History goes
through discover/pack/encrypt and lands as one object per Session (ADR-0003),
and only this file sequences the two. They are both encrypted now and still
distinct, because what separates them was never the storage - it is that a
Setup is a replacement and a History accumulates.

Sequences is now the whole of it. The rules each command asks live one module
down; what is left here is the four commands, the order they ask in, and the
few helpers that cannot leave without dragging a command with them. Where the
rules went, in CONTEXT.md's words:

    pairing         Pairing - the one-time code, its two halves that never do
                    each other's job, and the payload it wraps
    highwater       the High-water mark - how far into an Archive this
                    machine has read, and what that answers
    session         the Session - the smallest thing carryon moves as a unit,
                    settled member by member, one rule on both legs
    authentication  Authenticated - the tag over a Setup tree, and the one
                    freshness rule both Setup legs ask
    stored_setup    what a Destination serves as a Setup, turned into
                    something either leg can act on
    setup_out       a Setup on the way out - made machine-neutral, merged,
                    overlaid and sealed
    setup_in        a Setup on the way in - which stored item this machine
                    writes, and where

The one non-obvious decision, and the reason two of those helpers stayed: the
capture engine reads the shared adapter registry as a module global, so push
swaps the registry's *contents* in place - excludes applied, handpicked paths
added (ADR-0008) - for the duration of the capture. `capture` and
`is_installed` alias the same dict, so mutating it is the one change both
see, and the engine keeps its promise of never learning about any particular
caller. `_swapped_registry` and `_captured_state_reads` are that swap, they
are part of the sequencing rather than of any rule below, and cli.py reaches
for the first of them on this module.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import pathlib
import shutil
import tempfile
import time
from datetime import datetime, timezone

from . import (archive, bases, capture, choosing, config, crypto,
               destinations, external, history, keyring, prompting, rekey,
               setup_mark)
from .adapters import ADAPTERS, CATEGORIES, HISTORY, SETUP_CATEGORIES
from .destinations.base import printable

# --- what the commands ask, from the modules that own it ---------------------
#
# Bare names, never reached for through the module: the bodies these belong to
# left this file verbatim, so a command below still calls `_land_session(...)`
# the way it did when the function was defined above it.
#
# The second reason is the one that makes this band look wrong, and is why it
# is fenced rather than left among the ordinary imports. Callers say sync.X -
# cli.py for the commands and the registry helpers, the suite for forty-odd
# names in test bodies - so `_no_state`, `_setup_target`, `PAIR_ALPHABET` and
# their like are load-bearing here while nothing in this file mentions them.
# Looking unused is the normal state of this band. A name may go only when
# neither a body below calls it nor a caller says sync.X, which is a question
# about the whole tree and not one this file can answer about itself.
from .authentication import (_index_setup_entry,  # noqa: F401
                             setup_freshness)
from .highwater import (_STATE_REPORTED, _begin_command,  # noqa: F401
                        _index_removed_note, _load_state, _no_state,
                        _record_revision, _refuse_on_index_removal,
                        _refuse_on_rollback, _rollback_note, _seen_revision,
                        _state_path, _warn_on_rollback)
from .pairing import (LOCATOR_CHARS, PAIR_ALPHABET,  # noqa: F401
                      PAIRING_TTL_SECONDS, SECRET_CHARS, new_pairing_code,
                      parse_pairing_code, _pairing_payload)
from .session import (Notes, _canonical_members,  # noqa: F401
                      _choose_local_copy,
                      _extract_tree, _kept_local_members, _land_session,
                      _main_mismatch, _members_hash, _no_history_here,
                      _push_skip_reason, _rel_to_home, _report_deferred,
                      _report_other_copies, _report_refused,
                      _residue_mismatch, _residue_skip_reason, _restore_root,
                      _stored_members)
from .setup_in import (_declared_paths, _restore_setup_item,  # noqa: F401
                       _setup_target, _setup_writes)
from .setup_out import (_canon_home, _home_forms,  # noqa: F401
                        _neutralise_manifest, _neutralise_staged_setup,
                        _note_plaintext_removed, _push_partial_setup)
from .stored_setup import (_choose_setup_source,  # noqa: F401
                           _index_setup_names, _machine_name_refusal,
                           _no_setup_source_note, _setup_catalogue,
                           _stored_manifest, _vouched_machines)


# --- shared helpers ----------------------------------------------------------


def _utc_now() -> str:
    return (datetime.now(timezone.utc).isoformat(timespec="seconds")
            .replace("+00:00", "Z"))


def _subset(value, known, label):
    """A comma-separated flag value as a validated set, or None for 'all'.

    THE subset parser - cli.py's commands call this one too. It had a
    near-identical twin there, and two spellings of one rule is how
    `capture --category all` came to refuse a category the user never typed
    while push accepted the same flag: the twin expanded 'all' to the full
    set, history included, and capture rightly refuses history. One parser,
    and 'all' means None, because None is what every gate downstream
    already reads as "everything" - including the one that decides whether
    a push writes the Setup MAC - and a second spelling of "everything" is
    a fork nothing can pin (ADR-0010's shape, one flag over).

    `all` belongs to the CATEGORY vocabulary alone (ADR-0012 teaches it to
    the category flag, not to this function in general). An agent named on
    --agent is a key in a registry, and a registry key spelled 'all' must
    stay selectable the day an adapter claims it - so on that axis the word
    remains what it always was: an unknown name, refused with the list.

    An argument that names nothing - '', or the ',' an empty shell variable
    joins to - is refused rather than read. Empty used to mean everything
    here and an empty SET in cli.py's twin (every leg gated off, exit 0,
    nothing carried in either direction), and a wrapper with an unset
    variable deserves a sentence, not whichever of those the command it ran
    happened to consult.
    """
    if value is None:
        return None
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    if not chosen:
        raise SystemExit(
            f"--{label} names nothing - leave the flag out to mean "
            f"everything, or give it one of: {', '.join(known)}")
    all_ok = label == "category"
    unknown = chosen - set(known) - ({"all"} if all_ok else set())
    if unknown:
        raise SystemExit(
            f"unknown {label}: {', '.join(sorted(unknown))}\n"
            f"known {label}s: {', '.join(known)}")
    return None if all_ok and "all" in chosen else chosen


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


def _require_master(home, for_push: bool = False) -> bytes:
    """The master key, or a refusal naming what to do about not having one.

    `for_push` adds the cure that is only a cure on the way OUT. Since
    ADR-0014 a Setup is sealed like everything else, so a push with no key
    writes nothing at all - and a user who wanted a readable Setup rather than
    a published one has somewhere to put it that is not somebody else's
    storage. Saying so here is the difference between a refusal that reads as
    a dead end and one that names the thing they were actually after.
    """
    master = keyring.fetch_master(home=home)
    if master is None:
        cure = ("this machine holds no master key - run `carryon init`, or "
                "`carryon init --join CODE --dest SPEC` with a code from "
                "`carryon pair` on an already-paired machine, or `carryon "
                "init --recover` with your recovery key if no paired machine "
                "is left")
        if for_push:
            cure += (". Everything carryon carries is encrypted, a Setup "
                     "included, so there is nothing a keyless push could "
                     "write. For a Setup you can read, `carryon capture --out "
                     "DIR --apply` writes one here in the clear")
        raise SystemExit(cure)
    return master


def _print_rekey_notes(near: int, bare: int, non_utf8: int) -> None:
    """The Re-keying counts the design says are reported, never acted on."""
    if near:
        print(f"Re-keying: {_n(near, 'path')} matched this home folder only "
              "when ignoring case, left as written")
    if non_utf8:
        print(f"Re-keying: {_n(non_utf8, 'file')} not UTF-8, carried "
              "unchanged")
    if bare:
        print(f"Re-keying: {bare} bare '~' with nothing after it, left as "
              "written")


# --- init --------------------------------------------------------------------


def init(args, home) -> int:
    home = pathlib.Path(home)
    if keyring.fetch_master(home=home) is not None:
        raise SystemExit(
            "this machine already holds a master key - it already opens an "
            "Archive. Remove it deliberately (keychain service 'carryon') "
            "before running init again.")

    # Both legs that take a key ahead of the machine-name check below,
    # because a machine that kept its config takes its name from there and
    # not from the hostname - a hostname no name may be must not block it.
    if getattr(args, "recover", False):
        return _recover(args, home)
    if args.join:
        return _join(args, home)

    machine = _machine_name(args)

    spec = args.dest
    if not spec:
        # With a terminal on both ends, init asks; without one it prints the
        # candidates and exits exactly as it always did (ADR-0011). The old
        # third way - taking a lone candidate silently - is gone: nothing is
        # decided for the user, including the case with one obvious answer.
        candidates = destinations.detect_candidates(home)
        if prompting.available():
            spec = choosing.choose_destination(home, candidates)
        else:
            lines = [f"  {s:<44} {label}" for s, label in candidates]
            listing = "\n".join(lines) if lines else "  (none found)"
            raise SystemExit(
                "pick a Destination with --dest SPEC. Candidates on this "
                "machine:\n" + listing
                + f"\nA spec is {destinations.SPEC_FORMS}.")
    dest = destinations.from_spec(spec, home)  # validates the spec early
    # Both checks before anything is minted (ADR-0011). A refusal here has to
    # cost neither a key nor a config, for the same reason a refused machine
    # name does: `init` stores a master key before it saves anything else, so
    # the next run of the command it tells the user to make would refuse.
    choosing.confirm_fresh(dest)

    display, master = crypto.new_recovery_key()
    keyring.store_master(master, home=home)
    cfg = config.default_config()
    cfg["destination"] = spec
    cfg["machine"] = machine
    path = config.save(cfg, home)

    choosing.report(dest)
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


def _machine_name(args, fallback=None) -> str:
    """This machine's name for a fresh config, or a refusal naming why not.

    Here rather than at `config.save`, which is where `validate` would have
    caught it: by then this leg has minted and stored a master key (so a
    second `init` refuses, saying this machine already holds one), the join
    leg has already DELETED the pairing blob, which is one-time by design
    (ADR-0005), and the recover leg has asked for the recovery key. A refused
    name must cost none of them.

    `fallback` is the legs that take a key (`_existing_config`): a config
    that names no Destination yet may still name the machine, and that is
    the user's word over the hostname's.
    """
    machine = args.machine or fallback or config.default_config()["machine"]
    why = config.machine_name_refusal(machine)
    if why is not None:
        raise SystemExit(
            f"machine name {printable(machine)!r}: {why}."
            + ("" if args.machine else
               " That is this machine's hostname; name it explicitly with "
               "`carryon init --machine NAME`."))
    return machine


_NO_RECOVERY_KEY = ("nothing was entered - a paste that did not take; type "
                    "or paste the recovery key again")


def _ask_recovery_key() -> bytes:
    """The master key, from a recovery key typed at the terminal.

    Re-asked rather than refused on a parse error: the parse is a pure string
    check, so a typo costs nothing yet, and making someone re-run the command
    to correct one character of 32 would cost them the Destination dialogue
    as well. End of input cancels, as every question does.
    """
    while True:
        typed = prompting.secret("recovery key", blank=_NO_RECOVERY_KEY)
        try:
            return crypto.parse_recovery_key(typed)
        except crypto.CryptoError as exc:
            print(f"{exc} - try again")


def _same_destination(given: str, stored: str, home) -> bool:
    """Whether two specs name one place, not whether they are one string.

    The chooser stores '~/...' verbatim, which is what keeps an Archive
    machine-neutral, and a shell expands '~' before carryon ever sees a
    `--dest` - so the same Destination routinely arrives spelt two ways.
    Each spec is asked of from_spec, the one function that owns what a spec
    means, and compared by the line that names the place it resolved to.
    """
    if given == stored:
        return True
    return (destinations.from_spec(given, home).describe()
            == destinations.from_spec(stored, home).describe())


def _existing_config(args, home, leg: str, run: str, not_it: str,
                     unspent: str):
    """This machine's config, as a leg that takes a key keeps it.

    `--recover` and `--join` make the same move - a key arrives on a machine
    that holds none - and the machine they usually arrive on is one whose
    keychain entry is gone and whose config.json is not (ADR-0004's
    2026-10-18 amendment, and ADR-0005's of the same date). A fresh config
    would undo its handpicks and, under another name, make it a new machine
    in the Archive. So a config that names a Destination is kept whole, and
    a flag that disagrees with it is refused; one that names none is built
    on; one that will not load is refused rather than written over.

    Returns the config, whether it is kept, the spec (None when nothing has
    named one yet), the machine name and the config's path. Everything here
    is local, so each leg calls it before its key, its code or the network
    can be spent.
    """
    path = config.config_path(home)
    try:
        cfg = config.load(home)
    except SystemExit as exc:
        # load's own cure is written for plain `init`, which writes a fresh
        # config over the file. These legs keep the config rather than
        # writing one, so that cure would reach this same load and refuse
        # again.
        raise SystemExit(
            f"{exc}\n{leg} keeps this machine's config rather than "
            f"writing a new one, so fix {path} or remove it, then run "
            f"`{run}` again. {unspent}")
    if not cfg["destination"]:
        # A config with no Destination may still hold handpicks and a name,
        # so it is built on rather than replaced.
        return (cfg, False, args.dest,
                _machine_name(args, fallback=cfg["machine"]), path)
    spec, machine = cfg["destination"], cfg["machine"]

    def disagrees(flag, given, have):
        return SystemExit(
            f"{flag} {printable(given)!r} disagrees with this machine's "
            f"config, which says {printable(have)!r} ({path}). {leg} "
            "puts the key back and keeps the config as it is, so changing "
            f"either is not {not_it}: drop {flag}, or edit that file "
            f"first. {unspent}")
    if args.dest is not None and not _same_destination(args.dest, spec, home):
        raise disagrees("--dest", args.dest, spec)
    if args.machine is not None and args.machine != machine:
        raise disagrees("--machine", args.machine, machine)
    return cfg, True, spec, machine, path


def _take_key(home, cfg, kept, spec, machine, master, revision) -> None:
    """Store what a leg that takes a key has proved, config first.

    A config with no key is a machine a re-run takes the key back on, by
    the kept-config path; a key with no config is one every later `init`
    refuses as already holding a key. So a config that is not kept is
    written before the key (the recover leg's review finding 1). The
    revision goes under the config's spelling of the spec, which is the one
    every later push and pull looks the mark up by.
    """
    if not kept:
        fresh = dict(cfg)
        fresh["destination"] = spec
        fresh["machine"] = machine
        config.save(fresh, home)
    keyring.store_master(master, home=home)
    _record_revision(home, spec, revision)


def _say_config(kept, path) -> None:
    if kept:
        print(f"kept the existing config at {path}")
    else:
        print(f"config written to {path}")


def _recover(args, home) -> int:
    """`init --recover`: take a recovery key back (ADR-0004's 2026-10-18
    amendment).

    The order is the decision. A terminal first, because the key is asked
    for and never read from anywhere else. Then everything that can be
    refused without the key - a config that will not load, one the flags
    disagree with, a machine name no Archive may hold. Then the key,
    re-asked until it parses. Then the Destination, its probe, and the
    Index the key has to open - re-asking the key, against the same Index,
    until one does. Only after that is anything stored, so every refusal
    on the way leaves this machine exactly as it was.
    """
    _begin_command()
    if not prompting.available():
        raise SystemExit(
            "--recover needs a terminal: a recovery key is typed by a person, "
            "at a prompt that does not echo, and carryon never reads one from "
            "a pipe or an argument. Nothing was stored.")

    cfg, kept, spec, machine, path = _existing_config(
        args, home, "Recovery", "carryon init --recover", "recovery",
        "Nothing was stored.")

    print("Type the recovery key `carryon init` printed when this Archive "
          "was made. It is not echoed.")
    master = _ask_recovery_key()
    if spec is None:
        spec = choosing.choose_destination(
            home, destinations.detect_candidates(home))
    dest = destinations.from_spec(spec, home)
    choosing.confirm_recovering(dest)

    # The proof, read once: the bytes the key opens are the bytes the
    # catalogue comes from. Asked of the seal directly rather than read off
    # load_index's refusal, which answers 'wrong key' and 'not carryon's
    # Index' in one sentence - and here the first is the likely one, and a
    # key that parses but does not open is most often one slipped letter,
    # which must not cost the Destination dialogue above.
    blob = dest.read(archive.INDEX_KEY)
    if blob is None:
        index = archive.load_index(dest, master)
    else:
        while True:
            try:
                raw = crypto.unseal(blob, master, archive.INDEX_LABEL)
                break
            except crypto.CryptoError:
                print(f"that is not the recovery key for the Archive at "
                      f"{dest.describe()}: its Index will not open under it. "
                      "It may be a key from another `carryon init`, or one "
                      "letter off. Nothing has been stored - type it again, "
                      "or press Ctrl-D to stop.")
                master = _ask_recovery_key()
        index = archive.parse_index(raw)
        # The verdict, as soon as it is known and before anything else is
        # said (ADR-0011's 2026-10-19 amendment): in a real run it came last,
        # under the probe report, and read as the key not working. After the
        # parse, which can still refuse, so "accepted" never precedes a
        # refusal (review finding 1).
        print(f"recovery key accepted: it opened the Archive's Index at "
              f"{dest.describe()}.")

    removed = _index_removed_note(home, spec, index)
    if removed is not None:
        # Not _refuse_on_index_removal: its way out ends in a push, which a
        # machine with no key cannot make.
        raise SystemExit(
            f"refusing to recover: {removed}\nRestore an earlier copy of the "
            "Archive (a git Destination keeps one in its history), then run "
            "`carryon init --recover` again. Nothing was stored.")
    if archive.index_is_absent(index):
        if archive.occupied(dest):
            raise SystemExit(
                f"there is no Index at {dest.describe()}, but there are "
                "carryon objects there - an Archive whose catalogue is "
                "missing. The key cannot be proved against it, and nothing "
                "on a recovered machine could use that Archive until its "
                "Index is back. Restore an earlier copy of the Archive (a "
                "git Destination keeps one in its history), then run "
                "`carryon init --recover` again. Nothing was stored.")
        raise SystemExit(
            f"nothing to recover at {dest.describe()}: there is no Archive "
            "there to prove this recovery key against. Check the spec "
            "against the one your other machines use (a synced folder may "
            "still be syncing). To start a new Archive, run `carryon init` "
            "without --recover. Nothing was stored.")
    # A rollback warns rather than refuses: recovery writes nothing to the
    # Archive a stale catalogue could damage, and refusing would strand a
    # user whose Destination really did lose a write - pull's reasoning.
    _warn_on_rollback(home, spec, index)

    _take_key(home, cfg, kept, spec, machine, master,
              archive.index_revision(index))
    choosing.report(dest)
    print(f"recovered as {machine!r}: this machine opens the Archive again")
    _say_config(kept, path)
    return 0


def _join(args, home) -> int:
    # First, and before the dialogue below: parse_pairing_code is a pure
    # string check whose whole purpose is that a mangled code fails without
    # reaching the Destination. Asked after the prompts, it let a typo walk
    # the user through the Provider menu, put a live credential in
    # rclone.conf and create a billable bucket - and only then say the code
    # was never a code.
    code = parse_pairing_code(args.join)
    # Then the config, still before anything that can spend the code: the
    # code is one-time, so a refusal after the delete below would cost the
    # user the code as well (ADR-0005's 2026-10-18 amendment).
    unspent = "Nothing was stored, and the code is still good."
    cfg, kept, spec, machine, path = _existing_config(
        args, home, "Joining", "carryon init --join CODE",
        "joining this machine back", unspent)
    # Where the spec came from, for the refusals below that would otherwise
    # tell the user to check a spec they never typed (review finding 2).
    from_config = (f" No --dest was given, so carryon looked at "
                   f"{printable(spec)!r}, the Destination this machine's "
                   f"config names ({path}). If the code is for another "
                   "Archive, edit that file first."
                   if kept and args.dest is None else "")
    if not spec:
        # The same prompts as the other leg, then the code is spent
        # (ADR-0011): the second machine is the one that ADR is about, and
        # leaving it as the only path still needing --dest typed by hand
        # would put the friction exactly where it hurts.
        if prompting.available():
            spec = choosing.choose_destination(
                home, destinations.detect_candidates(home))
        else:
            raise SystemExit(
                "--join needs --dest: a pairing code travels through the "
                "Destination (ADR-0005), so name the same one the paired "
                f"machine uses. {unspent}")
    dest = destinations.from_spec(spec, home)

    # Read and delete are two steps, deliberately: the blob must survive a
    # failed unwrap AND a tampered payload, so the one-time delete happens
    # below, only once _pairing_payload has proved the code opened it.
    key = archive.pairing_key(code.locator)
    blob = dest.read(key)
    if blob is None:
        if not dest.list(archive.PREFIX + "/"):
            raise SystemExit(
                f"no Archive at {spec!r} - carryon found nothing "
                "there at all. Check the spec against the one `carryon "
                "pair` printed on the paired machine; a synced folder may "
                "also still be syncing." + from_config)
        raise SystemExit(
            "no pairing blob for that code - mistyped, already used, or "
            "never minted. Run `carryon pair` on a paired machine for a "
            "fresh one." + from_config)
    # The blob answered the join leg's occupancy question, so what is left
    # is reachability (ADR-0011) - and it runs BEFORE the unwrap because the
    # delete below is one-time: a code spent against a Destination this
    # machine cannot write to costs the code and leaves the machine unable
    # to push. A probe that fails here leaves the blob in place.
    choosing.confirm_joining(dest)
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
    # did not make - and "burnt" is the whole of the one-time property. The
    # probe above wrote and deleted its own object, and confirmed only its
    # own delete: a store that lies selectively about THIS key is exactly
    # what nothing upstream can have noticed. Said here rather than left to
    # the report line the layer already prints, because what it MEANS is
    # this leg's: the code the user is holding still opens the Archive.
    burnt = dest.delete(key)
    # created_at is a finite float by now, checked above the delete: an
    # expired code is a real code and is burnt, a payload carryon did not
    # write is refused and left in place.
    if time.time() - payload["created_at"] > PAIRING_TTL_SECONDS:
        raise SystemExit(
            "that pairing code expired (codes live 24 hours) and has now "
            "been deleted - mint a fresh one with `carryon pair`")
    # After the expiry check, so that "accepted" never precedes a refusal of
    # the same code (ADR-0011's 2026-10-19 amendment).
    print(f"pairing code accepted: it unwrapped the key the paired machine "
          f"left at {dest.describe()}.")

    # What this machine knows about the Archive before it has ever read it:
    # the revision the pairing machine saw. It arrived inside the wrap, so
    # the Destination could not have written it, and from here on an Archive
    # serving no Index is a removal rather than a fresh one (ADR-0009).
    # The pairing machine read the Index to mint the code, so a mark this
    # machine kept that is ahead of it is a rollback - --recover warns
    # there, and so does this (review finding 1), rather than leave the
    # next push to be the first to say so.
    revision = payload["index_revision"]
    _warn_on_rollback(home, spec, {"revision": revision})
    _take_key(home, cfg, kept, spec, machine, payload["master_key"], revision)
    choosing.report(dest)
    print(f"paired as {machine!r}: this machine now opens the Archive")
    _say_config(kept, path)
    if not burnt:
        print(f"warning: the pairing blob at {printable(key)} is still in the "
              "Archive, so that code is STILL LIVE until it expires (24 "
              "hours) and anyone who has seen it can join with it. Remove "
              "that object by hand, or treat the code as known.")
    return 0


# --- push --------------------------------------------------------------------


def _captured_state_reads(effective: dict, want_agents, categories,
                          home) -> list:
    """(item src, path it reads, why) for every path this push's Setup half
    would read that a Setup must not carry. Empty means there is no such path.

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


# Why push left a Session or project alone, where no comparison said so.
VANISHED = "a file in it disappeared while it was being read"
UNREADABLE_RECORD = ("this machine can't read the Archive's record for it, "
                     "so there is nothing to compare against")


def _n(count: int, noun: str, plural: str = None) -> str:
    """'1 Session', '2 Sessions'."""
    return f"{count} {noun if count == 1 else (plural or noun + 's')}"


def push(args, home) -> int:
    home = pathlib.Path(home)
    _begin_command()
    apply = bool(getattr(args, "apply", False))
    verbose = bool(getattr(args, "verbose", False))
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

    # Every push needs the key, History or not (ADR-0014): with both halves
    # sealed there is nothing a keyless push could write. A machine whose
    # keychain entry is gone pairs again rather than publishing in the clear.
    master = _require_master(home, for_push=True)

    print(f"Pushing to {dest.describe()}\n" if apply
          else f"Dry run: would push to {dest.describe()}\n")

    # Before a byte is written anywhere, Setup half included: a push onto an
    # Index this machine has already seen past destroys catalogue entries
    # rather than merely hiding them.
    index = archive.load_index(dest, master)
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
    # Read before the mark below is written, because that write replaces a
    # state.json that would not read, and with it the warning that the
    # Bases in it were lost.
    known_bases = bases.load(home, cfg["destination"]) if do_history else {}
    if apply:
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
    else:
        note = (_index_removed_note(home, cfg["destination"], index)
                or _rollback_note(home, cfg["destination"], index))
        if note:
            print(f"warning: {note}\n--apply will refuse until that is "
                  "sorted out.\n")

    # Setup half: the fail-closed capture engine, verbatim (ADR-0001), behind
    # one gate the engine cannot apply for itself - what it may read at all.
    # Staged under ~/.carryon rather than a TemporaryDirectory so a refusal
    # can honour capture's promise that the written files are left in place
    # for inspection.
    setup_code = 0
    setup_pushed = False
    # Filled by the capture with the digest the Setup mark records
    # (ADR-0015); empty when no capture ran.
    setup_seen = {}
    setup_withheld = setup_near = 0
    setup_undecodable = []
    setup_capture = None
    # One value this push writes into the Setup's tag and into the encrypted
    # Index entry beside it, so a pull can tell the tree this push meant from
    # every earlier tree whose tag also verifies (crypto.new_stamp).
    setup_stamp = crypto.new_stamp()
    state_reads = (_captured_state_reads(effective, want_agents,
                                         setup_categories, home)
                   if setup_categories else [])
    if state_reads:
        # Before the capture engine runs, so nothing is copied even locally.
        # ADR-0008's rule is about what a capture may READ, so sealing the
        # Setup (ADR-0014) does not answer it: a key carried into the Archive
        # is sealed under ITSELF, which every machine paired here can open.
        # Named in the report below.
        setup_code = 2 if apply else 1
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
        # A Setup is captured in the clear before it is published, so the
        # directory it is staged in has to be carryon's own. Named in the
        # report below; the History half is unaffected.
        setup_code = 2 if apply else 1
    elif staging_root is not None:
        staging = pathlib.Path(tempfile.mkdtemp(prefix="setup-",
                                                dir=str(staging_root)))
        try:
            # The silent half of the capture engine: the state check it would
            # make is the one asked just above, and its report is capture's
            # own, worded for a Setup in the clear (ADR-0016).
            with _swapped_registry(effective):
                setup_capture, manifest = capture.collect(
                    staging, not apply, want_agents, setup_categories, home,
                    digest_into=setup_seen)
            if apply:
                manifest, setup_withheld, setup_near, setup_undecodable = \
                    _neutralise_staged_setup(staging, manifest, home)
                if (setup_categories == set(SETUP_CATEGORIES)
                        and want_agents is None):
                    # The stamp goes INTO staging before the pack, so the tree
                    # and the value that says which tree it is are sealed
                    # together in one object (ADR-0014).
                    (staging / archive.SETUP_STAMP_NAME).write_bytes(
                        archive.stamp_bytes(now, setup_stamp))
                    _note_plaintext_removed(
                        machine,
                        archive.put_setup(dest, master, machine, staging))
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
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # History half: incremental per Session against the Index (ADR-0003).
    sessions_pushed = sessions_unchanged = sessions_skipped = 0
    residues_pushed = residues_unchanged = residues_skipped = 0
    agreed_bases = {}   # {cwd: {member: canonical bytes}} the Archive now holds
    credential_files = []
    missing_cwd = ()
    withheld_history = ()
    unreadable_history = ()
    unnamable_history = ()
    rk_near = rk_bare = rk_non_utf8 = 0
    index_changed = False
    # (label, why) for each Session and project left alone, named together
    # in the report rather than as they are met.
    session_skips, residue_skips = [], []

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
            label = f"{session.uuid} ({session.agent})"
            if members is None:
                sessions_skipped += 1
                session_skips.append((label, VANISHED))
                continue
            th = _members_hash(members)
            if not archive.needs_push(index, session.uuid, th):
                sessions_unchanged += 1
                continue
            if session.uuid in unreadable_records["sessions"]:
                # Its stored copy has nothing to be compared against.
                sessions_skipped += 1
                session_skips.append((label, UNREADABLE_RECORD))
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
                    session_skips.append((label, why))
                    continue
            try:
                tar_bytes, report = history.pack_session(session, home)
            except history.MemberUnreadable as exc:
                sessions_skipped += 1
                session_skips.append((label, str(exc)))
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
                residue_skips.append((printable(cwd), VANISHED))
                continue
            th = _members_hash(members)
            if cwd in unreadable_records["projects"]:
                # Same rule as the Session loop above, and a residue needs it
                # at least as much: memory files accumulate, so the copy this
                # push would write over is the only one that holds what the
                # other machines wrote.
                residues_skipped += 1
                residue_skips.append((printable(cwd), UNREADABLE_RECORD))
                continue
            entry = index["projects"].get(cwd)
            if entry is not None and entry.get("tree_hash") == th:
                residues_unchanged += 1
                # The same tree on both sides is an agreement about every
                # file in it, and recording it is how a machine that pushed
                # before the Base existed gets one before its first edit.
                agreed_bases[cwd] = members
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
                why = _residue_skip_reason(dest, master, cwd, entry, members,
                                           known_bases.get(cwd))
                if why is not None:
                    residues_skipped += 1
                    residue_skips.append((printable(cwd), why))
                    continue
            try:
                tar_bytes, report = history.pack_session(residue, home)
            except history.MemberUnreadable as exc:
                residues_skipped += 1
                residue_skips.append((printable(cwd), str(exc)))
                continue
            credential_files += [f"{printable(cwd)}: {rel}"
                                 for rel in report.credential_members]
            rk_near += report.near_misses
            rk_bare += report.bare_tokens
            rk_non_utf8 += report.non_utf8
            residues_pushed += 1
            if not apply:
                continue
            # Hashed over what was PACKED, not over the read above: a live
            # agent writing between the two reads would otherwise leave an
            # Index whose tree_hash describes bytes the object does not hold,
            # and the binding check would then refuse that project on both
            # legs for good.
            packed = _stored_members(tar_bytes)
            meta = {"agent": residue.agent, "machine": machine,
                    "tree_hash": _members_hash(packed), "pushed_at": now}
            archive.put_project(dest, master, cwd, tar_bytes, meta)
            index["projects"][cwd] = meta
            index_changed = True
            agreed_bases[cwd] = packed

    if apply and setup_pushed:
        # The seal already says a key holder wrote this Setup (ADR-0014).
        # What the Index has to carry is the question no seal answers: WHICH
        # of the Setups that open is the current one.
        index["setups"][machine] = {"pushed_at": now, "stamp": setup_stamp}
        index_changed = True
    if apply and index_changed:
        archive.save_index(dest, master, index)
        _record_revision(home, cfg["destination"],
                         archive.index_revision(index))
    if apply and setup_pushed:
        # After the Index is sealed, so the mark never names a stamp the
        # Index does not. A partial Setup sealed a new stamp over part of
        # the stored one, so no digest of this machine's whole Setup
        # describes it, and the mark goes rather than lies (ADR-0015).
        setup_mark.settle(
            home, cfg["destination"], setup_stamp,
            setup_seen.get("digest")
            if setup_mark.whole(setup_categories, want_agents) else None)
    if apply:
        # After the Index is sealed, so a Base never records an agreement
        # with a stored tree the Index does not name. A push replaces the
        # stored tree whole, so it replaces the project's Bases whole too.
        bases.record(home, cfg["destination"],
                     {cwd: _member_bases(members)
                      for cwd, members in agreed_bases.items()},
                     replace=True)

    # The report, in one place, so the two halves stay side by side. A
    # summary of what a user acts on, with the detail behind --verbose
    # (ADR-0016).
    verb = "pushed" if apply else "to push"
    if not setup_categories:
        # The same line pull prints for the same skip: a leg that merely
        # vanishes reads as a push that quietly carried the Setup.
        print(SETUP_NOT_CHOSEN)
    elif state_reads:
        print("Setup: not pushed - carryon won't carry these paths:")
        for _src, rel, why in state_reads:
            print(f"  ~/{printable(rel)}: {why}")
        print("  Remove the link, or drop the path from `carry`.")
    elif why_staging is not None:
        print(f"Setup: not pushed - carryon can't stage it: "
              f"{printable(why_staging)}")
    elif setup_capture is not None:
        _print_setup_summary(verb, setup_capture, manifest, setup_undecodable,
                             setup_withheld, setup_near, verbose)
    if do_history:
        def part(count, noun, plural, unchanged, skipped):
            extra = f"{unchanged} unchanged" + (f", {skipped} skipped"
                                                if skipped else "")
            return f"{_n(count, noun, plural)} {verb} ({extra})"
        print("History: "
              + part(sessions_pushed, "Session", None, sessions_unchanged,
                     sessions_skipped) + ", "
              + part(residues_pushed, "project memory", "project memories",
                     residues_unchanged, residues_skipped))
        if credential_files:
            # Counted, not named: a Transcript is not something a user edits.
            print(f"  possible secrets in "
                  f"{_n(len(credential_files), 'History file')}, carried "
                  "encrypted" + (":" if verbose else " (--verbose names them)"))
            if verbose:
                for label in credential_files:
                    print(f"    {label}")
        for skips, noun, plural in ((session_skips, "Session", None),
                                    (residue_skips, "project memory",
                                     "project memories")):
            if skips:
                print(f"Skipped {_n(len(skips), noun, plural)} rather than "
                      "overwrite the Archive's copy:")
                for label, why in skips:
                    print(f"  {label}: {why}")
        if withheld_history:
            print(f"{_n(len(withheld_history), 'History path')} not carried - "
                  "they lead to carryon's own key or config:")
            for rel in withheld_history:
                print(f"  ~/{printable(rel)}")
        if unreadable_history:
            print(f"{_n(len(unreadable_history), 'History path')} couldn't be "
                  "read, so nothing under them was carried:")
            for rel, why in unreadable_history:
                print(f"  ~/{printable(rel)}: {printable(why)}")
        if unnamable_history:
            # The Archive is what cannot hold these, not this machine.
            print(f"{_n(len(unnamable_history), 'History path')} can't be "
                  "stored in an Archive, so they stay on this machine:")
            for rel, why in unnamable_history:
                print(f"  ~/{printable(rel)}: {printable(why)}")
    if index_refused:
        # A push seals the catalogue again, so these are the entries it
        # carried through untouched rather than deleted (archive.save_index).
        count = len(index_refused)
        print(f"{_n(count, 'entry', 'entries')} in the Archive's Index "
              "couldn't be read - carried through unchanged:")
        for refusal in index_refused:
            print(f"  {printable(str(refusal.key))}: {refusal.why}")
    if do_history and missing_cwd:
        print(_no_cwd_line(len(missing_cwd), verbose))
        if verbose:
            for rel in missing_cwd:
                print(f"  ~/{printable(rel)}")
    if do_history and verbose:
        _print_rekey_notes(rk_near, rk_bare, rk_non_utf8)
    if not apply:
        print("\nDry run - add --apply to push")
    return setup_code


SETUP_NOT_CHOSEN = "Setup: skipped - no Setup category was chosen"


def _print_named(header: str, items: list, noun: str,
                 plural: str = None) -> None:
    """A count and the things behind it, or nothing when there are none."""
    if items:
        print(header.format(n=_n(len(items), noun, plural)))
        indent = "    " if header.startswith("  ") else "  "
        for item in items:
            print(indent + item)


def _no_cwd_line(count: int, verbose: bool) -> str:
    """Transcripts, and project folders holding only memory, with nothing to
    say where the project lives, so a pull elsewhere has nowhere to put
    them."""
    if count == 1:
        return ("1 History path has no recorded working directory, so it "
                "can't be restored on another machine"
                + (":" if verbose else " (--verbose lists it)"))
    return (f"{count} History paths have no recorded working directory, so "
            "they can't be restored on another machine"
            + (":" if verbose else " (--verbose lists them)"))


def _home_path_of(staged: str, manifest: dict) -> str:
    """A file's path under $HOME, from its path in the staged Setup: the
    item whose landing path holds it says where it came from."""
    for entry in manifest["agents"].values():
        for item in entry.get("items", ()):
            dst, src = item.get("dst"), item.get("src")
            if not (isinstance(dst, str) and isinstance(src, str)):
                continue
            if staged == dst:
                return src
            if staged.startswith(dst.rstrip("/") + "/"):
                return src.rstrip("/") + staged[len(dst.rstrip("/")):]
    return staged


def _print_setup_summary(verb, cap, manifest, undecodable, withheld, near,
                         verbose) -> None:
    """The Setup half of push's report: what went, and anything that did not
    go the way it was declared."""
    names = ", ".join(entry["name"] for entry in manifest["agents"].values())
    print(f"Setup: {verb}, encrypted ({names or 'nothing set up here'})")
    if verbose:
        for line in cap.log:
            if line:
                print(line)
    undecodable = [_home_path_of(rel, manifest) for rel in undecodable]
    for rel, why in cap.skipped:
        print(f"  not carried: {printable(rel)} - {why}")
    if len(undecodable) == 1:
        print(f"  not carried: 1 binary file ({printable(undecodable[0])}) - "
              "a Setup carries text files only")
    elif undecodable:
        print(f"  not carried: {len(undecodable)} binary files - a Setup "
              "carries text files only:")
        for rel in undecodable:
            print(f"    {printable(rel)}")
    for rel in cap.declined:
        print(f"  left out: {printable(rel)} (development files)")
    for entry in manifest["agents"].values():
        if entry["layout_drift"]:
            print(f"  {entry['name']}: "
                  f"{_n(len(entry['layout_drift']), 'expected path')} "
                  "missing - run `carryon doctor`")
    if cap.findings:
        print(f"  possible secrets in {_n(len(cap.findings), 'file')}, "
              "carried encrypted:")
        for label, hits in cap.findings:
            print(f"    {printable(label)} ({', '.join(hits)})")
    if verbose and withheld:
        # A MANIFEST path that names a directory on this machine; RESTORE.md
        # says so where it was (ADR-0006).
        print(f"  {_n(withheld, 'manifest path')} left out - "
              "they name a folder on this machine")
    if verbose and near:
        print(f"  {_n(near, 'path')} matched this home folder only when "
              "ignoring case, left as written")


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


def _member_bases(members: dict) -> dict:
    """{member: Base} for a tree of canonical bytes."""
    return {rel: bases.digest(data) for rel, data in members.items()}


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


def _settle_pulled_setup(home, spec, effective, staging, stamp, whole,
                         short) -> None:
    """The Setup mark a pull leaves, after every write, so the digest is of
    this machine's Setup as the pull left it and the stamp is the Index's
    for the Setup it laid down (ADR-0015). Part of a Setup leaves no mark.
    A Setup that did not land whole, or a machine holding Setup files the
    laid-down one never had, keeps the stamp with a digest that matches
    nothing: this machine has seen that Setup and does not hold it, which is
    what a push would publish."""
    if not whole:
        setup_mark.settle(home, spec, None, None)
        return
    digest, paths = setup_mark.capture_here(home, effective)
    if digest is not None:
        stored = {p.relative_to(staging).as_posix()
                  for p in staging.rglob("*") if p.is_file()}
        if short or set(paths) - stored:
            digest = setup_mark.UNSETTLED
    setup_mark.settle(home, spec, stamp, digest)


def pull(args, home) -> int:
    """Lay the Archive down here: union the History, replace the Setup
    (ADR-0002), restricted to `--category` where one was given (R6).

    The exit code means "something landed - or, on a dry run, was planned -
    that a person has to deal with", on one convention: `2 if apply else 1`,
    0 otherwise. Two things qualify (ADR-0012). A stored Setup carryon was
    offered and would not use (`setup_denied` below), which has been the code
    since the authentication rounds. And now a divergence - a Session whose
    mains have forked, a member inside one, or a residue file, wherever
    neither copy extends the other and the incoming one is filed under
    ~/.carryon/conflicts/. A divergence always printed a line and exited 0,
    which was survivable while pull was something you watched and is not
    survivable under `sync`, a command built to be run in a loop: a report
    nobody reads is not a report. An object the Archive would not open still
    ends in the SystemExit above the return, its own channel.
    """
    home = pathlib.Path(home)
    _begin_command()
    apply = bool(getattr(args, "apply", False))
    force = bool(getattr(args, "force", False))
    # Per-item lines go through `say`, which prints only under --verbose;
    # what a user acts on is collected and named in the summary (ADR-0016).
    notes = Notes(bool(getattr(args, "verbose", False)))
    say = notes.say
    maps = _parse_maps(getattr(args, "map", []))
    # The same three lines push derives, because `--category` means the same
    # thing on both legs (R6): `history` gates the Session AND residue legs -
    # a residue is part of a History - and the Setup leg restores only the
    # stored items whose category was chosen. No flag is everything, exactly
    # as before the flag existed.
    want_categories = _subset(getattr(args, "category", None), CATEGORIES,
                              "category")
    setup_categories = (set(SETUP_CATEGORIES) if want_categories is None
                        else want_categories & set(SETUP_CATEGORIES))
    do_history = want_categories is None or HISTORY in want_categories
    cfg, dest = _open_destination(home)
    master = _require_master(home)
    index = archive.load_index(dest, master)
    # Before the banner, because nothing has been read or written yet and the
    # refusal is the whole of what this pull has to say.
    _refuse_on_index_removal(home, cfg["destination"], index, "pull")

    print(f"Pulling from {dest.describe()}\n" if apply
          else f"Dry run: would pull from {dest.describe()}\n")
    _warn_on_rollback(home, cfg["destination"], index)
    # Read before the mark is raised, since recording this pull's revision
    # would make the rollback invisible to the Setup half below.
    rolled_back = _rollback_note(home, cfg["destination"], index)
    # Before the mark is written, as on push: that write replaces a
    # state.json that would not read.
    known_bases = bases.load(home, cfg["destination"]) if do_history else {}
    # One directory per pull for every file it replaces, Setup items and
    # memory files alike, so everything one run wrote over is in one place.
    backup_root = _backup_root(home)
    if apply:
        # A dry run is a plan and writes nothing under $HOME, high-water
        # mark included; it still reads the mark to warn.
        _record_revision(home, cfg["destination"],
                         archive.index_revision(index))

    effective = _effective_adapters(cfg, home)
    # A pull not asked for the History reads none of it, here or from the
    # Destination: the walk exists to feed the union rule, and the loops the
    # rule runs in are gated on the same flag below.
    local = (history.discover(home, list(effective.values()))
             if do_history else None)
    # Every copy per UUID, not one: a machine can hold the same Session in two
    # project dirs, and which of them the incoming tree lands on is a question
    # about the recorded cwd rather than about discovery order.
    local_by_uuid = {}
    if local is not None:
        for session in local.sessions:
            local_by_uuid.setdefault(session.uuid, []).append(session)

    restored = replaced = updated = unchanged = conflicts = 0
    diverged_sessions = []  # (uuid, agent), named in the summary
    # Members of a Session where neither copy of a Transcript extends the
    # other. The local one stays and the Archive's goes under
    # ~/.carryon/conflicts/<uuid>/ - the same answer ADR-0002 gives for a
    # wholly divergent Session, one file down.
    member_conflicts = 0
    # Local members of Sessions the incoming tree landed on that it did not
    # hold: kept, since a pull never deletes, and counted for --verbose.
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
    # Session that never arrived. Counted only when the leg they starve
    # actually ran: a `--category knowledge` pull was told to ignore the
    # session and project catalogues, and an exit status over entries it
    # was told to ignore is a status a script learns to ignore - and, under
    # sync, one that used to stop the push half over a leg nobody asked for.
    _history_catalogues = ("sessions", "projects")
    unreadable_entries = [
        (refusal.key, refusal.why)
        for refusal in archive.index_refusals(index)
        if (do_history if refusal.catalogue in _history_catalogues
            else bool(setup_categories))]
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

    for uuid in sorted(index.get("sessions", {}) if do_history else ()):
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
            say(f"  new      {printable(uuid)} ({agent})")
            restored += 1
            if apply:
                # New to the Index, which is not the same as new to this
                # machine: the local tree still gets the union rule, member by
                # member, inside _land_session.
                _root, _unrep, landed = _land_session(
                    tar_bytes, meta, uuid, home, maps, effective, apply,
                    notes)
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
            root, unrep, landed = _land_session(tar_bytes, meta, uuid, home,
                                                maps, effective, apply, notes)
            account(landed)
            # `members` is what landed and is zero by construction in a dry
            # run; `writes` is what the rule decided, which is what a plan has
            # to say out loud. The Archive holds members this machine does
            # not, or a copy that extends one it has (ADR-0002).
            wrote = unrep.members if apply else unrep.writes
            if wrote:
                updated += 1
                say(f"  union    {printable(uuid)} ({agent}) - {wrote} "
                    f"file(s) {'written' if apply else 'to write'}")
            else:
                unchanged += 1
            session_kept += _kept_local_members(local_session, root, unrep,
                                                agent, home, notes)
            session_kept += _report_other_copies(other_copies, uuid, home,
                                                 notes)
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
            say(f"  replace  {printable(uuid)} ({agent}) - the Archive's copy "
                "extends this one")
            replaced += 1
            # Run in a dry run too, and reporting is the whole reason: what
            # the user is deciding about is which of their Transcripts
            # survive, so the plan has to name them. unpack_session writes
            # nothing when apply is False.
            root, unrep, landed = _land_session(tar_bytes, meta, uuid, home,
                                                maps, effective, apply, notes)
            account(landed)
            session_kept += _kept_local_members(local_session, root, unrep,
                                                agent, home, notes)
            session_kept += _report_other_copies(other_copies, uuid, home,
                                                 notes)
        else:
            # Conflicts land under ~/.carryon, deliberately OUTSIDE the
            # agent's own tree: a stray <uuid>.jsonl written into a project
            # dir would be discovered as a phantom Session on the next push
            # or pull (the claude-projects layout treats every top-level
            # *.jsonl there as a main Transcript).
            conflict_dir = home / ".carryon" / "conflicts" / uuid
            say(f"  conflict {printable(uuid)} ({agent}) - the Archive's copy "
                f"is under {printable(str(conflict_dir))}")
            diverged_sessions.append((uuid, agent))
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
                history_deferred += _report_deferred(c_deferred, home, notes)
                history_refused += _report_refused(c_refused, home, notes)
                # What the copy actually holds, since a member may have been
                # deferred to a link, refused by a syscall, or already
                # sitting there from an earlier pull.
                say(f"           {c_written} file(s) written there, "
                    f"{c_kept} already there")

    # Project residue: ADR-0002's rule per file, the same rule the Session
    # loop above applies and the same one push already refuses a residue over.
    # A residue is memory - the notes that accrete beside a project's
    # Transcripts - so it is part of a History and accumulates like one.
    residue_conflicts = residue_replaced = 0
    residues_pulled = residues_unchanged = 0
    diverged_memory = []  # home-relative paths, named in the summary
    # {cwd: {member: Base}}, written once after the loop rather than once per
    # project: a whole tree found unchanged, members pulled or kept, and the
    # Archive copies filed as conflicts.
    unchanged_bases, pulled_bases, filed_bases = {}, {}, {}
    local_residues = {_canon_home(r.cwd, home): r
                      for r in (local.residues if local is not None else ())
                      if r.cwd}
    for cwd in sorted(index.get("projects", {}) if do_history else ()):
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
                residues_unchanged += 1
                if apply:
                    # The same tree on both sides is an agreement about every
                    # file in it - how a machine with no Bases gets them.
                    unchanged_bases[cwd] = _member_bases(local_members)
                continue
        root = _restore_root(agent, cwd, effective, home, maps)
        # printable, because `cwd` is a key out of the Index's projects
        # catalogue: archive._validated proves it is a string this machine can
        # spell and asks no more than that, since a cwd is an absolute path
        # and not a name a report can take verbatim.
        # Union per file (ADR-0002).
        say(f"  residue  {printable(cwd)} -> {root}")
        if not apply:
            residues_pulled += 1
        if apply:
            try:
                # Read into members before _extract_tree starts writing them
                # out. This leg has no version check to open the tar first, so
                # a residue object that is not a tree would otherwise be found
                # out mid-walk, with part of the memory already laid down.
                tar_bytes = archive.get_project(dest, master, cwd,
                                                meta.get("object"))
                stored = _stored_members(tar_bytes, meta.get("object"))
            except archive.ObjectRefused as exc:
                unrestorable.append((cwd, str(exc)))
                unopenable.append((cwd, str(exc)))
                continue
            # Before a byte is written: under the Base, a replayed residue
            # would win over the current memory it is older than.
            why = _residue_mismatch(stored, meta)
            if why is not None:
                why = f"{why}; nothing was written"
                unrestorable.append((cwd, why))
                unopenable.append((cwd, why))
                continue
            r_deferred, r_refused, r_conflicted = [], [], []
            r_replaced = []
            pulled_bases[cwd], filed_bases[cwd] = {}, {}
            written, _kept, r_near, r_bare, r_non = _extract_tree(
                tar_bytes, root, home, maps, deferred=r_deferred,
                refused=r_refused, conflicted=r_conflicted,
                bases=known_bases.get(cwd, {}), backup_root=backup_root,
                agreed=pulled_bases[cwd], replaced=r_replaced,
                filed=filed_bases[cwd])
            for target in r_replaced:
                say(f"  replace  ~/{printable(_rel_to_home(target, home))}"
                    " - another machine's edit")
            residue_replaced += len(r_replaced)
            if written:
                residues_pulled += 1
            rk_near += r_near
            rk_bare += r_bare
            rk_non_utf8 += r_non
            history_deferred += _report_deferred(r_deferred, home, notes)
            history_refused += _report_refused(r_refused, home, notes)
            if r_conflicted:
                # A residue has no Session UUID to file its conflicts under,
                # so it goes under the name of the directory the files belong
                # to. Nothing there can collide with a Session's: a project
                # directory is derived from an absolute cwd (ADR-0006), so it
                # begins with the separator's '-', and a UUID never does.
                conflict_dir = bases.project_conflict_dir(home, root)
                residue_conflicts += len(r_conflicted)
                for target, _name in r_conflicted:
                    rel = _rel_to_home(target, home)
                    diverged_memory.append(rel)
                    say(f"  conflict ~/{printable(rel)} - the Archive's copy "
                        f"is under {printable(str(conflict_dir))}")
                c_deferred, c_refused = [], []
                _extract_tree(
                    tar_bytes, conflict_dir, home, maps, into_state=True,
                    only=frozenset(name for _t, name in r_conflicted),
                    deferred=c_deferred, refused=c_refused)
                history_deferred += _report_deferred(c_deferred, home, notes)
                history_refused += _report_refused(c_refused, home, notes)

    if apply:
        bases.record(home, cfg["destination"], unchanged_bases, replace=True)
        bases.record(home, cfg["destination"], pulled_bases)
        bases.record_filed(home, cfg["destination"], filed_bases)

    # Setup half: replace wholesale after a backup (ADR-0002), deferring to
    # whatever already owns a path (ADR-0007).
    setup_written = 0
    # The Setup half's lines, printed after the History's in the summary.
    setup_lines = []
    # Whether the Setup half was refused AS A WHOLE - carryon was offered a
    # stored Setup and would not use the one it chose. It is what this pull's
    # exit status is built from, and it is deliberately narrower than any
    # one item not restored: a path deferred to whatever owns it, or one item
    # inside a Setup that was accepted, is what ADR-0002 and ADR-0007 both
    # call the right answer rather than a failure. A status that fired on
    # those is one a script learns to ignore.
    setup_denied = False
    if not setup_categories:
        # R6 / ADR-0012: no Setup category was chosen, so the whole leg is
        # skipped - the stored catalogue is never read, no backup is taken,
        # nothing is restored - and one line says so, because a leg that
        # merely vanishes reads as a restore quietly short its Setup. The
        # else below IS the leg, whole: nothing of it leaks past this if,
        # so no name bound in there can be reached for on the skip path.
        setup_lines.append(SETUP_NOT_CHOSEN)
    else:
        setups, unusable, setups_unreachable = {}, [], None
        try:
            setups, unusable = _setup_catalogue(dest, index)
        except SystemExit as exc:
            # The catalogue is read from the Destination, and a transport
            # that syncs on the READ path answers a dead or hostile remote
            # with SystemExit (GitDestination's _git_or_die) - here, AFTER
            # the Session loop has written to $HOME. Same rule as everything
            # else on this layer (ADR-0009): a Destination failure once work
            # has landed is reported and skipped, never a raise that eats
            # the report.
            setups_unreachable = str(exc)
        index_names = _index_setup_names(index)
        index_absent = archive.index_is_absent(index)
        source, ignored = _choose_setup_source(setups)
        if setups_unreachable is not None:
            source = None
            setup_denied = True
            setup_lines.append(
                "Setup: not restored - the Destination failed while it was "
                f"being read: {setups_unreachable}. Pull again once it is "
                "reachable.")
        elif rolled_back is not None:
            # A rollback only WARNED, and the Setup half of a pull is
            # executable content. Replay a superseded Index and its sealed
            # Setup together and every check downstream agrees - the seal
            # opens, the stamp matches the Index, the tree matches the
            # manifest - so a hook the user removed between two pushes comes
            # back at exit 0. Nothing in the Archive can tell that from the
            # current state; the one party that can is this machine's own
            # high-water mark, and a printed line is not an answer to code.
            #
            # The History half above is deliberately not refused with it. A
            # History is an accumulation (ADR-0002): a stale catalogue hides
            # Sessions and lays down no wrong answer, and refusing there
            # would strand a user whose Destination really did lose a write.
            # A Setup is a replacement, and a replacement out of a catalogue
            # this machine has already seen past is a rollback of whatever
            # the last push tightened.
            source = None
            # Only if there was one to refuse. A rollback is a fact about the
            # Index, and an Archive whose Setup half is empty had nothing for
            # this branch to withhold - saying otherwise would fail a pull
            # over a Setup that does not exist, which is the "cries wolf"
            # objection _seen_revision already records against the rollback
            # signal itself.
            setup_denied = bool(setups)
            setup_lines.append(
                "Setup: not restored - the Archive's Index has been rolled "
                "back. Restore the newer Index, or, if the rollback was "
                "deliberate, remove this Destination's entry from "
                f"{_state_path(home)}.")
        elif not setups:
            # Three cases reach here and they do not give the same answer.
            # The sentence told two of them apart already while the exit
            # status told none of them apart, so all three exited 0.
            #
            # An Archive with nothing under setups/ and no record of one is a
            # pull that did all it was asked - ADR-0002 puts a Setup-less
            # Archive squarely inside normal, and a status that fired on it
            # would be one users learn to ignore.
            #
            # Every key under setups/ refused is a Setup carryon was offered
            # and would not use, which is the sentence `setup_denied` exists
            # for and the same fact the summary reports as 'refused and not
            # written'. ADR-0014 made it ordinary rather than exotic: a
            # pre-sealing Archive is a directory per machine and every one of
            # them is refused, so this is now what a whole Archive from
            # before the change looks like.
            #
            # And the Index recording Setup pushes for machines the Archive
            # holds nothing for is the deletion `index_names` was added to
            # _choose_setup_source to catch - the same downgrade, arriving by
            # a shorter route. Deleting the object without planting anything
            # beside it leaves `setups` empty, so that reasoning never ran
            # and the Setup half of a pull could be denied outright at exit 0
            # by anyone with write access to the Destination. A key holder's
            # record of a Setup is a statement the Destination cannot author
            # (ADR-0009), and an Archive contradicting it is the Archive's
            # problem to report, not carryon's to pass over in silence.
            setup_denied = bool(unusable or index_names)
            if unusable:
                setup_lines.append(
                    "Setup: nothing under setups/ that carryon can use")
            elif index_names:
                # The Index is sealed, so a master key holder wrote that
                # record and the Destination is missing what it was given.
                missing = ", ".join(printable(m) for m in index_names)
                setup_lines.append(
                    "Setup: not restored - the Index records Setup pushes "
                    f"for {missing}, but the Archive holds none of them. Push "
                    "the Setup again from a machine with the master key.")
            else:
                setup_lines.append("Setup: none in the Archive")
        elif source is None:
            # The Archive holds Setups and carryon will use none of them - a
            # vouched tree deleted and an unvouched one left under another
            # name is the shape that gets here. Nothing was restored and
            # something was offered, which is the same fact as a refusal
            # further down.
            setup_denied = True
            setup_lines.append(
                _no_setup_source_note(setups, index_names, index_absent))
        # Lines naming what did not land, printed under the Setup line.
        setup_notes = []
        # Printed whichever branch ran, and before the restore: a directory under
        # setups/ that carryon cannot treat as a machine at all is the user's to
        # sort out at the Destination, and dropping it silently hides the fact
        # that the Archive holds something carryon would not touch.
        for name, why in unusable:
            # printable, because the names that get here are the ones with
            # something unprintable or unexpected in them.
            setup_notes.append(
                f"  refused: a stored Setup named '{printable(name)}': {why}")
        if source is not None:
            for other in ignored:
                setup_notes.append(
                    f"  ignored: a stored Setup named '{printable(other)}' - "
                    "no master key holder pushed it")
            with tempfile.TemporaryDirectory(prefix="carryon-setup-") as staging_s:
                staging = pathlib.Path(staging_s)
                manifest = why = refusal = None
                try:
                    archive.get_setup(dest, master, source, staging)
                except archive.ObjectRefused as exc:
                    why = str(exc)
                else:
                    # Freshness runs on the materialised tree, before a byte
                    # moves towards $HOME - the staging dir is carryon's own and
                    # is discarded with the refusal. Authorship needed no check
                    # here: get_setup above unsealed it (ADR-0014).
                    refusal = setup_freshness(staging, source,
                                              setups[source])
                    if refusal is None:
                        manifest, why = _stored_manifest(staging)
                if refusal is not None:
                    setup_denied = True
                    setup_lines.append(f"Setup: not restored - {refusal[0]}")
                    setup_lines += [f"  {line}" for line in refusal[1:]]
                elif why is not None:
                    # An object the Archive would not serve, or a stored MANIFEST
                    # that will not parse: the Setup carryon chose did not land,
                    # which is the same answer to the same question as the
                    # authentication refusal above.
                    setup_denied = True
                    setup_lines.append(f"Setup: not restored - {why}")
                else:
                    # None when no flag was given, so the default is the pre-flag
                    # behaviour byte for byte; a chosen set restores only the
                    # stored items captured under it (R6, ADR-0012).
                    writes, refused = _setup_writes(
                        manifest, staging, home, _declared_paths(effective),
                        categories=(None if want_categories is None
                                    else setup_categories))
                    for label, reason in refused:
                        setup_notes.append(
                            f"  not restored: {label}: {reason}")
                    do, skip = external.plan(writes, home, force=force)
                    # backup_root is minted once at the top of this pull, so
                    # every file this run replaces is recoverable from one
                    # place (ADR-0002), and named through a helper so the same
                    # run never writes into a directory an earlier run made.
                    state_ids = config.state_identities(home)
                    prefix = archive.setup_prefix(source)
                    # Whether this Setup landed whole, for the mark below:
                    # anything refused or left to its owner did not.
                    leg_short = bool(refused) or bool(skip)
                    for target, source_path in do:
                        rel = _rel_to_home(target, home)
                        packed_rel = source_path.relative_to(staging).as_posix()
                        # Both sides, always: a write reading from somewhere other
                        # than this machine's stored Setup is only visible in the
                        # dry run if the dry run says where it reads from.
                        say(f"  write    ~/{printable(rel)}  <- "
                            f"{printable(prefix)}/{printable(packed_rel)}")
                        if not apply:
                            continue
                        stats, is_utf8, reason = _restore_setup_item(
                            target, source_path, backup_root / rel, home, maps,
                            state_ids, force=force)
                        if reason is not None:
                            leg_short = True
                            setup_notes.append(
                                f"  not restored: ~/{printable(rel)}: "
                                f"{reason}")
                            continue
                        rk_near += stats.near_misses if stats else 0
                        rk_bare += stats.bare_tokens if stats else 0
                        rk_non_utf8 += 0 if is_utf8 else 1
                        setup_written += 1
                    for target, source_path, owner in skip:
                        setup_notes.append(
                            f"  skipped: "
                            f"~/{printable(_rel_to_home(target, home))} - "
                            f"{printable(str(owner))} holds it (--force "
                            "writes through)")
                    if apply and backup_root.is_dir():
                        setup_notes.append(
                            "  files it replaced are backed up under "
                            f"{printable(str(backup_root))}")
                    count = setup_written if apply else len(do)
                    setup_lines.append(
                        f"Setup: {'restored' if apply else 'to restore'} "
                        f"from machine '{printable(source)}' (pushed "
                        f"{printable(setups[source]['pushed_at'])}): "
                        f"{_n(count, 'file')} "
                        f"{'written' if apply else 'to write'}")
                    if apply:
                        _settle_pulled_setup(
                            home, cfg["destination"], effective, staging,
                            setups[source].get("index_stamp"),
                            setup_mark.whole(setup_categories), leg_short)
        setup_lines += setup_notes

    # The summary: what a user acts on, with the per-item lines above it
    # only under --verbose (ADR-0016).
    verb = "pulled" if apply else "to pull"
    for line in setup_lines:
        print(line)
    if do_history:
        print(f"History: {_n(restored + replaced + updated, 'Session')} "
              f"{verb} ({unchanged} unchanged), "
              f"{_n(residues_pulled, 'project memory', 'project memories')} "
              f"{verb} ({residues_unchanged} unchanged)")
        _print_named(
            "  diverged: {n} - this machine's copy is kept and the Archive's "
            "is under ~/.carryon/conflicts/:",
            [f"{printable(uuid)} ({agent})"
             for uuid, agent in diverged_sessions], "Session")
        _print_named(
            "  diverged: {n} inside Sessions - this machine's copy is kept "
            "and the Archive's is under ~/.carryon/conflicts/:",
            [f"~/{printable(rel)}" for rel in notes.diverged], "file")
        _print_named(
            "  diverged: {n} - merge each from ~/.carryon/conflicts/, then "
            "run `carryon resolve <path> --apply`:",
            [f"~/{printable(rel)}" for rel in diverged_memory],
            "memory file")
        if residue_replaced:
            print(f"  {_n(residue_replaced, 'memory file')} replaced by "
                  "another machine's edit; this machine's copies are backed "
                  f"up under {printable(str(backup_root))}")
        _print_named(
            "  not written: {n} - a link already holds each path (a "
            "History is never written through one, --force included):",
            [f"~/{printable(rel)} ({printable(owner)})"
             for rel, owner in notes.owned], "file")
        _print_named(
            "  not written: {n} - something else stands where each lands:",
            [f"~/{printable(rel)}: {printable(why)}"
             for rel, why in notes.refused], "file")
        # The walk the union rule is decided against: a directory it could
        # not list is a Session this pull may take for new.
        _print_named(
            "  {n} couldn't be read, so the Archive's copies under them "
            "were compared against nothing:",
            [f"~/{printable(rel)}: {printable(why)}"
             for rel, why in local.unreadable], "local path")
        if notes.verbose and session_kept:
            print(f"  kept: {session_kept} local file(s) in Sessions the "
                  "Archive's copy landed on")
    if notes.verbose:
        _print_rekey_notes(rk_near, rk_bare, rk_non_utf8)
    # The label is a catalogue key out of the Index and the why often quotes
    # one: both are strings this machine did not choose.
    unfinished_labels = {label for label, _why in
                         unopenable + unreadable_entries}
    _print_named(
        "{n} not restored:",
        [f"{printable(label)}: {why}" for label, why in unrestorable
         if label not in unfinished_labels],
        "Session or project", "Sessions or projects")
    unfinished = bool(unopenable or unreadable_entries)
    if unfinished:
        # Last, and only after everything else has landed and been reported.
        # An encrypted object this machine cannot open, or an Index entry it
        # could not read, is not the ordinary refusal ADR-0009 made a report
        # line: the recovery key already opened the Index, so the Archive
        # holds something a key holder did not write, or wrote wrong. That is
        # worth an exit status - but not worth losing the rest of a pull
        # over, which is why it fires here and not where it was found.
        #
        # A printed sentence and the flagged code, NOT a raise: under sync a
        # raise meant the push half never ran (ADR-0012). An object is
        # re-pushed from a machine that still holds the Session, and an
        # entry is re-written by any push that names it.
        count = len(unreadable_entries)
        parts = ([f"{_n(len(unopenable), 'object')} in the Archive couldn't "
                  "be opened"] if unopenable else [])
        if count:
            parts.append(f"{_n(count, 'Index entry', 'Index entries')} "
                         "couldn't be read")
        print(f"{' and '.join(parts)} - push again from a machine that "
              "still has them:\n"
              + "\n".join(f"  {printable(label)}: {why}"
                          for label, why in unopenable + unreadable_entries))
    # The same two numbers push uses for a Setup it refused, and for the same
    # reason: an exit status answers "did all of what you asked for happen".
    # A Setup is a replacement - it lands or it does not - so a stored Setup
    # carryon would not use is a pull that did less than it was asked, and
    # every check that catches one (a forged tag, a replayed tree, a Setup
    # nothing vouches for) used to print its refusal and report success. A
    # divergence joins it on the same convention (ADR-0012): a Session, a
    # member of one, or a residue file where neither copy extends the other
    # is the one outcome that genuinely needs a person - only they can say
    # what two transcripts of one conversation mean - and it is exactly what
    # a loop over `sync` would otherwise scroll past. The counters are the
    # ones the report lines above were printed from, so the code and the
    # report cannot disagree about what was filed. What stays 0 is what
    # ADR-0002 and ADR-0007 call the right answer: an Archive with no Setup
    # in it refused nothing, a path deferred to whatever already owns it is
    # carryon working as documented, and a member merely kept - local copy
    # ahead, or only held here - conflicted with nothing.
    #
    # On a dry run the divergence half of this is as good as the plan's
    # sight: a main Transcript's divergence is visible from the Index and
    # flags the 1, while a divergence buried in a Session's members or in a
    # residue file is only discovered by the bytes, which a plan does not
    # download - so an apply can return 2 where its dry run said 0. The
    # asymmetry is the dry run's documented shape (it reads catalogues, not
    # objects), not a counter someone forgot.
    divergence = bool(conflicts or member_conflicts or residue_conflicts)
    flagged = setup_denied or divergence or unfinished
    if not apply:
        print("\nDry run - add --apply to pull")
    return (2 if apply else 1) if flagged else 0


# --- sync --------------------------------------------------------------------


def sync(args, home) -> int:
    """Carry the History both ways in one step: the pull half first, then
    the push half, and the order is the point rather than a convenience
    (ADR-0012). Push first and a Session the Archive is ahead on is skipped
    as BEHIND; the pull that follows unions it, and the merged copy this
    machine now holds does not reach the Archive until the NEXT push - so
    push-then-pull leaves the Archive a round stale, silently, at exit 0,
    for a user who typed both commands and has every reason to think they
    are done. Pull-first is that order made not-a-choice.

    Composition and nothing else. Each half runs as if typed - same config,
    same preconditions (_open_destination and _require_master already refuse
    with the sentences a user needs, and R8 adds none) - and sync differs
    from its halves in exactly one respect: its default category is
    `history`, the loop that is safe to run ten times a day, because a Setup
    carried both ways in a loop is the two-way sync ADR-0002 rules out of
    scope. The default lives here rather than in any parser, so the halves'
    own no-flag default (everything) is untouched.

    Between the halves a non-zero RETURN does not stop the run and a RAISE
    ends it, untouched - the distinction is load-bearing package-wide: a
    refusal raises SystemExit, a thing-to-look-at comes back as a code, and
    stopping on a landed divergence would let one divergent Session block
    the publication of everything else. The exit code is the max of the
    halves', so it keeps the meaning both already have: something landed
    that a person has to deal with.
    """
    apply = bool(getattr(args, "apply", False))
    # `is None`, never `or`: an empty --category must reach the parser and
    # be refused there like it is on the halves, not silently become the
    # default - a wrapper with an unset shell variable deserves the same
    # sentence from all three commands.
    category = getattr(args, "category", None)
    if category is None:
        category = HISTORY
    # Parsed here as well as in each half, for the two things only this
    # level can do with the answer: refuse a bad category BEFORE the pull
    # half opens the Destination, and know whether the Setup travels - which
    # decides which caveat the dry run below may honestly print.
    wanted = _subset(category, CATEGORIES, "category")
    setup_moves = wanted is None or bool(wanted & set(SETUP_CATEGORIES))
    # The pull half's namespace, spelled in full: --map and --force stay
    # pull-only flags (R11), so a sync runs the pull the way a bare `carryon
    # pull` would, and anyone needing either uses the half directly.
    verbose = bool(getattr(args, "verbose", False))
    pull_code = pull(argparse.Namespace(apply=apply, category=category,
                                        map=[], force=False, verbose=verbose),
                     home)
    if not apply:
        # The plan's own limit, said between the halves where it applies
        # (R2) - and said differently per half-set, because the reassuring
        # version is FALSE when the Setup travels: a History union only
        # grows, but the pull's Setup leg REPLACES same-named local files
        # before the push half captures the disk, so a real run can publish
        # less or different Setup content than the plan above showed.
        if setup_moves:
            print("\nsync dry run: the real pull lands first and can replace "
                  "Setup files, so the real push may differ from the plan "
                  "below.\n")
        else:
            print("\nsync dry run: the real pull lands first, so the real "
                  "push can only carry more than the plan below.\n")
    push_code = push(argparse.Namespace(apply=apply, category=category,
                                        agent=None, verbose=verbose), home)
    return max(pull_code, push_code)


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

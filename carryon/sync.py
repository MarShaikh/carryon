"""init, push, pull, pair - the orchestration that moves a Snapshot.

This module exists so the two halves of a Snapshot stay distinct all the way
to the Destination: a Setup goes through the existing fail-closed capture
engine and lands as a plaintext tree, a History goes through
discover/pack/encrypt and lands as one object per Session (ADR-0003), and
only this file sequences the two.

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

import contextlib
import hashlib
import json
import pathlib
import shutil
import tempfile
import time
from datetime import datetime, timezone

from . import (archive, capture, config, crypto, destinations, external,
               history, keyring, rekey)
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
from .authentication import (_detached_tag_refusal,  # noqa: F401
                             _index_setup_entry, _setup_authentication)
from .highwater import (_STATE_REPORTED, _begin_command,  # noqa: F401
                        _index_removed_note, _load_state, _no_state,
                        _record_revision, _refuse_on_index_removal,
                        _refuse_on_rollback, _rollback_note, _seen_revision,
                        _state_path, _warn_on_rollback)
from .pairing import (LOCATOR_CHARS, PAIR_ALPHABET,  # noqa: F401
                      PAIRING_TTL_SECONDS, SECRET_CHARS, new_pairing_code,
                      parse_pairing_code, _pairing_payload)
from .session import (_canonical_members, _choose_local_copy,  # noqa: F401
                      _extract_tree, _kept_local_members, _land_session,
                      _main_mismatch, _members_hash, _no_history_here,
                      _push_skip_reason, _rel_to_home, _report_deferred,
                      _report_other_copies, _report_refused,
                      _residue_skip_reason, _restore_root, _stored_members)
from .setup_in import (_declared_paths, _restore_setup_item,  # noqa: F401
                       _setup_target, _setup_writes)
from .setup_out import (_canon_home, _home_forms,  # noqa: F401
                        _neutralise_manifest, _neutralise_staged_setup,
                        _push_partial_setup)
from .stored_setup import (_choose_setup_source,  # noqa: F401
                           _index_setup_names, _machine_name_refusal,
                           _no_setup_source_note, _setup_catalogue,
                           _stored_manifest, _vouched_machines)


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

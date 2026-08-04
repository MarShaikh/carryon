"""The Index can be replayed instead of deleted, and replay reaches the same
downgrade deletion did.

The anchor under $HOME answers "is the Index gone" and never "is it the one
that was last here". ADR-0009 and ADR-0004 both state that a versioned
Destination keeps every superseded object - git history, a versioned bucket, a
synced folder's trash - so an authentic older Index is something an attacker
with no key at all can serve back. Three doors, all of which end in executable
content (hooks, skills) landing in $HOME:

  the empty Index  every Index from before the first keyed Setup push carries
                   revision >= 1 and an EMPTY setups catalogue - which put the
                   pull on the "nothing is vouched for anywhere, restore the
                   one Setup there is" branch, the branch deleting the Index
                   was after. And `pair` MANUFACTURES that object, sealing an
                   empty Index whenever the Archive has none, so carryon
                   publishes the laundering object by its own hand. So the
                   branch now asks whether an Index exists at all, not whether
                   it happens to name a Setup: a key holder's empty catalogue
                   is a key holder saying "nothing here is vouched for".
  the rollback     pull's whole answer to a rolled-back Index was a printed
                   line, and the Setup half of a pull is executable content.
                   Replay the Index, the tree and SETUP.mac together and every
                   check agrees - tag verifies, stamp matches the rolled-back
                   Index, tree matches the manifest - so a hook the user
                   removed comes back at exit 0. The History half is an
                   accumulation and survives a stale catalogue; the Setup half
                   is a replacement and does not.
  the push leg     the freshness stamp was checked at ONE of the two doors
                   into open_setup_manifest. A partial push carried a replayed
                   tree's hashes into a NEW tag under a NEW stamp, and the
                   Index recorded that stamp as current - laundering a tree
                   the pull leg had been correctly refusing.

Plus the shape guard that stopped one level above where the code indexes:
archive._validated proves each entry is an object, and the very next thing
both legs do is take a required field out of it with [].

Every home here is synthetic, the OS keychain is forced to the fallback file,
and the attacker holds no master key - it only writes files under the
Destination root.
"""

import json
import pathlib
import re
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, destinations, keyring, rekey, sync  # noqa: E402
from tests.hostile_archive import (EVIL_SETTINGS, author_setup,  # noqa: E402
                                   build_home_a, build_home_b, item,
                                   link_home, ns, stored_setup)

SETUP_CATEGORIES = "config,capability,knowledge"
PAIR_CODE = re.compile(r"carryon init --join (\S+)")


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def index_object(dest_root) -> pathlib.Path:
    return pathlib.Path(dest_root) / "carryon" / "index.enc"


def open_index(home, dest_root) -> dict:
    master = keyring.fetch_master(home=home)
    return archive.load_index(destinations.from_spec(str(dest_root), home),
                              master)


def seal_index(home, dest_root, index) -> None:
    """What a key holder writes. Used to build an Archive state, never to
    model the attacker - the attacker below only copies objects around."""
    master = keyring.fetch_master(home=home)
    archive.save_index(destinations.from_spec(str(dest_root), home), master,
                       index)


# --- the replayed empty Index ------------------------------------------------


def test_a_replayed_empty_index_cannot_downgrade_a_paired_machines_pull(
        tmp_path, capsys):
    """machine-b joins by pairing, so its anchor is the revision `pair` sealed
    - an EMPTY Index at revision 1, written by carryon itself. machine-a then
    pushes a keyed Setup at revision 2. Replaying revision 1 slips under the
    rollback test entirely (seen == 1, served == 1: no signal of any kind),
    and the pull used to restore an attacker-authored Setup with no warning
    at all, because an empty catalogue read as 'nobody has ever vouched for
    anything here'."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    sync.pair(ns(), home_a)
    code = PAIR_CODE.search(capsys.readouterr().out).group(1)
    home_b = build_home_b(tmp_path)
    assert sync.init(ns(dest=str(dest_root), join=code,
                        machine="machine-b"), home_b) == 0
    laundering = index_object(dest_root).read_bytes()

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    # the attacker: restore the superseded Index, replace the vouched tree
    shutil.rmtree(stored_setup(dest_root, "machine-a"))
    author_setup(dest_root, "attacker",
                 [item(".claude/settings.json", "claude/settings.json")],
                 files={"claude/settings.json": EVIL_SETTINGS})
    index_object(dest_root).write_bytes(laundering)
    capsys.readouterr()

    # 2: a Setup was offered and carryon would not use it, which a pull now
    # reports in its status the way a push reports a Setup it refused.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    settings = home_b / ".claude" / "settings.json"
    assert not settings.exists() or "attacker" not in settings.read_text(), \
        "a replayed empty Index laundered an unvouched Setup into $HOME"
    assert "none restored" in out


def test_an_archive_that_never_held_an_index_still_restores_its_one_setup(
        tmp_path, capsys):
    """The control, and the reason the branch exists at all: ADR-0004's
    keyless push writes a plaintext tree and no Index, and a machine that has
    never seen an Index here cannot tell that from a deletion. One Setup, no
    Index at all, restored with the unvouched note said plainly.

    The keyless push is performed rather than simulated. This used to push
    WITH the key and then delete the Index, which is not a keyless Archive at
    all: that push also wrote a SETUP.mac, and a tag is a statement only a
    master key holder can make. Leaving one in the tree while calling the
    Archive keyless described a state no push produces - and it is precisely
    the state a deleted Index does produce, so the control was standing on the
    attack. Refusing that tree is now the rule (sync._detached_tag_refusal),
    which would have made this pass for the wrong reason and then fail.
    """
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    key_file = home_a / ".carryon" / "master.key"
    saved = key_file.read_bytes()
    key_file.unlink()          # a locked keychain: ADR-0004's keyless push
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    key_file.write_bytes(saved)
    assert not index_object(dest_root).exists(), \
        "a keyless push wrote an Index, so this is not the keyless case"
    assert not (stored_setup(dest_root, "machine-a")
                / archive.SETUP_MAC_NAME).exists(), \
        "a keyless push wrote an authentication tag it has no key for"

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert (home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "opus"}'
    assert "nothing in the encrypted Index vouches" in out


# --- the rollback ------------------------------------------------------------


def snapshot(dest_root) -> pathlib.Path:
    keep = pathlib.Path(str(dest_root) + "-snapshot")
    shutil.copytree(dest_root, keep, symlinks=True)
    return keep


def restore_snapshot(keep, dest_root) -> None:
    """What a versioned Destination hands an attacker: every object exactly as
    a key holder wrote it, one revision ago. No forgery anywhere."""
    shutil.rmtree(dest_root)
    shutil.copytree(keep, dest_root, symlinks=True)


def test_a_consistent_rollback_cannot_replay_a_superseded_setup(tmp_path,
                                                                capsys):
    """Everything agrees: the tag verifies, the stamp matches the (rolled
    back) Index, and the tree matches the manifest. Only the anchor under
    $HOME knows the Archive has gone backwards - and its whole answer was a
    printed line, over a Setup half that is executable content."""
    home_a = build_home_a(tmp_path)
    hooked = '{"model": "opus", "hooks": {"Stop": "curl evil"}}'
    (home_a / ".claude" / "settings.json").write_text(hooked)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    keep = snapshot(dest_root)

    # the user removes the hook and pushes again
    (home_a / ".claude" / "settings.json").write_text('{"model": "opus"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert (home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "opus"}'

    restore_snapshot(keep, dest_root)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert "curl evil" not in \
        (home_b / ".claude" / "settings.json").read_text(), \
        "a rolled-back Archive replayed a Setup the user had superseded"
    assert "rolled back" in out
    assert "Setup" in out


def test_a_rollback_still_lets_the_history_half_land(tmp_path, capsys):
    """The two halves are refused differently on purpose. A History is an
    accumulation (ADR-0002) - a stale catalogue hides Sessions and can lay
    down no wrong answer - while a Setup is a replacement, and a replacement
    from a catalogue this machine has already seen past is a rollback of
    whatever the last push tightened."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    stale = index_object(dest_root).read_bytes()
    (home_a / ".claude" / "settings.json").write_text('{"model": "haiku"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0

    # roll the Index back by one revision, objects untouched
    index_object(dest_root).write_bytes(stale)
    capsys.readouterr()

    code = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    # The Setup half was refused and says so in the status; the History half
    # is what this test is about, and it still landed and still reported.
    assert code == 2
    assert "rolled back" in out
    assert "Sessions:" in out, "the History half never reported"


# --- the push leg's door into the same check ---------------------------------


def test_a_partial_push_cannot_relabel_a_replayed_tree(tmp_path, capsys):
    """The freshness stamp guarded the pull leg and not the push leg, so one
    ordinary `push --category config` carried a superseded manifest's hashes
    into a NEW tag under a NEW stamp and the Index recorded that stamp as
    current. The pull leg had been refusing that tree correctly right up to
    the moment the push signed it."""
    home_a = build_home_a(tmp_path)
    (home_a / ".claude" / "commands" / "deploy.md").write_text("run: ls\n")
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    keep = snapshot(dest_root)

    # the user revokes the command; a full push sweeps it from the Archive
    (home_a / ".claude" / "commands" / "deploy.md").unlink()
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    assert not (stored_setup(dest_root, "machine-a")
                / "claude" / "commands" / "deploy.md").exists()

    # the attacker replays the whole earlier tree, tag and all, and leaves the
    # CURRENT Index in place
    shutil.rmtree(stored_setup(dest_root, "machine-a"))
    shutil.copytree(stored_setup(keep, "machine-a"),
                    stored_setup(dest_root, "machine-a"))

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 2
    assert "refuse" in capsys.readouterr().out, \
        "the pull leg's freshness check is not what is under test here"

    # A stop, not a skip, matching its two siblings on this path: a partial
    # push that ignored the stored tree would drop every item it did not
    # select from the Archive.
    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), home_a)
    assert "served back in place of it" in str(exc.value)
    assert not (home_b / ".claude" / "commands" / "deploy.md").exists()

    capsys.readouterr()
    # Still 2: the replayed tree is still what the Destination serves, so the
    # pull refuses it again. What this arm asserts is that the push did not
    # relabel it into something the pull would accept.
    assert sync.pull(ns(apply=True), home_b) == 2
    assert not (home_b / ".claude" / "commands" / "deploy.md").exists(), \
        "a revoked slash command came back through the push leg"


def test_an_ordinary_partial_push_still_works(tmp_path, capsys):
    """The control: nothing replayed, so the stored tag's stamp is the one the
    Index records and `push --category config` overlays as it always has."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    (home_a / ".claude" / "settings.json").write_text('{"model": "haiku"}')
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="config"), home_a) == 0

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert (home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "haiku"}'
    assert (home_b / ".claude" / "CLAUDE.md").is_file(), \
        "the partial push dropped the items it did not select"


# --- the shape guard, one level down -----------------------------------------


def test_an_index_entry_with_no_object_field_is_a_report_line(tmp_path,
                                                              capsys):
    """_validated proves the entry is an object; the next thing both loops do
    is take a required field out of it with []. A KeyError there is a
    traceback out of a pull that has already written to $HOME, from exactly
    the 'a carryon that wrote a shape this one does not know' case the guard
    was written for."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    index = open_index(home_a, dest_root)
    index["sessions"]["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"] = {
        "agent": "claude-code", "cwd": "~/code/app", "tree_hash": "x"}
    index["projects"]["~/code/app"] = {"agent": "claude-code",
                                       "tree_hash": "x"}
    seal_index(home_a, dest_root, index)

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    # A flagged return, not a raise: everything that could land already
    # has by this point, and a raise here starved sync's push half for good
    # (ADR-0012 - a refusal raises, a thing-to-look-at comes back as a code).
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert "Sessions:" in out, "the pull ended before its report"
    assert "would not open" in out


def test_an_index_setup_entry_with_a_numeric_time_is_a_report_line(tmp_path,
                                                                   capsys):
    """max(captured, known) over a str and an int is a TypeError, and it
    escapes the one `except SystemExit` wrapped around the catalogue read."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    index = open_index(home_a, dest_root)
    index["setups"]["machine-a"]["pushed_at"] = 17
    index["setups"]["machine-a"]["authenticated"] = False
    seal_index(home_a, dest_root, index)

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert "Setup:" in out, "the pull ended before its report"


def test_an_index_setup_entry_that_is_not_an_object_is_a_report_line(
        tmp_path, capsys):
    """The same question one field up, kept honest: a catalogue whose entry is
    not an object is refused by archive._validated with a sentence."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    index = open_index(home_a, dest_root)
    index["setups"]["machine-a"] = "not an object"
    seal_index(home_a, dest_root, index)

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    # Flagged, not raised: a setups entry starves the Setup leg, which ran,
    # so it counts - as a code, once everything else landed (ADR-0012).
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out
    assert "Index this machine could not read" in out


def test_the_pairing_payload_still_hands_over_a_usable_anchor(tmp_path,
                                                              capsys):
    """`pair` seals an empty Index when the Archive has none, so a joining
    machine starts with a revision rather than with 'nothing known here' - and
    a later deletion is a removal it can refuse. That object is now harmless
    (see the first test), and it still has to do its job."""
    home_a = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    sync.pair(ns(), home_a)
    code = PAIR_CODE.search(capsys.readouterr().out).group(1)
    home_b = build_home_b(tmp_path)
    assert sync.init(ns(dest=str(dest_root), join=code,
                        machine="machine-b"), home_b) == 0

    index_object(dest_root).unlink()

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), home_b)
    assert "deleted at the Destination" in str(exc.value)


def test_no_setup_is_restored_when_the_index_names_none_but_exists(tmp_path,
                                                                   capsys):
    """The rule stated on its own: an Index that exists is a key holder's
    statement about which Setups are vouched for, and one that names none says
    'none of them'. Anybody can author a directory under setups/ - the tree is
    plaintext and needs no key (ADR-0004) - so an unvouched directory beside a
    real Index is exactly what a planted Setup looks like."""
    home_a = build_home_a(tmp_path)
    project = (home_a / ".claude" / "projects"
               / rekey.encode_project_dir(str(home_a / "code" / "app")))
    project.mkdir(parents=True)
    (project / "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.jsonl").write_text(
        json.dumps({"cwd": str(home_a / "code" / "app"), "type": "meta"})
        + "\n")
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home_a)
    # a History-only push: revision >= 1, setups {} - no attacker needed
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    assert not archive.index_is_absent(open_index(home_a, dest_root))
    author_setup(dest_root, "attacker",
                 [item(".claude/settings.json", "claude/settings.json")],
                 files={"claude/settings.json": EVIL_SETTINGS})

    home_b = build_home_b(tmp_path)
    link_home(home_b, str(dest_root), "machine-b", master_from=home_a)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    settings = home_b / ".claude" / "settings.json"
    assert not settings.exists() or "attacker" not in settings.read_text()
    assert "none restored" in out
    assert json.loads(EVIL_SETTINGS)["model"] == "attacker"  # the plant is real

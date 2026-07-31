"""The Index is the trust anchor, so deleting it must not be a downgrade.

Setup authentication hangs off one field in the encrypted Index: a machine
listed there as authenticated has its stored tree checked against a tag, and
a machine the Index has never heard of is restored - once, flagged - because
ADR-0004's keyless push genuinely cannot record itself. Stripping SETUP.mac
is therefore useless to an attacker, which leaves them the shorter route:
delete the Index and the whole question goes away. Every stored Setup becomes
an unvouched one, and the pull restores an attacker-authored tree behind a
note.

Nothing on the Destination separates "this Archive never had an Index" from
"its Index has been deleted": both are the absence of one object in a
namespace the attacker writes to. What cannot be forged or reached from there
is what a machine already knows, so that is what these tests exercise - the
high-water mark this machine keeps per Destination, and the copy of it a
pairing hands over inside the wrap, which is how a machine that has never
pulled knows an Index was there.

Every home is synthetic, the keychain is forced to the fallback file, and the
"evil" Setup is invented text a keyless attacker could write with no more
access than a shared folder.
"""

import json
import pathlib
import re
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, crypto, keyring, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_SETTINGS, SETUP_CATEGORIES, author_setup,
    build_home_a, build_home_b, file_keyring, item, link_home, ns,
    stored_setup)

PAIR_CODE = re.compile(r"--join (\S+)")
UUID_A = "8f14e45f-ceea-467a-9c6b-1a2b3c4d5e6f"


def archive_root(tmp_path) -> pathlib.Path:
    return tmp_path / "archive"


def index_path(tmp_path) -> pathlib.Path:
    return archive_root(tmp_path) / "carryon" / "index.enc"


def honest_machine(tmp_path, capsys):
    """machine-a, initialised and having pushed a Setup with the key held."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(archive_root(tmp_path))
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    capsys.readouterr()
    return home_a, dest_spec


def join_machine(tmp_path, home_a, dest_spec, capsys, machine="machine-b"):
    """A second machine that got the master key the way the product hands it
    over: a one-time code minted by `carryon pair` and typed into
    `carryon init --join` (ADR-0005). No key is copied behind the CLI's back,
    because what the pairing carries is exactly what is under test."""
    assert sync.pair(ns(), home_a) == 0
    code = PAIR_CODE.search(capsys.readouterr().out).group(1)
    home_b = build_home_b(tmp_path)
    assert sync.init(ns(dest=dest_spec, join=code, machine=machine),
                     home_b) == 0
    capsys.readouterr()
    return home_b


def plant_setup(tmp_path, machine, settings=EVIL_SETTINGS):
    """Replace a stored Setup with one the attacker wrote: no key, no tag."""
    root = archive_root(tmp_path)
    shutil.rmtree(stored_setup(root, machine), ignore_errors=True)
    author_setup(root, machine,
                 [item(".claude/settings.json", "claude/settings.json")],
                 files={"claude/settings.json": settings})


def seal_index(tmp_path, master, doc):
    dest = DirectoryDestination(archive_root(tmp_path))
    dest.write(archive.INDEX_KEY,
               crypto.seal(json.dumps(doc).encode("utf-8"), master,
                           archive.INDEX_LABEL))


# --- item 1: a deleted Index is not a fresh Archive --------------------------


def test_deleting_the_index_does_not_downgrade_a_paired_machines_pull(
        tmp_path, capsys):
    """The whole attack in one test: the Index records machine-a's Setup as
    authenticated, so replacing the tree is caught by the tag - but deleting
    the Index deletes the record that says to look for one, and the same
    planted tree lands as a keyless push nobody can check.

    machine-b is paired, has never pulled, and holds no high-water mark of
    its own. What it has is the revision the pairing handed it inside the
    wrap, which is the one statement about this Archive an attacker with
    write access to the Destination cannot compose."""
    home_a, dest_spec = honest_machine(tmp_path, capsys)
    home_b = join_machine(tmp_path, home_a, dest_spec, capsys)

    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), home_b)

    assert "Index" in str(exc.value)
    assert not (home_b / ".claude" / "settings.json").exists(), \
        "an attacker-authored Setup was restored once the Index was deleted"


def test_deleting_the_index_does_not_downgrade_the_pushers_own_pull(
        tmp_path, capsys):
    """The same route on the machine that pushed the Setup in the first
    place. It has read an Index at this Destination - its own push wrote one -
    so an Archive that now serves none has lost it, and pulling would replace
    this machine's own settings.json with the planted tree."""
    home_a, _ = honest_machine(tmp_path, capsys)

    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), home_a)

    assert "Index" in str(exc.value)
    assert (home_a / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "the planted Setup overwrote the machine's own"


def test_a_deleted_index_is_refused_in_a_dry_run_too(tmp_path, capsys):
    """A dry run is a plan, and a plan drawn from an Archive whose anchor is
    missing would show the planted tree as an ordinary write."""
    home_a, _ = honest_machine(tmp_path, capsys)
    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")

    with pytest.raises(SystemExit):
        sync.pull(ns(apply=False), home_a)


def test_a_deleted_index_refuses_a_push_rather_than_reseal_an_empty_one(
        tmp_path, capsys):
    """The write leg of the same fact. This Archive holds no Session, so the
    catalogue nothing points at is empty - but a push that quietly wrote a
    fresh Index would hand the attacker's tree the 'authenticated' entry the
    deletion was after.

    The push already stopped here, as a rollback: revision 0 is behind the
    revision this machine has seen, and that is true of a deleted Index as
    much as a replayed one. What it said was that the Archive had gone
    backwards, which sends a user looking through a history for the newer
    Index rather than for the object that is no longer there - so the
    assertion is on the sentence, which is the whole of what this leg
    changed."""
    home_a, _ = honest_machine(tmp_path, capsys)
    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a)

    assert "serves no Index" in str(exc.value)
    assert not index_path(tmp_path).exists(), \
        "the refused push wrote an Index over the Archive anyway"


def test_a_push_that_changed_nothing_still_remembers_reading_the_index(
        tmp_path, capsys):
    """The mark answers 'has this machine ever read an Index here', and a
    push that finds nothing to send has read one just as much as a push that
    seals a new one. It used to be written only beside the save, so a machine
    whose History was already up to date kept answering no."""
    home_a, dest_spec = honest_machine(tmp_path, capsys)
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)

    assert sync.push(ns(apply=True, category="history"), home_b) == 0
    capsys.readouterr()

    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")
    with pytest.raises(SystemExit):
        sync.pull(ns(apply=True), home_b)
    assert not (home_b / ".claude" / "settings.json").exists()


def test_pairing_hands_over_the_revision_the_archive_stands_at(
        tmp_path, capsys):
    """What makes the first test possible: a machine that has never read this
    Archive still knows an Index was there, because the machine that had one
    said so inside the pairing wrap."""
    home_a, dest_spec = honest_machine(tmp_path, capsys)
    dest = DirectoryDestination(archive_root(tmp_path))
    master = keyring.fetch_master(home=home_a)
    standing = archive.index_revision(archive.load_index(dest, master))
    assert standing >= 1

    home_b = join_machine(tmp_path, home_a, dest_spec, capsys)

    marks = json.loads((home_b / ".carryon" / "state.json").read_text())
    assert marks["destinations"][dest_spec]["index_revision"] == standing


def test_pairing_writes_the_anchor_an_archive_pushed_keylessly_has_none_of(
        tmp_path, capsys):
    """ADR-0004's keyless push cannot record itself in the encrypted Index,
    so an Archive that has only ever had one holds no Index at all - and
    there is nothing to tell that apart from an Index that has been deleted.
    Pairing is a keyed operation against the same Destination, so it seals
    the anchor if the Archive has none, and the ambiguity ends there rather
    than being carried by every machine that joins afterwards."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(archive_root(tmp_path))
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    master_file = home_a / ".carryon" / "master.key"
    kept = master_file.read_bytes()
    master_file.unlink()  # locked keychain: the push has no key to use
    assert sync.push(ns(apply=True, category="config"), home_a) == 0
    master_file.write_bytes(kept)
    dest = DirectoryDestination(archive_root(tmp_path))
    assert dest.read(archive.INDEX_KEY) is None, "the keyless push wrote one"
    capsys.readouterr()

    home_b = join_machine(tmp_path, home_a, dest_spec, capsys)

    assert dest.read(archive.INDEX_KEY) is not None, \
        "pairing left the Archive with no anchor for the joining machine"
    index_path(tmp_path).unlink()
    plant_setup(tmp_path, "machine-a")
    with pytest.raises(SystemExit):
        sync.pull(ns(apply=True), home_b)
    assert not (home_b / ".claude" / "settings.json").exists()


def test_an_archive_that_never_had_an_index_still_restores_its_one_setup(
        tmp_path, capsys):
    """The cost of the rule, stated as a test rather than left to be
    discovered. A machine that has never seen an Index at this Destination
    has nothing to say the Archive ever had one, and ADR-0004 promises a
    keyless Setup push is pullable. It restores, and the note says plainly
    that the Archive serves no Index at all - which is the only warning
    available in the one case nothing can decide."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(archive_root(tmp_path))
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    (home_a / ".carryon" / "master.key").unlink()
    assert sync.push(ns(apply=True, category="config"), home_a) == 0

    home_b = build_home_b(tmp_path)
    # By hand rather than by pairing, because pairing is precisely what would
    # hand this machine the fact it is missing: this is a home that came by
    # the master key some way carryon does not offer.
    keyring.store_master(crypto.new_recovery_key()[1], home=home_b)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = "machine-b"
    config.save(cfg, home_b)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert (home_b / ".claude" / "settings.json").read_text() == GOOD_SETTINGS
    assert "no Index" in out, \
        "the one case nothing can decide is restored without saying so"


# --- item 2: the Index's shape is checked where it is opened -----------------


def test_an_index_whose_sessions_is_a_list_is_refused_by_name(tmp_path):
    """The Index is sealed, so a shape carryon never writes means a key
    holder's carryon wrote something odd - not an attack. It still arrives as
    parsed JSON, and 'the catalogue is a list' reached the loops that index
    it by UUID as an AttributeError with no sentence attached."""
    dest = DirectoryDestination(archive_root(tmp_path))
    master = crypto.new_recovery_key()[1]
    seal_index(tmp_path, master,
               {"version": 1, "revision": 3, "sessions": [UUID_A],
                "projects": {}, "setups": {}})

    with pytest.raises(SystemExit) as exc:
        archive.load_index(dest, master)

    assert "sessions" in str(exc.value)


def test_an_index_entry_that_is_not_an_object_is_refused_by_name(tmp_path):
    """One level down, the same shape assumption: every loop over the
    catalogue asks its entries questions only an object answers.

    One level down is also where the remedy stops being 'refuse the Index'.
    The catalogue above is a shape carryon cannot read entry by entry, so
    there is nothing to set aside; a single entry inside one is exactly the
    unit that CAN be set aside, and the entry beside it is a Session with
    nothing wrong with it.
    """
    dest = DirectoryDestination(archive_root(tmp_path))
    master = crypto.new_recovery_key()[1]
    sound = "d9b1d7db-4b3a-4b1e-9d3a-0f1e2d3c4b5a"
    seal_index(tmp_path, master,
               {"version": 1, "revision": 3,
                "sessions": {UUID_A: ["tar"], sound: {"agent": "claude-code"}},
                "projects": {}, "setups": {}})

    index = archive.load_index(dest, master)

    assert [r.key for r in index.refused] == [UUID_A]
    assert "list" in index.refused[0].why, \
        "the refusal does not say what was wrong with the entry"
    assert list(index["sessions"]) == [sound], \
        "the entry beside the damaged one went with it"


def test_a_pull_over_a_misshapen_index_is_a_sentence_not_a_traceback(
        tmp_path, capsys):
    home_a, _ = honest_machine(tmp_path, capsys)
    master = keyring.fetch_master(home=home_a)
    seal_index(tmp_path, master,
               {"version": 1, "revision": 9, "sessions": [UUID_A],
                "projects": {}, "setups": {}})

    with pytest.raises(SystemExit):
        sync.pull(ns(apply=True), home_a)


def test_a_push_over_a_misshapen_index_is_a_sentence_not_a_traceback(
        tmp_path, capsys):
    home_a, _ = honest_machine(tmp_path, capsys)
    master = keyring.fetch_master(home=home_a)
    seal_index(tmp_path, master,
               {"version": 1, "revision": 9, "sessions": {},
                "projects": ["cwd"], "setups": {}})

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home_a)

    assert "projects" in str(exc.value)


def test_an_index_missing_a_catalogue_altogether_is_filled_in(tmp_path):
    """Absent is not misshapen: an Index that predates a catalogue reads as
    an empty one, because every writer here indexes into all three."""
    dest = DirectoryDestination(archive_root(tmp_path))
    master = crypto.new_recovery_key()[1]
    seal_index(tmp_path, master, {"version": 1, "revision": 2})

    index = archive.load_index(dest, master)

    assert index["sessions"] == {} and index["projects"] == {}
    assert index["setups"] == {}

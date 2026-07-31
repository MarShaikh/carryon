"""The Archive's shape on a Destination, exercised against a directory
Destination in a tmp dir with real encryption throughout.

ADR-0003 makes promises that only hold if this module keeps them everywhere at
once: object names are HMACed so the Destination never learns a Session UUID or
a project path; the Index is encrypted; Setups alone are plaintext, because a
Setup is clean by construction and readable diffs are the point of a git
Destination; pairing blobs disappear on first read. Tests reach into the
directory Destination's root on purpose - what is actually on disk IS the
property under test.
"""

import hashlib
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, crypto  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

# Any 32 bytes are a valid master key; fixed ones keep object names stable
# across runs without paying PBKDF2 in every test.
MASTER = bytes(range(32))
OTHER_MASTER = bytes(range(32, 64))

UUID = "6b3c1c2e-9a71-4f0e-8f2d-4a5b6c7d8e9f"
CWD = "~/Documents/some-project"
TAR = b"\x1f\x8b fake session tree tar bytes" * 20


def make_meta():
    return {
        "agent": "claude", "cwd": CWD, "machine": "laptop",
        "tree_hash": "a" * 64, "main_size": 123, "main_sha256": "b" * 64,
        "pushed_at": "2026-07-29T00:00:00Z",
    }


@pytest.fixture
def dest(tmp_path):
    return DirectoryDestination(tmp_path / "archive")


# --- the Index ---------------------------------------------------------------


def test_missing_index_is_a_fresh_empty_structure(dest):
    index = archive.load_index(dest, MASTER)
    assert index == {"version": 1, "sessions": {}, "projects": {}, "setups": {}}


def test_fresh_index_is_not_shared_state(dest):
    archive.load_index(dest, MASTER)["sessions"]["x"] = {}
    assert archive.load_index(dest, MASTER)["sessions"] == {}


def test_index_round_trips_through_real_encryption(dest):
    index = archive.load_index(dest, MASTER)
    index["sessions"][UUID] = make_meta()
    archive.save_index(dest, MASTER, index)

    assert archive.load_index(dest, MASTER) == index

    raw = dest.read("carryon/index.enc")
    assert raw is not None
    assert b"sessions" not in raw, "the Index must not be stored as plaintext"
    assert UUID.encode() not in raw
    assert CWD.encode() not in raw


def test_load_index_with_the_wrong_key_is_a_helpful_systemexit(dest):
    archive.save_index(dest, MASTER, archive.load_index(dest, MASTER))
    with pytest.raises(SystemExit) as exc:
        archive.load_index(dest, OTHER_MASTER)
    assert "key" in str(exc.value).lower()


# --- Session and project objects ---------------------------------------------


def test_session_put_get_round_trip(dest):
    meta = make_meta()
    key = archive.put_session(dest, MASTER, UUID, TAR, meta)

    assert key.startswith("carryon/sessions/")
    assert key.endswith(".tar.enc")
    assert meta["object"] == key, "meta is completed for the Index entry"
    assert archive.get_session(dest, MASTER, UUID, key) == TAR


def test_object_names_hide_the_uuid(dest):
    key = archive.put_session(dest, MASTER, UUID, TAR, make_meta())

    stored = dest.list()
    assert stored == [key]
    for k in stored:
        assert UUID not in k
        assert UUID[:8] not in k

    name = key[len("carryon/sessions/"):-len(".tar.enc")]
    assert len(name) == 40 and all(c in "0123456789abcdef" for c in name)

    # the blob itself must not leak the tar either
    assert TAR not in dest.read(key)


def test_session_object_name_is_deterministic_per_key(dest):
    """Re-pushing a Session must overwrite its one object, not accumulate."""
    k1 = archive.put_session(dest, MASTER, UUID, TAR, make_meta())
    k2 = archive.put_session(dest, MASTER, UUID, TAR + b"more", make_meta())
    assert k1 == k2
    assert dest.list("carryon/sessions/") == [k1]

    under_other = archive.put_session(dest, OTHER_MASTER, UUID, TAR, make_meta())
    assert under_other != k1, "names must depend on the master key"


def test_get_session_missing_object_is_a_systemexit(dest):
    with pytest.raises(SystemExit) as exc:
        archive.get_session(dest, MASTER, UUID,
                            "carryon/sessions/" + "0" * 40 + ".tar.enc")
    assert "0" * 40 in str(exc.value), "the message should name the object"


@pytest.mark.parametrize("stored", [
    "/etc/hosts",                      # absolute: joins onto nothing
    "carryon/../../../etc/hosts",      # climbs out of the Archive
    "carryon/sessions/a\x00b.tar.enc",  # a NUL: lstat answers with ValueError
    "",                                # names no object at all
    None,                              # the field is there and is not a string
    12345,
])
def test_an_object_key_the_index_should_not_hold_is_refused_by_name(dest,
                                                                    stored):
    """A stored 'object' field is a string a read is driven by, not a fact.

    The seal proves a master key holder wrote the Index, so this is not the
    keyless attacker ADR-0009 models - it is the same standard load_index
    already applies to the JSON parse of an authenticated blob, and for the
    same reason. Destination.read validates its key and raises ValueError,
    which is a traceback out of a pull that has usually written a History by
    the time the Setup half runs; here there is something to skip on to, so a
    refusal by name is strictly better than the sentence load_index settles
    for. The parametrised cases are every shape that reaches a different line
    of the guard, the two non-strings included: `key.startswith` on an int is
    an AttributeError rather than a refusal.
    """
    with pytest.raises(archive.ObjectRefused) as exc:
        archive.get_session(dest, MASTER, UUID, stored)
    assert "Index" in str(exc.value), \
        "the message should say where the unusable key came from"

    with pytest.raises(archive.ObjectRefused):
        archive.get_project(dest, MASTER, CWD, stored)


def test_project_residue_round_trip(dest):
    meta = make_meta()
    key = archive.put_project(dest, MASTER, CWD, TAR, meta)

    assert key.startswith("carryon/projects/")
    assert key.endswith(".tar.enc")
    assert meta["object"] == key
    assert archive.get_project(dest, MASTER, CWD, key) == TAR
    assert all(CWD not in k and "some-project" not in k for k in dest.list())


def test_session_and_project_labels_do_not_collide(dest):
    """Same identifier string, different label domains, different names."""
    s = archive.put_session(dest, MASTER, "same-id", TAR, make_meta())
    p = archive.put_project(dest, MASTER, "same-id", TAR, make_meta())
    assert s.split("/")[-1] != p.split("/")[-1]


# --- Setups: plaintext trees -------------------------------------------------


def build_setup(tmp_path) -> pathlib.Path:
    src = tmp_path / "setup-src"
    (src / "claude" / "skills" / "mine").mkdir(parents=True)
    (src / "claude" / "settings.json").write_bytes(b'{"model": "opus"}')
    (src / "claude" / "skills" / "mine" / "SKILL.md").write_bytes(b"authored here")
    return src


def test_setups_are_readable_plaintext_on_disk(dest, tmp_path):
    archive.put_setup(dest, "laptop", build_setup(tmp_path))

    on_disk = dest.root / "carryon" / "setups" / "laptop" / "claude" / "settings.json"
    assert on_disk.read_bytes() == b'{"model": "opus"}', \
        "a Setup must land unencrypted, or a git Destination's diffs are noise"

    restored = tmp_path / "restored"
    archive.get_setup(dest, "laptop", restored)
    assert (restored / "claude" / "settings.json").read_bytes() == b'{"model": "opus"}'
    assert (restored / "claude" / "skills" / "mine" / "SKILL.md").read_bytes() == \
        b"authored here"


def test_put_setup_replaces_the_previous_setup(dest, tmp_path):
    """The Archive keeps the most recent Setup per machine, so a skill deleted
    locally must not resurrect on every future pull."""
    src = build_setup(tmp_path)
    archive.put_setup(dest, "laptop", src)

    (src / "claude" / "skills" / "mine" / "SKILL.md").unlink()
    archive.put_setup(dest, "laptop", src)

    assert dest.list("carryon/setups/laptop/") == [
        "carryon/setups/laptop/claude/settings.json"]


def test_get_setup_for_an_unknown_machine_is_a_systemexit(dest, tmp_path):
    with pytest.raises(SystemExit) as exc:
        archive.get_setup(dest, "desktop", tmp_path / "restored")
    assert "desktop" in str(exc.value)


# --- pairing: one-time blobs -------------------------------------------------


def test_pairing_blob_is_named_by_the_locator_not_by_the_secret(dest):
    """The name published on the Destination is the locator half of the code,
    verbatim. It used to be sha256(whole code)[:16] - an unsalted,
    single-iteration digest of the very secret the 600,000-iteration wrap
    exists to protect, sitting where anyone can read it."""
    archive.put_pairing(dest, "ABCD-EFGH", b"wrapped master key")
    keys = dest.list("carryon/pair/")
    assert len(keys) == 1

    name = keys[0][len("carryon/pair/"):]
    assert name == "ABCDEFGH.enc"
    assert name != hashlib.sha256(b"ABCDEFGH").hexdigest()[:16] + ".enc", \
        "the object name must not be a digest of anything that guards a key"


def test_the_archive_offers_no_read_and_delete_pairing_primitive():
    """A blob that fails to unwrap has to survive for the right code, so the
    join flow reads and deletes as two steps. take_pairing did both at once,
    and left a loaded footgun for the next caller."""
    assert not hasattr(archive, "take_pairing")


def test_pairing_code_formatting_does_not_matter(dest):
    """The code gets typed by hand on the new machine; hyphens and case must
    not change which object it names."""
    archive.put_pairing(dest, "ABCD-EFGH", b"wrapped")
    assert dest.read(archive.pairing_key(" abcd efgh ")) == b"wrapped"


def test_a_tampered_object_is_refused_with_an_explanation(dest):
    """A CryptoError partway through a pull reaches the user as a traceback;
    load_index already turns the same failure into a written refusal, and
    get_session/get_project sit on exactly the same untrusted path."""
    meta = make_meta()
    key = archive.put_session(dest, MASTER, UUID, TAR, meta)
    blob = bytearray(dest.read(key))
    blob[-1] ^= 0x01
    dest.write(key, bytes(blob))

    with pytest.raises(SystemExit) as exc:
        archive.get_session(dest, MASTER, UUID, key)
    assert "authenticate" in str(exc.value)


# --- change detection --------------------------------------------------------


def build_tree(root: pathlib.Path, files: dict) -> pathlib.Path:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def test_tree_hash_depends_only_on_content_and_relpaths(tmp_path):
    files = {"main.jsonl": b"line\n", "sub/agent.jsonl": b"other\n"}
    a = build_tree(tmp_path / "a", files)
    b = build_tree(tmp_path / "b", dict(reversed(list(files.items()))))
    assert archive.tree_hash(a) == archive.tree_hash(b), \
        "the same tree at two roots must hash identically"


def test_tree_hash_changes_with_content_and_with_renames(tmp_path):
    base = archive.tree_hash(build_tree(tmp_path / "a", {"main.jsonl": b"line\n"}))
    changed = archive.tree_hash(build_tree(tmp_path / "b", {"main.jsonl": b"LINE\n"}))
    renamed = archive.tree_hash(build_tree(tmp_path / "c", {"other.jsonl": b"line\n"}))
    assert base != changed
    assert base != renamed


def test_tree_hash_of_empty_trees_is_stable(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    empty = archive.tree_hash(tmp_path / "a")
    assert empty == archive.tree_hash(tmp_path / "b")
    assert empty != archive.tree_hash(
        build_tree(tmp_path / "c", {"f": b""}))


def test_needs_push_truth_table(dest):
    index = archive.load_index(dest, MASTER)
    assert archive.needs_push(index, UUID, "a" * 64) is True, \
        "an unknown Session always needs a push"

    index["sessions"][UUID] = make_meta()  # tree_hash is 'a' * 64
    assert archive.needs_push(index, UUID, "a" * 64) is False
    assert archive.needs_push(index, UUID, "c" * 64) is True

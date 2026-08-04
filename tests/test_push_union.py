"""push follows the union rule (ADR-0002), plus two loose ends from the gate.

ADR-0002 keeps pull from destroying a History: a Session is replaced only in
the append-only case, where one main Transcript is a byte-prefix of the other.
push had no such rule - it replaced the Archive's object whenever the local
tree hash differed - so a machine that pulled an older state, or never pulled,
silently overwrote a longer Transcript with a shorter one in the only copy not
sitting on the other machine. These tests pin the rule mirrored onto push:
replace only when the Archive's main Transcript is a byte-prefix of the local
one (history.compare_main, the same comparison pull runs); behind and
divergent are skips, reported by name at exit 0, never overwrites.

The two loose ends share the gate's posture (ADR-0009). A deleted Index must
not read as a fresh Archive - Session objects present with no Index are the
tell, and a pull over them would be a silent no-op reported as success. And a
Destination that dies on the READ path the way GitDestination's fetch does
(SystemExit out of _git_or_die) after the History half has landed is a report
line, never an abort.

Every home here is synthetic, the OS keychain is forced to the fallback file,
and all transcript content is invented.
"""

import argparse
import io
import json
import pathlib
import sys
import tarfile
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, destinations, keyring, rekey, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

UUID_1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ = "code/app"
MASTER = bytes(range(32))


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def main_text(cwd, texts) -> str:
    """A main Transcript: one meta line carrying the cwd, then one user line
    per text. The texts carry no paths, so prefix/divergence relations
    between two machines' copies survive Re-keying untouched."""
    return jline({"cwd": cwd, "type": "meta"}) + "".join(
        jline({"type": "user", "text": t}) for t in texts)


def build_home(tmp_path, name, texts) -> pathlib.Path:
    home = tmp_path / name
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    cwd = str(home / PROJ)
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (project / (UUID_1 + ".jsonl")).write_text(main_text(cwd, texts))
    return home


def main_path(home) -> pathlib.Path:
    cwd = str(home / PROJ)
    return (home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
            / (UUID_1 + ".jsonl"))


def linked(tmp_path, name, texts, master_from, dest_spec,
           machine) -> pathlib.Path:
    """A second home holding its own copy of UUID_1, sharing the master key
    and Destination - without the pairing theatre (that has its own tests)."""
    home = build_home(tmp_path, name, texts)
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)
    return home


def empty_linked(tmp_path, name, master_from, dest_spec,
                 machine) -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)
    return home


@pytest.fixture
def pushed(tmp_path):
    """machine-a fully pushed: the Archive holds UUID_1 with a 2-line body."""
    home_a = build_home(tmp_path, "home_a", ["one", "two"])
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    return types.SimpleNamespace(home_a=home_a, dest_spec=dest_spec,
                                 root=tmp_path / "archive")


def stored_session(pushed) -> tuple:
    """(object_key, blob, main_bytes) for UUID_1 as the Archive holds it."""
    master = keyring.fetch_master(home=pushed.home_a)
    dest = DirectoryDestination(pushed.root)
    index = archive.load_index(dest, master)
    meta = index["sessions"][UUID_1]
    blob = dest.read(meta["object"])
    tar = archive.get_session(dest, master, UUID_1, meta["object"])
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        main = t.extractfile(meta["main_path"]).read()
    return meta["object"], blob, main


def stored_texts(pushed) -> list:
    _, _, main = stored_session(pushed)
    return [json.loads(line).get("text")
            for line in main.decode().splitlines()[1:]]


# --- item 1: push mirrors ADR-0002's union rule -------------------------------


def test_push_from_a_machine_that_is_behind_skips_and_reports(
        pushed, tmp_path, capsys):
    """THE data loss this suite exists for: a machine holding a byte-prefix
    of the Archive's main Transcript - it pulled an older state, or never
    pulled - must not overwrite the longer copy with the shorter one."""
    home_b = linked(tmp_path, "home_behind", ["one"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    key_before, blob_before, _ = stored_session(pushed)
    capsys.readouterr()

    # the dry run already names the skip, so the plan matches the apply
    assert sync.push(ns(apply=False), home_b) == 0
    dry = capsys.readouterr().out
    assert UUID_1 in dry and "skip" in dry

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_texts(pushed) == ["one", "two"], \
        "a behind machine overwrote the longer Transcript with the shorter"
    key_after, blob_after, _ = stored_session(pushed)
    assert (key_after, blob_after) == (key_before, blob_before), \
        "the Archive's object was rewritten"
    assert UUID_1 in out and "skip" in out
    assert "pull" in out, "the report says what to do about it"
    assert "Sessions: 0 pushed" in out


def test_push_of_a_longer_divergent_copy_is_skipped_and_named(
        pushed, tmp_path, capsys):
    """Divergent with a LONGER local main: the Index's main_size/main_sha256
    already prove it (the stored prefix does not match), so the skip needs no
    download - but the property under test is the skip itself."""
    home_b = linked(tmp_path, "home_div",
                    ["one", "two point five, entirely different"],
                    pushed.home_a, pushed.dest_spec, "machine-b")
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_texts(pushed) == ["one", "two"], \
        "a divergent copy overwrote the Archive's"
    assert UUID_1 in out
    assert "diverged" in out.lower(), "the report names the divergence"
    assert "pull first" in out.lower(), "the report says what to do about it"


def test_push_of_a_shorter_divergent_copy_fetches_and_still_skips(
        pushed, tmp_path, capsys):
    """Divergent with a SHORTER local main: from the Index metadata alone
    this is indistinguishable from behind, so push must fetch the stored
    object, compare bytes, and still skip."""
    home_b = linked(tmp_path, "home_div_short", ["x"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_texts(pushed) == ["one", "two"]
    assert UUID_1 in out and "diverged" in out.lower()


def test_push_when_strictly_ahead_replaces_after_fetching_the_stored_tree(
        pushed, capsys):
    """The append-only case still pushes, and it fetches the Archive's copy
    before it replaces it.

    This used to be decided from the Index alone. An Index cannot be forged
    but it can disagree with the object it describes - a replay at exactly the
    recorded revision, or push's own write order after an interruption - and
    that made the one branch that authorised an overwrite the one branch
    acting on an unchecked claim. An entry may VETO without a download and may
    never AUTHORISE without one.
    """
    main = main_path(pushed.home_a)
    main.write_text(main.read_text() + jline({"type": "user",
                                              "text": "three"}))
    capsys.readouterr()

    assert sync.push(ns(apply=True), pushed.home_a) == 0
    out = capsys.readouterr().out

    assert "Sessions: 1 pushed" in out
    assert stored_texts(pushed) == ["one", "two", "three"]


def test_a_first_push_of_a_session_fetches_nothing(pushed, tmp_path, capsys,
                                                   monkeypatch):
    """What the fetch costs, bounded: a Session the Index has no entry for is
    the whole of a first push and there is nothing to compare it against, so
    no object is read for it. The download only ever pays for an overwrite."""
    main = main_path(pushed.home_a).parent
    other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    (main / (other + ".jsonl")).write_text(
        main_text(str(pushed.home_a / PROJ), ["fresh"]))

    def boom(*args, **kwargs):
        raise AssertionError("a Session with no Index entry was fetched")
    real_get_session = archive.get_session
    monkeypatch.setattr(sync.archive, "get_session", boom)
    capsys.readouterr()
    try:
        assert sync.push(ns(apply=True), pushed.home_a) == 0
    finally:
        # restored by hand, not undo(): the monkeypatch instance is shared
        # with the autouse keyring fixture, and undo() would strip that too
        monkeypatch.setattr(sync.archive, "get_session", real_get_session)
    out = capsys.readouterr().out

    assert "Sessions: 1 pushed" in out


def test_a_cheap_veto_still_costs_no_download(pushed, tmp_path, capsys,
                                              monkeypatch):
    """And the veto keeps its half of the bargain: a local main that cannot
    contain the stored one is refused from the Index alone."""
    home_b = linked(tmp_path, "home_veto", ["one"], pushed.home_a,
                    pushed.dest_spec, "machine-b")

    def boom(*args, **kwargs):
        raise AssertionError("a veto fetched a Session object")
    real_get_session = archive.get_session
    monkeypatch.setattr(sync.archive, "get_session", boom)
    capsys.readouterr()
    try:
        assert sync.push(ns(apply=True), home_b) == 0
    finally:
        monkeypatch.setattr(sync.archive, "get_session", real_get_session)
    out = capsys.readouterr().out

    assert UUID_1 in out and "skip" in out


def test_push_with_an_identical_main_but_a_changed_tree_replaces(
        pushed, capsys):
    """A Session is a tree, and the tree can grow while the main Transcript
    stands still - a subagent journal, most often. The local tree contains
    the stored one, so it is ahead everywhere and the change goes up; skipping
    it would strand the journal on this machine forever."""
    subtree = main_path(pushed.home_a).parent / UUID_1 / "subagents"
    subtree.mkdir(parents=True)
    (subtree / "journal.jsonl").write_text(jline({"step": 1}))
    capsys.readouterr()

    assert sync.push(ns(apply=True), pushed.home_a) == 0
    out = capsys.readouterr().out

    assert "Sessions: 1 pushed" in out
    master = keyring.fetch_master(home=pushed.home_a)
    dest = DirectoryDestination(pushed.root)
    meta = archive.load_index(dest, master)["sessions"][UUID_1]
    tar = archive.get_session(dest, master, UUID_1, meta["object"])
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        names = t.getnames()
    assert UUID_1 + "/subagents/journal.jsonl" in names


# --- the unit of comparison is the unit of replacement ------------------------


def stored_names(pushed) -> list:
    master = keyring.fetch_master(home=pushed.home_a)
    dest = DirectoryDestination(pushed.root)
    meta = archive.load_index(dest, master)["sessions"][UUID_1]
    tar = archive.get_session(dest, master, UUID_1, meta["object"])
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        return sorted(t.getnames())


def test_a_push_never_deletes_a_stored_subtree_its_main_says_nothing_about(
        pushed, tmp_path, capsys):
    """The comparison was the main Transcript and the replacement is the whole
    tree, so a Session whose subtree diverged while its main stood still read
    as 'ahead': the stored main WAS a byte-prefix of the local one, push
    replaced the whole object, and the subagent journal only the Archive held
    was deleted - reported as a successful push, with no skip line."""
    subtree = main_path(pushed.home_a).parent / UUID_1 / "subagents"
    subtree.mkdir(parents=True)
    (subtree / "journal.jsonl").write_text(jline({"step": 1}))
    assert sync.push(ns(apply=True), pushed.home_a) == 0
    journal = UUID_1 + "/subagents/journal.jsonl"
    assert journal in stored_names(pushed)

    # machine-b holds the same main Transcript and none of the subtree
    home_b = linked(tmp_path, "home_sub", ["one", "two"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert journal in stored_names(pushed), \
        "a push deleted a stored subtree its main Transcript said nothing about"
    assert UUID_1 in out and "skip" in out
    assert "pull first" in out.lower()


def test_pulling_first_brings_down_the_subtree_the_push_refused_over(
        pushed, tmp_path, capsys):
    """The cure every skip line names has to work. Pull decided 'unchanged'
    from the main Transcript alone and never fetched the tree, so the machine
    the push told to pull first could not obtain what it was missing."""
    subtree = main_path(pushed.home_a).parent / UUID_1 / "subagents"
    subtree.mkdir(parents=True)
    (subtree / "journal.jsonl").write_text(jline({"step": 1}))
    assert sync.push(ns(apply=True), pushed.home_a) == 0

    home_b = linked(tmp_path, "home_sub_pull", ["one", "two"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    landed = main_path(home_b).parent / UUID_1 / "subagents" / "journal.jsonl"
    assert landed.is_file(), \
        "pull declined to fetch a tree whose main Transcript matched"

    # and now the push it refused goes through, with nothing lost
    assert sync.push(ns(apply=True), home_b) == 0
    assert UUID_1 + "/subagents/journal.jsonl" in stored_names(pushed)


def test_project_residue_follows_the_same_union_rule(pushed, tmp_path,
                                                     capsys):
    """Residue was exempt from the rule entirely: put_project replaced the
    whole stored tar on any tree_hash difference, with no comparison and no
    skip line, while pull's residue leg unions per file and never deletes. A
    machine holding a byte-prefix of the Archive's memory file - the textbook
    BEHIND case - truncated it in the Archive and deleted files it never
    had."""
    project = main_path(pushed.home_a).parent
    memory = project / "memory"
    memory.mkdir()
    (memory / "notes.md").write_text("line one\nline two\n")
    (memory / "only-on-a.md").write_text("only machine-a has this\n")
    assert sync.push(ns(apply=True), pushed.home_a) == 0

    home_b = linked(tmp_path, "home_res", ["one", "two"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    b_memory = main_path(home_b).parent / "memory"
    b_memory.mkdir()
    (b_memory / "notes.md").write_text("line one\n")   # a strict byte-prefix
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    master = keyring.fetch_master(home=pushed.home_a)
    dest = DirectoryDestination(pushed.root)
    index = archive.load_index(dest, master)
    cwd = sorted(index["projects"])[0]
    tar = archive.get_project(dest, master, cwd, index["projects"][cwd]["object"])
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        names = sorted(t.getnames())
        notes = t.extractfile("memory/notes.md").read()

    assert notes == b"line one\nline two\n", \
        "a behind machine truncated the Archive's memory file"
    assert "memory/only-on-a.md" in names, \
        "a behind machine deleted a stored file it never had"
    assert "skip" in out and "pull first" in out.lower()


def test_a_transcript_that_vanishes_mid_push_is_reported_not_raised(
        pushed, tmp_path, capsys):
    """A live agent rotates a transcript while the walk is running. That
    escaped as a bare FileNotFoundError with Session objects already written
    and the Index never sealed - and on a FIRST push, that state makes
    load_index refuse for every machine thereafter, with 'delete the Archive
    and push afresh' as the named cure."""
    project = main_path(pushed.home_a).parent
    subtree = project / UUID_1 / "subagents"
    subtree.mkdir(parents=True)
    doomed = subtree / "journal.jsonl"
    doomed.write_text(jline({"step": 1}))

    real_members = sync._canonical_members

    def vanish(session, home):
        doomed.unlink(missing_ok=True)
        return real_members(session, home)
    sync._canonical_members = vanish
    capsys.readouterr()
    try:
        code = sync.push(ns(apply=True), pushed.home_a)
    finally:
        sync._canonical_members = real_members
    out = capsys.readouterr().out

    assert code == 0
    assert UUID_1 in out and "skip" in out
    assert "Sessions:" in out, "the push ended before its report"


def test_pull_then_append_then_push_round_trips(pushed, tmp_path, capsys):
    """The rule must not break the ordinary flow it exists to protect: pull,
    work (append), push - one rule for both directions, per ADR-0002."""
    home_b = empty_linked(tmp_path, "home_flow", pushed.home_a,
                          pushed.dest_spec, "machine-b")
    assert sync.pull(ns(apply=True), home_b) == 0
    main = main_path(home_b)
    main.write_text(main.read_text() + jline({"type": "user",
                                              "text": "from b"}))
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert "Sessions: 1 pushed" in out
    assert stored_texts(pushed) == ["one", "two", "from b"]


# --- item 1, adversarial pass: what the fast path may and may not decide -------
#
# The Index's main_size/main_sha256 stand in for a byte comparison it never
# runs, so the questions worth asking are which local shapes it lets through
# and what happens when the Index and the object it describes disagree. Every
# assertion below reads the Archive by DECRYPTING the stored object, never by
# believing the report - a skip that is printed and an object that is intact
# are two different claims.


def index_at(pushed):
    """The Archive's Index, opened with the master key machine-a holds."""
    dest = DirectoryDestination(pushed.root)
    return dest, archive.load_index(dest, keyring.fetch_master(
        home=pushed.home_a))


def test_an_empty_local_main_is_behind_rather_than_ahead(pushed, tmp_path,
                                                         capsys):
    """Zero bytes is a byte-prefix of everything, so the direction has to come
    out of the comparison rather than out of 'it differs'. An emptied main is
    also the shape a half-written file has, which is the one carryon must not
    read as the newer copy."""
    home_b = linked(tmp_path, "home_empty", ["one"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    main_path(home_b).write_text("")
    _, blob_before, _ = stored_session(pushed)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_texts(pushed) == ["one", "two"], \
        "an empty main Transcript overwrote the Archive's"
    assert stored_session(pushed)[1] == blob_before
    assert UUID_1 in out and "behind" in out


def test_equal_length_divergence_is_refused_without_a_download(pushed,
                                                               tmp_path,
                                                               capsys,
                                                               monkeypatch):
    """The one length the fast path cannot answer with 'longer, so ahead': the
    same size with different bytes. It has the prefix hash to decide with, so
    it must call divergence on the spot rather than fetch or - far worse -
    read equal lengths as equal Sessions."""
    home_b = linked(tmp_path, "home_eqlen", ["one", "TWO"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    _, blob_before, main_before = stored_session(pushed)
    canon, _, _ = rekey.apply_to_bytes(
        main_path(home_b).read_bytes(),
        lambda text: rekey.canonicalise_jsonl(text, home_b))
    assert len(canon) == len(main_before) and canon != main_before

    def boom(*args, **kwargs):
        raise AssertionError("equal lengths needed no download to separate")
    real_get_session = archive.get_session
    monkeypatch.setattr(sync.archive, "get_session", boom)
    capsys.readouterr()
    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out
    monkeypatch.setattr(sync.archive, "get_session", real_get_session)

    assert stored_session(pushed)[1] == blob_before, \
        "an equal-length divergent copy overwrote the Archive's"
    assert UUID_1 in out and "diverged" in out.lower()


def test_a_main_size_the_stored_object_contradicts_falls_back_to_the_bytes(
        pushed, tmp_path, capsys):
    """A main_size no local copy can reach sends the decision down the slow
    path, where the object decides. The fast path may only ever be a shortcut
    to the same answer, so a size that fits nothing must cost a download and
    an honest comparison rather than a verdict of its own."""
    home_b = linked(tmp_path, "home_bigsize", ["one", "elsewhere", "three"],
                    pushed.home_a, pushed.dest_spec, "machine-b")
    dest, index = index_at(pushed)
    index["sessions"][UUID_1]["main_size"] = 10 ** 9
    archive.save_index(dest, keyring.fetch_master(home=pushed.home_a), index)
    _, blob_before, _ = stored_session(pushed)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_session(pushed)[1] == blob_before
    assert stored_texts(pushed) == ["one", "two"]
    assert UUID_1 in out and "diverged" in out.lower()


def test_an_index_entry_naming_no_object_skips_rather_than_overwrites(
        pushed, tmp_path, capsys):
    """The slow path fetches what the Index names, and the Index is opened
    from a Destination: 'the entry names nothing to fetch' is a state a push
    has to survive. It must not read an unfetchable comparison as permission
    to write over what is there."""
    home_b = linked(tmp_path, "home_noobj", ["one"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    key_before, blob_before, _ = stored_session(pushed)
    dest, index = index_at(pushed)
    index["sessions"][UUID_1].pop("object")
    archive.save_index(dest, keyring.fetch_master(home=pushed.home_a), index)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert dest.read(key_before) == blob_before, \
        "the object the Index stopped naming was overwritten anyway"
    assert UUID_1 in out and "skip" in out


def test_a_replayed_index_cannot_talk_the_slow_path_into_an_overwrite(
        pushed, tmp_path, capsys):
    """An Index is authenticated but not fresh: a Destination can serve back
    an older authentic copy, and replaying the exact revision this machine
    last recorded slips under the rollback refusal, which only fires on a
    revision BELOW the high-water mark.

    The stale entry describes a SHORTER main Transcript than the object
    actually holds, and the local copy extends that shorter one - so from the
    Index alone this reads as the ordinary append-only case, and the Index is
    saying 'this push is safe' about bytes it has not seen. The stored object
    is fetched before any overwrite and checked against the entry that
    authorised the fetch (_main_mismatch); a disagreement is a skip (ADR-0009).
    """
    home_b = linked(tmp_path, "home_replay", ["one", "two"], pushed.home_a,
                    pushed.dest_spec, "machine-b")
    assert sync.push(ns(apply=True), home_b) == 0  # identical: unchanged, but
    index_key = pushed.root / "carryon" / "index.enc"   # the revision is read
    stale = index_key.read_bytes()

    main = main_path(pushed.home_a)
    main.write_text(main.read_text()
                    + jline({"type": "user", "text": "three"})
                    + jline({"type": "user", "text": "four"}))
    assert sync.push(ns(apply=True), pushed.home_a) == 0
    _, blob_before, _ = stored_session(pushed)
    # the objects are left exactly as they are; only the Index goes back
    index_key.write_bytes(stale)

    b_main = main_path(home_b)
    b_main.write_text(b_main.read_text()
                      + jline({"type": "user", "text": "b's own line"}))
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stored_session(pushed)[1] == blob_before, \
        "a replayed Index authorised overwriting bytes it does not describe"
    assert stored_texts(pushed) == ["one", "two", "three", "four"]
    assert UUID_1 in out and "skip" in out
    assert "Destination" in out, "the disagreement is not named"


def test_an_interrupted_push_cannot_talk_a_later_one_into_an_overwrite(
        pushed, tmp_path, capsys):
    """The same disagreement with no attacker at all. push writes each object
    inside the loop and seals the Index once, after it, so between the two the
    Archive holds an object newer than the Index describes - permanently, if
    the push is interrupted. Another machine's push then reads an Index that
    is the truth about an older object."""
    home_b = linked(tmp_path, "home_interrupt", ["one", "two"],
                    pushed.home_a, pushed.dest_spec, "machine-b")
    assert sync.push(ns(apply=True), home_b) == 0

    # machine-a appends and pushes, but the network dies before save_index
    main = main_path(pushed.home_a)
    main.write_text(main.read_text() + jline({"type": "user", "text": "three"}))
    real_save = sync.archive.save_index

    def die(*args, **kwargs):
        raise SystemExit("the Destination went away")
    sync.archive.save_index = die
    try:
        with pytest.raises(SystemExit):
            sync.push(ns(apply=True), pushed.home_a)
    finally:
        sync.archive.save_index = real_save
    blob_before = (pushed.root / "carryon").rglob("*.tar.enc")
    blob_before = sorted(p.read_bytes() for p in blob_before)

    b_main = main_path(home_b)
    b_main.write_text(b_main.read_text()
                      + jline({"type": "user", "text": "b's own line"}))
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    after = sorted(p.read_bytes()
                   for p in (pushed.root / "carryon").rglob("*.tar.enc"))
    assert after == blob_before, \
        "a stale Index authorised overwriting the object it does not describe"
    assert UUID_1 in out and "skip" in out


# --- item 2: a deleted Index must not read as a fresh Archive ------------------


def test_a_deleted_index_makes_a_pull_refuse_not_silently_no_op(
        pushed, tmp_path):
    """An attacker who deletes carryon/index.enc used to get load_index
    returning a fresh empty Index, so the History half of a pull quietly did
    nothing - and on a machine that has never pulled there is no high-water
    mark to notice. Session objects with no Index are the tell."""
    (pushed.root / "carryon" / "index.enc").unlink()
    home_b = empty_linked(tmp_path, "home_noidx", pushed.home_a,
                          pushed.dest_spec, "machine-b")

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), home_b)

    assert "Index" in str(exc.value)
    assert not (home_b / ".claude" / "projects").exists(), \
        "the pull half-ran against an Archive whose catalogue is missing"


def test_a_deleted_index_refuses_a_push_with_no_high_water_mark(
        pushed, tmp_path):
    """The push side of the same hole: a machine that never pushed or pulled
    here has seen no revision, so the rollback refusal stays quiet - and its
    push would re-seal a fresh catalogue that unlinks every stored Session."""
    (pushed.root / "carryon" / "index.enc").unlink()
    sessions_before = {p.name: p.read_bytes()
                       for p in (pushed.root / "carryon"
                                 / "sessions").iterdir()}
    home_b = linked(tmp_path, "home_push_noidx", ["mine"], pushed.home_a,
                    pushed.dest_spec, "machine-b")

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home_b)

    assert "Index" in str(exc.value)
    assert {p.name: p.read_bytes()
            for p in (pushed.root / "carryon" / "sessions").iterdir()} == \
        sessions_before, "the refused push still wrote Session objects"


def test_an_archive_with_no_session_objects_still_reads_as_fresh(tmp_path):
    """The other half of the tell: a genuinely fresh Archive, and one holding
    only what a keyless Setup push writes (ADR-0004) plus a pairing blob,
    must keep returning a fresh Index rather than refusing."""
    dest = DirectoryDestination(tmp_path / "archive")
    assert archive.load_index(dest, MASTER) == archive.fresh_index()

    dest.write("carryon/setups/laptop/MANIFEST.json", b"{}")
    dest.write("carryon/pair/ABCDEF.enc", b"wrapped")
    assert archive.load_index(dest, MASTER) == archive.fresh_index()


# --- item 3: a Destination dying on the READ path is a skip, not an abort -----


class DiesLikeGit:
    """A real Destination whose chosen operation fails the way
    GitDestination's does: SystemExit out of _git_or_die, on the READ path.

    Duck-typed rather than a Destination subclass, like hostile_archive's
    ListsOneExtraKey: what is under test is the engine's rule that a
    Destination failure after work has landed is reported and skipped, not
    any transport's internals.
    """

    GIT_MSG = "git fetch against ssh://evil/repo failed:\nfatal: dead remote"

    def __init__(self, inner, on):
        self._inner = inner
        self._on = on  # 'setup-list' | 'read-tree' | 'session-read'

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def list(self, prefix=""):
        if self._on == "setup-list" and \
                prefix.startswith(archive.SETUPS_PREFIX):
            raise SystemExit(self.GIT_MSG)
        return self._inner.list(prefix)

    def read(self, key):
        if self._on == "session-read" and \
                key.startswith(archive.SESSIONS_PREFIX):
            raise SystemExit(self.GIT_MSG)
        return self._inner.read(key)

    def read_tree(self, prefix, dst_dir):
        if self._on == "read-tree":
            raise SystemExit(self.GIT_MSG)
        return self._inner.read_tree(prefix, dst_dir)


def dying_destination(monkeypatch, on):
    real = destinations.from_spec
    monkeypatch.setattr(destinations, "from_spec",
                        lambda spec, home: DiesLikeGit(real(spec, home), on))


def test_a_destination_dying_at_the_setup_catalogue_does_not_abort_the_pull(
        pushed, tmp_path, capsys, monkeypatch):
    """_setup_catalogue runs AFTER the Session loop has written to $HOME, and
    GitDestination syncs (fetch, SystemExit on failure) on every read. The
    History that already landed deserves a report, so the Setup half is
    skipped with the reason named, never raised."""
    home_b = empty_linked(tmp_path, "home_gitlist", pushed.home_a,
                          pushed.dest_spec, "machine-b")
    dying_destination(monkeypatch, "setup-list")
    capsys.readouterr()

    # 2 rather than a raise: the History is reported and the run ends with a
    # status saying the Setup half did not land, which is the whole point of
    # skipping instead of raising - the report survives AND a script can see
    # that it is short.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert main_path(home_b).is_file(), "the History half did not land"
    assert "-" * 74 in out, "the pull died before its summary"
    assert "Setup" in out and "git fetch" in out, \
        "the skipped Setup half is not named with its reason"


def test_a_destination_dying_while_serving_a_session_is_a_skip_not_an_abort(
        pushed, tmp_path, capsys, monkeypatch):
    """The same failure one stage earlier, mid-Session-loop: the Session is
    reported and skipped like any other object the Destination would not
    serve (ADR-0009), the rest of the pull - the Setup half included - still
    runs, and the exit status says what was skipped."""
    home_b = empty_linked(tmp_path, "home_gitread", pushed.home_a,
                          pushed.dest_spec, "machine-b")
    dying_destination(monkeypatch, "session-read")
    capsys.readouterr()

    # Flagged, not raised: a finished pull reports its shortfall in the
    # exit code (ADR-0012) so sync's push half still runs - which is the
    # very property this test is about, one command up.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert "-" * 74 in out, "the pull died before its summary"
    assert (home_b / ".claude" / "settings.json").is_file(), \
        "the Setup half was lost with the failed Session read"
    assert UUID_1 in out, "the skipped Session is not named in the report"
    assert UUID_1 in out.split("pull finished with")[1], \
        "the closing sentence stopped naming the skipped Session"


def test_a_destination_dying_while_laying_out_the_setup_is_one_refusal(
        pushed, tmp_path, capsys, monkeypatch):
    """get_setup's guard turns what the transport raises into one refused
    Setup; SystemExit out of a git sync is a thing the transport raises."""
    home_b = empty_linked(tmp_path, "home_gittree", pushed.home_a,
                          pushed.dest_spec, "machine-b")
    dying_destination(monkeypatch, "read-tree")
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert main_path(home_b).is_file(), "the History half did not land"
    assert "-" * 74 in out
    assert "machine-a" in out and "git fetch" in out, \
        "the unreadable Setup is not named with its reason"

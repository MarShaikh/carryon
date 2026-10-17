"""The Base: an edit to per-project memory is an edit, not a divergence.

ADR-0002's amendment of 2026-10-17. The prefix rule assumes a file only grows,
and per-project memory does not: an agent rewrites a line of MEMORY.md in place
as often as it appends one. Under the prefix rule alone, that edit was a
divergence the moment it was made, and nothing ever ended it. Push skipped the
project and said "pull first". Pull filed the Archive's copy and kept the local
one. The next push compared against the same stored copy and skipped again.

These tests pin the three-way rule that replaces it for memory files: the
version this machine and the Archive last agreed on (the Base) decides which
side moved. They also pin the three things the Base made necessary: the binding
check of a fetched residue against the Index, the backup before a pull writes
over a local copy, and `carryon resolve`, which ends a filed divergence.

Every home here is synthetic, the OS keychain is forced to the fallback file,
and all content is invented.
"""

import argparse
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, keyring, rekey, resolve, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

UUID_1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ = "code/app"
NOTES = "alpha\nbeta\ngamma\n"
TODO = "one\ntwo\nthree\n"
SKIP = "\n  skip     "  # a skip line, not "not set up here, skipped"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False, paths=[])
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def project_dir(home) -> pathlib.Path:
    cwd = str(home / PROJ)
    return home / ".claude" / "projects" / rekey.encode_project_dir(cwd)


def memory(home) -> pathlib.Path:
    return project_dir(home) / "memory"


def build_home(tmp_path, name) -> pathlib.Path:
    home = tmp_path / name
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    cwd = str(home / PROJ)
    project = project_dir(home)
    project.mkdir(parents=True)
    (project / (UUID_1 + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "text": "hello"}))
    return home


def linked(tmp_path, name, master_from, dest_spec, machine) -> pathlib.Path:
    """A second home sharing the master key and Destination, holding no
    memory of its own until it pulls."""
    home = build_home(tmp_path, name)
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)
    return home


@pytest.fixture
def pair(tmp_path):
    """machine-a pushed two memory files, machine-b pulled them: both hold
    the same memory and both have recorded Bases for it."""
    home_a = build_home(tmp_path, "home_a")
    memory(home_a).mkdir()
    (memory(home_a) / "notes.md").write_text(NOTES)
    (memory(home_a) / "todo.md").write_text(TODO)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = linked(tmp_path, "home_b", home_a, dest_spec, "machine-b")
    assert sync.pull(ns(apply=True), home_b) == 0
    assert (memory(home_b) / "notes.md").read_text() == NOTES
    return types.SimpleNamespace(home_a=home_a, home_b=home_b,
                                 dest_spec=dest_spec,
                                 root=tmp_path / "archive")


def open_archive(p):
    master = keyring.fetch_master(home=p.home_a)
    dest = DirectoryDestination(p.root)
    return dest, master, archive.load_index(dest, master)


def stored_memory(p) -> dict:
    """{member name: text} of the one project residue the Archive holds."""
    dest, master, index = open_archive(p)
    (cwd, meta), = index["projects"].items()
    tar = archive.get_project(dest, master, cwd, meta["object"])
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        return {m.name: t.extractfile(m).read().decode()
                for m in t.getmembers() if m.isfile()}


def residue_object(p) -> tuple:
    """(object key, sealed blob) of the stored residue."""
    dest, _master, index = open_archive(p)
    (_cwd, meta), = index["projects"].items()
    return meta["object"], dest.read(meta["object"])


def bases_of(home, p) -> dict:
    state = json.loads((home / ".carryon" / "state.json").read_text())
    projects = state.get("bases", {}).get(p.dest_spec, {})
    (only,) = projects.values() if projects else ({},)
    return only


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def filed_copy(home, rel="memory/notes.md") -> pathlib.Path:
    return (home / ".carryon" / "conflicts" / project_dir(home).name / rel)


# --- the store -----------------------------------------------------------------


def test_push_records_a_base_for_every_memory_file_it_carries(pair):
    assert bases_of(pair.home_a, pair) == {
        "memory/notes.md": sha(NOTES), "memory/todo.md": sha(TODO)}


def test_pull_records_a_base_for_every_memory_file_it_lays_down(pair):
    assert bases_of(pair.home_b, pair) == {
        "memory/notes.md": sha(NOTES), "memory/todo.md": sha(TODO)}


def test_a_dry_run_records_no_base(tmp_path):
    home = build_home(tmp_path, "home_dry")
    memory(home).mkdir()
    (memory(home) / "notes.md").write_text(NOTES)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="m"), home)
    assert sync.push(ns(apply=False), home) == 0
    state = home / ".carryon" / "state.json"
    assert not state.exists() or "bases" not in json.loads(state.read_text())


def test_raising_the_high_water_mark_keeps_the_bases(pair):
    """_record_revision rewrites its Destination's entry whole, so Bases
    stored inside it would be wiped by every revision bump."""
    (memory(pair.home_a) / "extra.md").write_text("new note\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert sync.pull(ns(apply=True), pair.home_b) == 0
    assert bases_of(pair.home_b, pair)["memory/notes.md"] == sha(NOTES)
    assert bases_of(pair.home_b, pair)["memory/extra.md"] == sha("new note\n")


def test_an_unchanged_push_gives_an_upgraded_machine_its_bases(pair, capsys):
    """A machine that pushed before the Base existed has none, so its first
    in-place edit would hit the bare prefix rule again. A push or pull that
    finds the project unchanged records them."""
    state_path = pair.home_a / ".carryon" / "state.json"
    state = json.loads(state_path.read_text())
    del state["bases"]
    state_path.write_text(json.dumps(state))
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert bases_of(pair.home_a, pair)["memory/notes.md"] == sha(NOTES)

    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert SKIP not in capsys.readouterr().out
    assert stored_memory(pair)["memory/notes.md"] == "alpha\nBETA\ngamma\n"


def test_a_state_file_that_will_not_read_means_no_bases_and_one_warning(
        pair, capsys):
    """Never a gate: the Base can only make carryon less cautious, so losing
    it falls back to the prefix rule, said once."""
    (pair.home_a / ".carryon" / "state.json").write_bytes(b"\xff\xfe not json")
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    out = capsys.readouterr().out
    assert SKIP in out, "an edit with no readable Base was pushed anyway"
    assert stored_memory(pair)["memory/notes.md"] == NOTES
    assert out.count("Bases") == 1, "the lost Bases were not said exactly once"


# --- push ------------------------------------------------------------------------


def test_an_in_place_edit_is_pushed(pair, capsys):
    """THE bug: an edit to the middle of a memory file was a permanent
    skip."""
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    out = capsys.readouterr().out
    assert SKIP not in out
    assert stored_memory(pair)["memory/notes.md"] == "alpha\nBETA\ngamma\n"
    assert bases_of(pair.home_a, pair)["memory/notes.md"] == \
        sha("alpha\nBETA\ngamma\n")


def test_push_skips_when_the_archive_moved_and_pull_first_cures_it(
        pair, capsys):
    """Per file: machine-a edits notes, machine-b edits todo. b's push would
    replace the stored tree whole, a's edit with it, so it skips. This time
    the 'pull first' it names works."""
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    (memory(pair.home_b) / "todo.md").write_text("one\nTWO\nthree\n")
    capsys.readouterr()

    assert sync.push(ns(apply=True), pair.home_b) == 0
    out = capsys.readouterr().out
    assert SKIP in out and "pull first" in out
    assert "memory/notes.md" in out, "the skip does not name the file"
    assert stored_memory(pair)["memory/todo.md"] == TODO

    assert sync.pull(ns(apply=True), pair.home_b) == 0
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "alpha\nBETA\ngamma\n"
    assert (memory(pair.home_b) / "todo.md").read_text() == \
        "one\nTWO\nthree\n", "pull overwrote this machine's own edit"

    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_b) == 0
    assert SKIP not in capsys.readouterr().out
    assert stored_memory(pair) == {"memory/notes.md": "alpha\nBETA\ngamma\n",
                                   "memory/todo.md": "one\nTWO\nthree\n"}


def test_a_shortened_file_is_an_edit_too(pair, capsys):
    """Removing a line leaves a byte-prefix of the old file, which the prefix
    rule reads as 'behind'. With a Base, the Base decides first."""
    (memory(pair.home_a) / "notes.md").write_text("alpha\nbeta\n")
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert SKIP not in capsys.readouterr().out
    assert stored_memory(pair)["memory/notes.md"] == "alpha\nbeta\n"

    assert sync.pull(ns(apply=True), pair.home_b) == 0
    assert (memory(pair.home_b) / "notes.md").read_text() == "alpha\nbeta\n"
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_b) == 0
    assert SKIP not in capsys.readouterr().out


def test_an_edit_on_both_machines_is_still_a_divergence(pair, capsys):
    (memory(pair.home_a) / "notes.md").write_text("alpha\nFROM A\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    (memory(pair.home_b) / "notes.md").write_text("alpha\nFROM B\ngamma\n")
    capsys.readouterr()

    assert sync.push(ns(apply=True), pair.home_b) == 0
    assert SKIP in capsys.readouterr().out
    assert stored_memory(pair)["memory/notes.md"] == "alpha\nFROM A\ngamma\n"

    assert sync.pull(ns(apply=True), pair.home_b) == 2
    out = capsys.readouterr().out
    assert "conflict" in out and "carryon resolve" in out
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "alpha\nFROM B\ngamma\n"
    assert filed_copy(pair.home_b).read_text() == "alpha\nFROM A\ngamma\n"
    assert bases_of(pair.home_b, pair)["memory/notes.md"] == sha(NOTES), \
        "a conflict moved the Base"


def test_a_file_deleted_locally_is_still_a_skip(pair, capsys):
    """Deletions are out of scope: the Base answers edits only."""
    (memory(pair.home_a) / "todo.md").unlink()
    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert SKIP in capsys.readouterr().out
    assert stored_memory(pair)["memory/todo.md"] == TODO


# --- pull ------------------------------------------------------------------------


def test_another_machines_edit_lands_on_pull_and_the_old_copy_is_kept(
        pair, capsys):
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    capsys.readouterr()

    assert sync.pull(ns(apply=True), pair.home_b) == 0
    out = capsys.readouterr().out
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "alpha\nBETA\ngamma\n"
    rel = (memory(pair.home_b) / "notes.md").relative_to(pair.home_b)
    backups = list((pair.home_b / ".carryon" / "backups").glob(f"*/{rel}"))
    assert [b.read_text() for b in backups] == [NOTES], \
        "the copy this pull wrote over is not recoverable"
    assert "backed up" in out and "another machine's edit" in out
    assert bases_of(pair.home_b, pair)["memory/notes.md"] == \
        sha("alpha\nBETA\ngamma\n")


def test_pull_keeps_this_machines_edit_when_the_archive_did_not_move(pair):
    (memory(pair.home_b) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.pull(ns(apply=True), pair.home_b) == 0
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "alpha\nBETA\ngamma\n"
    assert not filed_copy(pair.home_b).exists()


# --- the binding check -----------------------------------------------------------


def test_a_replayed_residue_is_refused_on_pull(pair, capsys):
    """Under the Base a replay would win: the local copy equals the Base and
    the replayed one does not, so pull would write superseded memory over
    current memory."""
    key, old_blob = residue_object(pair)
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert sync.pull(ns(apply=True), pair.home_b) == 0
    # The Index moves on past what machine-b holds, so its pull fetches -
    # and the Destination serves the first version in place of the third.
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\nGAMMA\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    DirectoryDestination(pair.root).write(key, old_blob)
    capsys.readouterr()

    code = sync.pull(ns(apply=True), pair.home_b)
    out = capsys.readouterr().out
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "alpha\nBETA\ngamma\n", "a replayed residue overwrote current memory"
    assert code == 2
    assert "not the version the Index records" in out


def test_a_replayed_residue_is_refused_on_push(pair, capsys):
    key, old_blob = residue_object(pair)
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    DirectoryDestination(pair.root).write(key, old_blob)
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\nGAMMA\n")
    capsys.readouterr()

    assert sync.push(ns(apply=True), pair.home_a) == 0
    out = capsys.readouterr().out
    assert SKIP in out and "not the version the Index records" in out
    assert residue_object(pair) == (key, old_blob), \
        "push overwrote an object that is not the one the Index names"


# --- resolve ---------------------------------------------------------------------


@pytest.fixture
def diverged(pair):
    """Both machines edited notes.md; a pushed, b pulled and has a.s copy
    filed."""
    (memory(pair.home_a) / "notes.md").write_text("alpha\nFROM A\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    (memory(pair.home_b) / "notes.md").write_text("alpha\nFROM B\ngamma\n")
    assert sync.pull(ns(apply=True), pair.home_b) == 2
    assert filed_copy(pair.home_b).is_file()
    return pair


def test_resolve_with_no_paths_lists_what_is_filed(diverged, capsys):
    capsys.readouterr()
    assert resolve.run(ns(), diverged.home_b) == 0
    out = capsys.readouterr().out
    local = memory(diverged.home_b) / "notes.md"
    assert str(local.relative_to(diverged.home_b)) in out
    assert str(filed_copy(diverged.home_b)) in out


def test_resolve_ends_a_divergence_and_the_next_push_carries_the_merge(
        diverged, capsys):
    local = memory(diverged.home_b) / "notes.md"
    local.write_text("alpha\nFROM A\nFROM B\ngamma\n")   # merged by hand

    assert resolve.run(ns(paths=[str(local)]), diverged.home_b) == 0
    assert filed_copy(diverged.home_b).is_file(), "a dry run removed it"
    assert bases_of(diverged.home_b, diverged)["memory/notes.md"] == sha(NOTES)

    assert resolve.run(ns(paths=[str(local)], apply=True),
                           diverged.home_b) == 0
    assert not filed_copy(diverged.home_b).exists()
    assert bases_of(diverged.home_b, diverged)["memory/notes.md"] == \
        sha("alpha\nFROM A\ngamma\n")

    capsys.readouterr()
    assert sync.push(ns(apply=True), diverged.home_b) == 0
    assert SKIP not in capsys.readouterr().out
    assert stored_memory(diverged)["memory/notes.md"] == \
        "alpha\nFROM A\nFROM B\ngamma\n"

    assert sync.pull(ns(apply=True), diverged.home_a) == 0
    assert (memory(diverged.home_a) / "notes.md").read_text() == \
        "alpha\nFROM A\nFROM B\ngamma\n", "the merge did not reach machine-a"


def test_resolve_refuses_a_path_with_nothing_filed(pair):
    local = memory(pair.home_b) / "todo.md"
    with pytest.raises(SystemExit) as exc:
        resolve.run(ns(paths=[str(local)], apply=True), pair.home_b)
    assert "nothing is filed" in str(exc.value)
    assert bases_of(pair.home_b, pair)["memory/todo.md"] == sha(TODO)


def test_resolve_refuses_a_session_transcript(diverged):
    transcript = project_dir(diverged.home_b) / (UUID_1 + ".jsonl")
    with pytest.raises(SystemExit) as exc:
        resolve.run(ns(paths=[str(transcript)], apply=True),
                        diverged.home_b)
    assert "Session" in str(exc.value)
    assert filed_copy(diverged.home_b).is_file()


# --- review round: each one pinned ---------------------------------------------


def test_a_memory_file_written_mid_push_cannot_wedge_the_project(
        pair, monkeypatch, capsys):
    """tree_hash came from one read and the tar from a second. An agent
    writing between them left an Index describing bytes the object does not
    hold, and the binding check then refused that project on both legs for
    good."""
    from carryon import history
    pack = history.pack_session

    def racing_pack(residue, home):
        (memory(home) / "notes.md").write_text("written mid-push\n")
        return pack(residue, home)
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    monkeypatch.setattr(history, "pack_session", racing_pack)
    assert sync.push(ns(apply=True), pair.home_a) == 0
    monkeypatch.setattr(history, "pack_session", pack)

    capsys.readouterr()
    assert sync.push(ns(apply=True), pair.home_a) == 0
    assert "not the version the Index records" not in capsys.readouterr().out
    assert sync.pull(ns(apply=True), pair.home_b) == 0
    assert (memory(pair.home_b) / "notes.md").read_text() == \
        "written mid-push\n"


def test_a_resolve_whose_base_cannot_be_written_resolves_nothing(diverged):
    local = memory(diverged.home_b) / "notes.md"
    (diverged.home_b / ".carryon" / "state.json").write_bytes(b"\xff not json")
    with pytest.raises(SystemExit) as exc:
        resolve.run(ns(paths=[str(local)], apply=True), diverged.home_b)
    assert "nothing was resolved" in str(exc.value)
    assert filed_copy(diverged.home_b).is_file(), \
        "the filed copy went although no Base was recorded"


def test_a_refused_write_is_not_reported_as_replaced(pair, monkeypatch,
                                                     capsys):
    from carryon import external
    (memory(pair.home_a) / "notes.md").write_text("alpha\nBETA\ngamma\n")
    assert sync.push(ns(apply=True), pair.home_a) == 0
    real = external.write_owned
    monkeypatch.setattr(
        external, "write_owned",
        lambda target, *a, **kw: (
            "refused for this test" if target.name == "notes.md"
            and ".carryon" not in target.parts
            else real(target, *a, **kw)))
    capsys.readouterr()
    sync.pull(ns(apply=True), pair.home_b)
    out = capsys.readouterr().out
    assert "  replace  " not in out and "replaced by another" not in out
    assert (memory(pair.home_b) / "notes.md").read_text() == NOTES


def test_resolve_promotes_the_copy_pull_compared_not_the_file(diverged):
    """The filed file is an expansion of what pull compared, and expansion
    does not always run backwards. Here it is edited outright: the Base must
    still be the Archive's copy."""
    filed_copy(diverged.home_b).write_text("scribbled on\n")
    local = memory(diverged.home_b) / "notes.md"
    assert resolve.run(ns(paths=[str(local)], apply=True),
                       diverged.home_b) == 0
    assert bases_of(diverged.home_b, diverged)["memory/notes.md"] == \
        sha("alpha\nFROM A\ngamma\n")


def test_resolve_takes_a_path_spelled_with_dot_dot(diverged, monkeypatch):
    monkeypatch.chdir(memory(diverged.home_b))
    assert resolve.run(ns(paths=["../memory/notes.md"], apply=True),
                       diverged.home_b) == 0
    assert not filed_copy(diverged.home_b).exists()


def test_two_spellings_of_one_file_resolve_it_once(diverged, monkeypatch):
    monkeypatch.chdir(memory(diverged.home_b))
    local = memory(diverged.home_b) / "notes.md"
    assert resolve.run(ns(paths=["notes.md", str(local)], apply=True),
                       diverged.home_b) == 0
    assert not filed_copy(diverged.home_b).exists()

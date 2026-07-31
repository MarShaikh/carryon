"""The History restore leg must not write through a link it does not own.

ADR-0007 says carryon defers to whatever already owns a path, and both Setup
legs follow it. The History leg derives its root from an Index a master key
sealed and checks every member against config.lands_in_state, so nothing it
writes lands in ~/.carryon - and then hands the member to write_bytes, which
follows a symlink anywhere else. Authoring an Index needs a master key; a
symlink already sitting in the pulling machine's project tree needs none, and
neither does one a previous pull left there. The Setup leg has deferred to
those links since ADR-0007 and the Destination layer now refuses to read
through them - neither of which is evidence about this leg, which is the one
that never got the rule.

Three shapes, because a leaf test alone would pass over the one that keeps
recurring here: the member itself is a link, an ancestor DIRECTORY of it is a
link, and the link dangles. The dangling one matters on the residue leg
specifically - `target.exists()` is False through a broken link, so "existing
local files win" does not cover it and the write CREATES the file in the
linked-to repo. external.py already calls a broken link externally owned for
exactly that reason.

Every home here is synthetic and every byte in it invented; the "stolen" files
stand in for whatever a dotfiles repo or an external tree holds.
"""

import argparse
import io
import json
import os
import pathlib
import sys
import tarfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (config, external, history, keyring,  # noqa: E402
                     rekey, sync)

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
UUID_F = "ffffffff-ffff-4fff-8fff-ffffffffffff"
PROJ_REL = "code/snake_case_proj"

ELSEWHERE = "a repository carryon does not own\n"


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


def tar_of(members: dict) -> bytes:
    """A packed tree, in the shape pack_session produces."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_home(tmp_path, name="home") -> pathlib.Path:
    """A $HOME with an agent tree and a dotfiles repo beside it."""
    home = tmp_path / name
    (home / ".claude" / "projects").mkdir(parents=True)
    (home / "dotfiles").mkdir()
    return home


def project_root(home) -> pathlib.Path:
    """Where a Session pushed from cwd '~/<PROJ_REL>' is restored to."""
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / PROJ_REL)))


def meta(agent="claude-code") -> dict:
    return {"agent": agent, "cwd": "~/" + PROJ_REL}


# --- a Session's own members -------------------------------------------------


def test_a_restored_session_does_not_write_through_a_symlinked_member(
        tmp_path):
    """The leaf case: the project dir is an ordinary directory this machine
    owns, and one file in it is a link into a dotfiles repo. The Index is
    authenticated, so the Session is a key holder's - the link is not."""
    home = build_home(tmp_path)
    stolen = home / "dotfiles" / "notes.jsonl"
    stolen.write_text(ELSEWHERE)
    root = project_root(home)
    root.mkdir(parents=True)
    (root / (UUID_A + ".jsonl")).symlink_to(stolen)

    _, report = history.unpack_session(
        tar_of({UUID_A + ".jsonl": jline({"type": "meta", "n": 1}).encode()}),
        meta(), home)

    assert stolen.read_text() == ELSEWHERE, \
        "a restored Session wrote through a link into a repo carryon does " \
        "not own (ADR-0007)"
    assert report.deferred, "the deferral has to be reported, not silent"


def test_a_restored_session_does_not_write_through_a_symlinked_ancestor(
        tmp_path):
    """The case that keeps recurring in this codebase: the member's own name
    is innocent and a DIRECTORY above it is the link. target.parent.mkdir
    walks straight through one, so checking the leaf alone proves nothing."""
    home = build_home(tmp_path)
    claimed = home / "dotfiles" / "claimed"
    claimed.mkdir()
    root = project_root(home)
    root.mkdir(parents=True)
    (root / UUID_A).symlink_to(claimed)

    _, report = history.unpack_session(
        tar_of({UUID_A + "/subagents/journal.jsonl": b'{"step":1}\n'}),
        meta(), home)

    assert list(claimed.iterdir()) == [], \
        "a restored Session wrote below a linked directory it does not own"
    assert report.deferred


def test_a_restored_session_names_the_link_it_deferred_to(tmp_path):
    """Deference reads as a failure unless the report says what holds the
    path - the same thing the Setup leg's skip line says (ADR-0007)."""
    home = build_home(tmp_path)
    stolen = home / "dotfiles" / "notes.jsonl"
    stolen.write_text(ELSEWHERE)
    root = project_root(home)
    root.mkdir(parents=True)
    (root / (UUID_A + ".jsonl")).symlink_to(stolen)

    _, report = history.unpack_session(
        tar_of({UUID_A + ".jsonl": b"{}\n",
                "kept.jsonl": b'{"ok":1}\n'}), meta(), home)

    assert [t.name for t, _ in report.deferred] == [UUID_A + ".jsonl"]
    assert report.deferred[0][1].name == "notes.jsonl", \
        "the report names whatever holds the path"
    assert report.members == 1, "the member beside it still landed"
    assert (root / "kept.jsonl").read_bytes() == b'{"ok":1}\n'


def test_an_ordinary_restore_still_writes_every_member(tmp_path):
    """The control. A project dir with no link in it restores whole, or the
    tests above would pass over a leg that had stopped working."""
    home = build_home(tmp_path)
    root = project_root(home)

    _, report = history.unpack_session(
        tar_of({UUID_A + ".jsonl": jline({"cwd": "~/" + PROJ_REL}).encode(),
                UUID_A + "/subagents/journal.jsonl": b'{"step":1}\n'}),
        meta(), home)

    assert report.deferred == ()
    assert report.members == 2
    assert (root / (UUID_A + ".jsonl")).is_file()
    assert (root / UUID_A / "subagents" / "journal.jsonl").read_bytes() \
        == b'{"step":1}\n'


# --- the conflicts directory -------------------------------------------------


def test_a_conflicts_copy_does_not_write_through_a_symlink(tmp_path):
    """~/.carryon/conflicts is the one root that is carryon's own state on
    purpose (ADR-0002), so the state rule is turned off for it - which left
    nothing at all checking the members. A link one component in is written
    through, and a previous pull's tree is where one would sit."""
    home = build_home(tmp_path)
    config.state_dir(home).mkdir(parents=True, exist_ok=True)
    stolen = home / "dotfiles" / "stolen.jsonl"  # dangling on purpose
    conflicts = config.state_dir(home) / "conflicts" / UUID_A
    conflicts.mkdir(parents=True)
    (conflicts / "main.jsonl").symlink_to(stolen)

    written, _, _, _, _ = sync._extract_tree(
        tar_of({"main.jsonl": b'{"incoming":1}\n'}), conflicts, home, [],
        into_state=True)

    assert not stolen.exists(), \
        "the conflicts leg created a file in a repo carryon does not own"
    assert written == 0


def test_a_conflicts_copy_still_lands_when_nothing_holds_the_path(tmp_path):
    """The control for it: an ordinary conflicts tree is still written, or
    ADR-0002's 'local kept, incoming set aside' quietly sets nothing aside."""
    home = build_home(tmp_path)
    conflicts = config.state_dir(home) / "conflicts" / UUID_A

    written, _, _, _, _ = sync._extract_tree(
        tar_of({"main.jsonl": b'{"incoming":1}\n'}), conflicts, home, [],
        into_state=True)

    assert written == 1
    assert (conflicts / "main.jsonl").read_bytes() == b'{"incoming":1}\n'


# --- project residue ---------------------------------------------------------


def test_restored_residue_does_not_write_through_a_dangling_link(tmp_path):
    """The residue leg asks ADR-0002's rule of every local file, and that
    looks like it covers this - but reading the local copy follows the link,
    so a BROKEN one reads as 'nothing here yet' and the write creates the file
    at the other end. external.py calls a broken link externally owned for
    exactly this reason, and the ownership question is asked first."""
    home = build_home(tmp_path)
    stolen = home / "dotfiles" / "MEMORY.md"  # not created: the link dangles
    root = project_root(home)
    (root / "memory").mkdir(parents=True)
    (root / "memory" / "MEMORY.md").symlink_to(stolen)

    written, _, _, _, _ = sync._extract_tree(
        tar_of({"memory/MEMORY.md": b"incoming notes\n"}), root, home, [])

    assert not stolen.exists(), \
        "the residue leg created a file in a repo carryon does not own"
    assert written == 0


def test_restored_residue_does_not_write_through_a_linked_directory(tmp_path):
    """Same leg, ancestor shape: the whole memory dir is somebody else's."""
    home = build_home(tmp_path)
    claimed = home / "dotfiles" / "memory"
    claimed.mkdir()
    root = project_root(home)
    root.mkdir(parents=True)
    (root / "memory").symlink_to(claimed)

    sync._extract_tree(tar_of({"memory/MEMORY.md": b"incoming notes\n"}),
                       root, home, [])

    assert list(claimed.iterdir()) == [], \
        "the residue leg wrote below a linked directory it does not own"


def test_extract_tree_names_every_link_it_deferred_to(tmp_path):
    """The report line again, on the leg where a skipped file otherwise reads
    as one of the "kept (this machine's copy is ahead)" the summary already
    prints - which would be the wrong sentence about a path somebody else
    owns."""
    home = build_home(tmp_path)
    claimed = home / "dotfiles" / "memory"
    claimed.mkdir()
    root = project_root(home)
    root.mkdir(parents=True)
    (root / "memory").symlink_to(claimed)
    deferred = []

    written, _, _, _, _ = sync._extract_tree(
        tar_of({"memory/MEMORY.md": b"incoming\n", "AGENTS.md": b"kept\n"}),
        root, home, [], deferred=deferred)

    assert [t.name for t, _ in deferred] == ["MEMORY.md"]
    assert deferred[0][1].name == "memory"
    assert written == 1, "the member beside it still landed"
    assert (root / "AGENTS.md").read_bytes() == b"kept\n"


def test_restored_residue_still_lands_in_an_ordinary_directory(tmp_path):
    """The control for the residue leg."""
    home = build_home(tmp_path)
    root = project_root(home)

    written, kept, _, _, _ = sync._extract_tree(
        tar_of({"memory/MEMORY.md": b"incoming notes\n"}), root, home, [])

    assert (written, kept) == (1, 0)
    assert (root / "memory" / "MEMORY.md").read_bytes() == b"incoming notes\n"


# --- the state rule, split by who authored the path --------------------------


def test_a_link_into_carryons_own_state_is_deferred_and_the_key_survives(
        tmp_path):
    """A link into ~/.carryon is still never written through - but it is
    deferred and named, not refused whole.

    The refusal used to come first and it RESOLVED, so one planted link, which
    needs no key and no Destination access, was a permanent SystemExit on
    every pull from every machine, naming a tar member the user cannot find
    rather than the local link that caused it. ADR-0009 rules out exactly that
    shape elsewhere ("one planted object that raises is a permanent abort").
    The name that spells ~/.carryon is a key holder's doing and still refuses
    (see the test below); a link that resolves there is anybody's and defers,
    which is the same outcome for the key and a survivable one for the pull.
    """
    home = build_home(tmp_path)
    key = config.state_dir(home) / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("00112233" * 8 + "\n")
    root = project_root(home)
    root.parent.mkdir(parents=True, exist_ok=True)
    root.symlink_to(config.state_dir(home))

    _, report = history.unpack_session(
        tar_of({"master.key": b"deadbeef\n"}), meta(), home)

    assert key.read_text().startswith("00112233"), \
        "a restored Session overwrote the master key"
    assert report.members == 0
    assert [str(t) for t, _ in report.deferred] == [str(root / "master.key")]


def test_a_member_whose_name_spells_state_is_refused_whole(tmp_path):
    """The other half of the split, unchanged: when the landing path SPELLS
    ~/.carryon with no link involved, whoever composed it sealed the tar and
    derived the root, which needs the master key. There is no honest reading
    of that, so it refuses rather than deferring."""
    home = build_home(tmp_path)
    key = config.state_dir(home) / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("00112233" * 8 + "\n")

    with pytest.raises(SystemExit) as exc:
        sync._extract_tree(tar_of({"master.key": b"deadbeef\n"}),
                           config.state_dir(home), home, [])

    assert key.read_text().startswith("00112233")
    assert "carryon" in str(exc.value)


# --- end to end, through pull ------------------------------------------------


def main_lines(cwd, n=2) -> str:
    text = jline({"cwd": cwd, "type": "meta"})
    for i in range(1, n):
        text += jline({"type": "user", "text": f"edit {cwd}/main.py", "n": i})
    return text


def pushing_home(tmp_path) -> pathlib.Path:
    """A machine with one two-line Session, one Archive-only Session and one
    project residue - enough for both the 'new' and the 'replace' branch."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)
    project = home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(main_lines(cwd, 3))
    (project / (UUID_F + ".jsonl")).write_text(main_lines(cwd, 2))
    memory = project / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text(f"Notes live in {cwd}/notes.\n")
    return home


def pulling_home(tmp_path) -> pathlib.Path:
    home = build_home(tmp_path, "home_b")
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


def pushed_archive(tmp_path):
    """(home_a, dest_spec) with the History half pushed."""
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    return home_a, dest_spec


def test_pull_defers_to_a_link_in_the_project_tree_and_says_so(tmp_path,
                                                               capsys):
    """The whole leg, through pull: a Session the Archive holds and this
    machine does not, restored into a project dir where one member's name is
    already a link. Nothing in the Archive says so and nothing needs to - the
    link is on this side."""
    home_a, dest_spec = pushed_archive(tmp_path)
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    stolen = home_b / "dotfiles" / "stolen.jsonl"
    root = project_root(home_b)
    root.mkdir(parents=True)
    (root / (UUID_F + ".jsonl")).symlink_to(stolen)

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert not stolen.exists(), \
        "pull wrote through a link into a dotfiles repo"
    assert "externally owned" in out
    assert UUID_F in out
    # the Session with no link in its way still landed
    assert (root / (UUID_A + ".jsonl")).is_file()


def test_pull_does_not_delete_through_a_link_it_defers_to(tmp_path, capsys):
    """The other half of deferring: a replaced Session unlinks the local tree
    first (ADR-0002), and unlink through a linked project dir deletes the
    file in the other tool's tree. Skipping the write while keeping the
    delete would turn deference into data loss."""
    home_a, dest_spec = pushed_archive(tmp_path)
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    external_tree = home_b / "dotfiles" / "projects"
    external_tree.mkdir()
    root = project_root(home_b)
    root.parent.mkdir(parents=True, exist_ok=True)
    root.symlink_to(external_tree)
    # a byte-prefix of the Archive's copy: incoming is ahead, so pull replaces
    prefix = main_lines(str(home_b / PROJ_REL), 1)
    (external_tree / (UUID_A + ".jsonl")).write_text(prefix)

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert (external_tree / (UUID_A + ".jsonl")).read_text() == prefix, \
        "pull deleted a file through a link it then refused to write through"
    assert "externally owned" in out


def test_pull_reports_a_deferred_history_in_its_summary(tmp_path, capsys):
    """A pull that writes almost nothing must read as deference rather than
    as a failure (ADR-0007), and the summary is where that is read."""
    home_a, dest_spec = pushed_archive(tmp_path)
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    claimed = home_b / "dotfiles" / "projects"
    claimed.mkdir()
    root = project_root(home_b)
    root.parent.mkdir(parents=True, exist_ok=True)
    root.symlink_to(claimed)

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert list(claimed.iterdir()) == [], \
        "pull wrote a whole History below a linked directory"
    assert "externally owned" in out
    assert "--force" in out, \
        "the report has to say whether a flag writes through, either way"


def test_the_history_leg_asks_the_same_question_as_the_setup_leg(tmp_path):
    """One rule, not two spellings of one: both legs call external.classify,
    so a link the Setup leg defers to is one the History leg defers to."""
    home = build_home(tmp_path)
    claimed = home / "dotfiles" / "claimed"
    claimed.mkdir()
    root = project_root(home)
    root.mkdir(parents=True)
    (root / UUID_A).symlink_to(claimed)
    target = root / UUID_A / "subagents" / "journal.jsonl"

    status, owner = external.classify(target, home)

    assert status == external.EXTERNALLY_OWNED
    _, report = history.unpack_session(
        tar_of({UUID_A + "/subagents/journal.jsonl": b"{}\n"}), meta(), home)
    assert [str(o) for _, o in report.deferred] == [str(owner)]


# --- a directory this machine will not answer about --------------------------
#
# The other half of `_listing`'s sentence, which was written about the call
# that LISTS a directory and left the calls that ask what one IS. Path.is_dir()
# swallows exactly four errnos - ENOENT, ENOTDIR, EBADF, ELOOP - and raises
# every other one, EACCES included, so a mode-000 agent directory is a raw
# PermissionError out of the middle of a walk. `list`, `doctor` and `capture`
# over that same home all answer with a report line (adapters.present,
# layout._entries, capture.tree_files each say so in their own words); the
# History leg was the one that did not, so `push` and `pull` were the two
# commands that ended in a traceback.
#
# It needs no attacker: a backup restored with the wrong owner and an agent
# that once ran under sudo are the two causes layout.py already calls ordinary.


@pytest.mark.parametrize("command", ["push", "pull"])
def test_an_agent_directory_that_will_not_answer_is_not_a_traceback(
        command, tmp_path, capsys):
    """Every other command over the same home exits 0, so this one must too.

    The mode is set on the directory ABOVE the one the walk asks about, which
    is what makes the stat fail rather than the listing: `~/.claude` mode 000
    means every question about `~/.claude/projects` is an EACCES, including
    the `is_dir()` that decides whether there is anything to walk.
    """
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").write_text('{"model": "opus"}')
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    capsys.readouterr()

    (home / ".claude").chmod(0o000)
    try:
        if os.access(home / ".claude" / "projects", os.R_OK):
            return  # running as root: the mode decides nothing
        code = (sync.push if command == "push" else sync.pull)(
            ns(apply=True), home)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    finally:
        (home / ".claude").chmod(0o755)
    out = capsys.readouterr().out

    assert code in (0, 1, 2), out
    assert ".claude" in out, \
        f"a directory carryon could not look at went unmentioned:\n{out}"

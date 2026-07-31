"""Pull never deletes - ADR-0002's first Consequence, on the honest path.

Nothing here needs an attacker. Two machines that both hold the same Session
are enough, and the route in is the cure carryon itself prescribes: push skips
a Session it is behind on and tells the user to pull first. They pull, the
Archive's main Transcript is longer than theirs, and the replacement branch
used to unlink every local member whose name the incoming tar did not carry -
including members the Archive never held at all.

A Session is a *tree*, and the tree is exactly where two machines diverge
without their main Transcripts diverging. Resume the same Session on both and
each grows subagent journals and workflow journals the other never saw while
the mains stay in a clean byte-prefix relation, which is the relation that
authorises the replacement. So "the incoming tree wins" has to mean it wins
the names it holds, not the directory: incoming members overwrite same-named
local ones, local-only members stay, and what stayed is counted and reported
rather than discarded. A stale member that must genuinely go - the Archive
holding it under a new name after a rename - is `--mirror`, which ADR-0002
defers on purpose and which is not this.

Every home here is synthetic and every transcript byte in it is invented.
"""

import argparse
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import config, keyring, rekey, sync  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ_REL = "code/app"

# The two members that exist on the pulling machine and nowhere else. Both are
# Transcripts of the Session (CONTEXT.md: a Transcript is one participant's
# record within it), because that is the shape the bug destroys: work spawned
# beneath a main Transcript that never diverged.
LOCAL_SUBAGENT = "subagents/local-only.jsonl"
LOCAL_WORKFLOW = "workflows/run-9/journal.jsonl"


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


def main_lines(cwd, n) -> str:
    """A main Transcript of n lines: the meta line carrying the cwd, then
    n - 1 user lines. Re-keying rewrites the cwd on the way out and back, so
    the prefix relation between two machines' copies survives the round trip.
    """
    text = jline({"cwd": cwd, "type": "meta"})
    for i in range(1, n):
        text += jline({"type": "user", "text": f"edit {cwd}/main.py", "n": i})
    return text


def project_root(home, rel=PROJ_REL) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / rel)))


def pushing_home(tmp_path) -> pathlib.Path:
    """machine-a: a three-line main Transcript, one subagent journal beneath
    it, and one project memory file beside it."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(main_lines(cwd, 3))
    sub = project / UUID_A / "subagents"
    sub.mkdir(parents=True)
    # Two lines, so a local copy can be a strict byte-prefix of this one
    # without being empty - the append-only case ADR-0002 lets the incoming
    # member win, and the one the control below is written from.
    (sub / "journal.jsonl").write_text(
        jline({"from": "machine-a", "n": 1}) + jline({"from": "machine-a",
                                                      "n": 2}))
    memory = project / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text(f"Notes live in {cwd}/notes.\n")
    return home


def pulling_home(tmp_path) -> pathlib.Path:
    """machine-b: the same Session, one line into it - a strict byte-prefix of
    the Archive's copy, which is what authorises the replacement - plus two
    journals of its own beneath it and one memory file of its own beside it."""
    home = tmp_path / "home_b"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(main_lines(cwd, 1))
    for rel, payload in ((LOCAL_SUBAGENT, {"from": "machine-b", "sub": 1}),
                         (LOCAL_WORKFLOW, {"from": "machine-b", "step": 1})):
        member = project / UUID_A / rel
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_text(jline(payload))
    memory = project / "memory"
    memory.mkdir()
    (memory / "LOCAL.md").write_text("machine-b's own notes\n")
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


@pytest.fixture
def behind(tmp_path):
    """machine-b, behind on the main Transcript and holding members of its
    own: the state push's 'pull first' leaves a user in."""
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_b


# --- the tree survives the replacement ---------------------------------------


def test_a_replace_keeps_local_only_members_of_the_session_tree(behind,
                                                                capsys):
    """The defect itself: a subagent journal and a workflow journal that exist
    only on the pulling machine, beneath a main Transcript that is a strict
    byte-prefix of the incoming one. Both must survive a pull that lands the
    longer main and the Archive's own members."""
    project = project_root(behind)
    subagent = project / UUID_A / LOCAL_SUBAGENT
    workflow = project / UUID_A / LOCAL_WORKFLOW
    before = (subagent.read_bytes(), workflow.read_bytes())
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    assert subagent.is_file(), \
        "pull deleted a subagent journal that existed only on this machine"
    assert workflow.is_file(), \
        "pull deleted a workflow journal that existed only on this machine"
    assert (subagent.read_bytes(), workflow.read_bytes()) == before

    # ...while still doing the whole of what the replacement is for.
    cwd_b = str(behind / PROJ_REL)
    assert (project / (UUID_A + ".jsonl")).read_text() == main_lines(cwd_b, 3)
    assert (project / UUID_A / "subagents" / "journal.jsonl").is_file(), \
        "the incoming member never landed, so this proves nothing"
    assert "replace" in out and UUID_A in out


def test_a_replace_still_lets_the_incoming_tree_win_a_shared_name(behind):
    """The control, and the other half of the union: a member both machines
    hold, where the local copy is a byte-prefix of the incoming one, is
    extended by it.

    Green before the fix as well as after, so it is evidence about nothing on
    its own. It is here as the guard rail on the fix's cheapest wrong shape -
    making the replacement skip whatever the local tree already holds, which
    keeps the journals and strands the Archive's copy of every name this
    machine happens to have.

    The local copy is append-only on purpose. This test used to plant a
    DIVERGENT one ({"from": "machine-b", "stale": true}) and assert the
    incoming member won, which is the one case ADR-0002 says must be kept
    aside instead - so the guard rail enshrined the defect the sibling suite
    (test_pull_member_union) was written to close.
    """
    project = project_root(behind)
    shared = project / UUID_A / "subagents" / "journal.jsonl"
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text(jline({"from": "machine-a", "n": 1}))

    assert sync.pull(ns(apply=True), behind) == 0

    assert len(shared.read_text().splitlines()) == 2, \
        "the incoming member did not extend the local byte-prefix of it"


def test_a_replace_reports_what_it_left_in_place(behind, capsys):
    """The count was computed and thrown away, so the deletion was silent and
    the keep would be too. Whatever a pull does to a Session tree has to be
    countable and to appear in the report, in the shape the rest of the report
    uses: a line against the Session and a line in the summary."""
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    session_line = [line for line in out.splitlines()
                    if UUID_A in line and "keep" in line]
    assert session_line, "the pull said nothing about the members it kept"
    assert "2" in session_line[0], \
        f"the kept members were not counted: {session_line[0]!r}"
    summary = [line for line in out.splitlines()
               if line.startswith("Sessions:") and "never deletes" in line]
    assert summary, "the summary never accounts for the members it kept"
    assert "2 local file(s)" in summary[0], \
        f"the kept members were miscounted in the summary: {summary[0]!r}"


def test_the_residue_leg_keeps_local_only_files_too(behind):
    """The other tree a pull writes into, asserted rather than assumed.

    The residue leg has never swept, so this proves the leg does not sweep
    rather than proving anything about the Session leg's fix. It is here
    because the two legs write to the same project dir and a later change
    could give the residue leg the Session leg's old posture without a test
    noticing.

    The file this machine is AHEAD on is asserted alongside, because the
    residue leg now runs ADR-0002's rule rather than "the existing local file
    always wins": a rule that replaces on a byte-prefix has to be shown not to
    replace on its reverse.
    """
    memory = project_root(behind) / "memory"
    local = memory / "LOCAL.md"
    ahead = memory / "MEMORY.md"
    ahead.write_text(f"Notes live in {behind / PROJ_REL}/notes.\nand more.\n")
    before = ahead.read_bytes()

    assert sync.pull(ns(apply=True), behind) == 0

    assert local.read_text() == "machine-b's own notes\n", \
        "the residue leg deleted a memory file the Archive never held"
    assert ahead.read_bytes() == before, \
        "the residue leg truncated a memory file this machine was ahead on"
    assert (memory / "MEMORY.md").is_file(), \
        "the incoming residue never landed, so this proves nothing"


def test_a_replace_sent_elsewhere_by_map_keeps_and_counts_the_whole_tree(
        behind, capsys):
    """`--map` sends the restore to a project dir the local Session is not in,
    so nothing of the local tree is superseded and all of it is kept. The
    report has to say so with a number like every other outcome: this branch
    already printed a sentence and returned a count nobody added up.
    """
    project = project_root(behind)

    def local_tree():
        return {str(p.relative_to(project)): p.read_bytes()
                for p in project.rglob("*") if p.is_file()}

    before = local_tree()
    capsys.readouterr()

    # Absolute on both sides, because that is the only shape a --map may
    # have: a fragment like 'code/app' is a substring match over every value
    # in every Transcript, and sync._parse_maps refuses one now (rekey.
    # map_refusal). Expansion against the local home runs before the maps do,
    # so naming this machine's own directories sends the restore to the same
    # place the fragment did.
    assert sync.pull(ns(apply=True,
                        map=[f"{behind}/code/app={behind}/code/elsewhere"]),
                     behind) == 0
    out = capsys.readouterr().out

    assert local_tree() == before, \
        "the local tree was swept for a replacement that landed elsewhere"
    # ...and the mapped copy did land, or the branch under test never ran.
    # Without this the test would pass on a pull that did nothing at all.
    elsewhere = project_root(behind, "code/elsewhere")
    assert (elsewhere / (UUID_A + ".jsonl")).is_file()
    summary = [line for line in out.splitlines()
               if line.startswith("Sessions:") and "never deletes" in line]
    assert summary, "the summary never accounts for the tree it kept"
    assert "3 local file(s)" in summary[0], \
        f"the kept tree was miscounted: {summary[0]!r}"

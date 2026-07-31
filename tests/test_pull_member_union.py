"""ADR-0002's union rule, asked of every Transcript in a Session, not just one.

A Session is a tree and every file in it is a Transcript - the main
conversation, a subagent's, a workflow's journal (CONTEXT.md). ADR-0002 states
one rule for all of them: "the incoming file replaces the local one only when
the local file is a byte-prefix of it - the append-only case - and otherwise
both are kept, the incoming copy under `~/.carryon/conflicts/`".

The replacement branch asked that question of the MAIN Transcript and of
nothing below it. One `compare_main` decided the whole tree, and then every
member of the incoming tar was written unconditionally: a subagent journal the
two machines had grown apart on was overwritten and its bytes were gone, and a
workflow journal this machine was strictly AHEAD on was truncated - verbatim
the harm ADR-0002 names ("overwrite the longer Transcript with the shorter
one") and the reason push refuses in the mirror-image situation. Nothing was
unlinked, so the fix that stopped pull deleting names did not touch it.

The same blindness reaches three more ways in, all of them here:

- a name comparison decides the report while the filesystem decides the write,
  so on a case-insensitive filesystem (APFS by default) a local member could be
  overwritten and reported kept in the same pull;
- a Session whose main Transcript is gone is not discovered at all, so its
  surviving subtree takes pull's `new` branch and is written straight over;
- a machine holding the same Session in two project dirs had the keep
  accounting attached to whichever copy discovery happened to keep.

Every home here is synthetic and every transcript byte in it is invented.
"""

import argparse
import json
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import config, keyring, rekey, sync  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ_REL = "code/app"

# Shared by both machines, and the member every relation below is played out
# on. Two lines on the pushing machine, so a local copy can be a strict
# byte-prefix of it without being empty.
SHARED = "subagents/journal.jsonl"
# Held by both, and longer here: the local machine is AHEAD on it while its
# main Transcript is behind. That is the ordinary shape after two machines
# resume the same Session, not a corner.
WORKFLOW = "workflows/run-9/journal.jsonl"
# Held by this machine and nobody else.
LOCAL_ONLY = "local-only.jsonl"


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


def journal(machine, count, start=1) -> str:
    """Lines with no path in them, so canonical bytes are the bytes on disk
    and a byte-prefix on one machine is a byte-prefix on the other."""
    return "".join(jline({"from": machine, "step": i})
                   for i in range(start, start + count))


def project_root(home, rel=PROJ_REL) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / rel)))


def write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def pushing_home(tmp_path) -> pathlib.Path:
    """machine-a: a three-line main Transcript and two journals beneath it."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 3))
    write(project / UUID_A / SHARED, journal("machine-a", 2))
    write(project / UUID_A / WORKFLOW, journal("machine-a", 3))
    return home


def pulling_home(tmp_path) -> pathlib.Path:
    """machine-b: the same Session one line in - a strict byte-prefix of the
    Archive's main, which is what authorises the replacement - holding the
    workflow journal 27 lines further on than the Archive does, plus one
    Transcript of its own."""
    home = tmp_path / "home_b"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 1))
    write(project / UUID_A / WORKFLOW,
          journal("machine-a", 3) + journal("machine-b", 27, start=4))
    write(project / UUID_A / LOCAL_ONLY, journal("machine-b", 1))
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


@pytest.fixture
def behind(tmp_path):
    """machine-b, behind on the main Transcript and ahead on a member of the
    tree beneath it: the state push's 'pull first' leaves a user in."""
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_b


def case_insensitive(path) -> bool:
    """Whether this filesystem folds case, asked of the directory under test
    rather than assumed from the platform: macOS ships case-insensitive APFS
    by default and can be formatted either way, and so can Linux."""
    probe = path / "CaseProbe"
    probe.write_text("x")
    try:
        return (path / "caseprobe").exists()
    finally:
        probe.unlink()


def kept_summary(out: str) -> str:
    lines = [line for line in out.splitlines()
             if line.startswith("Sessions:") and "never deletes" in line]
    return lines[0] if lines else ""


def conflicts_dir(home) -> pathlib.Path:
    """Where a divergent incoming copy is kept aside. The tree under it
    mirrors the project dir, so a member of the Session's subtree keeps its
    `<uuid>/` prefix - the same layout a wholly divergent Session lands in."""
    return home / ".carryon" / "conflicts" / UUID_A / UUID_A


# --- the four relations, per member -------------------------------------------


def test_a_divergent_member_is_kept_and_the_incoming_copy_goes_aside(
        behind, capsys):
    """The defect itself. Both machines hold `subagents/journal.jsonl` and
    neither copy is a prefix of the other - the case ADR-0002 answers with
    "both are kept, the incoming copy under ~/.carryon/conflicts/" - while
    the mains are in the clean prefix relation that authorises a replacement.

    The local Transcript used to be overwritten with no conflicts copy, no
    backup, and a report line saying the incoming tree wins every member.
    """
    project = project_root(behind)
    local = project / UUID_A / SHARED
    write(local, journal("machine-b", 40))
    before = local.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    assert local.read_bytes() == before, \
        "a divergent local Transcript was overwritten by the incoming one"
    aside = conflicts_dir(behind) / SHARED
    assert aside.is_file(), \
        "the incoming copy was not kept aside under ~/.carryon/conflicts/"
    assert json.loads(aside.read_text().splitlines()[0])["from"] == "machine-a"
    named = [line for line in out.splitlines()
             if SHARED.split("/")[-1] in line and "conflict" in line]
    assert named, f"the divergent member was never named in the report: {out}"


def test_a_member_this_machine_is_ahead_on_is_not_truncated(behind, capsys):
    """The same rule from the other side, and the one push already follows:
    `history.compare_main` answers 'incoming-prefix' for this member - the
    Archive's copy is a byte-prefix of the local one - so the local copy is
    ahead and stays. The main Transcript being behind says nothing about it.
    """
    project = project_root(behind)
    workflow = project / UUID_A / WORKFLOW
    before = workflow.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    assert workflow.read_bytes() == before, \
        "pull truncated a Transcript this machine was ahead on"
    assert len(workflow.read_text().splitlines()) == 30
    kept = [line for line in out.splitlines()
            if "keep" in line and "run-9" in line]
    assert kept, f"the member kept in place was never named: {out}"


def test_a_member_the_incoming_tree_extends_still_wins(behind):
    """The control, and the other half of the union: where the local copy IS
    a byte-prefix of the incoming one - the append-only case ADR-0002 names -
    the incoming member wins, exactly as before. A fix that simply stopped
    writing over local members would pass every other test in this file and
    strand the Archive's copy of every name this machine happens to hold.
    """
    project = project_root(behind)
    shared = project / UUID_A / SHARED
    write(shared, journal("machine-a", 1))  # the first of the two lines

    assert sync.pull(ns(apply=True), behind) == 0

    assert shared.read_text() == journal("machine-a", 2), \
        "the incoming member did not extend the local byte-prefix of it"
    assert not (conflicts_dir(behind) / SHARED).exists(), \
        "an append-only member was treated as a conflict"


def test_a_member_both_machines_hold_identically_is_left_alone(behind):
    """The fourth relation. Nothing to do is not the same as a write that
    happens to produce the same bytes: rewriting an identical member churns
    every mtime in the tree on every pull."""
    project = project_root(behind)
    shared = project / UUID_A / SHARED
    write(shared, journal("machine-a", 2))
    before = shared.stat().st_mtime_ns

    assert sync.pull(ns(apply=True), behind) == 0

    assert shared.read_text() == journal("machine-a", 2)
    assert shared.stat().st_mtime_ns == before, \
        "an identical member was rewritten rather than left alone"


# --- the name comparison and the filesystem ----------------------------------


def test_a_local_member_spelled_in_another_case_is_not_overwritten(
        behind, capsys):
    """`rel not in incoming` compares names; the filesystem compares paths.
    macOS is case-insensitive by default, so a local `Subagents/journal.jsonl`
    and an incoming `subagents/journal.jsonl` are one file to every syscall
    and two names to the report - which used to overwrite the local Transcript
    and then print `keep ... 1 file(s) this machine holds and the Archive did
    not` about it.

    On a case-sensitive filesystem the two are genuinely separate files and
    the local one is untouched for a different reason. Both are correct; what
    must never happen is the report claiming one and the filesystem doing the
    other, so the assertion is on the bytes and on the report agreeing.
    """
    project = project_root(behind)
    variant = project / UUID_A / "Subagents" / "journal.jsonl"
    write(variant, journal("machine-b", 20))
    before = variant.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    assert variant.read_bytes() == before, \
        "the local Transcript was overwritten through a case-folded name"
    assert "keep" in out, "the pull said nothing about what it left in place"
    # ...and the count agrees with the filesystem rather than with the names.
    # Where the two names are one file, the Archive DID hold it and the line
    # naming it is the conflict line above; counting it here as well would
    # say "the Archive did not" about a file the Archive just served.
    # The workflow journal is kept because this machine is ahead on it, and
    # local-only.jsonl because the Archive never held it. The third is the
    # case-variant: one more kept file where the filesystem keeps the two
    # names apart, and the SAME file as the incoming member where it does not.
    folded = case_insensitive(project)
    expected = "2 local file(s)" if folded else "3 local file(s)"
    assert expected in kept_summary(out), \
        f"kept files counted by name rather than by file: {kept_summary(out)!r}"
    if folded:
        assert "conflict" in out, \
            "the case-folded member was neither replaced nor reported"


def test_a_new_session_does_not_write_over_a_local_subtree(tmp_path, capsys):
    """A Session is discovered through its top-level `<uuid>.jsonl`, so a
    subtree whose main Transcript is gone - deleted, rotated, never pulled -
    is no Session at all to discovery. The Index still names the UUID, pull
    takes its `new` branch, and unpack_session used to write over every
    same-named local member with no comparison and no keep accounting, under
    a summary reading `1 new, 0 replaced`.
    """
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0

    home_b = tmp_path / "home_b"
    project = project_root(home_b)
    orphan = project / UUID_A / SHARED
    write(orphan, journal("machine-b", 40))
    before = orphan.read_bytes()
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert orphan.read_bytes() == before, \
        "a local Transcript was destroyed by a Session reported as new"
    assert (conflicts_dir(home_b) / SHARED).is_file(), \
        "the incoming copy was not kept aside under ~/.carryon/conflicts/"
    assert (project / (UUID_A + ".jsonl")).is_file(), \
        "the incoming main never landed, so this proves nothing"


def test_the_keep_accounting_follows_the_directory_written_into(
        behind, capsys):
    """The same Session in two project dirs - a copied project tree - used to
    hand the keep accounting to whichever copy discovery kept last. The line
    it printed described a `--map` that was not given ("the incoming tree was
    restored to another directory") and counted that copy's files, while the
    directory the pull actually wrote into got no line and no count at all.
    """
    project = project_root(behind)
    local = project / UUID_A / SHARED
    write(local, journal("machine-b", 40))
    copy = project_root(behind, "code/copy")
    shutil.copytree(project, copy)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), behind) == 0
    out = capsys.readouterr().out

    assert "restored to another directory" not in out, \
        "the report blamed a --map that was never given"
    assert local.read_bytes() == journal("machine-b", 40).encode(), \
        "the copy the incoming tree landed in lost a divergent Transcript"
    assert (copy / UUID_A / SHARED).is_file(), \
        "the other copy of the Session was touched"
    kept = [line for line in out.splitlines()
            if "keep" in line and str(copy.name) in line]
    assert kept, \
        f"the second copy of the Session was never accounted for: {out}"


def test_a_dry_run_says_which_local_members_it_would_keep(behind, capsys):
    """A plan that says `the incoming tree wins every member it holds` and
    nothing else is the same silence the keep line was added to end, one flag
    over. What the user is deciding about is which of their Transcripts
    survive, so the plan has to name them."""
    project = project_root(behind)
    write(project / UUID_A / SHARED, journal("machine-b", 40))
    capsys.readouterr()

    assert sync.pull(ns(apply=False), behind) == 0
    out = capsys.readouterr().out

    assert "keep" in out, "the plan says nothing about what it would keep"
    assert "conflict" in out, \
        "the plan says nothing about the divergent member it would keep aside"
    assert not conflicts_dir(behind).exists(), \
        "a dry run wrote to ~/.carryon/conflicts"
    assert (project / UUID_A / SHARED).read_text() == journal("machine-b", 40)


def test_a_second_divergent_pull_keeps_the_first_copy_it_set_aside(
        tmp_path, capsys):
    """The conflicts directory holds the only copy of a divergent incoming
    Transcript on the machine, and it was written with no union rule of its
    own - so a later pull wrote straight over what an earlier one saved. Same
    rule, one directory over: what is kept aside is replaced only by something
    that extends it.

    The copy is edited here between the two pulls, which is the ordinary way
    it stops being the Archive's bytes: it is set aside precisely so somebody
    can merge or annotate it. A rolled-back Archive reaches the same place,
    and push's own guard is what makes that the rarer of the two.
    """
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    write(project_root(home_b) / UUID_A / SHARED, journal("machine-b", 40))
    assert sync.pull(ns(apply=True), home_b) == 0
    aside = conflicts_dir(home_b) / SHARED
    assert aside.read_text() == journal("machine-a", 2)
    aside.write_text(journal("merged-by-hand", 9))
    before = aside.read_bytes()

    # machine-a carries on and pushes again, so machine-b is behind on the
    # main Transcript once more and the same divergent member comes back.
    write(project_root(home_a) / (UUID_A + ".jsonl"),
          main_lines(str(home_a / PROJ_REL), 5))
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert "replace" in out, "the second pull never reached the branch"
    assert aside.read_bytes() == before, \
        "the second pull overwrote the copy the first one kept aside"


# --- the same rule where the main Transcript did NOT move ---------------------
#
# Everything above drives the replacement branch, where the incoming main
# Transcript is longer. Its sibling is the branch pull takes when the two mains
# agree or the local one is ahead - and ADR-0002's rule never reached it. That
# branch unioned the tree with "existing local files always win", which is not
# the rule: it is the posture ADR-0002 rejects, since a Session is a tree and
# the tree is where two machines diverge while their mains stand still.
#
# The damage is both ways round. A member this machine is BEHIND on is never
# caught up, so push goes on refusing it and "pull first" - the cure every skip
# line names, and the one ADR-0002 promises works ("a machine that is behind
# catches up, after which its pushes go through again") - cures nothing. And a
# member that has DIVERGED is dropped on the floor rather than kept under
# ~/.carryon/conflicts/: carryon promises both copies survive, keeps one, and
# says nothing about the other. Pull the Archive down onto a new machine, wipe
# the old one - which is what this tool is for - and that copy is gone.


def level_home(tmp_path) -> pathlib.Path:
    """machine-b holding the SAME main Transcript as the Archive, with the
    tree beneath it in three relations to the Archive's at once: behind on
    one member, ahead on another, and holding a third the Archive never had.
    Its project memory is behind too, since a residue is part of a History
    and follows the same rule."""
    home = tmp_path / "home_level"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 3))
    write(project / UUID_A / SHARED, journal("machine-a", 1))
    write(project / UUID_A / WORKFLOW,
          journal("machine-a", 3) + journal("machine-b", 27, start=4))
    write(project / UUID_A / LOCAL_ONLY, journal("machine-b", 1))
    write(project / "memory" / "MEMORY.md", "one\n")
    return home


@pytest.fixture
def level(tmp_path):
    """machine-b level with the Archive on the main Transcript and behind it
    on the tree - the state two machines resuming one Session reach without
    either main ever diverging."""
    home_a = pushing_home(tmp_path)
    write(project_root(home_a) / "memory" / "MEMORY.md", "one\ntwo\n")
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    home_b = level_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_b


def residue_conflicts_dir(home) -> pathlib.Path:
    """Where a divergent incoming residue file is kept aside. A residue has no
    Session UUID, so it is filed under the project directory it belongs to -
    a name that cannot collide with a UUID, since a project dir is derived
    from an absolute cwd and so always begins with the separator's '-'."""
    return home / ".carryon" / "conflicts" / project_root(home).name


def test_a_member_this_machine_is_behind_on_is_caught_up(level, capsys):
    """The append-only case, on the branch that never asked. The mains agree,
    so nothing is replaced - and `subagents/journal.jsonl` here is a strict
    byte-prefix of the Archive's, which is exactly the relation ADR-0002 says
    the incoming copy wins."""
    shared = project_root(level) / UUID_A / SHARED
    assert shared.read_text() == journal("machine-a", 1)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), level) == 0
    out = capsys.readouterr().out

    assert shared.read_text() == journal("machine-a", 2), \
        "a member this machine was behind on was never caught up, so the " \
        "'pull first' the push told the user to run cured nothing"
    assert "union" in out, "the pull said nothing about what it wrote"


def test_a_memory_file_this_machine_is_behind_on_is_caught_up(level):
    """The residue leg of the same rule. push already refuses a residue it is
    behind on and names 'pull first' (ADR-0002's tree rule, mirrored); this is
    the pull that has to make that cure real."""
    memory = project_root(level) / "memory" / "MEMORY.md"
    assert memory.read_text() == "one\n"

    assert sync.pull(ns(apply=True), level) == 0

    assert memory.read_text() == "one\ntwo\n", \
        "a memory file this machine was behind on was never caught up"


def test_a_divergent_member_goes_aside_when_the_main_did_not_move(
        level, capsys):
    """Both copies are kept, or neither is. This branch kept the local one and
    discarded the Archive's without a line in the report - the one outcome
    ADR-0002 rules out in as many words."""
    shared = project_root(level) / UUID_A / SHARED
    write(shared, journal("machine-b", 40))
    before = shared.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=True), level) == 0
    out = capsys.readouterr().out

    assert shared.read_bytes() == before, \
        "the local copy of a divergent member was overwritten"
    aside = conflicts_dir(level) / SHARED
    assert aside.is_file(), \
        "the incoming copy of a divergent member was discarded rather than " \
        "kept under ~/.carryon/conflicts/"
    assert aside.read_text() == journal("machine-a", 2)
    assert [line for line in out.splitlines() if "conflict" in line], \
        f"the divergent member was never named in the report: {out}"


def test_a_divergent_memory_file_goes_aside_when_the_main_did_not_move(
        level, capsys):
    """The residue's version of the same collision, filed under the project
    rather than under a Session UUID it does not have."""
    memory = project_root(level) / "memory" / "MEMORY.md"
    memory.write_text("something else entirely\n")
    capsys.readouterr()

    assert sync.pull(ns(apply=True), level) == 0
    out = capsys.readouterr().out

    assert memory.read_text() == "something else entirely\n", \
        "a divergent memory file was overwritten by the Archive's copy"
    aside = residue_conflicts_dir(level) / "memory" / "MEMORY.md"
    assert aside.is_file(), \
        "the incoming copy of a divergent memory file was discarded"
    assert aside.read_text() == "one\ntwo\n"
    assert [line for line in out.splitlines() if "conflict" in line], \
        f"the divergent memory file was never named: {out}"


def test_a_member_this_machine_is_ahead_on_survives_the_union(level, capsys):
    """The other side of the same branch, and the reason it cannot simply be
    handed the incoming tree: this machine is 27 lines further on than the
    Archive is. It stays, and the report says so."""
    workflow = project_root(level) / UUID_A / WORKFLOW
    before = workflow.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=True), level) == 0
    out = capsys.readouterr().out

    assert workflow.read_bytes() == before, \
        "the union truncated a Transcript this machine was ahead on"
    assert [line for line in out.splitlines()
            if "keep" in line and "run-9" in line], \
        f"the member kept in place was never named: {out}"
    assert (project_root(level) / UUID_A / LOCAL_ONLY).is_file(), \
        "a member only this machine held was lost"


def test_pulling_first_makes_the_push_that_was_skipped_go_through(
        level, capsys):
    """The whole point of the rule, end to end. push refuses a Session and a
    residue it is behind on and names one cure; ADR-0002 promises that cure
    works ("a machine that is behind catches up, after which its pushes go
    through again"). It could not: the pull left both behind exactly as it
    found them, so the user was told to pull first for ever."""
    capsys.readouterr()
    assert sync.push(ns(apply=True, category="history"), level) == 0
    first = capsys.readouterr().out
    assert "pull first" in first, \
        "this machine was not behind, so nothing here is being tested"

    assert sync.pull(ns(apply=True), level) == 0
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="history"), level) == 0
    second = capsys.readouterr().out
    assert "pull first" not in second, \
        f"pulling first did not make the push it named possible:\n{second}"
    assert "Sessions: 1 pushed" in second


def test_a_dry_run_of_the_union_says_what_it_would_write(level, capsys):
    """A plan that writes nothing has to say what it would do, on this branch
    as on the replacement beside it. This one printed nothing at all: the
    whole union ran inside `if apply`, so the dry run reported `unchanged`
    about a Session it was about to write four files into."""
    shared = project_root(level) / UUID_A / SHARED
    before = shared.read_bytes()
    capsys.readouterr()

    assert sync.pull(ns(apply=False), level) == 0
    out = capsys.readouterr().out

    assert shared.read_bytes() == before, "a dry run wrote to the tree"
    assert not (level / ".carryon" / "conflicts").exists(), \
        "a dry run wrote to ~/.carryon/conflicts"
    assert "union" in out, "the plan never said it would write anything"
    assert [line for line in out.splitlines()
            if "keep" in line and "run-9" in line], \
        f"the plan never said what it would keep: {out}"

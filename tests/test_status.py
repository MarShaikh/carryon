"""`carryon status` says what is out of step and moves nothing (ADR-0015).

It reads the Index and this machine, downloads no object, writes nothing, and
exits 0 whenever it could answer. Every test drives `status.run(args, home)`
over test_sync's two synthetic machines and asserts on the report, because
the report is the whole of what the command does.

Every home is synthetic; nothing reads the real ~/.claude, and the OS
keychain is forced to the fallback file. All transcript content is invented.
"""

import argparse
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, cli, config, keyring, rekey, status, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from carryon.highwater import _record_revision  # noqa: E402
from tests.test_sync import (PROJ_REL, UUID_A, UUID_C, UUID_D, UUID_E,  # noqa: E402
                             UUID_F, build_home_a, build_home_b, link_home,
                             ns, tree_state)


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def run(home, capsys, verbose=False):
    capsys.readouterr()
    code = status.run(argparse.Namespace(verbose=verbose), home)
    return code, capsys.readouterr().out


def described(spec) -> str:
    return DirectoryDestination(pathlib.Path(spec)).describe()


@pytest.fixture
def two(tmp_path):
    """machine-a has pushed everything; machine-b is paired and has not
    pulled. b holds every branch of the union rule against the Archive."""
    home_a = build_home_a(tmp_path)
    spec = str(tmp_path / "archive")
    sync.init(ns(dest=spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = build_home_b(tmp_path)
    link_home(home_b, spec, "machine-b", master_from=home_a)
    return home_a, home_b, spec


# --- in step, and the shape of the report ------------------------------------


def test_a_machine_that_just_pushed_everything_is_in_step(two, capsys):
    home_a, _home_b, spec = two
    code, out = run(home_a, capsys)
    assert code == 0
    assert out == f"in step with {described(spec)}\n"


def test_the_history_counts_follow_the_union_rule(two, capsys):
    """b: D is local only and E is ahead (push); A is a prefix of the
    Archive's, C's rollout diverged and F is Archive-only (pull), and the
    project's memory is only in the Archive (pull)."""
    _home_a, home_b, spec = two
    code, out = run(home_b, capsys)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"status: {described(spec)}"
    assert ("History: 2 to push, 4 to pull - run `carryon sync --apply`"
            in lines)


def test_verbose_names_each_item_behind_a_count(two, capsys):
    _home_a, home_b, _spec = two
    _code, out = run(home_b, capsys, verbose=True)
    for uuid in (UUID_D, UUID_E):
        assert re.search(rf"^  push +{uuid} \(claude-code\)$", out, re.M), out
    for uuid in (UUID_A, UUID_F):
        assert re.search(rf"^  pull +{uuid} \(claude-code\)$", out, re.M), out
    assert re.search(rf"^  pull +{UUID_C} \(codex\)$", out, re.M), out
    assert re.search(rf"^  pull +memory ~/{PROJ_REL} \(claude-code\)$", out,
                     re.M), out


def test_without_verbose_no_item_is_listed(two, capsys):
    _home_a, home_b, _spec = two
    _code, out = run(home_b, capsys)
    assert UUID_D not in out


def test_a_session_whose_other_members_moved_is_to_push(two, capsys):
    home_a, _home_b, _spec = two
    cwd = str(home_a / PROJ_REL)
    project = (home_a / ".claude" / "projects"
               / rekey.encode_project_dir(cwd))
    (project / UUID_A / "subagents" / "second.jsonl").write_text('{"n":1}\n')
    _code, out = run(home_a, capsys, verbose=True)
    assert "History: 1 to push - run `carryon sync --apply`" in out
    assert re.search(rf"^  push +{UUID_A} \(claude-code\)$", out, re.M), out


# --- per-project memory, by its Base -----------------------------------------


@pytest.fixture
def agreed(two):
    """b has pulled, so both machines and the Archive agree on the memory
    file and b holds its Base. b pushes back so the Sessions are level too."""
    home_a, home_b, spec = two
    sync.pull(ns(apply=True), home_b)
    sync.push(ns(apply=True), home_b)
    sync.pull(ns(apply=True), home_a)
    return home_a, home_b, spec


def memory_file(home) -> pathlib.Path:
    cwd = str(home / PROJ_REL)
    return (home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
            / "memory" / "MEMORY.md")


def memory_line(out):
    return re.search(rf"^  (push|pull) +memory ~/{PROJ_REL} \(claude-code\)$",
                     out, re.M)


def test_memory_moved_only_here_is_to_push(agreed, capsys):
    _home_a, home_b, _spec = agreed
    memory_file(home_b).write_text("b's own note.\n")
    _code, out = run(home_b, capsys, verbose=True)
    assert memory_line(out).group(1) == "push", out


def test_memory_moved_only_in_the_archive_is_to_pull(agreed, capsys):
    home_a, home_b, _spec = agreed
    memory_file(home_a).write_text("a's newer note.\n")
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    _code, out = run(home_b, capsys, verbose=True)
    assert memory_line(out).group(1) == "pull", out


def test_memory_moved_on_both_sides_is_to_pull(agreed, capsys):
    home_a, home_b, _spec = agreed
    memory_file(home_a).write_text("a's newer note.\n")
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    memory_file(home_b).write_text("b's own note.\n")
    _code, out = run(home_b, capsys, verbose=True)
    assert memory_line(out).group(1) == "pull", out


# --- filed divergences -------------------------------------------------------


def test_a_filed_memory_copy_points_at_resolve(agreed, capsys):
    _home_a, home_b, _spec = agreed
    project_dir = memory_file(home_b).parent.parent.name
    filed = home_b / ".carryon" / "conflicts" / project_dir / "memory"
    filed.mkdir(parents=True)
    (filed / "MEMORY.md").write_text("the Archive's copy\n")
    _code, out = run(home_b, capsys)
    assert ("Filed: 1 memory file diverged - merge it, then run "
            "`carryon resolve`" in out), out


def test_a_filed_session_names_where_it_is(two, capsys):
    """On `two`, where b has never pulled, so nothing else is filed."""
    _home_a, home_b, _spec = two
    filed = home_b / ".carryon" / "conflicts" / UUID_A
    filed.mkdir(parents=True)
    (filed / (UUID_A + ".jsonl")).write_text('{"n":1}\n')
    _code, out = run(home_b, capsys)
    assert ("Filed: 1 Session diverged - the Archive's copy is under "
            "~/.carryon/conflicts/<uuid>/ for you to merge"
            in out), out
    assert "in step" not in out


# --- the Setup ---------------------------------------------------------------


def test_a_setup_changed_here_is_to_push(two, capsys):
    home_a, _home_b, _spec = two
    (home_a / ".claude" / "CLAUDE.md").write_text("New instructions.\n")
    _code, out = run(home_a, capsys)
    assert ("Setup: changed here since your last push - run "
            "`carryon push --apply` to send it") in out.splitlines()
    assert "History:" not in out


def test_a_setup_pushed_elsewhere_is_to_pull(two, capsys):
    home_a, home_b, _spec = two
    # 2, not 0: C's rollout diverged and is filed. The Setup still lands.
    assert sync.pull(ns(apply=True), home_b) == 2
    (home_a / ".claude" / "CLAUDE.md").write_text("New instructions.\n")
    assert sync.push(ns(apply=True), home_a) == 0
    _code, out = run(home_b, capsys)
    assert re.search(
        r"^Setup: machine-a pushed changes \(\d{4}-\d\d-\d\d \d\d:\d\d\) - "
        r"run `carryon pull --apply` to bring them here$", out, re.M), out


def test_a_setup_moved_on_both_sides_says_the_pull_replaces_yours(
        two, capsys):
    home_a, home_b, _spec = two
    sync.pull(ns(apply=True), home_b)
    (home_a / ".claude" / "CLAUDE.md").write_text("New instructions.\n")
    assert sync.push(ns(apply=True), home_a) == 0
    (home_b / ".claude" / "CLAUDE.md").write_text("b's instructions.\n")
    _code, out = run(home_b, capsys)
    assert re.search(
        r"^Setup: machine-a pushed changes \(.*\) - run `carryon pull "
        r"--apply` to bring them here; it replaces the changes made here, "
        r"after backing them up$", out, re.M), out
    assert ("Setup: changed here since your last push - run "
            "`carryon push --apply` to send it") in out.splitlines()


def test_a_machine_with_no_mark_says_its_setup_is_not_known(two, capsys):
    _home_a, home_b, _spec = two
    _code, out = run(home_b, capsys)
    assert "Setup: not known here until a full push or pull" in out


def test_a_setup_a_push_would_refuse_is_said_and_still_exit_0(two, capsys):
    home_a, _home_b, _spec = two
    claude_md = home_a / ".claude" / "CLAUDE.md"
    claude_md.unlink()
    claude_md.symlink_to(home_a / ".carryon" / "config.json")
    code, out = run(home_a, capsys)
    assert code == 0
    assert ("Setup: a push would refuse it - `carryon push` shows why"
            in out), out


def test_the_capture_plan_does_not_leak_into_the_report(two, capsys):
    home_a, _home_b, _spec = two
    (home_a / ".claude" / "CLAUDE.md").write_text("New instructions.\n")
    _code, out = run(home_a, capsys)
    assert "PLAN (dry run)" not in out
    assert "categories:" not in out


# --- reads, never writes -----------------------------------------------------


def test_status_writes_nothing_here_or_at_the_destination(two, capsys):
    _home_a, home_b, spec = two
    before = (tree_state(home_b), tree_state(spec))
    run(home_b, capsys, verbose=True)
    assert (tree_state(home_b), tree_state(spec)) == before


def test_status_reads_the_index_and_no_object(two, capsys, monkeypatch):
    _home_a, home_b, _spec = two
    read = []
    original = DirectoryDestination.read

    def counting(self, key):
        read.append(key)
        return original(self, key)
    monkeypatch.setattr(DirectoryDestination, "read", counting)
    run(home_b, capsys)
    assert read and set(read) == {archive.INDEX_KEY}, read


def test_a_rolled_back_index_is_warned_about_and_still_exit_0(two, capsys):
    home_a, _home_b, spec = two
    _record_revision(home_a, spec, 10_000)
    code, out = run(home_a, capsys)
    assert code == 0
    assert "has been rolled back" in out


def test_no_destination_refuses_as_push_and_pull_do(tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    with pytest.raises(SystemExit, match="no Destination configured"):
        status.run(argparse.Namespace(verbose=False), home)


def test_no_master_key_refuses_as_pull_does(two):
    _home_a, home_b, _spec = two
    (home_b / ".carryon" / "master.key").unlink()
    with pytest.raises(SystemExit, match="holds no master key"):
        status.run(argparse.Namespace(verbose=False), home_b)


# --- the command surface -----------------------------------------------------


def test_status_takes_verbose_and_nothing_else():
    parser = cli.build_parser()
    assert parser.parse_args(["status"]).verbose is False
    assert parser.parse_args(["status", "--verbose"]).verbose is True
    for flag in ("--apply", "--category", "--agent"):
        with pytest.raises(SystemExit):
            parser.parse_args(["status", flag, "x"])


def test_status_help_says_it_moves_nothing():
    parser = cli.build_parser()
    sub = next(a for a in parser._actions
               if isinstance(a, argparse._SubParsersAction))
    assert "moves nothing" in sub.choices["status"].format_help()


def test_memory_the_archive_has_never_seen_is_to_push(two, capsys):
    home_a, _home_b, _spec = two
    cwd = str(home_a / "code" / "other")
    memory = (home_a / ".claude" / "projects"
              / rekey.encode_project_dir(cwd) / "memory")
    memory.mkdir(parents=True)
    (memory / "MEMORY.md").write_text("A second project's notes.\n")
    # A project's cwd is read off its Transcripts, so memory with none
    # beside it has no cwd, and push skips it too.
    (memory.parent / "99999999-9999-4999-8999-999999999999.jsonl").write_text(
        '{"cwd":"%s","type":"meta"}\n' % cwd)
    _code, out = run(home_a, capsys, verbose=True)
    assert re.search(r"^  push +memory ~/code/other \(claude-code\)$", out,
                     re.M), out


def test_memory_with_no_base_is_to_pull(two, capsys):
    """b never agreed on anything with the Archive, so its differing copy has
    no Base, and pull's prefix rule is what decides."""
    _home_a, home_b, _spec = two
    memory_file(home_b).parent.mkdir(parents=True)
    memory_file(home_b).write_text("b's unrelated note.\n")
    _code, out = run(home_b, capsys, verbose=True)
    assert memory_line(out).group(1) == "pull", out


# --- review round 1: regressions ---------------------------------------------


def test_a_session_pull_filed_is_filed_and_not_also_to_pull(two, capsys):
    """C's rollout diverged on b. Once a pull has filed the Archive's copy,
    `sync` cannot close it, so it is reported as filed and nothing else."""
    _home_a, home_b, _spec = two
    assert sync.pull(ns(apply=True), home_b) == 2
    _code, out = run(home_b, capsys, verbose=True)
    assert UUID_C not in "".join(line for line in out.splitlines(True)
                                 if line.startswith("  pull")), out
    assert "Filed: 1 Session diverged" in out
    assert f"  filed    ~/.carryon/conflicts/{UUID_C}/" in out


def test_memory_a_pull_filed_is_filed_and_not_also_to_pull(agreed, capsys):
    home_a, home_b, _spec = agreed
    memory_file(home_a).write_text("a's newer note.\n")
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    memory_file(home_b).write_text("b's own note.\n")
    sync.pull(ns(apply=True, category="history"), home_b)
    _code, out = run(home_b, capsys, verbose=True)
    assert memory_line(out) is None, out
    assert "Filed: 1 memory file diverged" in out


def test_a_setup_pulled_short_of_an_owned_file_still_differs(tmp_path,
                                                             capsys):
    """b's CLAUDE.md belongs to a dotfiles repo, so the pull leaves it alone:
    the Setup did not land whole, and b's still differs from the Archive's."""
    home_a = build_home_a(tmp_path)
    spec = str(tmp_path / "archive")
    sync.init(ns(dest=spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = build_home_b(tmp_path, dotfiles=True)
    link_home(home_b, spec, "machine-b", master_from=home_a)
    sync.pull(ns(apply=True), home_b)
    _code, out = run(home_b, capsys)
    assert ("Setup: changed here since your last push - run "
            "`carryon push --apply` to send it") in out.splitlines(), out
    assert "pushed changes" not in out


def test_a_setup_file_only_this_machine_has_is_still_to_push(two, capsys):
    """The laid-down Setup never held b's settings.local.json, so agreeing
    with the Archive would hide a file only a push can publish."""
    _home_a, home_b, _spec = two
    (home_b / ".claude").mkdir(exist_ok=True)
    (home_b / ".claude" / "settings.local.json").write_text('{"b": 1}')
    sync.pull(ns(apply=True), home_b)
    _code, out = run(home_b, capsys)
    assert ("Setup: changed here since your last push - run "
            "`carryon push --apply` to send it") in out.splitlines(), out


def test_a_setup_pulled_whole_is_in_step(two, capsys):
    _home_a, home_b, _spec = two
    sync.pull(ns(apply=True), home_b)
    _code, out = run(home_b, capsys)
    assert "Setup:" not in out, out


def test_an_adapter_reworded_by_an_upgrade_is_not_a_setup_change(two):
    import dataclasses
    from carryon import setup_mark
    home_a, _home_b, _spec = two
    effective = sync._effective_adapters(config.load(home_a), home_a)
    reworded = {
        key: dataclasses.replace(
            adapter, verified_against="a later version",
            items=tuple(dataclasses.replace(item, note="reworded")
                        for item in adapter.items))
        for key, adapter in effective.items()}
    assert (setup_mark.digest_here(home_a, reworded)
            == setup_mark.digest_here(home_a, effective))


def test_a_setup_this_machine_would_refuse_still_says_what_to_pull(
        two, capsys):
    home_a, home_b, _spec = two
    sync.pull(ns(apply=True), home_b)
    (home_a / ".claude" / "CLAUDE.md").write_text("New instructions.\n")
    assert sync.push(ns(apply=True), home_a) == 0
    claude_md = home_b / ".claude" / "CLAUDE.md"
    claude_md.unlink()
    claude_md.symlink_to(home_b / ".carryon" / "config.json")
    _code, out = run(home_b, capsys)
    assert "Setup: a push would refuse it" in out
    assert re.search(r"^Setup: machine-a pushed changes \(.*\) - run "
                     r"`carryon pull --apply` to bring them here$", out,
                     re.M), out

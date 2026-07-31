"""What a restore writes through, deletes through, and crashes on.

The History leg gained ADR-0007's deference last round, asked as
`external.classify` - "is a symlink claiming this path". Everything below is
the same harm reached without a symlink, or the same rule asked about the
wrong path, or the walk raising where the whole layer promises a report line:

  identity      a HARD link is a second directory entry for the same inode.
                classify says 'ours', write_bytes truncates the OTHER name,
                and a dotfiles repo is edited exactly as ADR-0007 forbids -
                which ADR-0009 already says in as many words one syscall over
                ("A hard link is refused for the same reason").
  the path      the delete-through guard classified the directory DISCOVERY
                found while the write happens under the root the Index's cwd
                DERIVES. With `--map` those differ, so the guard answered
                about a directory nobody was writing to: the local transcript
                was deleted, every write was deferred, and nothing landed
                anywhere.
  the crash     a directory planted where a member lands is an unhandled
                IsADirectoryError out of pull, on both runners, after earlier
                Sessions were written and before any report. The Setup leg
                closed this exact shape with a named try; the History leg is
                the same loop with the same two syscalls.
  the refusal   config.lands_in_state RESOLVES, so one dangling link planted
                in a project tree - no key, no Destination access - turned
                every pull into a permanent SystemExit naming a tar member the
                user cannot find. A NAME that spells ~/.carryon is a key
                holder's doing and refuses; a link that RESOLVES there is the
                planted case and defers.
  the runners   resolve() answers a symlink loop with RuntimeError on 3.9.6
                and with the unresolved path on 3.13, so the two required
                runners disagreed about a planted loop. Both must report it.
  the capture   the History leg has no `unsafe_reads` equivalent, so a link
                at '<slug>/<uuid>/notes.jsonl -> ~/.carryon/master.key' was
                packed, and restore laid the master key down at mode 0644 in
                a project directory on every machine that pulled.

Every home here is synthetic, every byte in it invented, and the "master key"
is recognisable hex that is not a real key.
"""

import argparse
import json
import os
import pathlib
import stat
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (config, external, history, keyring,  # noqa: E402
                     rekey, sync)
from tests.timeouts import time_limit  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ_REL = "code/snake_case_proj"
MANAGED = "# managed by my dotfiles repo\n"
FAKE_KEY = "00112233445566778899aabbccddeeff" * 2 + "\n"


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


def main_lines(cwd, n=2) -> str:
    text = jline({"cwd": cwd, "type": "meta"})
    for i in range(1, n):
        text += jline({"type": "user", "text": f"edit {cwd}/main.py", "n": i})
    return text


def project_root(home, rel=PROJ_REL) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / rel)))


def pushing_home(tmp_path, subtree=True) -> pathlib.Path:
    """One Session with a main Transcript and a subagent journal beneath it,
    plus per-project residue - one of each thing a restore writes."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)
    project = project_root(home)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(main_lines(cwd, 3))
    if subtree:
        sub = project / UUID_A / "subagents"
        sub.mkdir(parents=True)
        (sub / "journal.jsonl").write_text(jline({"step": 1}))
    memory = project / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text(f"Notes live in {cwd}/notes.\n")
    return home


def pulling_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home_b"
    (home / ".claude" / "projects").mkdir(parents=True)
    (home / "dotfiles").mkdir()
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


def pushed_archive(tmp_path, subtree=True):
    home_a = pushing_home(tmp_path, subtree)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    return home_a, dest_spec


def paired_pull(tmp_path, subtree=True):
    home_a, dest_spec = pushed_archive(tmp_path, subtree)
    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_a, home_b, dest_spec


# --- identity: a hard link is a second name for the same file ----------------


def test_pull_does_not_write_through_a_hard_link(tmp_path, capsys):
    """`ln ~/dotfiles/journal.jsonl <member path>`: nothing about that entry
    is a link as far as classify can see, and write_bytes truncates and
    rewrites the file the dotfiles repo owns."""
    _, home_b, _ = paired_pull(tmp_path)
    managed = home_b / "dotfiles" / "journal.jsonl"
    managed.write_text(MANAGED)
    member = project_root(home_b) / UUID_A / "subagents" / "journal.jsonl"
    member.parent.mkdir(parents=True)
    os.link(managed, member)

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert managed.read_text() == MANAGED, \
        "pull rewrote a file a dotfiles repo owns through a hard link"
    assert "externally owned" in out
    assert "journal.jsonl" in out


def test_a_named_pipe_where_a_member_lands_does_not_stop_the_pull(tmp_path,
                                                                   capsys):
    """`mkfifo <member path>`: one command, no key, no Destination access.

    Every other read in this package refuses a fifo and says why - the content
    gate ("a `carryon push` that never returns and prints nothing"), the
    Destination layer, capture's walk. The restore leg's ownership question
    called one 'ours', and the union rule then opened it to compare, which
    blocks until a writer comes. Not a wrong verdict: no verdict, for ever, on
    every pull from this machine.

    Under an alarm, since the failure is a pull that never returns and a test
    that never returns is no better.
    """
    _, home_b, _ = paired_pull(tmp_path)
    member = project_root(home_b) / UUID_A / "subagents" / "journal.jsonl"
    member.parent.mkdir(parents=True)
    os.mkfifo(str(member))

    with time_limit(20, "the pull never returned - it is waiting for the "
                        "other end of a named pipe"):
        assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert stat.S_ISFIFO(member.lstat().st_mode), \
        "the pipe was replaced rather than deferred to"
    assert "journal.jsonl" in out, "the member it declined to write went unnamed"
    # ...and the rest of the Session still landed, so this is deference and
    # not a pull that gave up at the first thing it would not touch.
    assert (project_root(home_b) / (UUID_A + ".jsonl")).is_file()


def test_the_setup_leg_defers_to_a_hard_link_too(tmp_path, capsys):
    """The same rule on the other leg, since one of them having it has never
    been evidence about the other. A Setup item whose local name is a hard
    link into a dotfiles repo is deference, not a write."""
    home_a = tmp_path / "home_a"
    (home_a / ".claude").mkdir(parents=True)
    (home_a / ".claude" / "settings.json").write_text('{"model": "opus"}')
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True,
                        category="config,capability,knowledge"), home_a) == 0

    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    managed = home_b / "dotfiles" / "settings.json"
    managed.write_text(MANAGED)
    (home_b / ".claude").mkdir(exist_ok=True)
    os.link(managed, home_b / ".claude" / "settings.json")

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert managed.read_text() == MANAGED, \
        "the Setup leg wrote through a hard link"
    assert "externally owned" in out


# --- the guard has to be about the path the write takes ----------------------


def test_a_replace_never_deletes_a_local_session_it_did_not_replace(
        tmp_path, capsys):
    """The delete-through guard asked about the directory DISCOVERY found
    while the write happens under the root the cwd DERIVES; `--map` makes
    those two different directories. Every write was deferred, every local
    file was deleted, and the transcript existed nowhere afterwards."""
    home_a, home_b, _ = paired_pull(tmp_path, subtree=False)
    # the local copy is a byte-prefix of the Archive's, so the incoming wins
    local = project_root(home_b)
    local.mkdir(parents=True)
    prefix = main_lines(str(home_b / PROJ_REL), 1)
    (local / (UUID_A + ".jsonl")).write_text(prefix)
    # ...but --map sends the restore to a project dir something else owns
    mapped = project_root(home_b, "code/other_proj")
    claimed = home_b / "dotfiles" / "projects"
    claimed.mkdir()
    mapped.symlink_to(claimed)

    # Absolute on both sides: a bare 'snake_case_proj' is a substring match
    # over every value in every Transcript, which sync._parse_maps refuses now
    # (rekey.map_refusal). '~' is expanded against the local home before the
    # maps run, so naming this machine's directories sends the restore to the
    # same project directory the fragment did.
    assert sync.pull(ns(apply=True,
                        map=[f"{home_b / PROJ_REL}="
                             f"{home_b / 'code' / 'other_proj'}"]),
                     home_b) == 0
    capsys.readouterr()

    assert (local / (UUID_A + ".jsonl")).read_text() == prefix, \
        "pull deleted the only copy of a Session it then wrote nowhere"
    assert list(claimed.iterdir()) == [], "the deferred write happened anyway"


def test_a_replace_in_the_same_directory_still_replaces(tmp_path):
    """The control for the rule above: with no --map the incoming tree lands
    exactly where the local one is, so ADR-0002's replacement still
    replaces."""
    _, home_b, _ = paired_pull(tmp_path)
    local = project_root(home_b)
    local.mkdir(parents=True)
    (local / (UUID_A + ".jsonl")).write_text(
        main_lines(str(home_b / PROJ_REL), 1))

    assert sync.pull(ns(apply=True), home_b) == 0

    assert (local / (UUID_A + ".jsonl")).read_text() == \
        main_lines(str(home_b / PROJ_REL), 3)
    assert (local / UUID_A / "subagents" / "journal.jsonl").is_file()


# --- report, never a traceback -----------------------------------------------


def test_a_directory_where_a_member_lands_is_reported_not_raised(tmp_path,
                                                                 capsys):
    """`mkdir <slug>/<uuid>.jsonl` needs no key and is invisible to discovery
    - a directory is not is_file(), so it is never a main Transcript. The next
    pull died with IsADirectoryError, no report, no summary, Setup half never
    reached, every later Session abandoned."""
    _, home_b, _ = paired_pull(tmp_path)
    root = project_root(home_b)
    (root / (UUID_A + ".jsonl")).mkdir(parents=True)

    code = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert code == 0
    assert UUID_A in out
    assert "-" * 20 in out, "the pull ended before its report"
    assert "Sessions:" in out


def test_a_directory_where_a_residue_member_lands_is_reported_not_raised(
        tmp_path, capsys):
    """The residue leg of the same plant. It used to escape only because that
    leg never wrote over anything already on disk, so a directory in the way
    was counted as a kept file and never looked at. The leg now runs
    ADR-0002's rule like every other, which means it reads the path and then
    writes - both of which a directory answers with an OSError - so the
    refusal has to be the reported kind and has to name the path."""
    _, home_b, _ = paired_pull(tmp_path)
    root = project_root(home_b)
    (root / "memory" / "MEMORY.md").mkdir(parents=True)

    code = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert code == 0
    assert "Project residue:" in out, "the pull ended before its report"
    assert "MEMORY.md" in out, "the member it could not write went unnamed"
    assert (root / "memory" / "MEMORY.md").is_dir(), \
        "the directory standing in the way was written over"


def test_a_planted_link_into_state_defers_rather_than_aborting_the_pull(
        tmp_path, capsys):
    """One dangling symlink into ~/.carryon, planted with no key and no
    Destination access, used to end every pull from every machine with a
    SystemExit naming a tar member the user cannot find. The name is not the
    key holder's here - it is the link's - so this is deference like any other
    link, named where it sits."""
    _, home_b, _ = paired_pull(tmp_path)
    root = project_root(home_b)
    root.mkdir(parents=True)
    (root / "memory").mkdir()
    (root / "memory" / "MEMORY.md").symlink_to(
        home_b / ".carryon" / "anything")

    code = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert code == 0
    assert not (home_b / ".carryon" / "anything").exists(), \
        "a restored History wrote into carryon's own state"
    assert "externally owned" in out
    assert "MEMORY.md" in out


def test_a_tar_member_that_spells_state_is_still_refused_whole(tmp_path):
    """The other half of that split, kept: a member whose NAME lands in
    ~/.carryon was composed by whoever sealed the tar, which needs the master
    key. There is no honest reading of it, so it refuses rather than
    deferring."""
    home = pulling_home(tmp_path)
    tar = history._tar_bytes([("master.key", b"deadbeef\n")])

    with pytest.raises(SystemExit) as exc:
        sync._extract_tree(tar, home / ".carryon", home, [])

    assert "carryon" in str(exc.value)


def test_a_symlink_loop_reads_the_same_on_both_runners(tmp_path, capsys):
    """resolve() raises RuntimeError('Symlink loop') on 3.9.6 and returns the
    unresolved path on 3.13, so a planted loop was a SystemExit on one runner
    and a clean deferral on the other - with both suites green, because no
    test built one."""
    _, home_b, _ = paired_pull(tmp_path)
    root = project_root(home_b)
    (root / "memory").mkdir(parents=True)
    loop = root / "memory" / "MEMORY.md"
    loop.symlink_to(loop)

    code = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert code == 0
    assert "MEMORY.md" in out
    assert "Sessions:" in out


# --- the capture leg of a History --------------------------------------------


def test_a_link_into_state_is_never_packed_into_a_session(tmp_path, capsys):
    """The Setup leg refuses this class outright and the History leg never
    asked. pack_session reads each member with read_bytes, which follows a
    link, and secrets.scan cannot see bare hex (ADR-0008's own reason the
    carve-out had to be a construction rule) - so the key travelled inside the
    encrypted tar and landed at mode 0644 in a project tree on every machine
    that pulled."""
    home_a = pushing_home(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    # The real fallback key this init wrote: what makes the leak invisible is
    # that the file holds bare hex, so nothing here is a stand-in.
    key = home_a / ".carryon" / "master.key"
    secret = key.read_text().strip()
    (project_root(home_a) / UUID_A / "notes.jsonl").symlink_to(key)

    assert sync.push(ns(apply=True, category="history"), home_a) == 0
    out = capsys.readouterr().out
    assert "notes.jsonl" in out, "the withheld member is not named"

    home_b = pulling_home(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0

    planted = [p for p in (home_b / ".claude").rglob("*")
               if p.is_file() and secret in
               p.read_bytes().decode("utf-8", "replace")]
    assert planted == [], "a master key was restored into a project tree"


def test_the_history_leg_asks_one_rule_both_legs_ask(tmp_path):
    """The rule itself, so a future caller cannot get a weaker spelling of it:
    what defers on the Setup leg defers here, hard links included."""
    home = pulling_home(tmp_path)
    managed = home / "dotfiles" / "notes.jsonl"
    managed.write_text(MANAGED)
    twin = home / ".claude" / "twin.jsonl"
    os.link(managed, twin)

    assert external.owner_of(twin, home)[0] == external.EXTERNALLY_OWNED
    assert external.owner_of(home / ".claude" / "fresh.jsonl", home)[0] == \
        external.ABSENT

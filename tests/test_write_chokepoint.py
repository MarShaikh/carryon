"""One question about who owns a path, asked wherever carryon writes content.

The read side got its chokepoint last round: `config.read_carryable` is the
one way to turn a user's path into bytes that leave the machine, and
tests/test_state_chokepoint.py walks the package's syntax tree to say so. The
write side was left as four separate answers, and the seventh round found the
same defect in each of the places nobody had reviewed:

  ~/.carryon/staging   made with a bare mkdir, so a link at that name sent a
                       whole plaintext Setup into the tree it pointed at - and
                       PERMANENTLY when the credential scan refused the Setup,
                       since a refusal keeps the staging tree on purpose.
  ~/.carryon/git       the same bare mkdir one directory over, leaving the
                       clone - index.enc and every plaintext Setup file in it -
                       inside somebody else's repository.
  ~/.carryon/conflicts answered from $HOME down while the backup beside it
                       answered from ~/.carryon down. One question, one
                       directory apart, two boundaries.
  capture --out        excused in the write allowlist as "carryon's own capture
                       output directory". It is a path the user names, carryon
                       never clears, and a link planted at an item's landing
                       path was followed into another tree.

So there is now ONE function - `config.state_write_path` - that answers "may
carryon write here, under its own state directory", makes the directories it
answers for, and hands back a sentence instead of a traceback when something
that is not a directory is standing in the way. And capture's writes ask
`external.owner_of` about the tree the user named, which is the same question
the restore leg has always asked about $HOME.

Every home here is synthetic; the "dotfiles repo" is an ordinary directory in
tmp_path standing in for one, and the planted credential is invented text.
"""

import json
import os
import pathlib
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (capture, config, external, history,  # noqa: E402
                     keyring, sync)
from carryon.destinations.git_repo import GitDestination  # noqa: E402
from tests.hostile_archive import (GOOD_SETTINGS, build_home_a,  # noqa: E402
                                   link_home, ns)
from tests.timeouts import time_limit  # noqa: E402

MANAGED = "# managed by my dotfiles repo\n"
LOCAL_SETTINGS = '{"model": "local-tweak"}'
PLANTED_KEY = 'api_key = "ZQ9f8e7d6c5b4a3s2"\n'


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def victim_tree(tmp_path) -> pathlib.Path:
    """A directory standing in for a dotfiles repo - a tree whose whole job is
    to be committed, which is what makes a stray file in it a publication."""
    victim = tmp_path / "dotfiles"
    victim.mkdir(exist_ok=True)
    return victim


def files_under(root) -> list:
    return sorted(str(p.relative_to(root)) for p in pathlib.Path(root).rglob("*")
                  if p.is_file() and not p.is_symlink())


def initialised(tmp_path, home=None):
    """A machine with a Destination and a key, ready to push."""
    home = home or build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    return home, dest_spec


# --- ~/.carryon/staging ------------------------------------------------------


def test_a_link_at_the_staging_root_is_not_written_through(tmp_path, capsys,
                                                           monkeypatch):
    """`~/.carryon/staging -> ~/dotfiles`, then `push --apply`.

    The staging tree is a whole plaintext Setup - settings, standing
    instructions, slash commands - and the mkdir that made room for it asked
    nobody. ADR-0007 is a rule about every write carryon makes, and this is
    the same defect config.write_state_bytes was written for, one directory
    over.

    The sweep at the end of a clean push is stubbed out, because what is under
    test is what carryon WRITES rather than what it tidies up afterwards: the
    files were in the user's repository while the push ran, a sync client
    watching that directory had them, and the refused-Setup case one test down
    does not tidy up at all.
    """
    home, _ = initialised(tmp_path)
    victim = victim_tree(tmp_path)
    (home / ".carryon" / "staging").symlink_to(victim)
    monkeypatch.setattr(sync.shutil, "rmtree", lambda *a, **kw: None)

    sync.push(ns(apply=True, category="config,capability,knowledge"), home)
    report = capsys.readouterr().out

    assert not files_under(victim), (
        "a plaintext Setup was staged inside a tree carryon does not own:\n"
        + "\n".join(files_under(victim)))
    assert "SETUP REFUSED" in report, report


def test_a_refused_setup_is_never_left_in_a_tree_carryon_does_not_own(
        tmp_path, capsys):
    """The permanent case, and the worst one.

    A capture that meets a credential keeps its staging tree on purpose, for
    the user to inspect - so the one Setup carryon refuses to publish is the
    one that stays behind. Through a link at ~/.carryon/staging that is a
    refused Setup deposited inside a repository, under a report line telling
    the user not to transfer it."""
    home, _ = initialised(tmp_path)
    (home / ".claude" / "CLAUDE.md").write_text(PLANTED_KEY)
    victim = victim_tree(tmp_path)
    (home / ".carryon" / "staging").symlink_to(victim)

    sync.push(ns(apply=True, category="config,capability,knowledge"), home)
    capsys.readouterr()

    left = files_under(victim)
    assert not left, ("the Setup carryon refused to publish was left in a "
                      "tree carryon does not own: " + ", ".join(left))


@pytest.mark.parametrize("shape", ["file", "dangling"])
def test_something_that_is_not_a_directory_at_the_staging_root_is_a_sentence(
        shape, tmp_path, capsys):
    """A FileExistsError out of push, after the recovery key has been printed
    and before any report, is exactly the defect config.write_state_bytes'
    docstring claims to have closed: 'exist_ok forgives only for a directory,
    and that was a traceback out of init and out of every pairing'."""
    home, _ = initialised(tmp_path)
    standing = home / ".carryon" / "staging"
    if shape == "file":
        standing.write_text("not a directory\n")
    else:
        standing.symlink_to(tmp_path / "nowhere")

    code = sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home)
    report = capsys.readouterr().out

    assert code != 0, report
    assert "staging" in report


def test_an_ordinary_push_still_stages_and_publishes_a_setup(tmp_path, capsys):
    """The positive control: nothing above may turn an everyday push into a
    refusal, and the staging tree must still be cleaned up afterwards."""
    home, _ = initialised(tmp_path)

    code = sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home)
    report = capsys.readouterr().out

    assert code == 0, report
    stored = tmp_path / "archive" / "carryon" / "setups" / "machine-a"
    assert (stored / "claude" / "settings.json").read_text() == GOOD_SETTINGS
    assert not list((home / ".carryon" / "staging").glob("setup-*")), \
        "the staging tree was left behind by a clean push"


# --- ~/.carryon/git ----------------------------------------------------------


def test_a_link_at_the_git_clone_directory_is_not_cloned_through(tmp_path,
                                                                 capsys):
    """`~/.carryon/git -> ~/dotfiles` with a git Destination.

    Same bare mkdir, worse residue: a clone is not a staging tree and nothing
    sweeps it, so index.enc and the whole plaintext setups/<machine>/ tree
    stay in the victim's repository for good."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)],
                   check=True)
    home = tmp_path / "home_g"
    (home / ".carryon").mkdir(parents=True)
    victim = victim_tree(tmp_path)
    (home / ".carryon" / "git").symlink_to(victim)

    dest = GitDestination(str(origin), home=home)
    with pytest.raises(SystemExit) as caught:
        dest.write("carryon/index.enc", b"sealed")
    capsys.readouterr()

    assert not files_under(victim), (
        "a git clone was made inside a tree carryon does not own: "
        + ", ".join(files_under(victim)))
    assert "git" in str(caught.value)


def test_an_ordinary_git_destination_still_clones_and_writes(tmp_path):
    """The positive control for the clone directory's own guard."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)],
                   check=True)
    home = tmp_path / "home_g"
    home.mkdir()

    dest = GitDestination(str(origin), home=home)
    dest.write("carryon/index.enc", b"sealed")

    assert dest.read("carryon/index.enc") == b"sealed"


# --- one boundary for every write into carryon's own state -------------------


def test_the_state_directory_may_itself_be_a_link_on_every_leg(tmp_path,
                                                               capsys):
    """~/.carryon standing in a synced folder is an arrangement carryon
    supports by name - config.write_state_bytes says so in as many words: the
    directories carryon MAKES are answered for, not where its state directory
    lives. The backup leg drew that line and the conflicts leg beside it drew
    another, walking from $HOME down, so the same user's pull deferred every
    conflict copy while taking every backup. One question, one answer."""
    home = tmp_path / "home_s"
    (home / ".claude").mkdir(parents=True)
    elsewhere = tmp_path / "synced-state"
    elsewhere.mkdir()
    (home / ".carryon").symlink_to(elsewhere)

    backup = config.state_write_path(home, "backups", "stamp", ".claude",
                                     "settings.json")
    conflict = config.state_write_path(home, "conflicts", "uuid",
                                       "main.jsonl")

    assert backup[1] is None, backup[1]
    assert conflict[1] is None, conflict[1]
    assert (elsewhere / "backups" / "stamp" / ".claude").is_dir()
    assert (elsewhere / "conflicts" / "uuid").is_dir()


def test_a_link_at_any_component_carryon_makes_is_refused(tmp_path):
    """The other half of the same rule: everything BELOW ~/.carryon is
    carryon's to make, so a link standing at one of those names is somebody
    else claiming a path carryon is about to write into."""
    home = tmp_path / "home_s"
    (home / ".carryon").mkdir(parents=True)
    victim = victim_tree(tmp_path)
    (home / ".carryon" / "conflicts").symlink_to(victim)

    path, why = config.state_write_path(home, "conflicts", "uuid", "main.jsonl")

    assert path is None
    assert why and "conflicts" in why
    assert not files_under(victim)


@pytest.mark.parametrize("part", ["..", ".", "", "a/b", "a\x00b"])
def test_a_component_under_the_state_directory_is_one_plain_name(part,
                                                                 tmp_path):
    """The components come from a timestamp, an item's relative path and - for
    the copy a pull sets aside - a key that came back from a Destination. One
    '..' among them leaves the directory this function exists to keep the
    write inside, and two leave ~/.carryon altogether."""
    home = tmp_path / "home_s"
    (home / ".carryon").mkdir(parents=True)

    path, why = config.state_write_path(home, "backups", part, "settings.json")

    assert path is None
    assert why and "plain name" in why
    assert not [p for p in home.rglob("*") if p.is_file()]


def test_a_file_where_a_state_directory_belongs_is_a_sentence(tmp_path):
    """mkdir answers a plain file with FileExistsError, which exist_ok
    forgives only for a directory. Every caller of this function is a command
    in the middle of doing something, so the answer is a sentence."""
    home = tmp_path / "home_s"
    (home / ".carryon").mkdir(parents=True)
    (home / ".carryon" / "backups").write_text("not a directory\n")

    path, why = config.state_write_path(home, "backups", "stamp", "x")

    assert path is None
    assert why and "backups" in why


# --- pull's two writes into ~/.carryon ---------------------------------------


def setup_archive(tmp_path):
    """machine-a pushes a Setup; machine-b is paired and about to pull."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home_a) == 0
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    (home_b / ".claude" / "settings.json").write_text(LOCAL_SETTINGS)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_a, home_b


def test_force_writes_through_a_dotfiles_link_that_leaves_home(tmp_path,
                                                               capsys):
    """--force is documented as 'write through externally owned paths
    (dotfiles symlinks) instead of skipping them', and a checkout outside
    $HOME - /opt, /srv, a second volume - is an ordinary place to keep one.

    The backup that has to happen first reads the local file, and routing that
    read through the gate that asks whether CONTENT MAY LEAVE THIS MACHINE
    applied the $HOME boundary to bytes going into ~/.carryon and off no
    machine at all. The item was refused with a sentence about a rule that
    does not apply to it, and --force silently stopped working."""
    _, home_b = setup_archive(tmp_path)
    outside = tmp_path / "opt-dotfiles"
    outside.mkdir()
    managed = outside / "settings.json"
    managed.write_text(MANAGED)
    (home_b / ".claude" / "settings.json").unlink()
    (home_b / ".claude" / "settings.json").symlink_to(managed)

    code = sync.pull(ns(apply=True, force=True), home_b)
    report = capsys.readouterr().out

    assert code == 0, report
    assert managed.read_text() == GOOD_SETTINGS, (
        "--force did not write through the link it exists for:\n" + report)
    saved = [p for p in (home_b / ".carryon" / "backups").rglob("*")
             if p.is_file()]
    assert [p for p in saved if p.read_text() == MANAGED], \
        "--force wrote through the link without saving what was there"


def test_the_backup_leg_still_refuses_carryons_own_state(tmp_path):
    """The rule the backup read must keep: a local read is not a licence to
    copy the master key, whatever name it is wearing. Identity is the half
    that answers a hard link, and dropping the $HOME half must not drop it."""
    home = tmp_path / "home_r"
    (home / ".claude").mkdir(parents=True)
    (home / ".carryon").mkdir()
    key = home / ".carryon" / "master.key"
    key.write_text("00112233445566778899aabbccddeeff" * 2 + "\n")
    decoy = home / ".claude" / "settings.json"
    os.link(key, decoy)

    data, why = config.read_carryable(decoy, home, leaves_machine=False)

    assert data is None
    assert why == config.WHY_STATE


# --- capture --out is a path the user names ----------------------------------


def test_capture_does_not_write_through_a_link_in_the_out_directory(tmp_path,
                                                                    capsys):
    """`--out` is required, arbitrary and never cleared by carryon; a link
    planted at an item's landing path is the ordinary shape of ADR-0007's
    harm, and the write allowlist excused the whole directory as carryon's
    own."""
    home = build_home_a(tmp_path)
    victim = victim_tree(tmp_path)
    managed = victim / "settings.json"
    managed.write_text(MANAGED)
    out = tmp_path / "out"
    (out / "claude").mkdir(parents=True)
    (out / "claude" / "settings.json").symlink_to(managed)

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert managed.read_text() == MANAGED, (
        "capture wrote a user's settings through a link into another tree")
    assert "settings.json" in report
    assert code == 0, report


def test_capture_does_not_write_through_a_link_inside_a_captured_tree(
        tmp_path, capsys):
    """The same question one level in, where copy_tree does the writing rather
    than _write - the two used to be different answers to it."""
    home = build_home_a(tmp_path)
    victim = victim_tree(tmp_path)
    managed = victim / "ship.md"
    managed.write_text(MANAGED)
    out = tmp_path / "out"
    (out / "claude" / "commands").mkdir(parents=True)
    (out / "claude" / "commands" / "ship.md").symlink_to(managed)

    capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert managed.read_text() == MANAGED, \
        "copy_tree wrote through a link planted in the capture output"
    assert "ship.md" in report


def test_an_ordinary_capture_writes_everything_it_declares(tmp_path, capsys):
    """The positive control for the two above: the ownership question must not
    turn an everyday capture into a directory full of skips."""
    home = build_home_a(tmp_path)
    out = tmp_path / "out"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert code == 0, report
    assert (out / "claude" / "settings.json").read_text() == GOOD_SETTINGS
    assert (out / "claude" / "commands" / "ship.md").read_text() == "ship it\n"
    assert json.loads((out / "MANIFEST.json").read_text())["tool"] == "carryon"


# --- the enforcement: what the write allowlist may excuse --------------------


def test_the_write_allowlist_excuses_no_directory_the_user_named(tmp_path):
    """A one-line statement of what went wrong in the allowlist itself.

    "carryon's own capture output directory" was three entries' reason for
    needing no ownership question, and the directory in question is whatever
    the user typed after --out. An entry that says a path is carryon's own is
    a claim somebody can check, and this is the check."""
    import tests.test_state_chokepoint as chokepoint

    excuses = {where: why for (_mod, where), (why, _verbs)
               in chokepoint.ALLOWED_WRITES.items()}

    assert "capture output directory" not in " ".join(excuses.values()), (
        "the write allowlist still excuses writes into --out as carryon's "
        "own directory")


def test_no_function_asks_the_ownership_question_and_then_writes_itself(
        tmp_path):
    """The shape of the defect, stated directly rather than through a list.

    Every instance the last two rounds found looked the same in the syntax
    tree: one function calls external.owner_of, and a few lines later that
    same function calls something that puts bytes at a path. `history.
    write_member` had it, `capture._write_owned` had it, the Setup restore
    loop had it - and each was allowlisted with the sentence "asked
    immediately above the call", which is the gap being approved rather than
    closed.

    So the pair is what is forbidden now. A leg may ask the question (a skip
    line needs the owner, and it has to be asked before the union rule reads
    anything), and a leg may write - through external.write_owned, which asks
    it again where it counts. What it may not do is both by itself.
    """
    import tests.test_state_chokepoint as chokepoint

    asks = {(rel, where) for rel, where, _line, _verb
            in chokepoint._package_calls({"owner_of"}, set())}
    writes = {(rel, where) for rel, where, _line, _verb
              in chokepoint._package_writes()}

    both = sorted(asks & writes)
    assert both == [("external.py", "write_owned")], (
        "a function asks who owns a path and then writes to it itself; the "
        "interval between the two is what this round exists to close: "
        + ", ".join(f"{rel}:{where}()" for rel, where in both))


def test_external_owner_of_answers_for_any_root_a_caller_names(tmp_path):
    """The ownership question moved to the module named for it, and takes the
    root it is asked about: $HOME for a restore, ~/.carryon for a state write,
    the --out directory for a capture. One implementation, three boundaries -
    the alternative is what produced the four spellings above."""
    root = tmp_path / "root"
    (root / "inner").mkdir(parents=True)
    victim = victim_tree(tmp_path)
    (root / "inner" / "linked.md").symlink_to(victim / "x.md")
    plain = root / "inner" / "plain.md"
    plain.write_text("ours\n")

    assert external.owner_of(root / "inner" / "linked.md", root)[0] == \
        external.EXTERNALLY_OWNED
    assert external.owner_of(plain, root)[0] == external.OURS


# --- the writer answers for the name, on the descriptor it writes to ---------
#
# Everything above asks the ownership question and then, a syscall later, calls
# something that follows whatever is at the name by then. That gap is the last
# shape of this defect and it is the one the Destination layer already closed
# for its own tree: "A walk that inspects each component and then opens the
# whole path answers about the path it saw and opens the path that is there
# now" (ADR-0009). config.write_state_bytes closed it for ~/.carryon with
# O_NOFOLLOW and an fstat. The two legs that write into $HOME - a Session's
# members and a Setup's items - and the one that writes into --out were left
# with Path.write_bytes, which follows a link, follows a second name for the
# same file, blocks for ever on a named pipe, and truncates before any of that
# is known.
#
# So the question and the write are now one call: external.write_owned. It is
# asked twice on purpose - the planning ask above it still answers the report
# line, and this one answers the descriptor - which is the same shape
# config.read_carryable uses on the read side, where the path answer and the
# fstat on the open file are both kept.


def planted(tmp_path):
    """(root, victim file, the name a restore is about to write)."""
    root = tmp_path / "root"
    (root / "inner").mkdir(parents=True)
    victim = victim_tree(tmp_path)
    managed = victim / "journal.jsonl"
    managed.write_text(MANAGED)
    return root, managed, root / "inner" / "journal.jsonl"


def test_the_writer_refuses_a_link_nobody_asked_it_about(tmp_path):
    """The honest statement of the property: it is the WRITE that must refuse.

    Nothing here asks external.owner_of first, because the interval between an
    ask and a write is exactly what an attacker with write access to a project
    directory has - and because a rule that holds only when a caller remembers
    to ask is the rule this round exists to stop relying on.
    """
    root, managed, target = planted(tmp_path)
    target.symlink_to(managed)

    why = external.write_owned(target, b"incoming\n", root)

    assert why is not None, "the writer followed a link into another tree"
    assert managed.read_text() == MANAGED
    assert target.is_symlink(), "the writer replaced the link instead"


def test_the_writer_refuses_a_second_name_for_the_same_file(tmp_path):
    """A hard link is not a symlink, resolves to itself and answers every
    question a path rule can put; st_nlink on the open descriptor is the tell,
    and it is the same one config.write_state_bytes already uses."""
    root, managed, target = planted(tmp_path)
    os.link(managed, target)

    why = external.write_owned(target, b"incoming\n", root)

    assert why is not None, "the writer rewrote the file behind a second name"
    assert managed.read_text() == MANAGED


def test_the_writer_leaves_the_bytes_it_refuses_exactly_as_it_found_them(
        tmp_path):
    """A pull never removes or truncates, and Path.write_bytes truncates first
    and asks afterwards. What the writer declines to write it must not have
    already destroyed - which is why the open carries no O_TRUNC and the
    ftruncate happens after the fstat."""
    root, managed, target = planted(tmp_path)
    os.link(managed, target)
    before = managed.read_bytes()

    assert external.write_owned(target, b"", root) is not None
    assert managed.read_bytes() == before, \
        "the file was truncated by a write the machine then refused"
    assert target.stat().st_size == len(before)


def test_the_writer_refuses_something_that_is_not_an_ordinary_file(tmp_path):
    """A named pipe answers open() by waiting for a reader that may never come.
    config.read_carryable refuses one, destinations/base refuses one, and
    capture.tree_files refuses one; the restore leg's writer did not - so a
    mkfifo in a project directory, which needs no key and no Destination
    access, was a pull that never returned and printed nothing."""
    root = tmp_path / "root"
    root.mkdir()
    fifo = root / "member.jsonl"
    os.mkfifo(str(fifo))

    with time_limit(what="the writer never came back from the pipe"):
        why = external.write_owned(fifo, b"incoming\n", root)

    assert why is not None
    assert "ordinary file" in why, why


def test_force_still_writes_through_a_link_the_user_owns(tmp_path):
    """--force means "write through the link I own" (ADR-0007), and the two
    checks this adds must not quietly take that away: the Setup leg's whole
    documented use is a dotfiles-managed settings.json."""
    root, managed, target = planted(tmp_path)
    target.symlink_to(managed)

    assert external.write_owned(target, b"forced\n", root, force=True) is None
    assert managed.read_text() == "forced\n"


def test_the_writer_sets_the_mode_on_the_file_it_wrote(tmp_path):
    """capture carried an item's mode over with shutil.copymode, which is a
    chmod BY NAME - a second follow of the link the write had just refused to
    follow, in the function whose own docstring rules that out. The descriptor
    is the only thing that cannot have changed underneath."""
    root = tmp_path / "root"
    root.mkdir()
    source = tmp_path / "runme.sh"
    source.write_text("#!/bin/sh\n")
    source.chmod(0o755)
    target = root / "runme.sh"

    assert external.write_owned(target, b"#!/bin/sh\n", root,
                                mode_from=source) is None
    assert target.stat().st_mode & 0o777 == 0o755


def test_an_ordinary_write_still_lands(tmp_path):
    """The positive control for all of the above."""
    root = tmp_path / "root"
    root.mkdir()
    target = root / "deep" / "member.jsonl"

    assert external.write_owned(target, b"incoming\n", root) is None
    assert target.read_bytes() == b"incoming\n"
    assert external.write_owned(target, b"longer incoming\n", root) is None
    assert target.read_bytes() == b"longer incoming\n"


def test_a_named_pipe_where_a_member_lands_does_not_hang_the_pull(tmp_path):
    """The same question through the leg it actually reaches.

    external.owner_of is what the restore leg asks before it reads the local
    copy for ADR-0002's union rule, and it answered 'ours' about a fifo - so
    the read hung before the write was ever reached. CONTEXT.md already calls
    'a path this machine will not answer about' externally owned; this is that
    sentence applied to the one shape it had never been asked about.

    Under an alarm, because the failure this is about is not a wrong answer -
    it is no answer at all, for ever.
    """
    home = tmp_path / "home"
    project = home / ".claude" / "projects" / "p"
    project.mkdir(parents=True)
    fifo = project / "member.jsonl"
    os.mkfifo(str(fifo))

    status, owner = external.owner_of(fifo, home)
    assert status == external.EXTERNALLY_OWNED, \
        "a named pipe where a Transcript belongs was carryon's to write"
    assert "ordinary file" in str(owner), owner

    with time_limit(what="reading the local copy of a member never returned"):
        # Asked directly, because the guard above is the caller's and a
        # question closed only where somebody remembered to ask it is the
        # arrangement this round exists to end. What is asserted is that it
        # ANSWERS - the failure here was never a wrong verdict, it was no
        # verdict, for ever.
        history.member_verdict(fifo, b"incoming", home)
        assert external.write_owned(fifo, b"incoming", home) is not None
    assert stat.S_ISFIFO(fifo.lstat().st_mode), \
        "the pipe was replaced rather than deferred to"
